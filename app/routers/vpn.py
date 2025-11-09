import os
import json
import base64
from typing import Optional
from datetime import datetime, timezone

import redis
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

from app.db import (
    init_db, upsert_vpn, fetch_assigned_ips, mark_vpn_removed,
    fetch_owner_user_id
)

# --- IPC to wgdaemon (no subprocess in FastAPI) ---
import socket as _sock
import json as _json

WG_SOCK_PATH = "/run/wgdaemon/wg.sock"

def _wg_ipc(action: str, payload: dict) -> None:
    req = {"action": action, **payload}
    data = _json.dumps(req).encode("utf-8")
    try:
        with _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM) as s:
            s.connect(WG_SOCK_PATH)
            s.sendall(data)
            resp_raw = s.recv(4096)
    except Exception:
        raise HTTPException(status_code=502, detail="wg_ipc_unreachable")
    try:
        resp = _json.loads(resp_raw.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=502, detail="wg_ipc_bad_json")
    if not resp.get("ok"):
        err = resp.get("error", "wg_ipc_failed")
        raise HTTPException(status_code=502, detail=err)

# ── 초기화 ─────────────────────────────────────────────────────────────────────
init_db()
r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

router = APIRouter(prefix="/vpn", tags=["vpn"])

# 서버/네트워크 기본값
SERVER_ENDPOINT = os.getenv("VPN_SERVER_ENDPOINT", "18.222.191.20:51820")
SERVER_WG_PUBKEY_B64 = os.getenv("VPN_SERVER_PUBKEY_B64", "SERVER_WG_PUBKEY_BASE64")
IP_NET = os.getenv("VPN_NET_PREFIX", "10.8.0.")
IP_START = int(os.getenv("VPN_IP_START_HOST", "2"))
IP_END = int(os.getenv("VPN_IP_END_HOST", "254"))

# ── 유틸 ───────────────────────────────────────────────────────────────────────
def _require_user(x_user_id: Optional[str]) -> int:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")
    try:
        return int(x_user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_user_header")

def _b64u_decode(s: str) -> bytes:
    s = (s or "").strip()
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        return base64.urlsafe_b64decode(s.encode("utf-8"))
    except Exception:
        raise ValueError("bad_base64")

def _verify_ed25519_b64(pubkey_b64u: str, message: bytes, sig_b64u: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    try:
        pub_bytes = _b64u_decode(pubkey_b64u)
        if len(pub_bytes) != 32:
            return False
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig = _b64u_decode(sig_b64u)
        if len(sig) != 64:
            return False
        pub.verify(sig, message)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

def _alloc_ip(used: set[str]) -> str:
    used_hosts = {int(ip.split(".")[-1].split("/")[0]) for ip in used if ip.startswith(IP_NET)}
    for host in range(IP_START, IP_END + 1):
        cidr = f"{IP_NET}{host}/32"
        if host not in used_hosts and cidr not in used:
            return cidr
    raise HTTPException(status_code=503, detail="no_available_ip")

def _parse_ts_rfc3339(s: str) -> datetime:
    # 허용 형식 예: "2025-11-09T18:35:10Z" 또는 소수점 포함
    if not s or not isinstance(s, str):
        raise ValueError("bad_timestamp")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        raise ValueError("bad_timestamp")
    if dt.tzinfo is None:
        raise ValueError("bad_timestamp_tz")
    return dt.astimezone(timezone.utc)

# ── 스키마 ────────────────────────────────────────────────────────────────────
class BeCreateInfoBody(BaseModel):
    device_id: str = Field(min_length=3)
    device_pubkey_b64: str        # Ed25519 공개키 (URL-safe Base64)
    registration_token: str

class CreateTunnelBody(BaseModel):
    device_id: str
    timestamp: str                # RFC3339(UTC) 권장: e.g., 2025-11-09T18:35:10Z
    registration_token: str
    signature_b64: str            # Ed25519 개인키로 "device_id|timestamp|token" 서명 (URL-safe Base64)
    client_pubkey_b64: str        # WireGuard 클라이언트 공개키 (URL-safe Base64)

# ── 1) 터널 생성 예정 정보 저장 ────────────────────────────────────────────────
@router.post("/tunnels/be_create_info")
def be_create_info(body: BeCreateInfoBody, x_user_id: Optional[str] = Header(None)):
    user_id = _require_user(x_user_id)

    reg_key = f"reg:{body.registration_token}"
    ttl = r.ttl(reg_key)
    if ttl is None or ttl <= 0:
        raise HTTPException(status_code=404, detail="register_token_not_found_or_expired")

    # 공개키 형식 점검
    try:
        if len(_b64u_decode(body.device_pubkey_b64)) != 32:
            raise ValueError()
    except Exception:
        raise HTTPException(status_code=400, detail="bad_device_pubkey")

    # 의도 저장
    intent_key = f"vpn_intent:{body.device_id}"
    payload = {
        "device_id": body.device_id,
        "device_pubkey_b64": body.device_pubkey_b64,
        "registration_token": body.registration_token,
        "owner_user_id": user_id,
    }
    r.setex(intent_key, ttl, json.dumps(payload))
    return {"ok": True, "device_id": body.device_id, "ttl": ttl}

# ── 2) 터널 생성 ───────────────────────────────────────────────────────────────
@router.post("/tunnels/create")
def vpn_create(body: CreateTunnelBody, x_user_id: Optional[str] = Header(None)):
    user_id = _require_user(x_user_id)

    # 2-1) 의도 로드
    intent_key = f"vpn_intent:{body.device_id}"
    raw = r.get(intent_key)
    if not raw:
        raise HTTPException(status_code=404, detail="intent_not_found_or_expired")
    intent = json.loads(raw)
    token = intent.get("registration_token")
    device_pubkey_b64 = intent.get("device_pubkey_b64")
    owner_user_id = int(intent.get("owner_user_id") or user_id)

    # 2-2) 토큰 존재/재사용 차단 (SETNX used:token)
    if token != body.registration_token:
        raise HTTPException(status_code=400, detail="token_mismatch")
    reg_key = f"reg:{token}"
    if not r.exists(reg_key):
        # 토큰이 없거나 만료되었음
        raise HTTPException(status_code=404, detail="register_token_not_found_or_expired")
    # 재사용 차단(최초 1회 성공만 허용)
    if not r.setnx(f"used:{token}", 1):
        raise HTTPException(status_code=409, detail="token_reused")
    r.expire(f"used:{token}", 600)  # 사용 흔적 10분 유지
    r.delete(reg_key)               # 원 토큰 제거(단일 사용 보장)

    # 2-3) timestamp 신선도 검증(±5분)
    try:
        ts = _parse_ts_rfc3339(body.timestamp)
    except ValueError:
        raise HTTPException(status_code=400, detail="bad_timestamp")
    now = datetime.now(timezone.utc)
    skew = abs((now - ts).total_seconds())
    if skew > 300:
        raise HTTPException(status_code=400, detail="timestamp_out_of_range")

    # 서명 검증 (message = device_id|timestamp|token)
    msg = f"{body.device_id}|{body.timestamp}|{body.registration_token}".encode()
    if not _verify_ed25519_b64(device_pubkey_b64, msg, body.signature_b64):
        raise HTTPException(status_code=400, detail="invalid_signature")


    # 2-5) IP 할당
    used = fetch_assigned_ips()
    assigned_ip = _alloc_ip(used)
    allowed_ip = assigned_ip

    # 2-6) WireGuard 적용(IPC)
    _wg_ipc("add_peer", {
        "device_id": body.device_id,
        "client_pubkey_b64": body.client_pubkey_b64,
        "ip_cidr": allowed_ip
    })

    # 2-7) DB 저장 & intent 1회성 제거
    upsert_vpn(
        device_id=body.device_id,
        owner_user_id=owner_user_id,
        client_pubkey=body.client_pubkey_b64,
        assigned_ip=assigned_ip,
        allowed_ip=allowed_ip,
        status="registered",
    )
    r.delete(intent_key)

    return {
        "device_id": body.device_id,
        "status": "registered",
        "tunnel": {
            "server_vpn_pubkey": SERVER_WG_PUBKEY_B64,
            "server_endpoint": SERVER_ENDPOINT,
            "allowed_ips": allowed_ip,
            "persistent_keepalive": 25,
        },
    }

# ── 3) 터널 삭제(204) ─────────────────────────────────────────────────────────
@router.delete("/tunnels/{device_id}", status_code=204)
def vpn_delete_tunnel(device_id: str, x_user_id: Optional[str] = Header(None)):
    user_id = _require_user(x_user_id)
    owner = fetch_owner_user_id(device_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="not_found")
    if int(owner) != int(user_id):
        raise HTTPException(status_code=403, detail="forbidden")
    _wg_ipc("remove_peer", {"device_id": device_id})
    mark_vpn_removed(device_id)
    return
