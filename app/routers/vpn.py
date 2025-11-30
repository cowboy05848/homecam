import os, json, base64, time, socket as _sock
from typing import Optional
#11.12 코드업로드체크
import redis
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

# DB
try:
    from app.db import init_db, upsert_vpn, fetch_assigned_ips, mark_vpn_removed, fetch_owner_user_id
except ImportError:
    from app.db import init_db, upsert_vpn, fetch_assigned_ips, mark_vpn_removed, fetch_owner_user_id

# ── 설정/연결 ──────────────────────────────────────────────────────────────────
init_db()
r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

router = APIRouter(prefix="/vpn", tags=["vpn"])

SERVER_ENDPOINT = os.getenv("VPN_SERVER_ENDPOINT", "3.134.103.130:51820")
SERVER_WG_PUBKEY_B64 = os.getenv("VPN_SERVER_PUBKEY_B64", "SERVER_WG_PUBKEY_BASE64")
WG_SOCK_PATH = os.getenv("WG_SOCK_PATH", "/run/wgdaemon/wg.sock")

IP_NET = os.getenv("VPN_NET_PREFIX", "10.8.0.")
IP_START = int(os.getenv("VPN_IP_START_HOST", "2"))
IP_END   = int(os.getenv("VPN_IP_END_HOST", "254"))
FALLBACK_INTENT_TTL = int(os.getenv("INTENT_TTL_DEFAULT", "3000"))  # JWT 아님/exp 없음 폴백

# ── 유틸 ───────────────────────────────────────────────────────────────────────
def _require_user(x_user_id: Optional[str]) -> int:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")
    try:
        return int(x_user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_user_header")

import base64

def _b64_decode(s: str) -> bytes:
    if isinstance(s, str):
        s = s.encode()

    # Base64는 padding 없어도 decode 가능하게 보정할 수 있음
    s = s + b"=" * ((4 - len(s) % 4) % 4)

    return base64.b64decode(s)



def _verify_ed25519_b64(pubkey_b64: str, message: bytes, sig_b64: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    # Base64 decode 단계 에러 구분
    try:
        pub = _b64_decode(pubkey_b64)
        sig = _b64_decode(sig_b64)
    except (binascii.Error, ValueError, Exception):
        # 패딩/문자 깨진 경우 여기로
        raise HTTPException(status_code=400, detail="invalid_base64")

    # Ed25519 검증
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="invalid_signature")
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid_pubkey_format")
    except Exception:
        raise HTTPException(status_code=400, detail="verify_failed")

def _alloc_ip(used: set[str]) -> str:
    used_hosts = {int(ip.split(".")[-1].split("/")[0]) for ip in used if ip.startswith(IP_NET)}
    for host in range(IP_START, IP_END + 1):
        cidr = f"{IP_NET}{host}/32"
        if host not in used_hosts and cidr not in used:
            return cidr
    raise HTTPException(status_code=503, detail="no_available_ip")

def _wg_ipc(action: str, payload: dict) -> None:
    req = {"action": action, **payload}
    data = json.dumps(req).encode()
    try:
        with _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM) as s:
            s.connect(WG_SOCK_PATH)
            s.sendall(data)
            resp_raw = s.recv(4096)
    except Exception:
        raise HTTPException(status_code=502, detail="wg_ipc_unreachable")
    try:
        resp = json.loads(resp_raw.decode())
    except Exception:
        raise HTTPException(status_code=502, detail="wg_ipc_bad_json")
    if not resp.get("ok"):
        raise HTTPException(status_code=502, detail=resp.get("error", "wg_ipc_failed"))

# JWT 파싱(있으면 exp/iat/typ 확인, 없으면 허용)
def _parse_registration_token(token: str) -> dict:
    """
    - HS256 서명 JWT면 exp/iat/typ 검사
    - 그 외(서명 없음/랜덤 스트링 등)는 구조 검증 생략하고 빈 dict 반환
    """
    import jwt
    REG_TOKEN_SECRET = os.getenv("REG_TOKEN_SECRET")
    try:
        if REG_TOKEN_SECRET:
            claims = jwt.decode(
                token,
                REG_TOKEN_SECRET,
                algorithms=["HS256"],
                options={"require": ["exp", "iat"]},
                leeway=300,
            )
            # typ이 있으면 registration 권장
            if claims.get("typ") and claims["typ"] != "registration":
                raise HTTPException(status_code=400, detail="token_typ_invalid")
            return claims
        else:
            # 서명 미검증 모드: 구조만 보려 시도, 실패해도 통과
            try:
                return jwt.decode(token, options={"verify_signature": False})
            except Exception:
                return {}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token_expired")
    except jwt.InvalidTokenError:
        # 진짜 JWT인데 검증 실패인 경우
        raise HTTPException(status_code=400, detail="token_invalid")

# ── 스키마 ────────────────────────────────────────────────────────────────────
class BeCreateInfoBody(BaseModel):
    device_id: str = Field(min_length=3)
    device_pubkey: str          # ← 이름 변경
    registration_token: Optional[str] = None  # 헤더/바디 모두 지원

class CreateTunnelBody(BaseModel):
    device_id: str
    registration_token: str                # 토큰 원문
    signature: str                         # Ed25519 서명(base64, 토큰 원문 기준)
    client_public_key: str                 # WireGuard 공개키(base64, X25519)

# ── 1) 터널 생성 예정 정보 저장 ───────────────────────────────────────────────
@router.post("/tunnels/be_create_info")
def be_create_info(
    body: BeCreateInfoBody,
    authorization: Optional[str] = Header(None),
):
    # 토큰 추출: Authorization > body
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif body.registration_token:
        token = body.registration_token
    if not token:
        raise HTTPException(status_code=400, detail="registration_token_required")

    # JWT면 exp 사용, 아니면 폴백 TTL
    claims = {}
    try:
        claims = _parse_registration_token(token)
    except HTTPException as e:
        # JWT가 아닌 랜덤 토큰 환경도 있을 수 있으므로 token_invalid만 특별히 허용하지 않고 그대로 올림
        if e.detail == "token_invalid":
            raise
        else:
            raise

    now = int(time.time())
    print(f"[DEBUG] now={now}")

    if "exp" in claims:
        exp_val = int(claims["exp"])
        ttl = exp_val - now

        print(f"[DEBUG] exp={exp_val}")
        print(f"[DEBUG] calculated ttl (exp-now)={ttl}")

        if ttl <= 0:
            print("[DEBUG] token_expired detected")
            raise HTTPException(status_code=401, detail="token_expired")
    else:
        ttl = FALLBACK_INTENT_TTL
        print(f"[DEBUG] no exp in claims → TTL={ttl}")

    intent_key = f"vpn_intent:{body.device_id}"
    payload = {
        "device_id": body.device_id,
        "device_pubkey_b64": body.device_pubkey,  # ← 여기 body.device_pubkey 로 변경
        "registration_token": token,
        "jti": claims.get("jti"),
        "iss": claims.get("iss"),
        "iat": claims.get("iat"),
        "exp": claims.get("exp"),
    }
    r.setex(intent_key, ttl, json.dumps(payload))
    return {"ok": True, "device_id": body.device_id, "ttl": ttl}

# ── 2) 터널 생성 ───────────────────────────────────────────────────────────────
@router.post("/tunnels/create")
def vpn_create(body: CreateTunnelBody):

    intent_key = f"vpn_intent:{body.device_id}"
    raw = r.get(intent_key)
    if not raw:
        raise HTTPException(status_code=404, detail="intent_not_found_or_expired")

    intent = json.loads(raw)
    token = intent.get("registration_token")
    device_pubkey_b64 = intent.get("device_pubkey_b64")

    # 토큰 일치 확인
    if token != body.registration_token:
        raise HTTPException(status_code=400, detail="token_mismatch")

    # JWT인 경우 만료 다시 체크(서버시간 드리프트 대비)
    try:
        _ = _parse_registration_token(body.registration_token)
    except HTTPException as e:
        if e.detail in ("token_expired", "token_invalid"):
            raise

    # 서명 검증: registration_token(토큰 원문)만 서명 대상으로 사용
    msg = body.registration_token.encode()
    if not _verify_ed25519_b64(device_pubkey_b64, msg, body.signature):
        raise HTTPException(status_code=400, detail="invalid_signature")

    # IP 할당
    used = fetch_assigned_ips()
    assigned_ip = _alloc_ip(used)
    allowed_ip = assigned_ip

    # wgdaemon IPC 호출
    _wg_ipc("add_peer", {
    "device_id": body.device_id,
    "client_pubkey_b64": body.client_public_key,   # 필드 이름 변경 반영
    "ip_cidr": allowed_ip
    })

# DB upsert
    upsert_vpn(
    device_id=body.device_id,
    client_pubkey=body.client_public_key,          # 여기서도 변경
    assigned_ip=assigned_ip,
    allowed_ip=allowed_ip,
    status="registered",
    )


    # intent 사용 후 삭제
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
def vpn_delete_tunnel(device_id: str):
    owner = fetch_owner_user_id(device_id)
    if owner is None:
        raise HTTPException(status_code=404, detail="not_found")

    _wg_ipc("remove_peer", {"device_id": device_id})
    mark_vpn_removed(device_id)
    return
