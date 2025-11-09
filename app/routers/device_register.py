# app/routers/device_register.py

import os
import json
import time
import secrets
import base64
from typing import Optional

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# ───────────────── Redis 연결 ─────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# ───────────────── 유틸 ─────────────────
def _get_device_doc(dev_key: str):
    """
    device:{id} 가 Redis에 hash 또는 string(JSON)으로 저장됐더라도
    동일하게 dict로 반환한다. 없으면 None.
    """
    t = r.type(dev_key)
    if isinstance(t, bytes):  # 안전 보정
        t = t.decode()

    if t == "hash":
        data = r.hgetall(dev_key)
        if not data:
            return None
        # 숫자 필드 정리
        if "owner_user_id" in data:
            try:
                data["owner_user_id"] = int(data["owner_user_id"])
            except:
                pass
        if "registered_at" in data:
            try:
                data["registered_at"] = int(data["registered_at"])
            except:
                pass
        return data

    if t == "string":
        raw = r.get(dev_key)
        if not raw:
            return None
        try:
            data = json.loads(raw)
            return data
        except Exception:
            return None

    return None


def verify_ed25519_hex_pubkey_signature(pub_hex: str, message: bytes, sig_b64: str) -> bool:
    """
    Ed25519 공개키(hex)로 message에 대해 base64 서명을 검증한다.
    """
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig = base64.b64decode(sig_b64)
        pub.verify(sig, message)  # 예외 없으면 검증 성공
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ───────────────── 요청 모델 ─────────────────
class DeviceRegisterBody(BaseModel):
    model: str
    serial_no: str
    # 명세 표기 유지(오타 포함): 토큰을 Ed25519 개인키로 서명한 값의 base64
    signiture: str


# ───────────────── 라우터 ─────────────────
router = APIRouter(prefix="/devices", tags=["devices"])


# (공통) 인증 추출: 운영에서는 JWT 검증 교체 예정
def _get_user_id(authorization: Optional[str], x_user_id: Optional[str]) -> int:
    if x_user_id:
        return int(x_user_id)
    if authorization and authorization.lower().startswith("bearer "):
        try:
            return int(authorization.split(" ", 1)[1].strip())
        except Exception:
            pass
    raise HTTPException(status_code=401, detail="auth_required")


# ✅ 1) 기기 등록
@router.post("/register")
def device_register(body: DeviceRegisterBody, Authorization: Optional[str] = Header(None)):
    # 1) 등록 토큰 추출
    if not Authorization or not Authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="register_token_required")
    token = Authorization.split(" ", 1)[1].strip()

    # 2) 등록 예정 정보 조회
    reg_key = f"reg:{token}"
    raw = r.get(reg_key)
    if not raw:
        raise HTTPException(status_code=404, detail="register_token_not_found_or_expired")

    try:
        reg = json.loads(raw)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_register_payload")

    public_key = reg.get("public_key")     # HEX 문자열 기대
    ssid = reg.get("ssid")
    owner_user_id = int(reg.get("owner_user_id", 1))
    if not public_key or not ssid:
        raise HTTPException(status_code=400, detail="invalid_register_payload")

    # 3) 서명 검증 (message=token bytes, signature=base64)
    if not verify_ed25519_hex_pubkey_signature(public_key, token.encode(), body.signiture):
        raise HTTPException(status_code=400, detail="invalid_signature")

    # 4) device_id 생성
    yyyy = time.strftime("%Y")
    tail = secrets.token_hex(2).upper()
    device_id = f"CAM-{yyyy}-{tail}"

    # 5) 디바이스 영구 저장 (Hash)
    dev_key = f"device:{device_id}"
    now_ts = int(time.time())
    r.hset(dev_key, mapping={
        "device_id": device_id,
        "owner_user_id": owner_user_id,
        "model": body.model,
        "serial_no": body.serial_no,
        "ssid": ssid,
        "public_key": public_key,
        "status": "registered",
        "registered_at": now_ts,
    })
    r.set(f"device_owner:{device_id}", owner_user_id)

    # 6) 토큰 소진
    r.set(f"reg_status:{token}", "completed")
    r.delete(reg_key)

    # 7) 응답
    return {
        "device_id": device_id,
        "owner_user_id": owner_user_id,
        "model": body.model,
        "status": "registered",
    }


# ✅ 2) 기기 조회
@router.get("/{device_id}/status")
def device_status(device_id: str,
                  Authorization: Optional[str] = Header(None),
                  x_user_id: Optional[str] = Header(None)):
    user_id = _get_user_id(Authorization, x_user_id)

    dev_key = f"device:{device_id}"
    doc = _get_device_doc(dev_key)
    if not doc or int(doc.get("owner_user_id", -1)) != user_id:
        raise HTTPException(
            status_code=404,
            detail={"error": "not_found", "message": "기기가 존재하지 않거나 다른 사용자의 기기입니다."}
        )

    return {
        "device_id": doc.get("device_id"),
        "owner_user_id": doc.get("owner_user_id"),
        "model": doc.get("model"),
        "status": doc.get("status", "unknown"),
    }


# ✅ 3) 등록 토큰 발급
@router.post("/registration-token")
def issue_registration_token(x_user_id: Optional[str] = Header(None)):
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")

    token = secrets.token_urlsafe(16)  # URL-safe
    # 토큰에는 최소한 owner_user_id를 저장. (public_key/ssid는 클라이언트가 이후 등록 요청에서 사용)
    r.setex(f"reg:{token}", 3000, json.dumps({"owner_user_id": x_user_id}))
    return {"token": token, "expires_in_seconds": 3000}


# ✅ 4) 기기 삭제 (string/hash 모두 지원)
@router.delete("/{device_id}")
def device_delete(device_id: str,
                  Authorization: Optional[str] = Header(None),
                  x_user_id: Optional[str] = Header(None)):
    user_id = _get_user_id(Authorization, x_user_id)

    dev_key = f"device:{device_id}"
    key_type = r.type(dev_key)
    if isinstance(key_type, bytes):  # 안전 보정
        key_type = key_type.decode()

    # 저장 타입별로 문서 추출
    if key_type == "string":
        raw = r.get(dev_key)
        if not raw:
            raise HTTPException(status_code=404, detail="not_found")
        try:
            doc = json.loads(raw)
        except Exception:
            raise HTTPException(status_code=500, detail="invalid_data_format")

    elif key_type == "hash":
        doc = r.hgetall(dev_key)
        if not doc:
            raise HTTPException(status_code=404, detail="not_found")

    else:
        # 키 자체가 없거나 비정상 타입
        raise HTTPException(status_code=404, detail="not_found")

    # 소유자 검증 (owner_user_id가 문자열이더라도 안전 변환)
    try:
        owner = int(doc.get("owner_user_id", -1))
    except Exception:
        raise HTTPException(status_code=500, detail="invalid_owner_field")

    if owner != int(user_id):
        raise HTTPException(status_code=403, detail="forbidden")

    # 실제 삭제
    r.delete(dev_key)
    r.delete(f"device_owner:{device_id}")
    return {}