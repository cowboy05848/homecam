# app/routers/device_register.py
import os, json, time, secrets, base64
from typing import Optional
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import redis
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

# ── Redis 연결 ────────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# ── 요청 모델 ────────────────────────────────────────────────────────────────
class DeviceRegisterBody(BaseModel):
    model: str
    serial_no: str
    # 스펙 표기 유지(오타 포함): 토큰을 Ed25519 개인키로 서명한 값의 base64
    signiture: str

# ── 유틸 ─────────────────────────────────────────────────────────────────────
def verify_ed25519_hex_pubkey_signature(pub_hex: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig = base64.b64decode(sig_b64)
        pub.verify(sig, message)  # 예외 없으면 OK
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

# ── 라우터 ───────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/devices", tags=["devices"])

@router.post("/register")
def device_register(body: DeviceRegisterBody, Authorization: Optional[str] = Header(None)):
    """
    기기가 QR에서 읽은 토큰으로 자체 정보와 함께 등록.
    Auth: Authorization: Bearer <등록토큰>
    검증: reg:{token} 에 저장된 public_key 로 token 서명(signiture) 검증
    성공 시: device:{device_id} 저장 후 요약 반환
    """
    # 1) 토큰 추출
    if not Authorization or not Authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="register_token_required")
    token = Authorization.split(" ", 1)[1].strip()

    # 2) 등록 예정 정보 로드
    reg_key = f"reg:{token}"
    raw = r.get(reg_key)
    if not raw:
        raise HTTPException(status_code=404, detail="register_token_not_found_or_expired")
    reg = json.loads(raw)
    public_key = reg.get("public_key")  # HEX 문자열 기대
    ssid = reg.get("ssid")

    if not public_key or not ssid:
        raise HTTPException(status_code=400, detail="invalid_register_payload")

    # 3) 서명 검증 (message=token bytes, signature=base64)
    if not verify_ed25519_hex_pubkey_signature(public_key, token.encode(), body.signiture):
        raise HTTPException(status_code=400, detail="invalid_signature")

    # 4) device_id 생성 및 소유자 결정(토큰 발급 시 저장했다면 그 값, 없으면 1)
    yyyy = time.strftime("%Y")
    tail = secrets.token_hex(2).upper()
    device_id = f"CAM-{yyyy}-{tail}"
    owner_user_id = int(r.get(f"reg_owner:{token}") or 1)

    # 5) 디바이스 영구 저장 (Redis에 JSON 그대로)
    dev_key = f"device:{device_id}"
    device_doc = {
        "device_id": device_id,
        "owner_user_id": owner_user_id,
        "model": body.model,
        "serial_no": body.serial_no,
        "ssid": ssid,
        "public_key": public_key,
        "status": "registered",
        "registered_at": int(time.time())
    }
    r.set(dev_key, json.dumps(device_doc))
    r.set(f"device_owner:{device_id}", owner_user_id)

    # 6) 토큰 1회성 소진 처리
    r.set(f"reg_status:{token}", "completed")
    r.delete(reg_key)

    # 7) 사양에 맞는 요약 반환
    return {
        "device_id": device_id,
        "owner_user_id": owner_user_id,
        "model": body.model,
        "status": "registered"
    }
    # --- 기기 조회: /devices/{device_id}/status (JWT 또는 X-User-Id) ----------------
from fastapi import Header

def _get_user_id(authorization: str | None, x_user_id: str | None) -> int:
    # 간단 모드: JWT 대신 개발 편의용 X-User-Id 허용 (숫자만)
    if x_user_id:
        return int(x_user_id)
    if authorization and authorization.lower().startswith("bearer "):
        # 운영 시 JWT 검증 로직으로 교체 가능
        try:
            return int(authorization.split(" ",1)[1].strip())
        except Exception:
            pass
    raise HTTPException(status_code=401, detail="auth_required")

@router.get("/{device_id}/status")
def device_status(
    device_id: str,
    Authorization: str | None = Header(default=None),
    x_user_id: str | None = Header(default=None)
):
    user_id = _get_user_id(Authorization, x_user_id)
    dev_key = f"device:{device_id}"
    raw = r.get(dev_key)
    if not raw:
        raise HTTPException(
            status_code=404,
            detail={"error":"not_found","message":"기기가 존재하지 않거나 다른 사용자의 기기입니다."}
        )
    doc = json.loads(raw)
    if int(doc.get("owner_user_id",-1)) != int(user_id):
        raise HTTPException(
            status_code=404,
            detail={"error":"not_found","message":"기기가 존재하지 않거나 다른 사용자의 기기입니다."}
        )
    return {
        "device_id": doc["device_id"],
        "owner_user_id": doc["owner_user_id"],
        "model": doc.get("model"),
        "status": doc.get("status","unknown")
    }
    # --- 5) 등록 토큰 발급 API: POST /devices/registration-token --------------
import secrets
from fastapi import Depends

@router.post("/registration-token")
def issue_registration_token(x_user_id: str | None = Header(default=None)):
    """
    (임시 구현) 사용자 인증은 X-User-Id 로 대체.
    실제로는 JWT 인증으로 변경 필요.
    """
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")
    
    # 1) 랜덤 토큰 생성 (URL-safe)
    token = secrets.token_urlsafe(16)

    # 2) 5분(300초) 만료 Redis에 저장 (예: reg:토큰 → {} or 사용자 정보)
    r.setex(f"reg:{token}", 300, json.dumps({"owner_user_id": x_user_id}))

    return {
        "token": token,
        "expires_in_seconds": 300
    }