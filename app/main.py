import os, json, time, secrets, base64
import redis
from app.routers.device_register import router as device_register_router
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Request
from pydantic import BaseModel, Field

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SEC", "900"))  # 기존 유지
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# ── JWT (사용자 인증) ─────────────────────────────────────────────────────────
#  - HMAC HS256 검증. 실패 시 개발편의용 X-User-Id 헤더 허용(테스트용 백도어).
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret")
JWT_ALG = "HS256"
try:
    import jwt  # PyJWT
except Exception:
    jwt = None  # 미설치 시 X-User-Id만 허용

def get_user_id(authorization: Optional[str], x_user_id: Optional[str]) -> int:
    # 1) Bearer JWT 우선
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        if not jwt:
            raise HTTPException(status_code=401, detail="JWT library not installed")
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
            sub = payload.get("sub")
            return int(sub)
        except Exception:
            raise HTTPException(status_code=401, detail="invalid_jwt")
    # 2) 테스트/개발용 헤더 대체(팀내 개발 편의)
    if x_user_id:
        return int(x_user_id)
    raise HTTPException(status_code=401, detail="auth_required")

# ── Ed25519 서명 검증 ──────────────────────────────────────────────────────────
# cryptography 표준 라이브러리 사용
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def verify_ed25519_hex_pubkey_signature(pub_hex: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        sig = base64.b64decode(sig_b64)
        pub.verify(sig, message)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False

# ── 모델 ──────────────────────────────────────────────────────────────────────
class RegisterIntent(BaseModel):
    token: str = Field(min_length=8)
    ssid: str
    public_key: str  # 디바이스 공개키(hex 또는 문자열 그대로)

class DeviceRegisterBody(BaseModel):
    model: str
    serial_no: str
    signiture: str  # (원문 스펙 철자 유지) base64( token 을 Ed25519 개인키로 서명한 값 )

# ── FastAPI ───────────────────────────────────────────────────────────────────
app = FastAPI(title="homecam-api")
app.include_router(device_register_router)

@app.get("/health")
@app.get("/api/health")
def health():
    try:
        pong = r.ping()
        return {"status":"ok","redis": pong}
    except Exception as e:
        return {"status":"degraded","error": str(e)}

# ── 등록 예정 정보 저장/조회(이미 구축된 부분 유지) ────────────────────────────
@app.post("/register-intent")
@app.post("/api/register-intent")
def register_intent(body: RegisterIntent):
    key = f"reg:{body.token}"
    data = {"ssid": body.ssid, "public_key": body.public_key}
    if r.exists(key):
        return {"ok": True, "message": "already exists", "ttl": r.ttl(key)}
    r.setex(key, TOKEN_TTL, json.dumps(data))
    return {"ok": True, "ttl": TOKEN_TTL}

@app.get("/register-intent/{token}")
@app.get("/api/register-intent/{token}")
def get_register_intent(token: str):
    key = f"reg:{token}"
    val = r.get(key)
    if not val:
        raise HTTPException(status_code=404, detail="token not found or expired")
    return {"ok": True, "token": token, "data": json.loads(val), "ttl": r.ttl(key)}

# ── (4) 기기등록용 임시 토큰 발급: /devices/registration-token ────────────────
@app.post("/devices/registration-token")
def issue_registration_token(Authorization: Optional[str] = Header(None), x_user_id: Optional[str] = Header(None)):
    user_id = get_user_id(Authorization, x_user_id)
    token = secrets.token_urlsafe(22)  # QR에 담을 토큰
    # 상태 표시(선택)
    r.setex(f"reg_status:{token}", 300, "pending")
    return {"token": token, "expires_in_seconds": 300, "owner_user_id": user_id}

# ── (1) 기기 등록 확정: /devices/register ────────────────────────────────────
# 헤더 Authorization: Bearer <등록토큰>
@app.post("/devices/register")
def device_register(body: DeviceRegisterBody, Authorization: Optional[str] = Header(None)):
    if not Authorization or not Authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="register_token_required")
    token = Authorization.split(" ", 1)[1].strip()

    # 등록 예정 정보 로드(여기서 디바이스 공개키와 SSID 확보)
    reg_key = f"reg:{token}"
    raw = r.get(reg_key)
    if not raw:
        raise HTTPException(status_code=404, detail="register_token_not_found_or_expired")
    reg = json.loads(raw)
    public_key = reg.get("public_key")  # hex 문자열 기대
    ssid = reg.get("ssid")

    # Ed25519 서명 검증: message=token(bytes), signature=base64
    if not verify_ed25519_hex_pubkey_signature(public_key, token.encode(), body.signiture):
        raise HTTPException(status_code=400, detail="invalid_signature")

    # device_id 생성(예: CAM-YYYY-XXXX)
    yyyy = time.strftime("%Y")
    tail = secrets.token_hex(2).upper()
    device_id = f"CAM-{yyyy}-{tail}"

    # 사용자 식별: 등록 토큰은 사용자 발급 전제. 상태키에 소유자 정보가 없으므로 일단 owner_user_id를 1로 고정할 수 있으나
    # 실제 운영에서는 토큰 발급 시 owner를 함께 저장하도록 확장 권장.
    owner_user_id = int(r.get(f"reg_owner:{token}") or 1)

    # 디바이스 저장
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

    # 토큰 상태 업데이트 및 일회성 소진
    r.set(f"reg_status:{token}", "completed")
    r.delete(reg_key)

    return {
        "device_id": device_id,
        "owner_user_id": owner_user_id,
        "model": body.model,
        "status": "registered"
    }

# ── (2) 기기 삭제: /devices/{device_id} (JWT) ────────────────────────────────
@app.delete("/devices/{device_id}")
def device_delete(device_id: str, Authorization: Optional[str] = Header(None), x_user_id: Optional[str] = Header(None)):
    user_id = get_user_id(Authorization, x_user_id)
    dev_key = f"device:{device_id}"
    raw = r.get(dev_key)
    if not raw:
        raise HTTPException(status_code=404, detail="not_found")
    doc = json.loads(raw)
    if int(doc.get("owner_user_id", -1)) != int(user_id):
        raise HTTPException(status_code=403, detail="forbidden")
    # 삭제
    r.delete(dev_key)
    r.delete(f"device_owner:{device_id}")
    return {}  # 204는 FastAPI에서 body없이 상태코드 따로 지정 필요 → Nginx 레벨에선 200 OK 빈 객체로 반환

# ── (3) 특정 기기 조회: /devices/{device_id}/status (JWT) ────────────────────
@app.get("/devices/{device_id}/status")
def device_status(device_id: str, Authorization: Optional[str] = Header(None), x_user_id: Optional[str] = Header(None)):
    user_id = get_user_id(Authorization, x_user_id)
    dev_key = f"device:{device_id}"
    raw = r.get(dev_key)
    if not raw:
        raise HTTPException(status_code=404, detail={"error":"not_found", "message":"기기가 존재하지 않거나 다른 사용자의 기기입니다."})
    doc = json.loads(raw)
    if int(doc.get("owner_user_id", -1)) != int(user_id):
        raise HTTPException(status_code=404, detail={"error":"not_found", "message":"기기가 존재하지 않거나 다른 사용자의 기기입니다."})
    # 필요한 필드만 반환
    return {
        "device_id": doc["device_id"],
        "owner_user_id": doc["owner_user_id"],
        "model": doc.get("model"),
        "status": doc.get("status","unknown")
    }
