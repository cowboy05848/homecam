# /home/ubuntu/homecam-api/app/routers/vpn.py
import os, json
from typing import Optional
import redis
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel

r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

router = APIRouter(prefix="/vpn/tunnels", tags=["vpn"])

class BeCreateInfoBody(BaseModel):
    device_id: str                    # "CAM-2025-0001"
    device_pubkey: str                # Ed25519 공개키 (base64)
    registration_token: str           # 토큰 원문

@router.post("/be_create_info")
def be_create_info(body: BeCreateInfoBody, x_user_id: Optional[str] = Header(None)):
    # 1) 등록토큰 유효성 (Redis의 reg:{token} 남은 TTL 사용)
    reg_key = f"reg:{body.registration_token}"
    ttl = r.ttl(reg_key)
    if ttl is None or ttl <= 0:
        raise HTTPException(status_code=404, detail="register_token_not_found_or_expired")

    # 2) device_id를 PK처럼 임시저장 (TTL = 등록토큰 TTL)
    key = f"vpn:be_create_info:{body.device_id}"
    payload = {
        "device_id": body.device_id,
        "device_pubkey_b64": body.device_pubkey,
        "registration_token": body.registration_token,
        "owner_user_id": int(x_user_id) if x_user_id else None
    }
    r.setex(key, ttl, json.dumps(payload))

    return {"ok": True, "device_id": body.device_id, "ttl": ttl}