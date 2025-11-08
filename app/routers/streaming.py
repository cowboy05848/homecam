# /home/ubuntu/homecam-api/app/routers/streaming.py
import os
import json
import ipaddress
import subprocess
from typing import Optional

import redis
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

from app.db import fetch_vpn_by_device

# ────────────────────────────────── Redis 연결 ─────────────────────────────────
r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)

router = APIRouter(prefix="/stream", tags=["stream"])

# ────────────────────────────────── 설정 ───────────────────────────────────────
STREAM_SERVER_URL = os.getenv("STREAM_SERVER_URL", "http://127.0.0.1:9000")
STREAM_SESSION_TTL = int(os.getenv("STREAM_SESSION_TTL", "600"))  # 10분

# ────────────────────────────────── 스키마 ─────────────────────────────────────
class StreamStartBody(BaseModel):
    device_id: str = Field(min_length=3)

class StreamStartResp(BaseModel):
    device_id: str
    session_id: str
    assigned_ip: str
    stream_url: str
    expires_in: int

class MotionEventBody(BaseModel):
    device_id: str = Field(min_length=3)
    event_type: str = Field(min_length=1, description="e.g., motion, person, sound")
    timestamp: Optional[str] = Field(default=None, description="ISO8601 or epoch(ms)")
    thumbnail_url: Optional[str] = None
    extra: Optional[dict] = None

# ────────────────────────────────── 1) 스트리밍 시작 ───────────────────────────
@router.post("/start", response_model=StreamStartResp)
def stream_start(body: StreamStartBody, x_user_id: Optional[str] = Header(None)):
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")

    # 1) 해당 디바이스의 VPN 상태/내부 IP 확인
    rec = fetch_vpn_by_device(body.device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device_not_found")
    if rec["status"] not in ("active", "registered"):
        raise HTTPException(status_code=409, detail=f"device_not_active:{rec['status']}")

    assigned_ip = rec["assigned_ip"]  # 예: 10.8.0.X/32
    ip_only = assigned_ip.split("/")[0]

    # 2) 세션 ID 생성 (간단 키)
    import secrets
    session_id = secrets.token_urlsafe(16)

    # 3) 스트리밍 서버 호출(실서버 연동 전인 경우 생략)
    # 여기서는 "스트리밍 서버가 해당 내부 IP로 캡쳐/프록시를 시작한다"는 가정을 하고,
    # 실제 호출 대신 Redis에 세션만 기록한다.
    sess_key = f"stream_session:{body.device_id}"
    sess_val = {
        "device_id": body.device_id,
        "owner_user_id": int(x_user_id),
        "assigned_ip": assigned_ip,
        "session_id": session_id
    }
    r.setex(sess_key, STREAM_SESSION_TTL, json.dumps(sess_val))

    # 4) 클라이언트가 재생할 URL 템플릿 반환
    # (실제 연동 시, 스트리밍 서버 게이트웨이 URL/토큰 등으로 교체)
    stream_url = f"{STREAM_SERVER_URL}/play/{session_id}?target={ip_only}"

    return StreamStartResp(
        device_id=body.device_id,
        session_id=session_id,
        assigned_ip=assigned_ip,
        stream_url=stream_url,
        expires_in=STREAM_SESSION_TTL
    )

# ────────────────────────────────── 2) 모션 이벤트 수신 ────────────────────────
@router.post("/motion-event")
def motion_event(body: MotionEventBody, x_user_id: Optional[str] = Header(None)):
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")

    # 디바이스 존재/소유 확인(간단히 존재만 체크)
    rec = fetch_vpn_by_device(body.device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device_not_found")

    # 이벤트를 Redis 리스트로 적재(운영 시 알림 서비스와 연동)
    list_key = f"motion_events:{body.device_id}"
    r.lpush(list_key, json.dumps({
        "device_id": body.device_id,
        "event_type": body.event_type,
        "timestamp": body.timestamp,
        "thumbnail_url": body.thumbnail_url,
        "extra": body.extra,
        "reported_by": int(x_user_id)
    }))
    # 보관기간: 리스트 키에 TTL 부여(예: 1일)
    r.expire(list_key, 86400)

    return {"ok": True}
