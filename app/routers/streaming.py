import os, json
from typing import Optional
import redis
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

try:
    from app.db import fetch_vpn_by_device
except ImportError:
    from db import fetch_vpn_by_device

r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
router = APIRouter(prefix="/stream", tags=["stream"])

STREAM_SERVER_URL  = os.getenv("STREAM_SERVER_URL", "http://127.0.0.1:9000")
STREAM_SESSION_TTL = int(os.getenv("STREAM_SESSION_TTL", "600"))

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
    timestamp: Optional[str] = None
    thumbnail_url: Optional[str] = None
    extra: Optional[dict] = None

def _require_user(x_user_id: Optional[str]) -> int:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")
    try:
        return int(x_user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_user_header")

@router.post("/start", response_model=StreamStartResp)
def stream_start(body: StreamStartBody, x_user_id: Optional[str] = Header(None)):
    user_id = _require_user(x_user_id)

    rec = fetch_vpn_by_device(body.device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device_not_found")
    if int(rec.get("owner_user_id") or user_id) != user_id:
        raise HTTPException(status_code=403, detail="forbidden")
    if rec["status"] not in ("active", "registered"):
        raise HTTPException(status_code=409, detail=f"device_not_active:{rec['status']}")

    assigned_ip = rec["assigned_ip"]
    ip_only = assigned_ip.split("/")[0]

    import secrets
    session_id = secrets.token_urlsafe(16)

    sess_key = f"stream_session:{body.device_id}"
    sess_val = {
        "device_id": body.device_id,
        "owner_user_id": user_id,
        "assigned_ip": assigned_ip,
        "session_id": session_id
    }
    r.setex(sess_key, STREAM_SESSION_TTL, json.dumps(sess_val))

    stream_url = f"{STREAM_SERVER_URL}/play/{session_id}?target={ip_only}"

    return StreamStartResp(
        device_id=body.device_id,
        session_id=session_id,
        assigned_ip=assigned_ip,
        stream_url=stream_url,
        expires_in=STREAM_SESSION_TTL
    )

@router.post("/motion-event")
def motion_event(body: MotionEventBody, x_user_id: Optional[str] = Header(None)):
    user_id = _require_user(x_user_id)

    rec = fetch_vpn_by_device(body.device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device_not_found")
    if int(rec.get("owner_user_id") or user_id) != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    list_key = f"motion_events:{body.device_id}"
    r.lpush(list_key, json.dumps({
        "device_id": body.device_id,
        "event_type": body.event_type,
        "timestamp": body.timestamp,
        "thumbnail_url": body.thumbnail_url,
        "extra": body.extra,
        "reported_by": user_id
    }))
    r.expire(list_key, 86400)
    return {"ok": True}
