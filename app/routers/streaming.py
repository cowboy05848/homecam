import os
import json
from typing import Optional

import redis
import httpx
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

# DB
try:
    from app.db import fetch_vpn_by_device
except ImportError:
    from db import fetch_vpn_by_device

# ── Redis / 기본 설정 ────────────────────────────────────────────────────────
r = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    decode_responses=True,
)

router = APIRouter(prefix="/stream", tags=["stream"])

# MediaMTX SDP 교환용 URL
# 기본값: http://127.0.0.1:8889/whip
# 우리는 .env에 MEDIAMTX_SDP_URL=http://127.0.0.1:8889/mystream/whip 로 넣어둠
MEDIAMTX_SDP_URL = os.getenv(
    "MEDIAMTX_SDP_URL",
    "http://127.0.0.1:8889/whip",
)

# ── 스키마 ───────────────────────────────────────────────────────────────────


class StreamStartBody(BaseModel):
    device_id: str = Field(min_length=3)
    sdp_offer: str


class StreamStartResp(BaseModel):
    device_id: str
    sdp_answer: str


class MotionEventBody(BaseModel):
    device_id: str = Field(min_length=3)
    event_type: str = Field(min_length=1, description="e.g., motion, person, sound")
    timestamp: Optional[str] = None
    thumbnail_url: Optional[str] = None
    extra: Optional[dict] = None


# ── 공통 유틸 ────────────────────────────────────────────────────────────────


def _require_user(x_user_id: Optional[str]) -> int:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="auth_required")
    try:
        return int(x_user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_user_header")


# ── 1) 스트리밍 시작 (SDP offer → MediaMTX → SDP answer) ───────────────────


@router.post("/start", response_model=StreamStartResp)
async def stream_start(body: StreamStartBody, x_user_id: Optional[str] = Header(None)):
    """
    스트리밍 시작 엔드포인트 (/stream/start, POST, mTLS는 프록시(Nginx)에서 처리)

    요청 body 예시:
    {
      "device_id": "CAM-2025-0001",
      "sdp_offer": "v=0\\r\\n..."
    }

    동작:
    1) x_user_id로 사용자 인증
    2) device_id 기준으로 VPN 정보 조회 + 소유자/상태 확인
    3) sdp_offer를 MediaMTX(MEDIAMTX_SDP_URL)로 전달
    4) MediaMTX가 반환한 sdp_answer를 그대로 반환
    """
    user_id = _require_user(x_user_id)

    # 1) 디바이스/소유자/상태 확인 (VPN 정보 기준)
    rec = fetch_vpn_by_device(body.device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device_not_found")

    owner_user_id = int(rec.get("owner_user_id") or user_id)
    if owner_user_id != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    if rec["status"] not in ("active", "registered"):
        raise HTTPException(
            status_code=409,
            detail=f"device_not_active:{rec['status']}",
        )

    # 2) MediaMTX로 SDP offer 전달
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            url = MEDIAMTX_SDP_URL
            resp = await client.post(
                url,
                content=body.sdp_offer,
                headers={"Content-Type": "application/sdp"},
            )
    except Exception:
        raise HTTPException(status_code=502, detail="mediamtx_unreachable")

    if resp.status_code not in (200, 201):
        raise HTTPException(
            status_code=502,
            detail=f"mediamtx_bad_status_{resp.status_code}",
        )

    sdp_answer = resp.text.strip()
    if not sdp_answer:
        raise HTTPException(status_code=502, detail="empty_sdp_answer")

    return StreamStartResp(
        device_id=body.device_id,
        sdp_answer=sdp_answer,
    )


# ── 2) 모션 감지 이벤트 보고 ────────────────────────────────────────────────


@router.post("/motion-event")
def motion_event(body: MotionEventBody, x_user_id: Optional[str] = Header(None)):
    user_id = _require_user(x_user_id)

    rec = fetch_vpn_by_device(body.device_id)
    if not rec:
        raise HTTPException(status_code=404, detail="device_not_found")
    if int(rec.get("owner_user_id") or user_id) != user_id:
        raise HTTPException(status_code=403, detail="forbidden")

    list_key = f"motion_events:{body.device_id}"

    r.lpush(
        list_key,
        json.dumps(
            {
                "device_id": body.device_id,
                "event_type": body.event_type,
                "timestamp": body.timestamp,
                "thumbnail_url": body.thumbnail_url,
                "extra": body.extra,
                "reported_by": user_id,
            }
        ),
    )
    r.expire(list_key, 86400)  # 1일 보관

    return {"ok": True}
