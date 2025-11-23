import os
import json
from typing import Optional
from datetime import datetime

import redis
import httpx
from fastapi import APIRouter, HTTPException, Header, Request
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

# 스트리밍 관련 라우터
router = APIRouter(prefix="/stream", tags=["stream"])

# 모션 이벤트 / 알림 관련 라우터
event_router = APIRouter(prefix="/event", tags=["event"])

# MediaMTX SDP 교환용 URL
# 기본값: http://127.0.0.1:8889/whip
# 우리는 .env에 MEDIAMTX_SDP_URL=http://127.0.0.1:8889/mystream/whip 로 넣어둠
# 모션 이벤트를 API 서버로 전달하는 내부 API URL
# (실제 API 서버 주소에 맞게 .env 또는 여기 기본값을 조정하면 됨)
MEDIAMTX_SDP_URL = os.getenv(
    "MEDIAMTX_SDP_URL",
    "http://127.0.0.1:8889/whip",
)

MOTION_PUSH_API_URL = os.getenv(
    "MOTION_PUSH_API_URL",
    "http://127.0.0.1:8000/api/push/motion",  # 예시 URL
)

# ── 스키마 ───────────────────────────────────────────────────────────────────


class StreamStartBody(BaseModel):
    device_id: str = Field(min_length=3)
    sdp_offer: str


class StreamStartResp(BaseModel):
    device_id: str
    sdp_answer: str


class MotionNotifyBody(BaseModel):
    # 예: "2025-10-18T13:00:30Z"
    detected_at: datetime


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


@event_router.post("/notify", status_code=204)
async def motion_notify(body: MotionNotifyBody, request: Request):
    """
    모션 감지 시 IPcam이 스트리밍 서버에게 호출하는 API

    요구사항:
    - 초기 인증 이후, 추가 인증 없음 (VPN 터널 + HTTPS로 보호)
    - body: { "detected_at": "2025-10-18T13:00:30Z" }
    - 내부적으로 스트리밍 서버가 API 서버에 푸시 알림 전달 API 호출
    - API 서버가 해당 기기/사용자 없으면 404 not_found 반환

    동작:
    1) VPN 터널을 통해 들어온 IPcam의 IP(요청 IP)를 확인
    2) API 서버(MOTION_PUSH_API_URL)로 모션 이벤트 전달
    3) API 서버 응답에 따라 404 또는 204로 응답
    """

    # 1) 요청을 보낸 IPcam의 IP 주소 (VPN에서 할당된 10.8.0.x 등이 올 것)
    source_ip = request.client.host

    # 2) API 서버에 모션 이벤트 전달
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                MOTION_PUSH_API_URL,
                json={
                    "source_ip": source_ip,
                    "detected_at": body.detected_at.isoformat(),
                },
            )
    except Exception:
        # API 서버에 아예 접속이 안 되는 경우 등
        raise HTTPException(status_code=502, detail="push_api_unreachable")

    # 3) API 서버의 응답 코드에 따라 처리
    if resp.status_code == 404:
        # 요구사항: "해당 기기 또는 사용자 없음" → 404 not_found
        raise HTTPException(status_code=404, detail="not_found")

    if resp.status_code not in (200, 201, 204):
        # 그 외 에러는 502로 래핑
        raise HTTPException(
            status_code=502,
            detail=f"push_api_failed:{resp.status_code}",
        )

    # 성공(200/201/204)이면 이 API는 204 No Content 반환
    return
