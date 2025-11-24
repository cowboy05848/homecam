# app/routers/auth.py

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(prefix="/auth", tags=["auth"])


class SessionSetBody(BaseModel):
    # 세션 키 및 세션 이름을 암호화 한 256byte (문자열로 전달된다고 가정)
    signed_session_info: str = Field(..., min_length=1)
    # IPcam 공개키 256byte (문자열로 전달된다고 가정)
    ipcam_pub_key: str = Field(..., min_length=1)


@router.post("/session/set", status_code=204)
async def set_session(body: SessionSetBody):
    """
    세션 키 전달 엔드포인트

    - 엔드포인트: /auth/session/set  (실제 URI는 /api/auth/session/set)
    - 메소드: POST
    - mTLS로 인증은 Nginx/TLS 레벨에서 처리된다고 가정
    - body:
      {
        "signed_session_info": "....",
        "ipcam_pub_key": "...."
      }
    - TLS 수준에서 인증 실패 시 애초에 이 함수까지 도달하지 않음
    - 애플리케이션 레벨에선 204 No Content 반환
    """

    # TODO: 여기서 signed_session_info / ipcam_pub_key 검증 및
    #       Redis/DB 저장 로직이 필요하면 추후 추가
    # 지금 요구사항 기준으로는 "엔드포인트 추가"만 되어 있으면 됨.
    return