from fastapi import FastAPI, APIRouter
from app.routers.vpn import router as vpn_router
from app.routers.streaming import router as stream_router

# FastAPI 앱 초기화
app = FastAPI(title="Homecam API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")


# 기본 헬스체크 엔드포인트
@app.get("/")
def root():
    return {"ok": True, "service": "homecam"}

@app.get("/healthz")
def healthz():
    return {"ok": True}

# /api 프리픽스 아래 라우터 묶기 (nginx location /api/ 와 매칭)
api = APIRouter(prefix="/api")

# /api/vpn/... 엔드포인트 추가
api.include_router(vpn_router)

# /api/stream/... 엔드포인트 추가
api.include_router(stream_router)

# FastAPI 앱에 /api 전체 라우터 등록
app.include_router(api)
