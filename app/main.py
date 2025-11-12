from fastapi import FastAPI
try:
    from app.routers.vpn import router as vpn_router
    from app.routers.streaming import router as stream_router
except ImportError:
    from routers.vpn import router as vpn_router
    from routers.streaming import router as stream_router

from fastapi import APIRouter

app = FastAPI(title="Homecam API", version="1.0.0")

# / → 헬스체크
@app.get("/")
def root():
    return {"ok": True, "service": "homecam"}

@app.get("/healthz")
def healthz():
    return {"ok": True}

# /api 프리픽스 아래에 라우터 묶기 (nginx location /api/ 와 맞춤)
api = APIRouter(prefix="/api")
api.include_router(vpn_router)      # /api/vpn/...
api.include_router(stream_router)   # /api/stream/...
app.include_router(api)