from fastapi import FastAPI

# 패키지 충돌(uvicorn의 /srv/fastapi/app.py 모듈명 'app')을 피하기 위해
# 먼저 app.* 임포트를 시도하고, 실패하면 루트 임포트로 폴백한다.
try:
    from app.db import init_db
    from app.routers.device_register import router as device_register_router
    from app.routers.streaming import router as streaming_router
    from app.routers.vpn import router as vpn_router
except ImportError:
    from db import init_db
    from routers.device_register import router as device_register_router
    from routers.streaming import router as streaming_router
    from routers.vpn import router as vpn_router

app = FastAPI(title="Homecam API", version="1.0.0")

# DB 테이블 보장
init_db()

# 라우터 등록
app.include_router(device_register_router)   # /devices/...
app.include_router(streaming_router)         # /stream/...
app.include_router(vpn_router)               # /vpn/...

@app.get("/")
def root():
    return {"status": "ok", "service": "homecam"}
