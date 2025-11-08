# /home/ubuntu/homecam-api/app/main.py
from fastapi import FastAPI
from app.db import init_db
from app.routers.device_register import router as device_register_router
from app.routers.streaming import router as streaming_router
from app.routers.vpn import router as vpn_router

app = FastAPI(title="Homecam API", version="1.0.0")

# DB 테이블 보장
init_db()

# 라우터 등록
app.include_router(device_register_router)
app.include_router(streaming_router)
app.include_router(vpn_router)

@app.get("/")
def root():
    return {"status": "ok", "service": "homecam"}