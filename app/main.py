import os, json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SEC", "900"))
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

app = FastAPI(title="homecam-api")

class RegisterIntent(BaseModel):
    token: str = Field(min_length=8)
    ssid: str
    public_key: str

@app.get("/health")
@app.get("/api/health")
def health():
    try:
        pong = r.ping()
        return {"status":"ok","redis": pong}
    except Exception as e:
        return {"status":"degraded","error": str(e)}

@app.post("/register-intent")
@app.post("/api/register-intent")
def register_intent(body: RegisterIntent):
    key = f"reg:{body.token}"
    data = {"ssid": body.ssid, "public_key": body.public_key}
    if r.exists(key):
        return {"ok": True, "message": "already exists", "ttl": r.ttl(key)}
    r.setex(key, TOKEN_TTL, json.dumps(data))
    return {"ok": True, "ttl": TOKEN_TTL}

@app.get("/register-intent/{token}")
@app.get("/api/register-intent/{token}")
def get_register_intent(token: str):
    key = f"reg:{token}"
    val = r.get(key)
    if not val:
        raise HTTPException(status_code=404, detail="token not found or expired")
    return {"ok": True, "token": token, "data": json.loads(val), "ttl": r.ttl(key)}
