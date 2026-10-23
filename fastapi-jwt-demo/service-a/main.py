"""Service A: the caller. Builds (or reuses) a JWT and calls service B with it.

GET /call-b?kind=<kind>&path=/data   -> returns B's status and body

kinds:
  static      SERVICE_TOKEN from .env if set (long-lived), else a freshly minted 1-year token
  short       minted now, expires in 60 seconds
  reporter    different sub/role, same key
  admin       role=admin (try path=/admin)
  wrong-key   signed with a key B doesn't know      -> 401
  expired     exp in the past                        -> 401
  empty       Bearer header with no token (the original bug) -> 401
  none        no Authorization header at all          -> 401
"""
import datetime as dt
import logging
import os
from pathlib import Path

import httpx
import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set (see .env.example)")
SERVICE_TOKEN = os.environ.get("SERVICE_TOKEN", "").strip()
SERVICE_B_URL = os.environ.get("SERVICE_B_URL", "http://127.0.0.1:8002")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [service-a] %(message)s")
log = logging.getLogger("service-a")

app = FastAPI(title="service-a")


def mint(sub: str, role: str, ttl: dt.timedelta, key: str = SECRET_KEY) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {"sub": sub, "role": role, "aud": "service-b", "iss": "service-a", "iat": now, "exp": now + ttl}
    return jwt.encode(claims, key, algorithm="HS256")


def headers_for(kind: str) -> dict:
    if kind == "static":
        token = SERVICE_TOKEN or mint("service-a", "service", dt.timedelta(days=365))
    elif kind == "short":
        token = mint("service-a", "service", dt.timedelta(seconds=60))
    elif kind == "reporter":
        token = mint("reporting-job", "reader", dt.timedelta(minutes=5))
    elif kind == "admin":
        token = mint("ops-bot", "admin", dt.timedelta(minutes=5))
    elif kind == "wrong-key":
        token = mint("service-a", "service", dt.timedelta(minutes=5), key="this-is-NOT-the-shared-secret-so-B-will-reject-it")
    elif kind == "expired":
        token = mint("service-a", "service", dt.timedelta(seconds=-30))
    elif kind == "empty":
        # What f"Bearer {os.environ.get('TOKEN', '')}" produces when the env var is unset.
        # httpx rejects the trailing space as an illegal header value, so send the bare
        # scheme; B sees the same thing: a Bearer header with no token. (curl can send
        # the exact "Bearer " form; see README.)
        return {"Authorization": "Bearer"}
    elif kind == "none":
        return {}
    else:
        raise HTTPException(status_code=400, detail=f"unknown kind {kind!r}")
    return {"Authorization": f"Bearer {token}"}


@app.get("/call-b")
async def call_b(kind: str = "static", path: str = "/data"):
    headers = headers_for(kind)
    log.info("calling service-b %s with kind=%s", path, kind)
    try:
        async with httpx.AsyncClient(base_url=SERVICE_B_URL, timeout=5.0) as client:
            resp = await client.get(path, headers=headers)
    except httpx.HTTPError as e:
        log.error("service-b unreachable: %s", e)
        raise HTTPException(status_code=502, detail=f"service-b unreachable: {e}")

    try:
        body = resp.json()
    except ValueError:
        body = resp.text
    # Pass B's status through so the caller sees the 401/403 as-is.
    return JSONResponse(status_code=resp.status_code, content={"kind": kind, "b_status": resp.status_code, "b_body": body})
