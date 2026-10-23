"""Service B: the callee. Validates an HS256 JWT signed with the shared SECRET_KEY.

Every auth failure becomes a 401 (or 403 for a valid token with the wrong role),
never a 500, and the reason is logged.
"""
import logging
import os
from pathlib import Path

import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request

# Load ../.env (shared by both services); a real env var wins over the file.
load_dotenv(Path(__file__).resolve().parent.parent / ".env")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is not set (see .env.example)")

ALGORITHM = "HS256"
AUDIENCE = "service-b"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [service-b] %(message)s")
log = logging.getLogger("service-b")

app = FastAPI(title="service-b")


def unauthorized(reason: str) -> HTTPException:
    log.warning("401 Unauthorized: %s", reason)
    return HTTPException(
        status_code=401,
        detail=f"Unauthorized: {reason}",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_jwt(request: Request) -> dict:
    """Parse 'Authorization: Bearer <token>' defensively and verify the token.

    The original bug was `header.split(" ")[1]` on "Bearer " (empty token from a
    missing env var), which raised IndexError -> 500. Here every shape of bad
    header is handled explicitly.
    """
    header = request.headers.get("Authorization")
    if header is None:
        raise unauthorized("missing Authorization header")

    scheme, _, token = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        raise unauthorized(f"expected Bearer scheme, got {scheme or 'empty header'!r}")
    token = token.strip()
    if not token:
        raise unauthorized("empty bearer token (caller's token env var is probably unset)")

    try:
        claims = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],  # never let the token pick its own algorithm
            audience=AUDIENCE,
            options={"require": ["sub", "iat", "exp", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise unauthorized("token expired")
    except jwt.InvalidSignatureError:
        raise unauthorized("bad signature (signed with a different key)")
    except jwt.InvalidAudienceError:
        raise unauthorized(f"wrong audience (expected {AUDIENCE!r})")
    except jwt.MissingRequiredClaimError as e:
        raise unauthorized(f"missing required claim: {e.claim}")
    except jwt.DecodeError as e:
        raise unauthorized(f"malformed token: {e}")
    except jwt.InvalidTokenError as e:  # catch-all for any other PyJWT validation error
        raise unauthorized(f"invalid token: {e}")

    log.info("authorized sub=%s role=%s", claims.get("sub"), claims.get("role"))
    return claims


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/data")
def data(claims: dict = Depends(require_jwt)):
    return {
        "message": f"hello {claims['sub']}, here is your data",
        "items": [{"id": 1, "name": "alpha"}, {"id": 2, "name": "beta"}],
        "claims": claims,
    }


@app.get("/admin")
def admin(claims: dict = Depends(require_jwt)):
    # Authentication (who you are) passed; this is authorization (what you may do).
    if claims.get("role") != "admin":
        log.warning("403 Forbidden: sub=%s role=%s", claims.get("sub"), claims.get("role"))
        raise HTTPException(status_code=403, detail="Forbidden: admin role required")
    return {"message": "admin-only data", "claims": claims}
