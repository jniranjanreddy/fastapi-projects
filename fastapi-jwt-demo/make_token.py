"""Mint demo JWTs signed with SECRET_KEY from .env.

    python make_token.py                 # print every kind
    python make_token.py short           # print just one token (handy for curl)
    python make_token.py --decode <jwt>  # show a token's claims without verifying it
"""
import datetime as dt
import json
import os
import sys
from pathlib import Path

import jwt
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    sys.exit("SECRET_KEY is not set (copy .env.example to .env)")


def mint(sub: str, role: str, ttl: dt.timedelta, key: str = SECRET_KEY) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {"sub": sub, "role": role, "aud": "service-b", "iss": "service-a", "iat": now, "exp": now + ttl}
    return jwt.encode(claims, key, algorithm="HS256")


KINDS = {
    # valid: all signed with the one shared key, different claims/lifetimes
    "static": lambda: mint("service-a", "service", dt.timedelta(days=365)),
    "short": lambda: mint("service-a", "service", dt.timedelta(seconds=60)),
    "reporter": lambda: mint("reporting-job", "reader", dt.timedelta(minutes=5)),
    "admin": lambda: mint("ops-bot", "admin", dt.timedelta(minutes=5)),
    # invalid
    "wrong-key": lambda: mint("service-a", "service", dt.timedelta(minutes=5), key="this-is-NOT-the-shared-secret-so-B-will-reject-it"),
    "expired": lambda: mint("service-a", "service", dt.timedelta(seconds=-30)),
}

if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--decode"] and len(args) == 2:
        print(json.dumps(jwt.decode(args[1], options={"verify_signature": False}), indent=2))
    elif len(args) == 1 and args[0] in KINDS:
        print(KINDS[args[0]]())
    elif not args:
        for name, make in KINDS.items():
            print(f"{name:10} {make()}")
    else:
        sys.exit(f"usage: make_token.py [{'|'.join(KINDS)}] | --decode <jwt>")
