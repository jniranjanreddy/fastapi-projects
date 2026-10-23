# FastAPI service-to-service JWT demo

Two local FastAPI services. **service-a** (port 8001) calls **service-b** (port 8002) with
`Authorization: Bearer <jwt>`. The token is HS256, signed with one shared `SECRET_KEY`.

```
client ──► service-a :8001  /call-b?kind=...   (mints/uses a token)
                │  Authorization: Bearer <jwt>
                ▼
           service-b :8002  /data, /admin      (verifies with the same SECRET_KEY)
```

What it shows:

- **One key, many valid tokens.** A long-lived "static" service token, a 60-second token, and
  tokens with different `sub`/`role` claims all verify with the same `SECRET_KEY`. The key
  proves *who signed* the token. The claims say *who it is for* and *how long it lasts*.
- **Clean 401s, never 500s.** Service B parses the header defensively. A missing header, the
  wrong scheme, an empty token, a malformed token, a bad signature, expiry, wrong audience
  and missing claims each return a 401 with the reason logged.
- **401 vs 403.** `/admin` takes any valid token but returns 403 unless `role=admin`.

The original bug: `request.headers["Authorization"].split(" ")[1]` on `"Bearer "` gives `""`,
and on `"Bearer"` raises `IndexError`, which surfaces as a 500. See `require_jwt` in
[service-b/main.py](service-b/main.py) for the fix.

## Setup (once)

```bash
cd fastapi-jwt-demo
python -m venv .venv
.venv/Scripts/activate          # Windows Git Bash; on macOS/Linux: source .venv/bin/activate
pip install -r service-a/requirements.txt -r service-b/requirements.txt
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SECRET_KEY in .env
```

Both services load `../.env` (this folder's `.env`). A real environment variable overrides it.
`.env` is git-ignored. Use only demo secrets here.

## Run (two terminals, venv activated)

```bash
# terminal 1
cd service-b && uvicorn main:app --port 8002
```

```bash
# terminal 2
cd service-a && uvicorn main:app --port 8001
```

Watch terminal 1: every rejection logs a `401 Unauthorized: <reason>` line.

## Through service-a (`/call-b?kind=...`)

| kind        | token                                        | expected |
|-------------|----------------------------------------------|----------|
| `static`    | `SERVICE_TOKEN` from `.env`, else a 1-year token | 200 |
| `short`     | expires in 60 s                              | 200 |
| `reporter`  | `sub=reporting-job`, `role=reader`           | 200 |
| `admin`     | `sub=ops-bot`, `role=admin`                  | 200 |
| `wrong-key` | signed with a different secret               | 401 |
| `expired`   | `exp` 30 s in the past                       | 401 |
| `empty`     | `Authorization: Bearer` with no token        | 401 |
| `none`      | no Authorization header                      | 401 |

```bash
curl -i "http://127.0.0.1:8001/call-b?kind=static"
curl -i "http://127.0.0.1:8001/call-b?kind=short"
curl -i "http://127.0.0.1:8001/call-b?kind=reporter"
curl -i "http://127.0.0.1:8001/call-b?kind=wrong-key"
curl -i "http://127.0.0.1:8001/call-b?kind=expired"
curl -i "http://127.0.0.1:8001/call-b?kind=empty"
curl -i "http://127.0.0.1:8001/call-b?kind=none"

# authorization (403) vs authentication (401)
curl -i "http://127.0.0.1:8001/call-b?kind=admin&path=/admin"      # 200
curl -i "http://127.0.0.1:8001/call-b?kind=reporter&path=/admin"   # 403
```

Service A passes B's status through, so the curl status line shows B's answer.

## Straight to service-b with `make_token.py`

```bash
python make_token.py                  # print every kind
python make_token.py --decode "$(python make_token.py admin)"   # inspect claims (unverified)

TOKEN=$(python make_token.py short)
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8002/data                        # 200

curl -i http://127.0.0.1:8002/data                                                          # 401 missing header
curl -i -H "Authorization: Bearer " http://127.0.0.1:8002/data                              # 401 empty token (the original bug)
curl -i -H "Authorization: Bearer not.a.jwt" http://127.0.0.1:8002/data                     # 401 malformed
curl -i -H "Authorization: Basic abc" http://127.0.0.1:8002/data                            # 401 wrong scheme
curl -i -H "Authorization: Bearer $(python make_token.py wrong-key)" http://127.0.0.1:8002/data   # 401 bad signature
curl -i -H "Authorization: Bearer $(python make_token.py expired)" http://127.0.0.1:8002/data     # 401 expired
```

To use a fixed static token, run `python make_token.py static`, put the output in
`SERVICE_TOKEN=` in `.env`, and restart service-a.

## Notes

- `jwt.decode(..., algorithms=["HS256"])` pins the algorithm. Never let the token's header choose it.
- B requires `sub`, `iat`, `exp` and `aud=service-b`. A token minted for another audience is rejected
  even though the same key signed it.
- Rotating `SECRET_KEY` invalidates every token at once, which is the main trade-off of one shared HS256 key.
  Per-service keys or RS256 (private key signs, public key verifies) avoid that.
- A static long-lived token can't be revoked, only waited out or killed by rotating the key. Prefer short
  `exp` plus minting per call (`kind=short`) when the caller can hold the secret.
- httpx refuses to send `Bearer ` with a trailing space, so `kind=empty` sends a bare `Bearer`.
  curl sends the exact `"Bearer "` form.
