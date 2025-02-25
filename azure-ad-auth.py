## Azure Ad authetication Working fine.
## This is tested with the below URL
## http://localhost:8000/login


from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse, HTMLResponse
from httpx import AsyncClient
from pydantic import BaseModel

app = FastAPI()

# Azure AD Configuration
CLIENT_ID = ""
CLIENT_SECRET = ""
TENANT_ID = ""
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = "http://localhost:8000/auth/callback"

SCOPES = {
    "openid": "OpenID Connect",
    "profile": "User profile",
    "email": "User email",
}

# OAuth2 Scheme
# OAuth2 Scheme
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{AUTHORITY}/oauth2/v2.0/authorize",
    tokenUrl=f"{AUTHORITY}/oauth2/v2.0/token",
    scopes=SCOPES,
)

# Model for Token Response
class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    scope: str
    id_token: str

# Redirect to Azure AD for login
@app.get("/login")
async def login():
    auth_url = (
        f"{AUTHORITY}/oauth2/v2.0/authorize?"
        f"client_id={CLIENT_ID}&"
        f"response_type=code&"
        f"redirect_uri={REDIRECT_URI}&"
        f"response_mode=query&"
        f"scope={' '.join(SCOPES.keys())}"
    )
    return RedirectResponse(url=auth_url)

# Callback endpoint to handle the authorization code
@app.get("/auth/callback")
async def callback(code: str):
    token_url = f"{AUTHORITY}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
        "scope": " ".join(SCOPES.keys()),
    }
    async with AsyncClient() as client:
        response = await client.post(token_url, data=data)
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        token_data = TokenResponse(**response.json())

    # Display a success message
    success_message = """
    <html>
        <body>
            <h1>Azure AD Authentication Successful!</h1>
            <p>You have successfully authenticated with Azure AD.</p>
            <p><strong>Access Token:</strong> {access_token}</p>
        </body>
    </html>
    """.format(access_token=token_data.access_token)

    return HTMLResponse(content=success_message, status_code=200)

# Protected route
@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    return {"message": "You are authenticated!", "token": token}

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
