from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.responses import RedirectResponse
import msal
from typing import Optional

app = FastAPI()

# Azure AD Configuration
CLIENT_ID = ""
CLIENT_SECRET = ""
TENANT_ID = ""
REDIRECT_URI = "http://localhost:80/auth/callback"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]

# OAuth2 configuration
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{AUTHORITY}/oauth2/v2.0/authorize",
    tokenUrl=f"{AUTHORITY}/oauth2/v2.0/token",
    scopes={"User.Read": "Read user profile"},
    auto_error=False  # Set to False to handle unauthenticated users manually
)

# MSAL client
msal_app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    authority=AUTHORITY,
    client_credential=CLIENT_SECRET
)

async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)) -> dict:
    """Validate token or redirect to login if no token"""
    if not token:  # If no token is provided, redirect to Azure AD
        auth_url = msal_app.get_authorization_request_url(
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        raise HTTPException(status_code=307, detail=auth_url, headers={"Location": auth_url})
    
    try:
        result = msal_app.acquire_token_by_authorization_code(
            code=token,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        
        if "access_token" not in result:
            raise HTTPException(status_code=401, detail="Authentication failed: " + result.get("error_description", "Unknown error"))
            
        return {
            "access_token": result["access_token"],
            "user_info": result.get("id_token_claims")
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")

@app.get("/")
async def root(current_user: dict = Depends(get_current_user)):
    """Root endpoint requiring authentication"""
    return {"message": "Welcome! You are authenticated", "user": current_user}

@app.get("/auth/callback")
async def auth_callback(code: str):
    """Handle the callback from Azure AD"""
    user = await get_current_user(token=code)
    return user

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
