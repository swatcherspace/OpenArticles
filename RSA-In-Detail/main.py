import base64
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import json
import jwt
from datetime import datetime, timedelta

app = FastAPI()
security = HTTPBearer()

# Load private key for signing JWT
try:
    with open("private.pem", "rb") as f:
        PRIVATE_KEY = f.read()
except FileNotFoundError:
    print("Warning: private.pem not found")
    PRIVATE_KEY = None

# Load your RS256 public key (PEM format)
try:
    with open("public.pem", "r") as f:
        PUBLIC_KEY = f.read()
except FileNotFoundError:
    print("Warning: public.pem not found")
    PUBLIC_KEY = None

# Example App IDs and Secrets
VALID_APPS = {}
try:
    with open("app.json", "r") as f:
        VALID_APPS = json.load(f)
        print(f"Loaded apps: {list(VALID_APPS.keys())}")
except Exception as e:
    print(f"Error loading app json: {e}")
    VALID_APPS = {}

# Token validity (8 hours in seconds)
TOKEN_EXPIRY_SECONDS = 8 * 60 * 60
ALGORITHM = "RS256"
ISSUER = "https://127.0.0.1:8000"

class AppCredentials(BaseModel):
    app_name_b64: str
    app_secret_b64: str

def decode_b64(value: str) -> str:
    try:
        decoded = base64.b64decode(value).decode("utf-8")
        print(f"Decoded value: {decoded}")
        return decoded
    except Exception as e:
        print(f"Base64 decode error: {e}")
        raise

@app.post("/issue-token")
def issue_token(credentials: AppCredentials):
    if not PRIVATE_KEY:
        raise HTTPException(status_code=500, detail="Server configuration error: Missing private key")
    
    try:
        app_name = decode_b64(credentials.app_name_b64)
        app_secret = decode_b64(credentials.app_secret_b64)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 input: {str(e)}")

    # Validate credentials
    print(f"Validating app: {app_name}")
    print(f"Available apps: {list(VALID_APPS.keys())}")
    
    if app_name not in VALID_APPS or VALID_APPS[app_name] != app_secret:
        raise HTTPException(status_code=403, detail="Invalid application credentials")

    # Create JWT token
    now = datetime.utcnow()
    payload = {
        "iss": ISSUER,  # Issuer
        "aud": ISSUER,#app_name,  # Audience (application name)
        "iat": int(now.timestamp()),  # Issued at
        "exp": int((now + timedelta(seconds=TOKEN_EXPIRY_SECONDS)).timestamp()),  # Expires at
        "sub": app_name,  # Subject (app name)
        "app_name": app_name  
    }
    
    try:
        token = jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM)
        return {"access_token": token, "token_type": "bearer"}
    except Exception as e:
        print(f"JWT encoding error: {e}")
        raise HTTPException(status_code=500, detail=f"Token generation failed: {str(e)}")

def verify_jwt_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not PUBLIC_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server configuration error: Missing public key"
        )
    
    token = credentials.credentials
    print(f"Verifying token: {token[:50]}...")  # Only print first 50 chars for security
    
    try:
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"verify_aud": False}
        )
        aud = payload.get("aud")
        if aud not in VALID_APPS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid audience: {aud}"
            )
        
        print(f"Token verified successfully for: {payload.get('sub')}")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
    except Exception as e:
        print(f"Unexpected error during token verification: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed"
        )

@app.get("/secure-data")
def secure_data(payload: dict = Depends(verify_jwt_token)):
    return {
        "message": "Access granted",
        "token_payload": payload,
        "app_name": payload.get("sub"),
        "issued_at": datetime.fromtimestamp(payload.get("iat", 0)).isoformat(),
        "expires_at": datetime.fromtimestamp(payload.get("exp", 0)).isoformat()
    }

# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "has_private_key": PRIVATE_KEY is not None,
        "has_public_key": PUBLIC_KEY is not None,
        "loaded_apps": len(VALID_APPS)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)