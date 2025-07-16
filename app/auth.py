# app/auth.py
import os
import requests
from fastapi import FastAPI, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from dotenv import load_dotenv

load_dotenv()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google")

if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Google Client ID and Secret must be set as environment variables.")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_google_auth_url():
    return (
        f"https://accounts.google.com/o/oauth2/auth"
        f"?response_type=code"
        f"&client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri={GOOGLE_REDIRECT_URI}"
        f"&scope=openid%20profile%20email"
        f"&access_type=offline"
    )

def exchange_code_for_token(code: str):
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    try:
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Failed to retrieve access token.")
        return access_token
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error during token exchange: {str(e)}")

def get_user_info(access_token: str):
    try:
        user_info_resp = requests.get(
            "https://www.googleapis.com/oauth2/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        user_info_resp.raise_for_status()
        return user_info_resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user info: {str(e)}")

def verify_token(token: str):
    try:
        jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
        jwks_response = requests.get(jwks_url)
        jwks_response.raise_for_status()
        jwks = jwks_response.json()

        unverified_header = jwt.get_unverified_header(token)
        rsa_key = next(
            (
                {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
                for key in jwks["keys"]
                if key["kid"] == unverified_header["kid"]
            ),
            None,
        )
        if not rsa_key:
            raise HTTPException(status_code=400, detail="Unable to find appropriate key.")

        payload = jwt.decode(token, rsa_key, algorithms=["RS256"], audience=GOOGLE_CLIENT_ID)
        return payload
    except jwt.JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token verification failed: {str(e)}")
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Error fetching public keys: {str(e)}")
