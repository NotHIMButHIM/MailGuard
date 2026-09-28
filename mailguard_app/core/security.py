from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from passlib.context import CryptContext
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import httpx
from mailguard_app.config import get_settings
from mailguard_app.core.exceptions import AuthenticationError

settings = get_settings()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    to_encode.setdefault("type", "access")
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise AuthenticationError("Could not validate credentials")


def verify_google_id_token(token: str) -> Dict[str, Any]:
    try:
        request = google_requests.Request()
        client_id = settings.GOOGLE_CLIENT_ID
        id_info = id_token.verify_oauth2_token(token, request, client_id)

        if id_info["iss"] not in ["accounts.google.com", "https://accounts.google.com"]:
            raise AuthenticationError("Invalid Google token issuer")

        return {
            "google_id": id_info.get("sub"),
            "email": id_info.get("email"),
            "full_name": id_info.get("name", id_info.get("email", "").split("@")[0]),
            "avatar_url": id_info.get("picture"),
            "email_verified": id_info.get("email_verified", False)
        }
    except Exception as e:
        raise AuthenticationError(f"Failed to verify Google Token: {str(e)}")


async def exchange_google_code_for_tokens(code: str, redirect_uri: Optional[str] = None) -> Dict[str, Any]:
    uri = redirect_uri or settings.GOOGLE_REDIRECT_URI
    data = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "grant_type": "authorization_code"
    }
    if uri:
        data["redirect_uri"] = uri

    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.post(
            "https://oauth2.googleapis.com/token",
            data=data,
            headers={"Accept": "application/json"}
        )
        if res.status_code != 200:
            raise AuthenticationError(f"Failed to exchange authorization code: {res.text}")
        return res.json()


async def refresh_google_access_token(refresh_token: str) -> Optional[str]:
    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.post(
            "https://oauth2.googleapis.com/token",
            data=data,
            headers={"Accept": "application/json"}
        )
        if res.status_code == 200:
            return res.json().get("access_token")
    return None


async def fetch_google_user_profile(access_token: str) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        res = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if res.status_code != 200:
            raise AuthenticationError("Failed to fetch Google user profile")
        data = res.json()
        return {
            "google_id": data.get("sub"),
            "email": data.get("email"),
            "full_name": data.get("name", data.get("email", "").split("@")[0]),
            "avatar_url": data.get("picture"),
            "email_verified": data.get("email_verified", False)
        }
