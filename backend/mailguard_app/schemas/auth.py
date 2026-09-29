from pydantic import BaseModel, EmailStr
from typing import Optional
from mailguard_app.schemas.user import UserRole, UserResponse


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    user: UserResponse


class LoginRequest(BaseModel):
    email: str
    password: str


class GoogleAuthRequest(BaseModel):
    id_token: Optional[str] = None
    credential: Optional[str] = None
    auth_code: Optional[str] = None
    code: Optional[str] = None
    access_token: Optional[str] = None
    redirect_uri: Optional[str] = None
    preferred_role: Optional[UserRole] = UserRole.EMPLOYEE


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None
    exp: Optional[int] = None
    type: Optional[str] = None
    session_token: Optional[str] = None
