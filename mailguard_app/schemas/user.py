from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    EMPLOYEE = "EMPLOYEE"


class UserBase(BaseModel):
    email: str
    full_name: str
    role: UserRole = UserRole.EMPLOYEE
    is_active: bool = True
    organization_name: Optional[str] = "Default Organization"


class UserCreate(UserBase):
    password: str = Field(min_length=6)


class UserResponse(UserBase):
    id: int
    avatar_url: Optional[str] = None
    is_google_user: bool = False
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
