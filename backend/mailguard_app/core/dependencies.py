from typing import AsyncGenerator, Optional
from fastapi import Depends, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.database import get_db
from mailguard_app.models.user import UserSession, User
from mailguard_app.core.security import decode_token
from mailguard_app.core.exceptions import AuthenticationError, PermissionDeniedError
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.user import UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


async def get_token_payload(
    token: Optional[str] = Depends(oauth2_scheme),
    authorization: Optional[str] = Header(None)
) -> TokenPayload:
    actual_token = token
    if not actual_token and authorization and authorization.startswith("Bearer "):
        actual_token = authorization.split(" ")[1]

    if not actual_token:
        raise AuthenticationError("Not authenticated")

    payload_dict = decode_token(actual_token)
    if payload_dict.get("type") and payload_dict.get("type") != "access":
        raise AuthenticationError("Invalid token type")

    return TokenPayload(
        sub=str(payload_dict.get("sub")),
        role=payload_dict.get("role"),
        email=payload_dict.get("email"),
        exp=payload_dict.get("exp"),
        type=payload_dict.get("type"),
        session_token=payload_dict.get("session_token")
    )


async def get_current_user_token(
    payload: TokenPayload = Depends(get_token_payload),
    db: AsyncSession = Depends(get_db)
) -> TokenPayload:
    if payload.session_token:
        stmt = select(UserSession).where(UserSession.session_token == payload.session_token)
        sess = (await db.execute(stmt)).scalar_one_or_none()
        if not sess or not sess.is_active:
            raise AuthenticationError("Session has been revoked or expired. Please log in again.")
    return payload


async def require_admin(
    payload: TokenPayload = Depends(get_current_user_token)
) -> TokenPayload:
    if payload.role != UserRole.ADMIN.value:
        raise PermissionDeniedError("Admin privileges required")
    return payload


async def require_employee(
    payload: TokenPayload = Depends(get_current_user_token)
) -> TokenPayload:
    if payload.role not in [UserRole.EMPLOYEE.value, UserRole.ADMIN.value]:
        raise PermissionDeniedError("Employee or Admin privileges required")
    return payload
