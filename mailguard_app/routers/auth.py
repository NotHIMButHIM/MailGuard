import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Request, Query, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from mailguard_app.database import get_db
from mailguard_app.models.user import User, UserSession
from mailguard_app.models.audit import AuditLog
from mailguard_app.config import get_settings
from mailguard_app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    verify_google_id_token,
    exchange_google_code_for_tokens,
    fetch_google_user_profile
)
from mailguard_app.core.dependencies import (
    get_current_user_token,
    require_admin,
    require_employee
)
from mailguard_app.core.exceptions import AuthenticationError, ConflictError
from mailguard_app.schemas.user import UserCreate, UserResponse, UserRole
from mailguard_app.schemas.auth import (
    LoginRequest,
    GoogleAuthRequest,
    Token,
    TokenPayload
)

router = APIRouter(prefix="/auth", tags=["Authentication & Unified Portal Login"])
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.email == user_in.email)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise ConflictError("User with this email already exists")

    new_user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=user_in.role.value,
        is_active=user_in.is_active,
        organization_name=user_in.organization_name
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    audit = AuditLog(
        user_id=new_user.id,
        action="USER_REGISTERED",
        entity_type="User",
        entity_id=str(new_user.id),
        details={"email": new_user.email, "role": new_user.role}
    )
    db.add(audit)
    await db.commit()

    return new_user


@router.post("/login", response_model=Token)
async def login_unified(
    login_data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == login_data.email)
    user = (await db.execute(stmt)).scalar_one_or_none()

    if not user or not user.hashed_password or not verify_password(login_data.password, user.hashed_password):
        raise AuthenticationError("Invalid email or password")

    if not user.is_active:
        raise AuthenticationError("Account is inactive")

    client_ip = "127.0.0.1"
    user_agent = "Unknown"
    if request and request.client:
        client_ip = request.client.host
    if request and hasattr(request, "headers"):
        user_agent = request.headers.get("user-agent", "Unknown")

    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = client_ip

    session_token = f"sess_{uuid.uuid4().hex}"
    new_session = UserSession(
        user_id=user.id,
        session_token=session_token,
        ip_address=client_ip,
        user_agent=user_agent,
        is_active=True
    )
    db.add(new_session)

    audit = AuditLog(
        user_id=user.id,
        action="LOGIN_SUCCESS",
        entity_type="User",
        entity_id=str(user.id),
        ip_address=client_ip,
        user_agent=user_agent,
        details={"role": user.role, "method": "password"}
    )
    db.add(audit)
    await db.commit()
    await db.refresh(user)

    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name,
        "session_token": session_token
    }
    access_token = create_access_token(token_data)

    user_resp = UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=UserRole(user.role),
        is_active=user.is_active,
        organization_name=user.organization_name,
        avatar_url=user.avatar_url,
        is_google_user=user.is_google_user,
        last_login_at=user.last_login_at,
        last_login_ip=user.last_login_ip
    )

    return Token(
        access_token=access_token,
        token_type="bearer",
        role=UserRole(user.role),
        user=user_resp
    )


@router.post("/google/login", response_model=Token)
async def google_login(
    payload: GoogleAuthRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    access_token_google = None
    refresh_token_google = None
    google_profile = None

    id_token_to_verify = payload.id_token or payload.credential
    code_to_exchange = payload.auth_code or payload.code

    callback_uri = payload.redirect_uri
    if not callback_uri and request:
        callback_uri = str(request.url).split("?")[0]

    if id_token_to_verify:
        try:
            google_profile = verify_google_id_token(id_token_to_verify)
        except Exception:
            google_profile = None

    if not google_profile and code_to_exchange:
        try:
            token_response = await exchange_google_code_for_tokens(code_to_exchange, callback_uri)
            access_token_google = token_response.get("access_token")
            refresh_token_google = token_response.get("refresh_token")

            if "id_token" in token_response:
                try:
                    google_profile = verify_google_id_token(token_response["id_token"])
                except Exception:
                    pass

            if not google_profile and access_token_google:
                google_profile = await fetch_google_user_profile(access_token_google)
        except Exception as e:
            raise AuthenticationError(f"Google authorization failed: {str(e)}")

    if not google_profile and payload.access_token:
        access_token_google = payload.access_token
        google_profile = await fetch_google_user_profile(payload.access_token)

    if not google_profile:
        raise AuthenticationError("Could not authenticate Google credentials")

    google_id = str(google_profile.get("google_id") or "")
    email = str(google_profile.get("email") or "")
    if not email:
        raise AuthenticationError("Google profile did not provide an email address")

    full_name = google_profile.get("full_name") or email.split("@")[0]
    avatar_url = google_profile.get("avatar_url")

    stmt = select(User).where((User.google_id == google_id) | (User.email == email))
    user = (await db.execute(stmt)).scalar_one_or_none()

    client_ip = "127.0.0.1"
    user_agent = "Unknown"
    if request and request.client:
        client_ip = request.client.host
    if request and hasattr(request, "headers"):
        user_agent = request.headers.get("user-agent", "Unknown")

    if user:
        if user.role == "ADMIN":
            raise AuthenticationError("Administrator accounts are restricted to corporate email and password authentication only.")
        user.is_google_user = True
        user.google_id = google_id
        if avatar_url:
            user.avatar_url = avatar_url
        if access_token_google:
            user.google_access_token = access_token_google
        if refresh_token_google:
            user.google_refresh_token = refresh_token_google
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = client_ip
    else:
        if payload.preferred_role and payload.preferred_role == UserRole.ADMIN:
            raise AuthenticationError("Administrator accounts cannot be authenticated via Google OAuth. Please sign in with email and password.")
        user = User(
            email=email,
            full_name=full_name,
            role="EMPLOYEE",
            is_active=True,
            is_google_user=True,
            google_id=google_id,
            google_access_token=access_token_google,
            google_refresh_token=refresh_token_google,
            avatar_url=avatar_url,
            organization_name="Enterprise Corp",
            last_login_at=datetime.now(timezone.utc),
            last_login_ip=client_ip
        )
        db.add(user)
        await db.flush()

    session_token = f"sess_{uuid.uuid4().hex}"
    new_session = UserSession(
        user_id=user.id,
        session_token=session_token,
        ip_address=client_ip,
        user_agent=user_agent,
        is_active=True
    )
    db.add(new_session)

    audit = AuditLog(
        user_id=user.id,
        action="LOGIN_GOOGLE_SUCCESS",
        entity_type="User",
        entity_id=str(user.id),
        ip_address=client_ip,
        user_agent=user_agent,
        details={"email": user.email, "role": user.role, "google_id": google_id}
    )
    db.add(audit)
    await db.commit()
    await db.refresh(user)

    token_data = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "full_name": user.full_name,
        "session_token": session_token
    }
    app_token = create_access_token(token_data)

    user_resp = UserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=UserRole(user.role),
        is_active=user.is_active,
        organization_name=user.organization_name,
        avatar_url=user.avatar_url,
        is_google_user=user.is_google_user,
        last_login_at=user.last_login_at,
        last_login_ip=user.last_login_ip
    )

    return Token(
        access_token=app_token,
        token_type="bearer",
        role=UserRole(user.role),
        user=user_resp
    )


@router.get("/google/callback")
async def google_callback_get(
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    if error:
        raise AuthenticationError(f"Google OAuth error: {error}")

    if state == "ADMIN":
        raise AuthenticationError("Administrator accounts are restricted to email and password authentication only.")

    if not code:
        raise AuthenticationError("Authorization code is missing from callback")

    callback_uri = str(request.url).split("?")[0]
    auth_req = GoogleAuthRequest(code=code, redirect_uri=callback_uri, preferred_role=UserRole.EMPLOYEE)

    token_result = await google_login(payload=auth_req, request=request, db=db)
    target_portal = "/portal/employee"

    accept = request.headers.get("accept", "")
    if "text/html" in accept or "application/xhtml+xml" in accept or not accept or "*/*" in accept:
        user_json = token_result.user.model_dump_json()
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <script>
        localStorage.setItem("mailguard_token", "{token_result.access_token}");
        localStorage.setItem("mailguard_role", "{token_result.role.value}");
        localStorage.setItem("mailguard_user", JSON.stringify({user_json}));
        document.cookie = "mailguard_token={token_result.access_token}; path=/; SameSite=Lax";
        window.location.replace("{target_portal}");
    </script>
</head>
<body style="font-family:sans-serif;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
    <div style="text-align:center;">
        <h2 style="color:#38bdf8;">Authentication Successful</h2>
        <p>Redirecting to Mailguard Security Gateway...</p>
    </div>
</body>
</html>"""
        response = HTMLResponse(content=html_content)
        response.set_cookie(
            key="mailguard_token",
            value=token_result.access_token,
            path="/",
            samesite="lax",
            httponly=False
        )
        return response

    return token_result


@router.post("/google/callback", response_model=Token)
async def google_callback_post(
    request: Request,
    payload: GoogleAuthRequest,
    db: AsyncSession = Depends(get_db)
):
    return await google_login(payload=payload, request=request, db=db)


@router.post("/logout")
async def logout_user(
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.is_active == True)
        .values(is_active=False)
    )
    audit = AuditLog(
        user_id=user_id,
        action="LOGOUT",
        entity_type="User",
        entity_id=str(user_id),
        details={"email": current_user.email}
    )
    db.add(audit)
    await db.commit()
    return {"status": "logged_out", "message": "Session invalidated"}


@router.get("/me", response_model=UserResponse)
async def get_current_profile(
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise AuthenticationError("User not found")
    return user


@router.get("/admin-only-probe")
async def probe_admin_access(admin_user: TokenPayload = Depends(require_admin)):
    return {
        "status": "authorized",
        "message": "Welcome to Admin Security Portal",
        "user": admin_user.email,
        "role": admin_user.role
    }


@router.get("/employee-only-probe")
async def probe_employee_access(employee_user: TokenPayload = Depends(require_employee)):
    return {
        "status": "authorized",
        "message": "Welcome to Employee Spam Prevention Portal",
        "user": employee_user.email,
        "role": employee_user.role
    }
