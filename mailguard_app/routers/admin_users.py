from datetime import datetime, timedelta, timezone
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update, delete
from sqlalchemy.orm import selectinload
from mailguard_app.database import get_db
from mailguard_app.models.user import User, UserSession
from mailguard_app.models.email import Email
from mailguard_app.models.prevention import EmployeePreventionRule
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.dependencies import require_admin
from mailguard_app.core.exceptions import NotFoundError, ConflictError
from mailguard_app.core.security import get_password_hash
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.dashboard import (
    ActiveEmployeeSessionResponse,
    EmployeeDataSummary,
    EmployeeCreateRequest
)
from mailguard_app.schemas.user import UserResponse

router = APIRouter(prefix="/admin", tags=["Admin Portal & Employee Monitoring"])


@router.get("/employees", response_model=List[EmployeeDataSummary])
async def list_employees_and_data(
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.role == "EMPLOYEE").order_by(User.created_at.desc())
    employees = (await db.execute(stmt)).scalars().all()

    summaries = []
    for emp in employees:
        total_emails = (await db.execute(select(func.count(Email.id)).where(Email.user_id == emp.id))).scalar() or 0
        quarantined = (await db.execute(select(func.count(Email.id)).where(Email.user_id == emp.id, Email.status == "QUARANTINED"))).scalar() or 0
        rules_count = (await db.execute(select(func.count(EmployeePreventionRule.id)).where(EmployeePreventionRule.user_id == emp.id, EmployeePreventionRule.is_active == True))).scalar() or 0

        summaries.append(EmployeeDataSummary(
            user_id=emp.id,
            email=emp.email,
            full_name=emp.full_name,
            organization_name=emp.organization_name,
            total_emails=total_emails,
            quarantined_emails=quarantined,
            active_prevention_rules=rules_count,
            last_login_at=emp.last_login_at,
            last_login_ip=emp.last_login_ip
        ))

    return summaries


@router.get("/users", response_model=List[UserResponse])
@router.get("/users/", response_model=List[UserResponse])
async def list_all_users_admin(
    limit: int = 100,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).order_by(User.created_at.desc()).limit(limit)
    users = (await db.execute(stmt)).scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("/employees", response_model=EmployeeDataSummary)
async def create_employee_manually(
    payload: EmployeeCreateRequest,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == payload.email.strip().lower())
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise ConflictError(f"User with email '{payload.email}' already exists.")

    new_employee = User(
        email=payload.email.strip().lower(),
        full_name=payload.full_name.strip(),
        hashed_password=get_password_hash(payload.password) if payload.password else None,
        role="EMPLOYEE",
        organization_name=payload.organization_name or "Default Organization",
        is_active=True
    )
    db.add(new_employee)
    await db.commit()
    await db.refresh(new_employee)

    audit = AuditLog(
        user_id=int(admin_user.sub),
        action="CREATE_EMPLOYEE_MANUAL",
        entity_type="User",
        entity_id=str(new_employee.id),
        details={"email": new_employee.email, "full_name": new_employee.full_name}
    )
    db.add(audit)
    await db.commit()

    return EmployeeDataSummary(
        user_id=new_employee.id,
        email=new_employee.email,
        full_name=new_employee.full_name,
        organization_name=new_employee.organization_name,
        total_emails=0,
        quarantined_emails=0,
        active_prevention_rules=0,
        last_login_at=None,
        last_login_ip=None
    )


@router.delete("/employees/{employee_id}")
async def delete_employee(
    employee_id: int,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    emp = (await db.execute(select(User).where(User.id == employee_id, User.role == "EMPLOYEE"))).scalar_one_or_none()
    if not emp:
        raise NotFoundError("Employee not found")

    await db.delete(emp)
    audit = AuditLog(
        user_id=int(admin_user.sub),
        action="DELETE_EMPLOYEE",
        entity_type="User",
        entity_id=str(employee_id),
        details={"email": emp.email}
    )
    db.add(audit)
    await db.commit()
    return {"status": "deleted", "employee_id": employee_id}


@router.delete("/sessions/inactive")
@router.delete("/sessions/inactive/all")
@router.post("/sessions/purge-inactive")
async def purge_inactive_sessions(
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
    # Mark idle sessions as inactive
    await db.execute(
        update(UserSession)
        .where(UserSession.is_active == True, UserSession.last_activity < cutoff)
        .values(is_active=False)
    )
    # Purge all inactive sessions from database
    result = await db.execute(
        delete(UserSession).where(UserSession.is_active == False)
    )
    removed = result.rowcount or 0
    await db.commit()
    return {"status": "success", "removed_count": removed}


@router.get("/active-sessions", response_model=List[ActiveEmployeeSessionResponse])
@router.get("/sessions", response_model=List[ActiveEmployeeSessionResponse])
@router.get("/users/sessions", response_model=List[ActiveEmployeeSessionResponse])
async def list_active_employee_sessions(
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    # Keep active admin's session timestamp refreshed and active
    current_uid = int(admin_user.sub) if admin_user.sub else None
    if current_uid:
        await db.execute(
            update(UserSession)
            .where(UserSession.user_id == current_uid)
            .values(last_activity=datetime.now(timezone.utc), is_active=True)
        )

    # Deactivate other sessions older than 60 minutes of inactivity (exclude current admin)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=60)
    deact_stmt = update(UserSession).where(
        UserSession.is_active == True,
        UserSession.last_activity < cutoff
    )
    if current_uid:
        deact_stmt = deact_stmt.where(UserSession.user_id != current_uid)
    await db.execute(deact_stmt)
    await db.commit()

    stmt = (
        select(UserSession)
        .where(UserSession.is_active == True)
        .options(selectinload(UserSession.user))
        .order_by(UserSession.last_activity.desc())
    )
    sessions = (await db.execute(stmt)).scalars().all()

    output = []
    for s in sessions:
        user_obj = s.user
        resp = ActiveEmployeeSessionResponse(
            id=s.id,
            user_id=s.user_id,
            session_token=s.session_token,
            ip_address=s.ip_address or "127.0.0.1",
            user_agent=s.user_agent or "Browser / WebApp",
            is_active=s.is_active,
            last_activity=s.last_activity or s.created_at,
            created_at=s.created_at,
            user=UserResponse.model_validate(user_obj) if user_obj else None,
            user_name=user_obj.full_name if user_obj else f"User #{s.user_id}",
            user_email=user_obj.email if user_obj else "unknown@mailguard.corp",
            user_role=user_obj.role if user_obj else "EMPLOYEE"
        )
        output.append(resp)

    return output


@router.delete("/sessions/{session_id}")
@router.delete("/users/sessions/{session_id}")
async def revoke_employee_session(
    session_id: int,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    sess = (await db.execute(select(UserSession).where(UserSession.id == session_id))).scalar_one_or_none()
    if not sess:
        raise NotFoundError("Session not found")

    target_user_id = sess.user_id
    await db.delete(sess)
    audit = AuditLog(
        user_id=int(admin_user.sub),
        action="REVOKE_EMPLOYEE_SESSION",
        entity_type="UserSession",
        entity_id=str(session_id),
        details={"target_user_id": target_user_id}
    )
    db.add(audit)
    await db.commit()
    return {"status": "revoked_and_removed", "session_id": session_id}
