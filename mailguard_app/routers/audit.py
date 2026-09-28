from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.database import get_db
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.dependencies import require_admin
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.audit import AuditLogResponse

router = APIRouter(prefix="/audit", tags=["Security Audit Logs"])


@router.get("/logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    logs = (await db.execute(stmt)).scalars().all()
    return logs
