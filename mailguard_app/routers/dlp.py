from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.database import get_db
from mailguard_app.models.dlp import DLPIncident
from mailguard_app.core.dependencies import require_admin
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.dlp import DLPIncidentResponse

router = APIRouter(prefix="/dlp", tags=["Data Loss Prevention (DLP)"])


@router.get("/incidents", response_model=List[DLPIncidentResponse])
async def list_dlp_incidents(
    severity: str = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(DLPIncident).order_by(DLPIncident.created_at.desc()).limit(limit)
    if severity:
        stmt = stmt.where(DLPIncident.severity == severity)
    incidents = (await db.execute(stmt)).scalars().all()
    return incidents
