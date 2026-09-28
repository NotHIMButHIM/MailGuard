from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, update
from mailguard_app.database import get_db
from mailguard_app.models.user import User, UserSession
from mailguard_app.models.email import Email
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.models.dlp import DLPIncident
from mailguard_app.core.dependencies import get_current_user_token
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.dashboard import DashboardStatsResponse

router = APIRouter(prefix="/dashboard", tags=["Dashboard Statistics"])


@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_statistics(
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    is_admin = current_user.role == "ADMIN"
    user_id = int(current_user.sub)

    email_filter = [] if is_admin else [Email.user_id == user_id]

    total_scanned = (await db.execute(select(func.count(Email.id)).where(*email_filter))).scalar() or 0
    clean_emails = (await db.execute(select(func.count(Email.id)).where(Email.status == "CLEAN", Email.threat_verdict == "CLEAN", *email_filter))).scalar() or 0

    # Spam = SPAM verdict + SUSPICIOUS verdict (borderline threats)
    spam_detected = (await db.execute(select(func.count(Email.id)).where(
        or_(Email.threat_verdict == "SPAM", Email.threat_verdict == "SUSPICIOUS"),
        *email_filter
    ))).scalar() or 0

    phishing_detected = (await db.execute(select(func.count(Email.id)).where(Email.threat_verdict == "PHISHING", *email_filter))).scalar() or 0

    # Quarantined = currently quarantined + released (were quarantined) + blocked
    quarantined_count = (await db.execute(select(func.count(Email.id)).where(
        or_(Email.status == "QUARANTINED", Email.status == "BLOCKED", Email.status == "RELEASED"),
        *email_filter
    ))).scalar() or 0

    dlp_filter = [] if is_admin else [DLPIncident.user_id == user_id]
    dlp_count = (await db.execute(select(func.count(DLPIncident.id)).where(*dlp_filter))).scalar() or 0

    cutoff = datetime.now(timezone.utc) - timedelta(hours=2)

    # Automatically mark sessions inactive if idle for > 2 hours
    await db.execute(
        update(UserSession)
        .where(UserSession.is_active == True, UserSession.last_activity < cutoff)
        .values(is_active=False)
    )

    # Touch calling user's active session
    await db.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id, UserSession.is_active == True)
        .values(last_activity=datetime.now(timezone.utc))
    )
    await db.commit()

    active_sessions = (await db.execute(
        select(func.count(UserSession.id))
        .where(UserSession.is_active == True, UserSession.last_activity >= cutoff)
    )).scalar() or 0
    total_employees = (await db.execute(select(func.count(User.id)).where(User.role == "EMPLOYEE"))).scalar() or 0

    return DashboardStatsResponse(
        total_scanned=total_scanned,
        clean_emails=clean_emails,
        spam_detected=spam_detected,
        phishing_detected=phishing_detected,
        quarantined_count=quarantined_count,
        dlp_incidents_count=dlp_count,
        active_employees_logged_in=active_sessions,
        total_registered_employees=total_employees,
        threat_breakdown={
            "CLEAN": clean_emails,
            "SPAM": spam_detected,
            "PHISHING": phishing_detected,
            "BLOCKED": total_scanned - (clean_emails + spam_detected + phishing_detected) if total_scanned > 0 else 0
        }
    )
