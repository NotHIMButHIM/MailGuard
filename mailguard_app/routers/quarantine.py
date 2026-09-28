from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from mailguard_app.database import get_db
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.models.email import Email
from mailguard_app.models.user import User
from mailguard_app.models.release_request import ReleaseRequest
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.dependencies import require_admin, get_current_user_token
from mailguard_app.core.exceptions import NotFoundError, PermissionDeniedError
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.quarantine import (
    QuarantineResponse,
    QuarantineReleaseRequest
)
from mailguard_app.schemas.release_request import (
    ReleaseRequestCreate,
    ReleaseRequestDecision,
    ReleaseRequestResponse
)
from mailguard_app.services.isolation import isolation_engine
from mailguard_app.services.gmail_sync import gmail_sync_service

router = APIRouter(prefix="/quarantine", tags=["Admin Quarantine & Email Isolation"])


@router.get("", response_model=List[QuarantineResponse])
async def list_quarantined_emails(
    released_only: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(QuarantineRecord)
        .options(
            selectinload(QuarantineRecord.email).selectinload(Email.attachments),
            selectinload(QuarantineRecord.email).selectinload(Email.scan_result)
        )
        .order_by(QuarantineRecord.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if released_only is not None:
        stmt = stmt.where(QuarantineRecord.is_released == released_only)

    results = (await db.execute(stmt)).scalars().all()
    return results


@router.post("/{quarantine_id}/release", response_model=QuarantineResponse)
async def release_quarantined_email(
    quarantine_id: int,
    payload: QuarantineReleaseRequest,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(QuarantineRecord)
        .where(QuarantineRecord.id == quarantine_id)
        .options(
            selectinload(QuarantineRecord.email).selectinload(Email.attachments),
            selectinload(QuarantineRecord.email).selectinload(Email.scan_result)
        )
    )
    record = (await db.execute(stmt)).scalar_one_or_none()
    if not record:
        raise NotFoundError("Quarantine record not found")

    admin_id = int(admin_user.sub)
    released_record = await isolation_engine.release_email(
        quarantine_record=record,
        admin_user_id=admin_id,
        db=db
    )

    if record.email and record.email.gmail_message_id:
        user_obj = (await db.execute(select(User).where(User.id == record.email.user_id))).scalar_one_or_none()
        if user_obj and user_obj.is_google_user:
            try:
                await gmail_sync_service.restore_gmail_message(user_obj, record.email.gmail_message_id, db=db)
            except Exception:
                pass

    return released_record


# =====================================================================
# RELEASE REQUEST / TICKET WORKFLOW ENDPOINTS
# =====================================================================

@router.post("/requests", response_model=ReleaseRequestResponse)
async def submit_release_request(
    payload: ReleaseRequestCreate,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    """Submits a ticket from employee requesting release of a blocked or quarantined email."""
    user_id = int(current_user.sub)
    stmt = (
        select(Email)
        .where(Email.id == payload.email_id)
        .options(
            selectinload(Email.attachments),
            selectinload(Email.scan_result),
            selectinload(Email.quarantine_record)
        )
    )
    email = (await db.execute(stmt)).scalar_one_or_none()
    if not email:
        raise NotFoundError("Target email record not found")

    if current_user.role != "ADMIN" and email.user_id != user_id:
        raise PermissionDeniedError("Cannot request release for an email not belonging to your inbox")

    # Check if a pending ticket already exists
    stmt_existing = (
        select(ReleaseRequest)
        .where(ReleaseRequest.email_id == payload.email_id, ReleaseRequest.status == "PENDING")
    )
    existing_req = (await db.execute(stmt_existing)).scalar_one_or_none()
    if existing_req:
        # Update justification if pending
        existing_req.justification = payload.justification
        await db.commit()
        await db.refresh(existing_req)
        return _format_release_response(existing_req, email, current_user.email, "")

    # Calculate spam severity level
    spam_score = float(email.spam_score or 0.0)
    has_malicious = any(a.is_malicious for a in (email.attachments or []))
    if email.threat_verdict in ["BEC_IMPERSONATION", "MALICIOUS"] or has_malicious:
        spam_level = "CRITICAL"
    elif spam_score >= 0.75 or email.threat_verdict in ["PHISHING", "SPAM"]:
        spam_level = "HIGH"
    elif spam_score >= 0.40 or email.threat_verdict == "SUSPICIOUS":
        spam_level = "MEDIUM"
    else:
        spam_level = "LOW"

    ticket = ReleaseRequest(
        email_id=email.id,
        user_id=email.user_id,
        justification=payload.justification.strip(),
        status="PENDING",
        spam_score=spam_score,
        spam_level=spam_level,
        admin_notes=""
    )
    db.add(ticket)

    audit = AuditLog(
        user_id=user_id,
        action="RELEASE_REQUEST_SUBMITTED",
        entity_type="ReleaseRequest",
        entity_id=str(email.id),
        details={
            "email_id": email.id,
            "subject": email.subject,
            "spam_level": spam_level,
            "justification": payload.justification
        }
    )
    db.add(audit)
    await db.commit()
    await db.refresh(ticket)

    requester_user = (await db.execute(select(User).where(User.id == email.user_id))).scalar_one_or_none()
    user_name = requester_user.full_name if requester_user else ""
    user_email = requester_user.email if requester_user else ""

    return _format_release_response(ticket, email, user_name, user_email)


@router.get("/requests", response_model=List[ReleaseRequestResponse])
async def list_release_requests(
    status_filter: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    """Lists release request tickets. Admins see all; employees see their own."""
    stmt = (
        select(ReleaseRequest)
        .options(
            selectinload(ReleaseRequest.email).selectinload(Email.attachments),
            selectinload(ReleaseRequest.email).selectinload(Email.scan_result),
            selectinload(ReleaseRequest.user)
        )
        .order_by(ReleaseRequest.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    if current_user.role != "ADMIN":
        stmt = stmt.where(ReleaseRequest.user_id == int(current_user.sub))

    if status_filter:
        stmt = stmt.where(ReleaseRequest.status == status_filter.upper())

    tickets = (await db.execute(stmt)).scalars().all()
    out = []
    for t in tickets:
        u_name = t.user.full_name if t.user else "Unknown"
        u_email = t.user.email if t.user else "unknown@mailguard.local"
        out.append(_format_release_response(t, t.email, u_name, u_email))
    return out


@router.get("/requests/email/{email_id}")
async def get_email_release_request(
    email_id: int,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    """Fetches the latest release ticket for a specific email."""
    stmt = (
        select(ReleaseRequest)
        .where(ReleaseRequest.email_id == email_id)
        .order_by(ReleaseRequest.created_at.desc())
    )
    ticket = (await db.execute(stmt)).scalars().first()
    if not ticket:
        return None
    return ticket


@router.post("/requests/{request_id}/decide", response_model=ReleaseRequestResponse)
async def decide_release_request(
    request_id: int,
    payload: ReleaseRequestDecision,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Admin verifies spam level and approves or denies the release ticket."""
    admin_id = int(admin_user.sub)
    stmt = (
        select(ReleaseRequest)
        .where(ReleaseRequest.id == request_id)
        .options(
            selectinload(ReleaseRequest.email).selectinload(Email.attachments),
            selectinload(ReleaseRequest.email).selectinload(Email.scan_result),
            selectinload(ReleaseRequest.email).selectinload(Email.quarantine_record),
            selectinload(ReleaseRequest.user)
        )
    )
    ticket = (await db.execute(stmt)).scalar_one_or_none()
    if not ticket:
        raise NotFoundError("Release request ticket not found")

    decision = payload.action.upper()
    if decision not in ["APPROVE", "DENY"]:
        raise ValueError("Decision action must be 'APPROVE' or 'DENY'")

    from datetime import datetime, timezone
    ticket.status = "APPROVED" if decision == "APPROVE" else "DENIED"
    ticket.admin_notes = (payload.admin_notes or "").strip()
    ticket.reviewed_by_user_id = admin_id
    ticket.reviewed_at = datetime.now(timezone.utc)

    email = ticket.email
    if decision == "APPROVE" and email:
        # 1. Release Quarantine Record if present
        if email.quarantine_record:
            await isolation_engine.release_email(
                quarantine_record=email.quarantine_record,
                admin_user_id=admin_id,
                db=db
            )

        # 2. Transition email status to RELEASED
        await db.execute(
            update(Email)
            .where(Email.id == email.id)
            .values(status="RELEASED", isolation_status="RELEASED")
        )

        # 3. Restore message in Gmail if linked
        if email.gmail_message_id:
            user_obj = (await db.execute(select(User).where(User.id == email.user_id))).scalar_one_or_none()
            if user_obj and user_obj.is_google_user:
                try:
                    await gmail_sync_service.restore_gmail_message(user_obj, email.gmail_message_id, db=db)
                except Exception:
                    pass

    audit = AuditLog(
        user_id=admin_id,
        action=f"RELEASE_REQUEST_{ticket.status}",
        entity_type="ReleaseRequest",
        entity_id=str(ticket.id),
        details={
            "ticket_id": ticket.id,
            "email_id": email.id if email else None,
            "decision": ticket.status,
            "admin_notes": ticket.admin_notes
        }
    )
    db.add(audit)
    await db.commit()
    await db.refresh(ticket)

    u_name = ticket.user.full_name if ticket.user else ""
    u_email = ticket.user.email if ticket.user else ""
    return _format_release_response(ticket, email, u_name, u_email)


def _format_release_response(ticket: ReleaseRequest, email: Optional[Email], user_name: str, user_email: str) -> ReleaseRequestResponse:
    return ReleaseRequestResponse(
        id=ticket.id,
        email_id=ticket.email_id,
        user_id=ticket.user_id,
        justification=ticket.justification,
        status=ticket.status,
        spam_score=ticket.spam_score,
        spam_level=ticket.spam_level,
        admin_notes=ticket.admin_notes or "",
        reviewed_by_user_id=ticket.reviewed_by_user_id,
        reviewed_at=ticket.reviewed_at,
        created_at=ticket.created_at,
        email=email,
        user_name=user_name,
        user_email=user_email
    )
