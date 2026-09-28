from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from mailguard_app.database import get_db
from mailguard_app.models.user import User, UserSession
from mailguard_app.models.email import Email
from mailguard_app.core.dependencies import get_current_user_token
from mailguard_app.core.exceptions import NotFoundError, PermissionDeniedError
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.email import EmailCreate, EmailResponse
from mailguard_app.services.scanner import mail_scanner
from mailguard_app.services.gmail_sync import gmail_sync_service

router = APIRouter(prefix="/emails", tags=["Emails & Inbox Scanning"])


@router.get("", response_model=List[EmailResponse])
async def list_emails(
    status_filter: Optional[str] = None,
    threat_filter: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Email)
        .options(
            selectinload(Email.attachments),
            selectinload(Email.scan_result)
        )
        .order_by(Email.created_at.desc())
        .limit(limit)
        .offset(offset)
    )

    # Touch caller's active session timestamp
    if current_user.sub:
        try:
            await db.execute(
                update(UserSession)
                .where(UserSession.user_id == int(current_user.sub), UserSession.is_active == True)
                .values(last_activity=datetime.now(timezone.utc))
            )
            await db.commit()
        except Exception:
            pass

    if current_user.role != "ADMIN":
        stmt = stmt.where(Email.user_id == int(current_user.sub))

    if status_filter:
        stmt = stmt.where(Email.status == status_filter)
    if threat_filter:
        stmt = stmt.where(Email.threat_verdict == threat_filter)

    results = (await db.execute(stmt)).scalars().all()
    return results


@router.get("/{email_id}", response_model=EmailResponse)
async def get_email_detail(
    email_id: int,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Email)
        .where(Email.id == email_id)
        .options(
            selectinload(Email.attachments),
            selectinload(Email.scan_result)
        )
    )
    email = (await db.execute(stmt)).scalar_one_or_none()
    if not email:
        raise NotFoundError("Email not found")

    if current_user.role != "ADMIN" and email.user_id != int(current_user.sub):
        raise PermissionDeniedError("Access to this email is restricted")

    return email


@router.post("/scan", status_code=status.HTTP_201_CREATED)
async def scan_manual_email(
    payload: EmailCreate,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    result = await mail_scanner.scan_and_ingest_email(
        user_id=user_id,
        sender=payload.sender,
        recipient=payload.recipient,
        subject=payload.subject,
        body_plain=payload.body_plain,
        body_html=payload.body_html or "",
        attachments_meta=payload.attachments_meta or [],
        raw_headers=payload.raw_headers or {},
        db=db
    )
    return result


@router.post("/sync-gmail")
async def sync_gmail_inbox(
    max_messages: int = Query(10, ge=1, le=50),
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise NotFoundError("User not found")

    if not user.google_access_token:
        return {
            "status": "skipped",
            "message": "User has not connected Google account or provided Gmail access tokens."
        }

    try:
        raw_messages = await gmail_sync_service.fetch_recent_messages(user, max_results=max_messages, db=db)
    except Exception as e:
        return {
            "status": "error",
            "message": getattr(e, "detail", str(e))
        }

    synced_results = []

    for msg in raw_messages:
        stmt = select(Email).where(Email.gmail_message_id == msg.get("gmail_message_id"))
        existing = (await db.execute(stmt)).scalar_one_or_none()
        if existing:
            if existing.status in ["QUARANTINED", "BLOCKED"]:
                try:
                    await gmail_sync_service.quarantine_gmail_message(user, msg.get("gmail_message_id"), db=db)
                except Exception:
                    pass
            continue

        res = await mail_scanner.scan_and_ingest_email(
            user_id=user.id,
            sender=msg.get("sender", ""),
            recipient=msg.get("recipient", user.email),
            subject=msg.get("subject", ""),
            body_plain=msg.get("body_plain", ""),
            body_html=msg.get("body_html", ""),
            gmail_message_id=msg.get("gmail_message_id"),
            attachments_meta=msg.get("attachments", []),
            db=db
        )
        synced_results.append(res)

    return {
        "status": "completed",
        "synced_count": len(synced_results),
        "results": synced_results
    }
