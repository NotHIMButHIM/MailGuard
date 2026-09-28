from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.database import get_db
from mailguard_app.models.feedback import AnalystFeedback
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.dependencies import get_current_user_token
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.feedback import (
    AnalystFeedbackCreate,
    AnalystFeedbackResponse
)

router = APIRouter(prefix="/feedback", tags=["Model Feedback & False-Positive Reporting"])


@router.get("", response_model=List[AnalystFeedbackResponse])
async def list_feedback(
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(AnalystFeedback).order_by(AnalystFeedback.created_at.desc())
    if current_user.role != "ADMIN":
        stmt = stmt.where(AnalystFeedback.user_id == int(current_user.sub))
    feedbacks = (await db.execute(stmt)).scalars().all()
    return feedbacks


@router.post("", response_model=AnalystFeedbackResponse, status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    payload: AnalystFeedbackCreate,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    fb = AnalystFeedback(
        email_id=payload.email_id,
        user_id=user_id,
        original_verdict=payload.original_verdict,
        corrected_verdict=payload.corrected_verdict,
        feedback_type=payload.feedback_type,
        comments=payload.comments or "",
        is_used_for_retraining=False
    )
    db.add(fb)
    await db.commit()
    await db.refresh(fb)

    audit = AuditLog(
        user_id=user_id,
        action="SUBMIT_FEEDBACK",
        entity_type="AnalystFeedback",
        entity_id=str(fb.id),
        details={"email_id": fb.email_id, "type": fb.feedback_type}
    )
    db.add(audit)
    await db.commit()
    return fb
