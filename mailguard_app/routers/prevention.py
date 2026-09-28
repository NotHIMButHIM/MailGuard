from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from mailguard_app.database import get_db
from mailguard_app.models.prevention import EmployeePreventionRule
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.dependencies import get_current_user_token
from mailguard_app.core.exceptions import NotFoundError, PermissionDeniedError
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.prevention import (
    EmployeePreventionRuleCreate,
    EmployeePreventionRuleResponse
)

router = APIRouter(prefix="/prevention", tags=["Employee Spam Prevention & Pre-Blocking"])


@router.get("/rules", response_model=List[EmployeePreventionRuleResponse])
async def list_prevention_rules(
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    stmt = select(EmployeePreventionRule).where(EmployeePreventionRule.user_id == user_id).order_by(EmployeePreventionRule.created_at.desc())
    rules = (await db.execute(stmt)).scalars().all()
    return rules


@router.post("/rules", response_model=EmployeePreventionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_prevention_rule(
    rule_in: EmployeePreventionRuleCreate,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    rule = EmployeePreventionRule(
        user_id=user_id,
        rule_type=rule_in.rule_type,
        pattern=rule_in.pattern,
        action=rule_in.action or "BLOCK",
        is_active=rule_in.is_active if rule_in.is_active is not None else True
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    audit = AuditLog(
        user_id=user_id,
        action="CREATE_PREVENTION_RULE",
        entity_type="EmployeePreventionRule",
        entity_id=str(rule.id),
        details={"rule_type": rule.rule_type, "pattern": rule.pattern}
    )
    db.add(audit)
    await db.commit()

    return rule


@router.patch("/rules/{rule_id}/toggle", response_model=EmployeePreventionRuleResponse)
async def toggle_rule_active(
    rule_id: int,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    rule = (await db.execute(select(EmployeePreventionRule).where(EmployeePreventionRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise NotFoundError("Rule not found")

    if rule.user_id != user_id and current_user.role != "ADMIN":
        raise PermissionDeniedError("Permission denied")

    rule.is_active = not rule.is_active
    await db.commit()
    await db.refresh(rule)
    return rule


@router.delete("/rules/{rule_id}")
async def delete_prevention_rule(
    rule_id: int,
    current_user: TokenPayload = Depends(get_current_user_token),
    db: AsyncSession = Depends(get_db)
):
    user_id = int(current_user.sub)
    rule = (await db.execute(select(EmployeePreventionRule).where(EmployeePreventionRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise NotFoundError("Rule not found")

    if rule.user_id != user_id and current_user.role != "ADMIN":
        raise PermissionDeniedError("Permission denied")

    await db.delete(rule)
    audit = AuditLog(
        user_id=user_id,
        action="DELETE_PREVENTION_RULE",
        entity_type="EmployeePreventionRule",
        entity_id=str(rule_id),
        details={"pattern": rule.pattern}
    )
    db.add(audit)
    await db.commit()
    return {"status": "deleted", "rule_id": rule_id}
