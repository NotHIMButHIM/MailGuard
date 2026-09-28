from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.database import get_db
from mailguard_app.models.policy import PolicyRule
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.dependencies import require_admin
from mailguard_app.core.exceptions import NotFoundError
from mailguard_app.schemas.auth import TokenPayload
from mailguard_app.schemas.policy import PolicyRuleCreate, PolicyRuleResponse

router = APIRouter(prefix="/policies", tags=["Security Policies & Engine Rules"])


@router.get("", response_model=List[PolicyRuleResponse])
async def list_policies(
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(PolicyRule).order_by(PolicyRule.priority.asc())
    policies = (await db.execute(stmt)).scalars().all()
    return policies


@router.post("", response_model=PolicyRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_in: PolicyRuleCreate,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    policy = PolicyRule(
        name=policy_in.name,
        description=policy_in.description or "",
        scope=policy_in.scope or "GLOBAL",
        condition_expression=policy_in.condition_expression,
        priority=policy_in.priority or 100,
        action=policy_in.action or "QUARANTINE",
        is_active=policy_in.is_active if policy_in.is_active is not None else True
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)

    audit = AuditLog(
        user_id=int(admin_user.sub),
        action="CREATE_POLICY_RULE",
        entity_type="PolicyRule",
        entity_id=str(policy.id),
        details={"name": policy.name, "action": policy.action}
    )
    db.add(audit)
    await db.commit()
    return policy


@router.delete("/{policy_id}")
async def delete_policy(
    policy_id: int,
    admin_user: TokenPayload = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    policy = (await db.execute(select(PolicyRule).where(PolicyRule.id == policy_id))).scalar_one_or_none()
    if not policy:
        raise NotFoundError("Policy not found")

    await db.delete(policy)
    audit = AuditLog(
        user_id=int(admin_user.sub),
        action="DELETE_POLICY_RULE",
        entity_type="PolicyRule",
        entity_id=str(policy_id),
        details={"name": policy.name}
    )
    db.add(audit)
    await db.commit()
    return {"status": "deleted", "policy_id": policy_id}
