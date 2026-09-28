import re
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from mailguard_app.models.prevention import EmployeePreventionRule
from mailguard_app.models.policy import PolicyRule


class PolicyEngine:
    async def evaluate_employee_prevention(
        self,
        user_id: int,
        sender: str,
        subject: str,
        body: str,
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        stmt = select(EmployeePreventionRule).where(
            EmployeePreventionRule.user_id == user_id,
            EmployeePreventionRule.is_active == True
        )
        result = await db.execute(stmt)
        rules = result.scalars().all()

        sender_lower = sender.lower()
        sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
        content = f"{subject} {body}".lower()

        for rule in rules:
            pat = rule.pattern.lower().strip()
            matched = False

            if rule.rule_type == "BLOCK_SENDER":
                if pat in sender_lower or sender_lower in pat:
                    matched = True
            elif rule.rule_type == "BLOCK_DOMAIN":
                domain_pat = pat.split("@")[-1].strip() if "@" in pat else pat
                if domain_pat and (
                    domain_pat == sender_domain 
                    or domain_pat in sender_domain 
                    or sender_domain.endswith(domain_pat)
                    or pat in sender_lower
                ):
                    matched = True
            elif rule.rule_type == "KEYWORD_FILTER" and pat in content:
                matched = True
            elif rule.rule_type == "REGEX_RULE" and re.search(pat, content):
                matched = True

            if matched:
                rule.hits_count += 1
                await db.commit()
                return {
                    "rule_id": rule.id,
                    "rule_type": rule.rule_type,
                    "pattern": rule.pattern,
                    "action": rule.action,
                    "reason": f"Matched employee pre-block rule: {rule.rule_type} -> {rule.pattern}"
                }
        return None

    async def evaluate_system_policies(
        self,
        sender: str,
        subject: str,
        body: str,
        attachment_names: List[str],
        db: AsyncSession
    ) -> Optional[Dict[str, Any]]:
        stmt = select(PolicyRule).where(PolicyRule.is_active == True).order_by(PolicyRule.priority.asc())
        result = await db.execute(stmt)
        policies = result.scalars().all()

        for policy in policies:
            expr = policy.condition_expression or {}
            blocked_exts = expr.get("attachment_extensions", [])
            for att in attachment_names:
                for ext in blocked_exts:
                    if att.lower().endswith(ext.lower()):
                        return {
                            "policy_id": policy.id,
                            "name": policy.name,
                            "action": policy.action,
                            "reason": f"Violated policy '{policy.name}': blocked attachment extension {ext}"
                        }
        return None


policy_engine = PolicyEngine()
