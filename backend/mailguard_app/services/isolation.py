import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from mailguard_app.models.email import Email
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.models.audit import AuditLog


class EmailIsolationEngine:
    def sanitize_html(self, html_content: str) -> str:
        if not html_content:
            return ""
        sanitized = re.sub(r"<script.*?>.*?</script>", "", html_content, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r"<iframe.*?>.*?</iframe>", "", sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'href=["\'](http[s]?://.*?)["\']', r'href="#" data-isolated-url="\1" class="isolated-link"', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'src=["\'](http[s]?://.*?)["\']', r'src="" data-blocked-src="\1"', sanitized, flags=re.IGNORECASE)
        return sanitized

    async def isolate_and_quarantine(
        self,
        email: Email,
        reason: str,
        isolation_level: str = "QUARANTINED",
        db: AsyncSession = None,
        admin_user_id: Optional[int] = None
    ) -> QuarantineRecord:
        email.status = "QUARANTINED"
        email.isolation_status = isolation_level

        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        quarantine_record = QuarantineRecord(
            email_id=email.id,
            user_id=email.user_id,
            reason=reason,
            isolation_level=isolation_level,
            is_released=False,
            quarantine_expires_at=expires_at,
            action_history=[{
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "ISOLATED_AND_QUARANTINED",
                "isolation_level": isolation_level,
                "reason": reason,
                "triggered_by": "SCANNER" if not admin_user_id else f"ADMIN_{admin_user_id}"
            }]
        )

        if db:
            db.add(quarantine_record)
            audit = AuditLog(
                user_id=admin_user_id or email.user_id,
                action="EMAIL_ISOLATED",
                entity_type="Email",
                entity_id=str(email.id),
                details={"reason": reason, "isolation_level": isolation_level}
            )
            db.add(audit)
            await db.commit()
            await db.refresh(quarantine_record)

        return quarantine_record

    async def release_email(
        self,
        quarantine_record: QuarantineRecord,
        admin_user_id: int,
        db: AsyncSession
    ) -> QuarantineRecord:
        quarantine_record.is_released = True
        quarantine_record.released_by_user_id = admin_user_id
        quarantine_record.released_at = datetime.now(timezone.utc)

        history = list(quarantine_record.action_history or [])
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "RELEASED_FROM_QUARANTINE",
            "released_by": admin_user_id
        })
        quarantine_record.action_history = history

        await db.execute(
            update(Email)
            .where(Email.id == quarantine_record.email_id)
            .values(status="RELEASED", isolation_status="RELEASED")
        )

        audit = AuditLog(
            user_id=admin_user_id,
            action="RELEASE_QUARANTINE",
            entity_type="QuarantineRecord",
            entity_id=str(quarantine_record.id),
            details={"email_id": quarantine_record.email_id}
        )
        db.add(audit)
        await db.commit()
        await db.refresh(quarantine_record)
        return quarantine_record


isolation_engine = EmailIsolationEngine()
