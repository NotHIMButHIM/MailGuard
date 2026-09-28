import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))

import asyncio
from sqlalchemy import text
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.core.security import get_password_hash
from mailguard_app.models.user import User


async def clean_database():
    async with AsyncSessionLocal() as db:
        await db.execute(text("TRUNCATE TABLE user_sessions, analyst_feedbacks, audit_logs, remediation_tasks, notifications, employee_prevention_rules, dlp_incidents, policy_rules, scan_results, quarantine_records, attachments, emails, users CASCADE;"))
        await db.commit()

        admin_user = User(
            email="admin@mailguard.enterprise",
            hashed_password=get_password_hash("AdminPass@2026!"),
            full_name="Mailguard System Administrator",
            role="ADMIN",
            is_active=True
        )
        db.add(admin_user)
        await db.commit()
        print("Database cleaned and initial admin seeded: admin@mailguard.enterprise")


if __name__ == "__main__":
    asyncio.run(clean_database())
