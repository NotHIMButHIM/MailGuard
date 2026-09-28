import asyncio
import os
import sys
from pathlib import Path

root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from sqlalchemy import select
from mailguard_app.database import engine, AsyncSessionLocal, Base
from mailguard_app.models.user import User
from mailguard_app.core.security import get_password_hash


async def seed_admin(
    email: str = None,
    password: str = None,
    full_name: str = None
):
    admin_email = email or os.getenv("ADMIN_EMAIL", "admin@mailguard.enterprise")
    admin_pass = password or os.getenv("ADMIN_PASSWORD", "AdminPass@2026!")
    admin_name = full_name or os.getenv("ADMIN_NAME", "System Administrator")

    async with AsyncSessionLocal() as session:
        stmt = select(User).where(User.email == admin_email)
        existing = (await session.execute(stmt)).scalar_one_or_none()

        if existing:
            existing.role = "ADMIN"
            existing.hashed_password = get_password_hash(admin_pass)
            existing.full_name = admin_name
            existing.is_active = True
            await session.commit()
            print(f"Updated existing admin user: {admin_email}")
            return existing

        new_admin = User(
            email=admin_email,
            hashed_password=get_password_hash(admin_pass),
            full_name=admin_name,
            role="ADMIN",
            is_active=True,
            organization_name="Enterprise Security"
        )
        session.add(new_admin)
        await session.commit()
        await session.refresh(new_admin)
        print(f"Admin user successfully created: {admin_email}")
        return new_admin


if __name__ == "__main__":
    email_arg = sys.argv[1] if len(sys.argv) > 1 else None
    pass_arg = sys.argv[2] if len(sys.argv) > 2 else None
    name_arg = sys.argv[3] if len(sys.argv) > 3 else None
    asyncio.run(seed_admin(email_arg, pass_arg, name_arg))
