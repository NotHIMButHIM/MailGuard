import asyncio
import pytest
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import UserSession, User
from sqlalchemy import delete, select


@pytest.fixture(autouse=True, scope="session")
def cleanup_test_sessions_after_suite():
    yield
    async def _cleanup():
        async with AsyncSessionLocal() as session:
            test_users = (await session.execute(
                select(User.id).where(User.email.not_in(["admin@mailguard.enterprise", "employee@mailguard.enterprise"]))
            )).scalars().all()
            if test_users:
                await session.execute(
                    delete(UserSession).where(UserSession.user_id.in_(test_users))
                )
            await session.execute(
                delete(UserSession).where(UserSession.is_active == False)
            )
            await session.commit()

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_cleanup())
        else:
            loop.run_until_complete(_cleanup())
    except Exception:
        asyncio.run(_cleanup())
