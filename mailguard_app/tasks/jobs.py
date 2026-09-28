import asyncio
import concurrent.futures
from mailguard_app.tasks.celery_app import celery_app
from mailguard_app.services.scanner import mail_scanner
from mailguard_app.services.gmail_sync import gmail_sync_service
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import User
from sqlalchemy import select


def _run_sync(coro):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    return asyncio.run(coro)


@celery_app.task(name="tasks.async_scan_email")
def async_scan_email(email_data: dict):
    async def _run():
        async with AsyncSessionLocal() as session:
            return await mail_scanner.scan_and_ingest_email(
                user_id=email_data.get("user_id"),
                sender=email_data.get("sender"),
                recipient=email_data.get("recipient"),
                subject=email_data.get("subject"),
                body_plain=email_data.get("body_plain", ""),
                body_html=email_data.get("body_html", ""),
                attachments_meta=email_data.get("attachments_meta", []),
                db=session
            )
    return _run_sync(_run())


@celery_app.task(name="tasks.sync_all_gmail_accounts")
def sync_all_gmail_accounts():
    async def _run():
        async with AsyncSessionLocal() as session:
            stmt = select(User).where(User.is_google_user == True, User.google_access_token != None)
            users = (await session.execute(stmt)).scalars().all()
            synced_count = 0
            for u in users:
                try:
                    msgs = await gmail_sync_service.fetch_recent_messages(u, max_results=10, db=session)
                    for m in msgs:
                        from mailguard_app.models.email import Email
                        stmt_existing = select(Email).where(Email.gmail_message_id == m.get("gmail_message_id"))
                        existing = (await session.execute(stmt_existing)).scalar_one_or_none()
                        if existing:
                            if existing.status in ["QUARANTINED", "BLOCKED"]:
                                try:
                                    await gmail_sync_service.quarantine_gmail_message(u, m.get("gmail_message_id"), db=session)
                                except Exception:
                                    pass
                            continue
                        await mail_scanner.scan_and_ingest_email(
                            user_id=u.id,
                            sender=m.get("sender", ""),
                            recipient=m.get("recipient", u.email),
                            subject=m.get("subject", ""),
                            body_plain=m.get("body_plain", ""),
                            body_html=m.get("body_html", ""),
                            gmail_message_id=m.get("gmail_message_id"),
                            attachments_meta=m.get("attachments", []),
                            db=session
                        )
                        synced_count += 1
                except Exception:
                    continue
            return {"synced_messages_count": synced_count}
    return _run_sync(_run())
