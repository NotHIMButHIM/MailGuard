import pytest
from unittest.mock import MagicMock
from mailguard_app.tasks.celery_app import celery_app
from mailguard_app.tasks.jobs import async_scan_email, sync_all_gmail_accounts
from scripts.seed_admin import seed_admin
from scripts.run_smtp_relay import MailguardSMTPHandler


def test_celery_app_configuration_and_task_registration():
    celery_app.loader.import_default_modules()
    registered = list(celery_app.tasks.keys())
    assert "tasks.async_scan_email" in registered
    assert "tasks.sync_all_gmail_accounts" in registered
    assert celery_app.conf.task_serializer == "json"
    assert celery_app.conf.timezone == "UTC"


@pytest.mark.asyncio
async def test_seed_admin_script():
    admin = await seed_admin(
        email="test_phase5_admin@mailguard.enterprise",
        password="AdminTestPassword@2026!",
        full_name="Phase 5 Test Admin"
    )
    assert admin is not None
    assert admin.email == "test_phase5_admin@mailguard.enterprise"
    assert admin.role == "ADMIN"
    assert admin.is_active is True

    updated_admin = await seed_admin(
        email="test_phase5_admin@mailguard.enterprise",
        password="AdminTestPassword@2026!Updated",
        full_name="Phase 5 Test Admin Updated"
    )
    assert updated_admin.full_name == "Phase 5 Test Admin Updated"


@pytest.mark.asyncio
async def test_async_scan_email_task_execution():
    admin = await seed_admin(
        email="scan_target@mailguard.enterprise",
        password="AdminTestPassword@2026!",
        full_name="Scan Target"
    )
    email_payload = {
        "user_id": admin.id,
        "sender": "external_vendor@partner.com",
        "recipient": admin.email,
        "subject": "Monthly Security Review Meeting",
        "body_plain": "Hello Team, please find our scheduled review meeting agenda attached.",
        "body_html": "<p>Hello Team, please find our scheduled review meeting agenda attached.</p>",
        "attachments_meta": []
    }
    result = async_scan_email(email_payload)
    assert isinstance(result, dict)
    assert "email_id" in result
    assert "threat_verdict" in result
    assert result["threat_verdict"] in ["CLEAN", "SPAM", "PHISHING", "SUSPICIOUS", "QUARANTINED", "ISOLATED"]


@pytest.mark.asyncio
async def test_sync_all_gmail_accounts_task_execution():
    result = sync_all_gmail_accounts()
    assert isinstance(result, dict)
    assert "synced_messages_count" in result
    assert isinstance(result["synced_messages_count"], int)


@pytest.mark.asyncio
async def test_smtp_relay_handler_processing():
    admin = await seed_admin(
        email="relay_target@mailguard.enterprise",
        password="AdminTestPassword@2026!",
        full_name="Relay Target"
    )
    handler = MailguardSMTPHandler()
    mock_server = MagicMock()
    mock_session = MagicMock()
    mock_session.peer = ("127.0.0.1", 54321)

    mock_envelope = MagicMock()
    mock_envelope.mail_from = "vendor@external.com"
    mock_envelope.rcpt_tos = [admin.email]
    mock_envelope.content = (
        f"From: vendor@external.com\r\n"
        f"To: {admin.email}\r\n"
        f"Subject: Inbound Relay Security Test\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        f"This is an inbound message passed through the Mailguard SMTP Relay.\r\n"
    ).encode("utf-8")

    response = await handler.handle_DATA(mock_server, mock_session, mock_envelope)
    assert "250 Message accepted" in response
