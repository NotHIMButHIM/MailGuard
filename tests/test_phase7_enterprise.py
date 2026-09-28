import pytest
import uuid
import urllib.parse
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from main import app
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import User
from mailguard_app.models.email import Email
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.services.bec_defense import bec_engine
from mailguard_app.services.safelinks import safelinks_service
from mailguard_app.services.banner_injection import banner_injector
from mailguard_app.services.scanner import mail_scanner


# =====================================================================
# 1. BEC & EXECUTIVE IMPERSONATION DEFENSE TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_bec_display_name_spoofing():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        # Create registered corporate executive user
        exec_user = User(
            email=f"ceo_{uid}@mailguard.enterprise",
            full_name=f"Himadri Pal {uid}",
            role="ADMIN",
            is_active=True
        )
        session.add(exec_user)
        await session.commit()
        await session.refresh(exec_user)

        # Attacker spoofs executive display name with external address
        spoofed_sender = f'"{exec_user.full_name}" <attacker.scammer@gmail.com>'
        bec_hit = await bec_engine.evaluate_impersonation(
            raw_sender=spoofed_sender,
            subject="Urgent: Wire payment needed today",
            body="Please process this payment immediately.",
            db=session
        )

        assert bec_hit is not None
        assert bec_hit["is_impersonation"] is True
        assert bec_hit["type"] == "DISPLAY_NAME_SPOOFING"
        assert exec_user.full_name in bec_hit["reason"]


@pytest.mark.asyncio
async def test_bec_executive_title_spoofing():
    async with AsyncSessionLocal() as session:
        # Free webmail sender claiming to be CEO
        sender = '"CEO Office" <company.executive.desk@yahoo.com>'
        bec_hit = await bec_engine.evaluate_impersonation(
            raw_sender=sender,
            subject="Quick task for payroll",
            body="Are you at your desk right now?",
            db=session
        )

        assert bec_hit is not None
        assert bec_hit["is_impersonation"] is True
        assert bec_hit["type"] == "EXECUTIVE_TITLE_SPOOFING"


@pytest.mark.asyncio
async def test_bec_typosquatting_domain():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        # Register administrator with corporate domain
        admin = User(
            email=f"admin_{uid}@mycorpdomain.com",
            full_name="Corp Admin",
            role="ADMIN",
            is_active=True
        )
        session.add(admin)
        await session.commit()

        # Sender uses lookalike domain (edit distance 1)
        typo_sender = f"billing@myc0rpdomain.com"
        bec_hit = await bec_engine.evaluate_impersonation(
            raw_sender=typo_sender,
            subject="Invoice correction",
            body="Please review",
            db=session
        )

        assert bec_hit is not None
        assert bec_hit["is_impersonation"] is True
        assert bec_hit["type"] == "TYPOSQUATTING_DOMAIN"


@pytest.mark.asyncio
async def test_bec_legitimate_sender_passes():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        exec_user = User(
            email=f"legit_{uid}@company.com",
            full_name="Sarah Connor",
            role="EMPLOYEE",
            is_active=True
        )
        session.add(exec_user)
        await session.commit()

        # Legitimate sender matching both name and email
        sender = f'"Sarah Connor" <{exec_user.email}>'
        bec_hit = await bec_engine.evaluate_impersonation(
            raw_sender=sender,
            subject="Status update",
            body="Here is my weekly status report.",
            db=session
        )

        assert bec_hit is None


# =====================================================================
# 2. TIMEOF-CLICK SAFELINKS URL REWRITING & REPUTATION TESTS
# =====================================================================

def test_safelinks_url_inspection():
    # 1. Clean well-known URL
    clean = safelinks_service.inspect_url("https://github.com/torvalds/linux")
    assert clean["is_safe"] is True
    assert clean["threat_level"] == "CLEAN"

    # 2. Direct IP Address Host
    ip_url = safelinks_service.inspect_url("http://185.220.101.5/malware.exe")
    assert ip_url["is_safe"] is False
    assert ip_url["threat_level"] == "MALICIOUS"

    # 3. Suspicious / Abusive TLD
    tld_url = safelinks_service.inspect_url("https://urgent-verification.top/auth")
    assert tld_url["is_safe"] is False
    assert tld_url["threat_level"] == "SUSPICIOUS"

    # 4. Credential Harvesting Path
    phish_path = safelinks_service.inspect_url("https://secure-portal-update.com/signin/password_reset")
    assert phish_path["is_safe"] is False
    assert "Credential harvesting" in phish_path["reason"]

    # 5. Non-standard Port
    port_url = safelinks_service.inspect_url("http://example-site.org:8443/download")
    assert port_url["is_safe"] is False
    assert "port" in port_url["reason"]


def test_safelinks_html_and_plain_rewriting():
    html_input = '<p>Check <a href="https://example.com/login">this link</a> and <a href="http://portal.xyz">portal</a>.</p>'
    rewritten_html = safelinks_service.rewrite_html_links(html_input)

    assert "/api/v1/safelinks/redirect?url=" in rewritten_html
    assert 'data-original-href="https://example.com/login"' in rewritten_html
    assert 'title="Protected by Mailguard SafeLinks"' in rewritten_html

    plain_input = "Please visit https://company.top/auth for confirmation."
    rewritten_plain = safelinks_service.rewrite_plain_links(plain_input)

    assert "/api/v1/safelinks/redirect?url=" in rewritten_plain


# =====================================================================
# 3. IN-EMAIL SECURITY WARNING BANNER INJECTION TESTS
# =====================================================================

def test_banner_injection_variations():
    # 1. BEC Critical Banner
    bec_mock = {"is_impersonation": True, "reason": "Display name mimics CEO."}
    html_bec = banner_injector.inject_banner(
        html_body="<html><body><p>Hello team</p></body></html>",
        threat_verdict="BEC_IMPERSONATION",
        bec_hit=bec_mock,
        is_external=True
    )
    assert "MAILGUARD SECURITY WARNING BANNER" in html_bec
    assert "Critical Warning: Potential Executive Impersonation" in html_bec
    assert "Display name mimics CEO." in html_bec

    # 2. Phishing / Suspicious Alert Banner
    html_phish = banner_injector.inject_banner(
        html_body="<p>Click here to update billing</p>",
        threat_verdict="PHISHING",
        bec_hit=None,
        is_external=True
    )
    assert "Security Alert: Elevated Threat Signals Detected" in html_phish

    # 3. External Clean Notice Banner
    html_ext = banner_injector.inject_banner(
        html_body="<p>Standard inbound communication</p>",
        threat_verdict="CLEAN",
        bec_hit=None,
        is_external=True
    )
    assert "Notice: External Sender" in html_ext


# =====================================================================
# 4. SAFELINKS HTTP API ENDPOINTS TESTS
# =====================================================================

@pytest.mark.asyncio
async def test_safelinks_api_inspect_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Inspect clean URL
        res_clean = await client.get("/api/v1/safelinks/inspect", params={"url": "https://google.com"})
        assert res_clean.status_code == 200
        assert res_clean.json()["is_safe"] is True

        # Inspect malicious URL
        res_bad = await client.get("/api/v1/safelinks/inspect", params={"url": "http://192.168.1.1/exploit"})
        assert res_bad.status_code == 200
        assert res_bad.json()["is_safe"] is False


@pytest.mark.asyncio
async def test_safelinks_api_redirect_flow():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Safe URL -> Redirect 302
        safe_target = "https://github.com/features"
        res_safe = await client.get(
            "/api/v1/safelinks/redirect",
            params={"url": safe_target},
            follow_redirects=False
        )
        assert res_safe.status_code == 302
        assert res_safe.headers.get("location") == safe_target

        # Malicious URL -> Block Warning Page 200
        bad_target = "http://phish-login-update.top/account"
        res_bad = await client.get(
            "/api/v1/safelinks/redirect",
            params={"url": bad_target},
            follow_redirects=False
        )
        assert res_bad.status_code == 200
        assert "Dangerous Destination Blocked" in res_bad.text
        assert "Mailguard SafeLinks" in res_bad.text
        assert "High-risk domain extension" in res_bad.text


# =====================================================================
# 5. SCANNER INTEGRATION WITH PHASE 7 ENGINES
# =====================================================================

@pytest.mark.asyncio
async def test_scanner_with_bec_and_safelinks_orchestration():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        exec_user = User(
            email=f"president_{uid}@mailguard.corp",
            full_name=f"President Jane {uid}",
            role="ADMIN",
            is_active=True
        )
        employee = User(
            email=f"staff_{uid}@mailguard.corp",
            full_name="Staff Member",
            role="EMPLOYEE",
            is_active=True
        )
        session.add_all([exec_user, employee])
        await session.commit()
        await session.refresh(exec_user)
        await session.refresh(employee)

        # Ingest email spoofing executive display name with links
        scan_result = await mail_scanner.scan_and_ingest_email(
            user_id=employee.id,
            sender=f'"{exec_user.full_name}" <external.attacker@gmail.com>',
            recipient=employee.email,
            subject="Immediate Gift Card Purchase",
            body_plain="Please click https://giftcard-portal.xyz to buy cards.",
            body_html='<p>Click <a href="https://giftcard-portal.xyz">here</a></p>',
            db=session
        )

        # Assert BEC triggered and quarantined
        assert scan_result["status"] == "QUARANTINED"
        assert scan_result["threat_verdict"] == "BEC_IMPERSONATION"
        assert scan_result["bec"] is not None
        assert scan_result["bec"]["is_impersonation"] is True

        # Assert SafeLinks rewrote links and banner was injected
        assert "/api/v1/safelinks/redirect" in scan_result["processed_html"]
        assert "/api/v1/safelinks/redirect" in scan_result["processed_plain"]
        assert "MAILGUARD SECURITY WARNING BANNER" in scan_result["processed_html"]
        assert "Potential Executive Impersonation" in scan_result["processed_html"]

        # Verify persisted email in DB
        email_stmt = select(Email).where(Email.id == scan_result["email_id"])
        saved_email = (await session.execute(email_stmt)).scalar_one()
        assert saved_email.threat_verdict == "BEC_IMPERSONATION"
        assert "/api/v1/safelinks/redirect" in saved_email.body_html
