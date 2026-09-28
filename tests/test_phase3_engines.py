import pytest
import uuid
from sqlalchemy import select
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import User
from mailguard_app.models.email import Email
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.models.prevention import EmployeePreventionRule
from mailguard_app.ml.predict import predictor
from mailguard_app.ml.model_registry import get_model_registry
from mailguard_app.services.auth_check import auth_checker
from mailguard_app.services.nlp_check import nlp_engine
from mailguard_app.services.dlp_check import dlp_inspector
from mailguard_app.services.sandbox_check import sandbox_analyzer
from mailguard_app.services.isolation import isolation_engine
from mailguard_app.services.scanner import mail_scanner


def test_ml_prediction_pipeline():
    spam_sample = "Congratulations! You won 1,000,000 dollars. Wire transfer funds immediately."
    spam_res = predictor.predict_all("Claim Prize", spam_sample)
    assert spam_res["spam_score"] > 0.5
    assert spam_res["verdict"] in ["SPAM", "PHISHING", "SUSPICIOUS"]

    phish_sample = "Urgent action required: Update your Microsoft Office 365 credentials to prevent account termination."
    phish_res = predictor.predict_all("Account Security Alert", phish_sample)
    assert phish_res["phishing_score"] > 0.5

    clean_sample = "Hi team, here are the meeting notes for tomorrow's sprint review."
    clean_res = predictor.predict_all("Sprint Review Notes", clean_sample)
    assert clean_res["verdict"] == "CLEAN"
    assert clean_res["spam_score"] < 0.5


def test_email_auth_checker():
    spf_pass = auth_checker.check_spf("user@google.com")
    assert spf_pass == "PASS"

    spf_fail = auth_checker.check_spf("bad@phishdomain.com")
    assert spf_fail == "FAIL"

    eval_res = auth_checker.evaluate_all("attacker@phishdomain.com")
    assert eval_res["spf_status"] == "FAIL"
    assert eval_res["is_authenticated"] is False


def test_nlp_threat_engine():
    analysis = nlp_engine.analyze(
        "Urgent: Action Required",
        "Your account is suspended. Login to verify your credentials within 24 hours."
    )
    assert analysis["total_hits"] >= 2
    assert analysis["nlp_score"] > 0.3
    assert "urgency" in analysis["categories"]
    assert "credential_harvesting" in analysis["categories"]


def test_dlp_inspector():
    text_with_pii = "My PAN card is ABCDE1234F and Aadhaar number is 2345 6789 0123. Credit card 4111222233334444."
    incidents = dlp_inspector.inspect_text(text_with_pii)
    types = [inc["pattern_type"] for inc in incidents]
    assert "PAN" in types
    assert "AADHAAR" in types
    assert "CREDIT_CARD" in types

    sample_mask = [inc["masked_sample"] for inc in incidents if inc["pattern_type"] == "PAN"][0]
    assert sample_mask.startswith("AB")
    assert sample_mask.endswith("4F")


def test_sandbox_attachment_analyzer():
    res_exe = sandbox_analyzer.analyze_file("payload.exe", "application/x-msdownload")
    assert res_exe["is_malicious"] is True
    assert res_exe["sandbox_verdict"] == "MALICIOUS"

    res_pdf = sandbox_analyzer.analyze_file("document.pdf", "application/pdf")
    assert res_pdf["is_malicious"] is False
    assert res_pdf["sandbox_verdict"] == "CLEAN"


@pytest.mark.asyncio
async def test_employee_pre_blocking_in_scanner():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        employee = User(
            email=f"emp_preblock_{uid}@mailguard.local",
            full_name="David Employee",
            role="EMPLOYEE"
        )
        session.add(employee)
        await session.commit()
        await session.refresh(employee)

        rule = EmployeePreventionRule(
            user_id=employee.id,
            rule_type="BLOCK_DOMAIN",
            pattern="spammer-domain.net",
            action="BLOCK",
            is_active=True
        )
        session.add(rule)
        await session.commit()

        result = await mail_scanner.scan_and_ingest_email(
            user_id=employee.id,
            sender="promo@spammer-domain.net",
            recipient=employee.email,
            subject="Special Deal Just For You",
            body_plain="Click here to buy discount products.",
            body_html="<p>Click here</p>",
            db=session
        )

        assert result["status"] == "BLOCKED"
        assert result["isolation_status"] == "PRE_BLOCKED"
        assert result["threat_verdict"] == "BLOCKED"


@pytest.mark.asyncio
async def test_full_scanner_orchestration_and_isolation():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        admin = User(
            email=f"admin_iso_{uid}@mailguard.local",
            full_name="Admin Iso",
            role="ADMIN"
        )
        employee = User(
            email=f"emp_iso_{uid}@mailguard.local",
            full_name="Eve Employee",
            role="EMPLOYEE"
        )
        session.add_all([admin, employee])
        await session.commit()
        await session.refresh(admin)
        await session.refresh(employee)

        scan_out = await mail_scanner.scan_and_ingest_email(
            user_id=employee.id,
            sender="billing@suspicious-bank.xyz",
            recipient=employee.email,
            subject="Urgent: Wire Transfer Required for Invoice #9021",
            body_plain="Please wire transfer funds immediately. Attached is invoice.exe",
            body_html="<script>alert(1)</script><p>Wire funds</p>",
            attachments_meta=[{
                "filename": "invoice.exe",
                "content_type": "application/x-msdownload"
            }],
            db=session
        )

        assert scan_out["status"] == "QUARANTINED"
        assert scan_out["isolation_status"] in ["ISOLATED", "AIR_GAPPED"]
        assert scan_out["email_id"] is not None
        assert scan_out["quarantine_id"] is not None

        q_stmt = select(QuarantineRecord).where(QuarantineRecord.id == scan_out["quarantine_id"])
        q_record = (await session.execute(q_stmt)).scalar_one()
        assert q_record.is_released is False

        released = await isolation_engine.release_email(
            quarantine_record=q_record,
            admin_user_id=admin.id,
            db=session
        )
        assert released.is_released is True
        assert released.released_by_user_id == admin.id
