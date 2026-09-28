import pytest
import uuid
from sqlalchemy import select
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import User, UserSession
from mailguard_app.models.email import Email, Attachment, ScanResult
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.models.prevention import EmployeePreventionRule
from mailguard_app.models.policy import PolicyRule
from mailguard_app.models.dlp import DLPIncident
from mailguard_app.models.ml_model import MLModelRegistry
from mailguard_app.models.audit import AuditLog
from mailguard_app.core.security import get_password_hash


@pytest.mark.asyncio
async def test_user_and_session_creation():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        admin = User(
            email=f"admin_{uid}@mailguard.local",
            hashed_password=get_password_hash("adminsecret"),
            full_name="Chief Admin",
            role="ADMIN",
            is_active=True,
            organization_name="Enterprise Corp"
        )
        employee = User(
            email=f"emp_{uid}@mailguard.local",
            full_name="Alice Employee",
            role="EMPLOYEE",
            is_active=True,
            is_google_user=True,
            google_id=f"google-sub-{uid}",
            organization_name="Enterprise Corp"
        )
        session.add_all([admin, employee])
        await session.commit()
        await session.refresh(admin)
        await session.refresh(employee)

        assert admin.id is not None
        assert admin.role == "ADMIN"
        assert employee.id is not None
        assert employee.role == "EMPLOYEE"
        assert employee.is_google_user is True

        user_session = UserSession(
            user_id=employee.id,
            session_token=f"sess-token-{uid}",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 Test Agent",
            is_active=True
        )
        session.add(user_session)
        await session.commit()
        await session.refresh(user_session)

        assert user_session.id is not None
        assert user_session.user_id == employee.id


@pytest.mark.asyncio
async def test_employee_prevention_rule():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        employee = User(
            email=f"emp_prev_{uid}@mailguard.local",
            full_name="Bob Employee",
            role="EMPLOYEE",
            is_active=True
        )
        session.add(employee)
        await session.commit()
        await session.refresh(employee)

        rule = EmployeePreventionRule(
            user_id=employee.id,
            rule_type="BLOCK_DOMAIN",
            pattern="phishdomain.com",
            action="BLOCK",
            is_active=True
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)

        assert rule.id is not None
        assert rule.pattern == "phishdomain.com"
        assert rule.user_id == employee.id


@pytest.mark.asyncio
async def test_email_scanning_quarantine_flow():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        admin = User(
            email=f"admin_scan_{uid}@mailguard.local",
            full_name="Security Admin",
            role="ADMIN"
        )
        employee = User(
            email=f"emp_scan_{uid}@mailguard.local",
            full_name="Charlie Employee",
            role="EMPLOYEE"
        )
        session.add_all([admin, employee])
        await session.commit()
        await session.refresh(admin)
        await session.refresh(employee)

        email = Email(
            user_id=employee.id,
            sender="attacker@phishdomain.com",
            recipient=employee.email,
            subject="Urgent: Verify Your Credentials",
            body_plain="Please click the malicious link immediately.",
            body_html="<p>Please click the malicious link immediately.</p>",
            status="QUARANTINED",
            isolation_status="ISOLATED",
            spam_score=0.95,
            phishing_score=0.98,
            threat_verdict="PHISHING"
        )
        session.add(email)
        await session.commit()
        await session.refresh(email)

        attachment = Attachment(
            email_id=email.id,
            filename="invoice.exe",
            content_type="application/octet-stream",
            file_size=1048576,
            storage_path="./storage/attachments/invoice.exe",
            md5_hash="098f6bcd4621d373cade4e832627b4f6",
            sha256_hash="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            is_malicious=True,
            sandbox_verdict="MALICIOUS",
            scan_details={"signature": "Trojan.Generic"}
        )
        scan_res = ScanResult(
            email_id=email.id,
            spf_status="FAIL",
            dkim_status="FAIL",
            dmarc_status="FAIL",
            nlp_score=0.92,
            dlp_hits=[{"type": "CREDIT_CARD", "count": 1}],
            ocr_extracted_text="Invoice Details",
            sandbox_details={"network_calls": ["198.51.100.23"]},
            ml_spam_probability=0.95,
            ml_phishing_probability=0.98,
            final_verdict="MALICIOUS"
        )
        quarantine = QuarantineRecord(
            email_id=email.id,
            user_id=employee.id,
            reason="High confidence Phishing & Malicious Attachment",
            isolation_level="AIR_GAPPED",
            action_history=[{"action": "QUARANTINED", "by": "AUTOMATED_SCANNER"}]
        )
        dlp = DLPIncident(
            email_id=email.id,
            user_id=employee.id,
            pattern_type="CREDIT_CARD",
            matches_count=1,
            severity="HIGH",
            masked_sample="4111-XXXX-XXXX-1111"
        )
        audit = AuditLog(
            user_id=admin.id,
            action="QUARANTINE_EMAIL",
            entity_type="Email",
            entity_id=str(email.id),
            details={"threat_verdict": "PHISHING"}
        )

        session.add_all([attachment, scan_res, quarantine, dlp, audit])
        await session.commit()

        q_stmt = select(QuarantineRecord).where(QuarantineRecord.email_id == email.id)
        saved_q = (await session.execute(q_stmt)).scalar_one()
        assert saved_q.isolation_level == "AIR_GAPPED"
        assert saved_q.is_released is False


@pytest.mark.asyncio
async def test_ml_model_registry_and_policy():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        ml_entry = MLModelRegistry(
            model_name=f"spam_model_{uid}",
            model_version="1.0.0",
            file_path="./ml_models/spam_model.pkl",
            accuracy=0.982,
            f1_score=0.978,
            is_active=True,
            trained_samples_count=5572,
            hyperparameters={"alpha": 0.1, "max_features": 5000}
        )
        policy = PolicyRule(
            name=f"Block Executable Attachments {uid}",
            description="Isolate any email carrying executable files",
            scope="GLOBAL",
            condition_expression={"attachment_extensions": [".exe", ".bat", ".vbs"]},
            priority=1,
            action="ISOLATE",
            is_active=True
        )
        session.add_all([ml_entry, policy])
        await session.commit()
        await session.refresh(ml_entry)
        await session.refresh(policy)

        assert ml_entry.id is not None
        assert policy.id is not None
        assert policy.action == "ISOLATE"
