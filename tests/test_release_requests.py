import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select
from main import app
from mailguard_app.database import AsyncSessionLocal
from mailguard_app.models.user import User
from mailguard_app.models.email import Email
from mailguard_app.models.quarantine import QuarantineRecord
from mailguard_app.models.release_request import ReleaseRequest
from mailguard_app.services.scanner import mail_scanner
from mailguard_app.core.security import create_access_token


@pytest.mark.asyncio
async def test_submit_and_approve_release_request():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        admin = User(
            email=f"admin_rel_{uid}@mailguard.corp",
            full_name=f"Admin Rel {uid}",
            role="ADMIN",
            is_active=True
        )
        employee = User(
            email=f"emp_rel_{uid}@mailguard.corp",
            full_name=f"Employee Rel {uid}",
            role="EMPLOYEE",
            is_active=True
        )
        session.add_all([admin, employee])
        await session.commit()
        await session.refresh(admin)
        await session.refresh(employee)

        # Ingest a spam email for the employee
        scan_res = await mail_scanner.scan_and_ingest_email(
            user_id=employee.id,
            sender="promotions@external-sales.biz",
            recipient=employee.email,
            subject="Special promotional discount for you",
            body_plain="Click here to claim your cash reward prize immediately.",
            body_html="<p>Click prize</p>",
            db=session
        )
        email_id = scan_res["email_id"]
        assert email_id is not None

    emp_token = create_access_token({"sub": str(employee.id), "email": employee.email, "role": employee.role})
    admin_token = create_access_token({"sub": str(admin.id), "email": admin.email, "role": admin.role})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Employee submits a release ticket
        headers_emp = {"Authorization": f"Bearer {emp_token}"}
        req_res = await client.post(
            "/api/v1/quarantine/requests",
            json={
                "email_id": email_id,
                "justification": "This is a legitimate partner vendor quotation required for project billing."
            },
            headers=headers_emp
        )
        assert req_res.status_code == 200
        ticket_data = req_res.json()
        assert ticket_data["status"] == "PENDING"
        assert ticket_data["email_id"] == email_id
        assert ticket_data["spam_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        ticket_id = ticket_data["id"]

        # 2. Verify employee can fetch ticket status for email
        check_res = await client.get(f"/api/v1/quarantine/requests/email/{email_id}", headers=headers_emp)
        assert check_res.status_code == 200
        assert check_res.json()["id"] == ticket_id
        assert check_res.json()["status"] == "PENDING"

        # 3. Admin lists tickets and sees employee's request with spam level
        headers_admin = {"Authorization": f"Bearer {admin_token}"}
        list_res = await client.get("/api/v1/quarantine/requests", headers=headers_admin)
        assert list_res.status_code == 200
        tickets = list_res.json()
        matching = [t for t in tickets if t["id"] == ticket_id]
        assert len(matching) == 1
        assert matching[0]["user_email"] == employee.email

        # 4. Admin approves release ticket
        decide_res = await client.post(
            f"/api/v1/quarantine/requests/{ticket_id}/decide",
            json={
                "action": "APPROVE",
                "admin_notes": "Verified vendor contract on file. Approved for release."
            },
            headers=headers_admin
        )
        assert decide_res.status_code == 200
        decided = decide_res.json()
        assert decided["status"] == "APPROVED"
        assert "Verified vendor" in decided["admin_notes"]

    # 5. Verify database state: Email transitioned to RELEASED
    async with AsyncSessionLocal() as session:
        email_obj = (await session.execute(select(Email).where(Email.id == email_id))).scalar_one()
        assert email_obj.status == "RELEASED"
        assert email_obj.isolation_status == "RELEASED"


@pytest.mark.asyncio
async def test_admin_deny_release_request_based_on_spam_level():
    uid = uuid.uuid4().hex[:8]
    async with AsyncSessionLocal() as session:
        admin = User(
            email=f"admin_deny_{uid}@mailguard.corp",
            full_name=f"Admin Deny {uid}",
            role="ADMIN",
            is_active=True
        )
        employee = User(
            email=f"emp_deny_{uid}@mailguard.corp",
            full_name=f"Employee Deny {uid}",
            role="EMPLOYEE",
            is_active=True
        )
        session.add_all([admin, employee])
        await session.commit()
        await session.refresh(admin)
        await session.refresh(employee)

        # Ingest malicious attachment email
        scan_res = await mail_scanner.scan_and_ingest_email(
            user_id=employee.id,
            sender="malware@threat-actor.org",
            recipient=employee.email,
            subject="Invoice details attached",
            body_plain="Please open the attached file.",
            body_html="<p>Open file</p>",
            attachments_meta=[{"filename": "payload.exe", "content_type": "application/x-msdownload"}],
            db=session
        )
        email_id = scan_res["email_id"]

    emp_token = create_access_token({"sub": str(employee.id), "email": employee.email, "role": employee.role})
    admin_token = create_access_token({"sub": str(admin.id), "email": admin.email, "role": admin.role})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Employee requests release
        headers_emp = {"Authorization": f"Bearer {emp_token}"}
        req_res = await client.post(
            "/api/v1/quarantine/requests",
            json={
                "email_id": email_id,
                "justification": "I believe this invoice is real."
            },
            headers=headers_emp
        )
        assert req_res.status_code == 200
        ticket_id = req_res.json()["id"]
        assert req_res.json()["spam_level"] == "CRITICAL"

        # Admin denies request based on critical threat level
        headers_admin = {"Authorization": f"Bearer {admin_token}"}
        deny_res = await client.post(
            f"/api/v1/quarantine/requests/{ticket_id}/decide",
            json={
                "action": "DENY",
                "admin_notes": "Denied: Sandbox confirmed malicious Windows executable payload in attachment."
            },
            headers=headers_admin
        )
        assert deny_res.status_code == 200
        denied_ticket = deny_res.json()
        assert denied_ticket["status"] == "DENIED"
        assert "Sandbox confirmed malicious" in denied_ticket["admin_notes"]

    # Verify email remains quarantined in database
    async with AsyncSessionLocal() as session:
        email_obj = (await session.execute(select(Email).where(Email.id == email_id))).scalar_one()
        assert email_obj.status == "QUARANTINED"
