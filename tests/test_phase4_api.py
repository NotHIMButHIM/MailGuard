import pytest
import uuid
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.mark.asyncio
async def test_unified_auth_and_portal_api_flow():
    uid = uuid.uuid4().hex[:8]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        admin_reg = await ac.post("/api/v1/auth/register", json={
            "email": f"admin_{uid}@example.com",
            "password": "Password123!",
            "full_name": "Portal Admin",
            "role": "ADMIN",
            "is_active": True,
            "organization_name": "CyberSec Global"
        })
        assert admin_reg.status_code == 201

        emp_reg = await ac.post("/api/v1/auth/register", json={
            "email": f"emp_{uid}@example.com",
            "password": "Password123!",
            "full_name": "Portal Employee",
            "role": "EMPLOYEE",
            "is_active": True,
            "organization_name": "CyberSec Global"
        })
        assert emp_reg.status_code == 201

        admin_login = await ac.post("/api/v1/auth/login", json={
            "email": f"admin_{uid}@example.com",
            "password": "Password123!"
        })
        assert admin_login.status_code == 200
        admin_data = admin_login.json()
        assert admin_data["role"] == "ADMIN"
        admin_token = admin_data["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        emp_login = await ac.post("/api/v1/auth/login", json={
            "email": f"emp_{uid}@example.com",
            "password": "Password123!"
        })
        assert emp_login.status_code == 200
        emp_data = emp_login.json()
        assert emp_data["role"] == "EMPLOYEE"
        emp_token = emp_data["access_token"]
        emp_headers = {"Authorization": f"Bearer {emp_token}"}

        rule_res = await ac.post("/api/v1/prevention/rules", headers=emp_headers, json={
            "rule_type": "BLOCK_DOMAIN",
            "pattern": "spammer-bad.com",
            "action": "BLOCK"
        })
        assert rule_res.status_code == 201
        rule_id = rule_res.json()["id"]

        list_rules = await ac.get("/api/v1/prevention/rules", headers=emp_headers)
        assert list_rules.status_code == 200
        assert len(list_rules.json()) >= 1

        toggle_res = await ac.patch(f"/api/v1/prevention/rules/{rule_id}/toggle", headers=emp_headers)
        assert toggle_res.status_code == 200
        assert toggle_res.json()["is_active"] is False

        del_rule = await ac.delete(f"/api/v1/prevention/rules/{rule_id}", headers=emp_headers)
        assert del_rule.status_code == 200

        scan_res = await ac.post("/api/v1/emails/scan", headers=emp_headers, json={
            "sender": "evil@spammer-bad.com",
            "recipient": f"emp_{uid}@example.com",
            "subject": "Urgent Invoice Attached",
            "body_plain": "Please review this immediately or your service will be terminated."
        })
        assert scan_res.status_code in [200, 201]
        scan_data = scan_res.json()
        assert "threat_verdict" in scan_data

        quarantine_list = await ac.get("/api/v1/quarantine", headers=admin_headers)
        assert quarantine_list.status_code == 200

        emp_emails = await ac.get("/api/v1/emails", headers=emp_headers)
        assert emp_emails.status_code == 200
        assert len(emp_emails.json()) >= 1

        quarantine_id = None
        for q in quarantine_list.json():
            if q["email"]["recipient"] == f"emp_{uid}@example.com":
                quarantine_id = q["id"]
                break

        if quarantine_id:
            release_res = await ac.post(
                f"/api/v1/quarantine/{quarantine_id}/release",
                headers=admin_headers,
                json={"comments": "Verified safe by admin"}
            )
            assert release_res.status_code == 200
            assert release_res.json()["is_released"] is True

        ml_pred = await ac.post("/api/v1/ml-models/predict", headers=admin_headers, json={
            "subject": "Wire Transfer Needed",
            "body": "Send $50,000 to offshore bank account immediately."
        })
        assert ml_pred.status_code == 200
        assert ml_pred.json()["spam_score"] > 0.4

        stats_res = await ac.get("/api/v1/dashboard/stats", headers=admin_headers)
        assert stats_res.status_code == 200
        assert stats_res.json()["total_scanned"] >= 1


@pytest.mark.asyncio
async def test_google_oauth_login_flow():
    uid = uuid.uuid4().hex[:8]
    mock_google_profile = {
        "google_id": f"google-sub-{uid}",
        "email": f"google_user_{uid}@example.com",
        "full_name": "Google Test User",
        "avatar_url": "https://lh3.googleusercontent.com/a/default-user",
        "email_verified": True
    }

    transport = ASGITransport(app=app)
    with patch("mailguard_app.routers.auth.verify_google_id_token", return_value=mock_google_profile):
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post("/api/v1/auth/google/login", json={
                "credential": "mocked-jwt-id-token-xyz"
            })
            assert res.status_code == 200
            data = res.json()
            assert data["role"] == "EMPLOYEE"
            assert data["user"]["email"] == f"google_user_{uid}@example.com"
            assert data["user"]["is_google_user"] is True
            assert "access_token" in data


@pytest.mark.asyncio
async def test_admin_google_login_disallowed_and_manual_provisioning():
    uid = uuid.uuid4().hex[:8]
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        admin_reg = await ac.post("/api/v1/auth/register", json={
            "email": f"sysadmin_{uid}@mailguard.corp",
            "password": "AdminSecurePassword@2026!",
            "full_name": "System SOC Admin",
            "role": "ADMIN",
            "is_active": True,
            "organization_name": "Security Operations"
        })
        assert admin_reg.status_code == 201

        admin_login = await ac.post("/api/v1/auth/login", json={
            "email": f"sysadmin_{uid}@mailguard.corp",
            "password": "AdminSecurePassword@2026!"
        })
        assert admin_login.status_code == 200
        admin_token = admin_login.json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        mock_admin_google = {
            "google_id": f"google-admin-{uid}",
            "email": f"sysadmin_{uid}@mailguard.corp",
            "full_name": "System SOC Admin",
            "avatar_url": None,
            "email_verified": True
        }
        with patch("mailguard_app.routers.auth.verify_google_id_token", return_value=mock_admin_google):
            google_attempt = await ac.post("/api/v1/auth/google/login", json={
                "credential": "mocked-jwt-id-token-admin"
            })
            assert google_attempt.status_code == 401
            assert "restricted to corporate email and password" in google_attempt.json()["detail"]

        new_emp_email = f"provisioned_emp_{uid}@mailguard.corp"
        prov_res = await ac.post("/api/v1/admin/employees", headers=admin_headers, json={
            "email": new_emp_email,
            "full_name": "Provisioned Analyst",
            "password": "TempEmpPassword@2026!",
            "organization_name": "Threat Intel Team"
        })
        assert prov_res.status_code == 200
        emp_data = prov_res.json()
        assert emp_data["email"] == new_emp_email
        assert emp_data["full_name"] == "Provisioned Analyst"
        assert emp_data["organization_name"] == "Threat Intel Team"
        emp_user_id = emp_data["user_id"]

        emp_login = await ac.post("/api/v1/auth/login", json={
            "email": new_emp_email,
            "password": "TempEmpPassword@2026!"
        })
        assert emp_login.status_code == 200
        assert emp_login.json()["role"] == "EMPLOYEE"

        del_res = await ac.delete(f"/api/v1/admin/employees/{emp_user_id}", headers=admin_headers)
        assert del_res.status_code == 200
        assert del_res.json()["status"] == "deleted"
