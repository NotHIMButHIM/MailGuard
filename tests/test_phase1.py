import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from mailguard_app.core.security import create_access_token
from main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["features"]["unified_login"] is True
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"


@pytest.mark.asyncio
async def test_database_connection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.get("/api/v1/health/db")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "connected"
        assert data["query_result"] == 1


@pytest.mark.asyncio
async def test_role_based_access_probes():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        admin_token = create_access_token({"sub": "1", "email": "admin@example.com", "role": "ADMIN"})
        emp_token = create_access_token({"sub": "2", "email": "emp@example.com", "role": "EMPLOYEE"})

        res_admin_ok = await ac.get("/api/v1/auth/admin-only-probe", headers={"Authorization": f"Bearer {admin_token}"})
        assert res_admin_ok.status_code == 200
        assert res_admin_ok.json()["role"] == "ADMIN"

        res_admin_deny = await ac.get("/api/v1/auth/admin-only-probe", headers={"Authorization": f"Bearer {emp_token}"})
        assert res_admin_deny.status_code == 403

        res_emp_ok = await ac.get("/api/v1/auth/employee-only-probe", headers={"Authorization": f"Bearer {emp_token}"})
        assert res_emp_ok.status_code == 200

        res_emp_admin_ok = await ac.get("/api/v1/auth/employee-only-probe", headers={"Authorization": f"Bearer {admin_token}"})
        assert res_emp_admin_ok.status_code == 200
