import pytest
from pathlib import Path
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.mark.asyncio
async def test_auth_config_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/auth/config")
        assert res.status_code == 200
        data = res.json()
        assert "google_client_id" in data
        assert "google_redirect_uri" in data
        assert "frontend_url" in data
        assert "project_name" in data
        assert data["project_name"] == "Mailguard"


@pytest.mark.asyncio
async def test_cors_headers_for_netlify_origins():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Pre-flight OPTIONS request from a Netlify domain
        res = await client.options(
            "/api/v1/auth/config",
            headers={
                "Origin": "https://mailguard-portal.netlify.app",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization,Content-Type"
            }
        )
        assert res.status_code == 200
        assert "access-control-allow-origin" in res.headers
        assert res.headers["access-control-allow-origin"] == "https://mailguard-portal.netlify.app"
        assert res.headers.get("access-control-allow-credentials") == "true"


def test_frontend_distribution_files():
    root = Path(__file__).resolve().parent.parent
    frontend_dir = root / "frontend"
    backend_dir = root / "backend"

    # Frontend essentials
    assert (frontend_dir / "index.html").exists()
    assert (frontend_dir / "portal" / "employee.html").exists()
    assert (frontend_dir / "portal" / "admin.html").exists()
    assert (frontend_dir / "css" / "main.css").exists()
    assert (frontend_dir / "js" / "config.js").exists()
    assert (frontend_dir / "js" / "main.js").exists()
    assert (frontend_dir / "netlify.toml").exists()
    assert (frontend_dir / "_redirects").exists()
    assert (frontend_dir / "README.md").exists()

    # Backend essentials
    assert (backend_dir / "main.py").exists()
    assert (backend_dir / "render.yaml").exists()
    assert (backend_dir / "requirements.txt").exists()
    assert (backend_dir / "Dockerfile").exists()
    assert (backend_dir / "README.md").exists()
