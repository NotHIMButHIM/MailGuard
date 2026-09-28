import pytest
from httpx import AsyncClient, ASGITransport
from main import app


@pytest.mark.asyncio
async def test_root_redirect_to_login():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/", follow_redirects=False)
        assert response.status_code in [302, 307]
        assert "/login" in response.headers.get("location", "")


@pytest.mark.asyncio
async def test_favicon_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/favicon.ico")
        assert response.status_code == 204


@pytest.mark.asyncio
async def test_login_page_renders():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/login")
        assert response.status_code == 200
        assert "MAILGUARD" in response.text
        assert "Employee Portal" in response.text
        assert "Admin Portal" in response.text


@pytest.mark.asyncio
async def test_portal_views_render():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        emp_response = await client.get("/portal/employee")
        assert emp_response.status_code == 200
        assert "Employee Prevention Portal" in emp_response.text

        admin_response = await client.get("/portal/admin")
        assert admin_response.status_code == 200
        assert "Admin Security Operations Portal" in admin_response.text


@pytest.mark.asyncio
async def test_static_assets_serving():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        css_response = await client.get("/static/css/main.css")
        assert css_response.status_code == 200
        assert "glass-panel" in css_response.text

        js_response = await client.get("/static/js/main.js")
        assert js_response.status_code == 200
        assert "setAuthSession" in js_response.text
