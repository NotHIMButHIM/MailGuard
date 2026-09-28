from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from mailguard_app.config import get_settings
from mailguard_app.core.security import decode_token

router = APIRouter(tags=["Auth Views"])

templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))
settings = get_settings()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get("mailguard_token")
    if token:
        try:
            payload = decode_token(token)
            if payload and payload.get("role") == "ADMIN":
                return RedirectResponse(url="/portal/admin")
            elif payload:
                return RedirectResponse(url="/portal/employee")
        except Exception:
            pass

    return templates.TemplateResponse(
        request=request,
        name="auth/login.html",
        context={
            "google_client_id": settings.GOOGLE_CLIENT_ID or "",
            "google_redirect_uri": settings.GOOGLE_REDIRECT_URI or ""
        }
    )


@router.get("/logout")
async def logout_page():
    response = RedirectResponse(url="/login")
    response.delete_cookie("mailguard_token")
    return response
