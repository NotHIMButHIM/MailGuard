from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from mailguard_app.core.security import decode_token

router = APIRouter(prefix="/portal", tags=["Portal Views"])

templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/employee", response_class=HTMLResponse)
async def employee_portal_page(request: Request):
    return templates.TemplateResponse(request=request, name="portal/employee.html")


@router.get("/admin", response_class=HTMLResponse)
async def admin_portal_page(request: Request):
    token = request.cookies.get("mailguard_token")
    if token:
        try:
            payload = decode_token(token)
            if payload and payload.get("role") != "ADMIN":
                return RedirectResponse(url="/portal/employee")
        except Exception:
            pass
    return templates.TemplateResponse(request=request, name="portal/admin.html")
