from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

router = APIRouter(prefix="/portal", tags=["Portal Views"])

templates_dir = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/employee", response_class=HTMLResponse)
async def employee_portal_page(request: Request):
    return templates.TemplateResponse(request=request, name="portal/employee.html")


@router.get("/admin", response_class=HTMLResponse)
async def admin_portal_page(request: Request):
    return templates.TemplateResponse(request=request, name="portal/admin.html")
