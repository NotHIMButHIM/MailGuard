from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from mailguard_app.config import get_settings
from mailguard_app.core.middleware import RequestTimingMiddleware, SecurityHeadersMiddleware
from mailguard_app.core.security import decode_token
from mailguard_app.ml.model_registry import get_model_registry
from mailguard_app.routers.health import router as health_router
from mailguard_app.routers.auth import router as auth_router
from mailguard_app.routers.emails import router as emails_router
from mailguard_app.routers.prevention import router as prevention_router
from mailguard_app.routers.quarantine import router as quarantine_router
from mailguard_app.routers.admin_users import router as admin_users_router
from mailguard_app.routers.ml_models import router as ml_models_router
from mailguard_app.routers.policies import router as policies_router
from mailguard_app.routers.dlp import router as dlp_router
from mailguard_app.routers.audit import router as audit_router
from mailguard_app.routers.feedback import router as feedback_router
from mailguard_app.routers.dashboard import router as dashboard_router
from mailguard_app.routers.safelinks import router as safelinks_router
from mailguard_app.views.auth_views import router as auth_views_router
from mailguard_app.views.portal_views import router as portal_views_router

import asyncio

settings = get_settings()


async def _background_gmail_autofilter():
    """Background auto-filter: periodically polls Gmail without locking database or starving web traffic."""
    await asyncio.sleep(15)  # Allow server to fully bind and handle requests first
    while True:
        try:
            from mailguard_app.database import AsyncSessionLocal
            from mailguard_app.models.user import User
            from mailguard_app.services.gmail_sync import gmail_sync_service
            from sqlalchemy import select

            users_to_sync = []
            async with AsyncSessionLocal() as session:
                stmt = select(User).where(User.is_google_user == True, User.google_access_token.is_not(None))
                users_to_sync = (await session.execute(stmt)).scalars().all()

            for u in users_to_sync:
                try:
                    async with AsyncSessionLocal() as user_session:
                        await asyncio.wait_for(
                            gmail_sync_service.sync_and_filter_user_emails(u, max_results=10, db=user_session),
                            timeout=25.0
                        )
                except Exception:
                    continue
        except asyncio.CancelledError:
            break
        except Exception:
            pass
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-initialize database tables for fresh deployments (Render / PostgreSQL / SQLite)
    from mailguard_app.database import engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Auto-seed default administrator if not present
    from scripts.seed_admin import seed_admin
    try:
        await seed_admin()
    except Exception as e:
        print(f"Admin seeding notice: {e}")

    # Load ML models into registry
    get_model_registry()

    # Start background Gmail auto-filter worker
    task = asyncio.create_task(_background_gmail_autofilter())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Mailguard Security Gateway - Unified Admin and Employee Portal with Spam Prevention & Isolation",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTimingMiddleware)

static_path = Path(__file__).resolve().parent / "mailguard_app" / "static"
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

app.include_router(auth_views_router)
app.include_router(portal_views_router)

app.include_router(health_router, prefix=settings.API_V1_STR)
app.include_router(auth_router, prefix=settings.API_V1_STR)
app.include_router(emails_router, prefix=settings.API_V1_STR)
app.include_router(prevention_router, prefix=settings.API_V1_STR)
app.include_router(quarantine_router, prefix=settings.API_V1_STR)
app.include_router(admin_users_router, prefix=settings.API_V1_STR)
app.include_router(ml_models_router, prefix=settings.API_V1_STR)
app.include_router(policies_router, prefix=settings.API_V1_STR)
app.include_router(dlp_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(feedback_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(safelinks_router, prefix=settings.API_V1_STR)


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/")
async def root(request: Request):
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
    return RedirectResponse(url="/login")


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
