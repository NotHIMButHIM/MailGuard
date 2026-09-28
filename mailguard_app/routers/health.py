from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from mailguard_app.config import get_settings
from mailguard_app.database import get_db
from mailguard_app.schemas.health import HealthResponse

router = APIRouter(prefix="/health", tags=["Health & System Probes"])
settings = get_settings()


@router.get("", response_model=HealthResponse)
async def check_health():
    return HealthResponse(
        status="healthy",
        project=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        database="configured",
        timestamp=datetime.now(timezone.utc).isoformat(),
        features={
            "unified_login": True,
            "google_oauth": bool(settings.GOOGLE_CLIENT_ID),
            "admin_portal": True,
            "employee_portal": True,
            "isolation_engine": True,
            "ml_classifiers": True
        }
    )


@router.get("/db")
async def check_database(db: AsyncSession = Depends(get_db)):
    result = await db.execute(text("SELECT 1"))
    val = result.scalar()
    return {
        "status": "connected",
        "query_result": val,
        "database_url": settings.DATABASE_URL.split("://")[0] + "://..."
    }
