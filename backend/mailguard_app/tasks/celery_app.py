from celery import Celery
from mailguard_app.config import get_settings

settings = get_settings()

celery_app = Celery(
    "mailguard_tasks",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["mailguard_app.tasks.jobs"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300
)
