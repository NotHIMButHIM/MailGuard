from datetime import datetime, timezone
from sqlalchemy import Integer, String, Boolean, Float, DateTime, JSON
from sqlalchemy.orm import Mapped, mapped_column
from mailguard_app.database import Base


class MLModelRegistry(Base):
    __tablename__ = "ml_model_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    model_name: Mapped[str] = mapped_column(String(100), index=True, nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    accuracy: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    f1_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    trained_samples_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    hyperparameters: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
