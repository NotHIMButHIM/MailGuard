from datetime import datetime, timezone
from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from mailguard_app.database import Base


class QuarantineRecord(Base):
    __tablename__ = "quarantine_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    isolation_level: Mapped[str] = mapped_column(String(50), default="QUARANTINED", nullable=False)
    is_released: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    released_by_user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    released_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    quarantine_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    action_history: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    email: Mapped["Email"] = relationship("Email", back_populates="quarantine_record")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="quarantined_records")
    released_by: Mapped["User"] = relationship("User", foreign_keys=[released_by_user_id])
