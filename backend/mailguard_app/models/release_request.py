from datetime import datetime, timezone
from sqlalchemy import Integer, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from mailguard_app.database import Base


class ReleaseRequest(Base):
    __tablename__ = "release_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="PENDING", nullable=False)  # PENDING, APPROVED, DENIED
    spam_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    spam_level: Mapped[str] = mapped_column(String(50), default="LOW", nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    admin_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    reviewed_by_user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    email: Mapped["Email"] = relationship("Email", back_populates="release_requests")
    user: Mapped["User"] = relationship("User", foreign_keys=[user_id], back_populates="release_requests")
    reviewed_by: Mapped["User"] = relationship("User", foreign_keys=[reviewed_by_user_id])
