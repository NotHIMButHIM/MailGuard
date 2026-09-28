from datetime import datetime, timezone
from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from mailguard_app.database import Base


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedbacks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    original_verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    corrected_verdict: Mapped[str] = mapped_column(String(50), nullable=False)
    feedback_type: Mapped[str] = mapped_column(String(50), nullable=False)
    comments: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_used_for_retraining: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="feedbacks")
