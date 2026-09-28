from datetime import datetime, timezone
from sqlalchemy import Integer, String, Boolean, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from mailguard_app.database import Base


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    sender: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    body_plain: Mapped[str] = mapped_column(Text, default="", nullable=False)
    body_html: Mapped[str] = mapped_column(Text, default="", nullable=False)
    raw_mime_path: Mapped[str] = mapped_column(String(500), nullable=True)
    message_id: Mapped[str] = mapped_column(String(255), index=True, nullable=True)
    gmail_message_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=True)
    direction: Mapped[str] = mapped_column(String(50), default="INBOUND", nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="CLEAN", nullable=False)
    isolation_status: Mapped[str] = mapped_column(String(50), default="NONE", nullable=False)
    spam_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    phishing_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threat_verdict: Mapped[str] = mapped_column(String(50), default="CLEAN", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    user: Mapped["User"] = relationship("User", back_populates="emails")
    attachments: Mapped[list["Attachment"]] = relationship("Attachment", back_populates="email", cascade="all, delete-orphan")
    scan_result: Mapped["ScanResult"] = relationship("ScanResult", back_populates="email", uselist=False, cascade="all, delete-orphan")
    quarantine_record: Mapped["QuarantineRecord"] = relationship("QuarantineRecord", back_populates="email", uselist=False, cascade="all, delete-orphan")
    dlp_incidents: Mapped[list["DLPIncident"]] = relationship("DLPIncident", back_populates="email", cascade="all, delete-orphan")
    release_requests: Mapped[list["ReleaseRequest"]] = relationship("ReleaseRequest", back_populates="email", cascade="all, delete-orphan")


class Attachment(Base):
    __tablename__ = "attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    md5_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    sandbox_verdict: Mapped[str] = mapped_column(String(50), default="CLEAN", nullable=False)
    scan_details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    email: Mapped["Email"] = relationship("Email", back_populates="attachments")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email_id: Mapped[int] = mapped_column(Integer, ForeignKey("emails.id", ondelete="CASCADE"), unique=True, nullable=False)
    spf_status: Mapped[str] = mapped_column(String(50), default="PASS", nullable=False)
    dkim_status: Mapped[str] = mapped_column(String(50), default="PASS", nullable=False)
    dmarc_status: Mapped[str] = mapped_column(String(50), default="PASS", nullable=False)
    nlp_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    dlp_hits: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    ocr_extracted_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    sandbox_details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    ml_spam_probability: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ml_phishing_probability: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    final_verdict: Mapped[str] = mapped_column(String(50), default="CLEAN", nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    email: Mapped["Email"] = relationship("Email", back_populates="scan_result")
