from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict
from mailguard_app.schemas.email import EmailResponse


class ReleaseRequestCreate(BaseModel):
    email_id: int
    justification: str


class ReleaseRequestDecision(BaseModel):
    action: str  # "APPROVE" or "DENY"
    admin_notes: Optional[str] = ""


class ReleaseRequestResponse(BaseModel):
    id: int
    email_id: int
    user_id: int
    justification: str
    status: str
    spam_score: float
    spam_level: str
    admin_notes: str
    reviewed_by_user_id: Optional[int] = None
    reviewed_at: Optional[datetime] = None
    created_at: datetime
    email: Optional[EmailResponse] = None
    user_name: Optional[str] = None
    user_email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)
