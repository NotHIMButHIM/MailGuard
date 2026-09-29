from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from mailguard_app.schemas.email import EmailResponse


class QuarantineResponse(BaseModel):
    id: int
    email_id: int
    user_id: int
    reason: str
    isolation_level: str
    is_released: bool
    released_by_user_id: Optional[int] = None
    released_at: Optional[datetime] = None
    quarantine_expires_at: Optional[datetime] = None
    action_history: List[Dict[str, Any]]
    created_at: datetime
    email: Optional[EmailResponse] = None

    model_config = ConfigDict(from_attributes=True)


class QuarantineReleaseRequest(BaseModel):
    comments: Optional[str] = ""
