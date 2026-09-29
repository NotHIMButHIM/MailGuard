from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AnalystFeedbackCreate(BaseModel):
    email_id: int
    original_verdict: str
    corrected_verdict: str
    feedback_type: str
    comments: Optional[str] = ""


class AnalystFeedbackResponse(BaseModel):
    id: int
    email_id: int
    user_id: int
    original_verdict: str
    corrected_verdict: str
    feedback_type: str
    comments: str
    is_used_for_retraining: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
