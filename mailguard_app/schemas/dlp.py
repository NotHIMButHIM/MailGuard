from datetime import datetime
from pydantic import BaseModel, ConfigDict


class DLPIncidentResponse(BaseModel):
    id: int
    email_id: int
    user_id: int
    pattern_type: str
    matches_count: int
    severity: str
    masked_sample: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
