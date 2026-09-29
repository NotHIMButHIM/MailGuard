from datetime import datetime
from pydantic import BaseModel, ConfigDict
from typing import Optional


class EmployeePreventionRuleCreate(BaseModel):
    rule_type: str
    pattern: str
    action: Optional[str] = "BLOCK"
    is_active: Optional[bool] = True


class EmployeePreventionRuleResponse(BaseModel):
    id: int
    user_id: int
    rule_type: str
    pattern: str
    action: str
    is_active: bool
    hits_count: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
