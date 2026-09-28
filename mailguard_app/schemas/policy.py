from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict


class PolicyRuleCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    scope: Optional[str] = "GLOBAL"
    condition_expression: Dict[str, Any]
    priority: Optional[int] = 100
    action: Optional[str] = "QUARANTINE"
    is_active: Optional[bool] = True


class PolicyRuleResponse(BaseModel):
    id: int
    name: str
    description: str
    scope: str
    condition_expression: Dict[str, Any]
    priority: int
    action: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
