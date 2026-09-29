from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from mailguard_app.schemas.user import UserResponse


class ActiveEmployeeSessionResponse(BaseModel):
    id: int
    user_id: int
    session_token: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    is_active: bool
    last_activity: datetime
    created_at: datetime
    user: Optional[UserResponse] = None

    model_config = ConfigDict(from_attributes=True)


class EmployeeDataSummary(BaseModel):
    user_id: int
    email: str
    full_name: str
    organization_name: str
    total_emails: int
    quarantined_emails: int
    active_prevention_rules: int
    last_login_at: Optional[datetime] = None
    last_login_ip: Optional[str] = None


class EmployeeCreateRequest(BaseModel):
    email: str
    full_name: str
    password: str = "EmployeePass@2026!"
    organization_name: Optional[str] = "Default Organization"


class DashboardStatsResponse(BaseModel):
    total_scanned: int
    clean_emails: int
    spam_detected: int
    phishing_detected: int
    quarantined_count: int
    dlp_incidents_count: int
    active_employees_logged_in: int
    total_registered_employees: int
    threat_breakdown: Dict[str, int]
