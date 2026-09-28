from pydantic import BaseModel
from typing import Dict, Any


class HealthResponse(BaseModel):
    status: str
    project: str
    environment: str
    database: str
    timestamp: str
    features: Dict[str, Any]
