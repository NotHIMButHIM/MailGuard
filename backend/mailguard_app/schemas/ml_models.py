from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, ConfigDict


class MLModelResponse(BaseModel):
    id: int
    model_name: str
    model_version: str
    file_path: str
    accuracy: float
    f1_score: float
    is_active: bool
    trained_samples_count: int
    hyperparameters: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MLPredictRequest(BaseModel):
    subject: str
    body: str


class MLPredictResponse(BaseModel):
    spam_score: float
    phishing_score: float
    verdict: str
    heuristics: Dict[str, Any]


class MLRetrainRequest(BaseModel):
    model_type: Optional[str] = "ALL"
