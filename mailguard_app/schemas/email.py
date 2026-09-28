from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class AttachmentResponse(BaseModel):
    id: int
    filename: str
    content_type: str
    file_size: int
    is_malicious: bool
    sandbox_verdict: str
    scan_details: Dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class ScanResultResponse(BaseModel):
    id: int
    spf_status: str
    dkim_status: str
    dmarc_status: str
    nlp_score: float
    dlp_hits: List[Dict[str, Any]]
    ml_spam_probability: float
    ml_phishing_probability: float
    final_verdict: str
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EmailCreate(BaseModel):
    sender: str
    recipient: str
    subject: str
    body_plain: str
    body_html: Optional[str] = ""
    attachments_meta: Optional[List[Dict[str, Any]]] = []
    raw_headers: Optional[Dict[str, str]] = {}


class EmailResponse(BaseModel):
    id: int
    user_id: int
    sender: str
    recipient: str
    subject: str
    body_plain: str
    body_html: str
    direction: str
    status: str
    isolation_status: str
    spam_score: float
    phishing_score: float
    threat_verdict: str
    created_at: datetime
    attachments: Optional[List[AttachmentResponse]] = []
    scan_result: Optional[ScanResultResponse] = None

    model_config = ConfigDict(from_attributes=True)
