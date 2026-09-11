from typing import Any

from pydantic import BaseModel, Field


class EmailReportResponse(BaseModel):
    case_id: str
    case_number: str
    status: str
    risk_score: float
    risk_level: str
    confidence: float
    subject: str
    sender: str
    created_at: str


class CaseListResponse(BaseModel):
    cases: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class GmailScanRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=50)
