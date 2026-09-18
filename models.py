from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    tool: str
    rule_id: str
    cwe_id: Optional[int]
    severity_raw: str
    confidence: Optional[str]
    message: str
    file_path: str
    line_number: int
    risk_score: Optional[float] = None


class AnalyzeRequest(BaseModel):
    code: str
    filename: str = "submitted_code.py"


class AnalyzeResponse(BaseModel):
    findings: list[Finding]
    total_findings: int
    has_high_severity: bool


class RemediationRequest(BaseModel):
    code: str
    finding: Finding


class RemediationResponse(BaseModel):
    rule_id: str
    cwe_id: Optional[int]
    explanation: str
    secure_fix: str
    fixed_code: str    