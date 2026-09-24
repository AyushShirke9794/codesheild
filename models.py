from pydantic import BaseModel, Field
from typing import Optional, Any
from enum import Enum


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


class FunctionalTestCase(BaseModel):
    """
    Defines one expected-behavior test used to compare
    the original and remediated code.
    """

    input_data: dict[str, Any]
    expected_output: Any


class VerificationRequest(BaseModel):
    original_code: str
    fixed_code: str
    original_finding: Finding
    filename: str = "submitted_code.py"

    # Optional functional tests for behavior preservation.
    functional_tests: list[FunctionalTestCase] = Field(
        default_factory=list
    )


class VerificationResponse(BaseModel):
    verified: bool
    original_vulnerability_fixed: bool
    regression_detected: bool

    # Functional-equivalence results.
    functional_equivalent: bool
    functional_tests_passed: int
    functional_tests_failed: int

    original_finding: Finding
    remaining_findings: list[Finding]
    new_findings: list[Finding]
    status: str

    


class TrustDecision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class TrustGateRequest(BaseModel):
    verification: VerificationResponse
    remediation_attempt: int = Field(default=1, ge=1)


class TrustGateResponse(BaseModel):
    decision: TrustDecision
    reason: str
    risk_score: Optional[float]
    verification: VerificationResponse
    remediation_attempt: int


# Anchored to the CVSS High-severity band (CVSS base score 7.0 -> risk_score 70),
# not to our own model's Low/Medium/High buckets — that bucket has weak recall
# (F1 0.31) on only 11 training samples, so it isn't trustworthy as a gate.
# A missing risk_score (model wasn't run / failed) is treated at decision time
# as grounds for HUMAN_REVIEW, not REJECT — a gap in our own pipeline is not
# evidence the code is unsafe.
HIGH_RISK_THRESHOLD: float = 70.0