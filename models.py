from pydantic import BaseModel, Field
from typing import Optional, Any


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