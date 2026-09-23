from fastapi import FastAPI

from models import (
    AnalyzeRequest,
    AnalyzeResponse,
    RemediationRequest,
    RemediationResponse,
    VerificationRequest,
    VerificationResponse
)

from scanner import run_analysis
from finding_features import extract_features
from risk_engine import RiskEngine
from remediation_engine import RemediationEngine
from verification_engine import VerificationEngine


app = FastAPI(title="CodeShield-X")

risk_engine = RiskEngine()
remediation_engine = RemediationEngine()
verification_engine = VerificationEngine()


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_code(request: AnalyzeRequest):
    findings = run_analysis(
        request.code,
        request.filename
    )

    for finding in findings:
        try:
            features = extract_features(
                finding,
                request.code
            )

            finding.risk_score = risk_engine.predict(
                **features
            )

        except Exception as e:
            print(
                f"Risk prediction failed for "
                f"{finding.rule_id}: {e}"
            )

            finding.risk_score = None

    high_severity_labels = {
        "HIGH",
        "ERROR",
        "CRITICAL"
    }

    has_high = any(
        f.severity_raw.upper() in high_severity_labels
        for f in findings
    )

    return AnalyzeResponse(
        findings=findings,
        total_findings=len(findings),
        has_high_severity=has_high
    )


@app.post(
    "/remediate",
    response_model=RemediationResponse
)
def remediate_code(request: RemediationRequest):
    result = remediation_engine.generate_fix(
        code=request.code,
        finding=request.finding
    )

    return RemediationResponse(
        rule_id=request.finding.rule_id,
        cwe_id=request.finding.cwe_id,
        explanation=result["explanation"],
        secure_fix=result["secure_fix"],
        fixed_code=result["fixed_code"]
    )


@app.post(
    "/verify",
    response_model=VerificationResponse
)
def verify_code(request: VerificationRequest):
    result = verification_engine.verify(
        original_code=request.original_code,
        fixed_code=request.fixed_code,
        original_finding=request.original_finding,
        filename=request.filename
    )

    return VerificationResponse(
        **result
    )
