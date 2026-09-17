from fastapi import FastAPI
from models import AnalyzeRequest, AnalyzeResponse
from scanner import run_analysis

app = FastAPI(title="CodeShield-X")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_code(request: AnalyzeRequest):
    findings = run_analysis(request.code, request.filename)

    high_severity_labels = {"HIGH", "ERROR", "CRITICAL"}
    has_high = any(f.severity_raw.upper() in high_severity_labels for f in findings)

    return AnalyzeResponse(
        findings=findings,
        total_findings=len(findings),
        has_high_severity=has_high
    )
