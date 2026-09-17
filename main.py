from fastapi import FastAPI

app = FastAPI(title="CodeShield-X")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/analyze")
def analyze_code():
    # placeholder - Phase 2 will make this actually run Semgrep/Bandit
    return {"status": "not_implemented_yet"}
