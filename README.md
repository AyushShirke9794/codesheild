# CodeShield-X

**An Explainable, Closed-Loop Security Intelligence System for AI-Generated Code**

> "We don't trust AI to secure AI-generated code." Every LLM-generated security fix is independently re-scanned and tested before it is granted a Trust decision.

## Problem

LLMs increasingly generate production code, and that code can contain real security vulnerabilities (SQL injection, command injection, etc.). Existing tooling typically does one of: static analysis, ML risk prediction, or LLM-based fixing — in isolation. The unaddressed risk: the same AI that wrote the insecure code may also write an insecure "fix." CodeShield-X never accepts an LLM's own claim that it fixed something; every patch is independently verified.

## Architecture
AI-Generated Code
|
v
FastAPI Gateway
|
v
Semgrep + Bandit (SAST)
|
v
CWE Normalization + CWE Knowledge Graph
|
v
ML Risk Engine -> SHAP Explanation
|
v
LLM Remediation (Gemini)
|
v
Independent Verification
(re-SAST + security tests + regression check)
|
v
Trust Gate
/
PASS FAIL
| |
Trusted Remediation Loop


## Progress

| Phase | Description | Status |
|---|---|---|
| 1 | Foundation - FastAPI + Git + venv | Done |
| 2 | Detection - Semgrep/Bandit -> CWE-normalized findings | Done |
| 3 | Risk Intelligence - CWE graph + ML risk model + SHAP | Planned |
| 4 | Remediation - LLM (Gemini) generates patches | Planned |
| 5 | Verification - re-SAST + tests + regression detection | Planned |
| 6 | Trust Loop - Trust Gate + bounded retry + human review | Planned |
| 7 | Product/Research - dashboard + DB + Docker + experiments | Planned |

## Tech Stack

- **Backend:** Python, FastAPI, Uvicorn
- **Security scanning:** Semgrep, Bandit
- **ML (planned):** scikit-learn, XGBoost, SHAP
- **Knowledge graph (planned):** NetworkX + CWE relationship data
- **LLM (planned):** Gemini API
- **Frontend (planned):** React
- **Database (planned):** PostgreSQL
- **Deployment (planned):** Docker

## Research Question

Can an explainable closed-loop framework automatically detect, prioritize, remediate, and independently verify vulnerabilities in AI-generated code while reducing residual vulnerabilities and security regressions compared with conventional static analysis and unverified AI remediation?

## Setup

Server runs at `http://127.0.0.1:8000`. Interactive API docs at `http://127.0.0.1:8000/docs`.

## Current Endpoints

- `GET /health` - service liveness check
- `POST /analyze` - accepts `{"code": "...", "filename": "..."}`, returns CWE-normalized findings from both Semgrep and Bandit

## Baseline Reference

Extends the risk-relationship concept from "A generative AI cybersecurity risks mitigation model for code generation: using ANN-ISM hybrid approach" (Al-Hashimi, Scientific Reports 2026) into an executable, closed-loop detection-remediation-verification pipeline.
