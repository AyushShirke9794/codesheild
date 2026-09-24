from models import (
    TrustDecision,
    TrustGateRequest,
    TrustGateResponse,
    HIGH_RISK_THRESHOLD,
)


def evaluate_trust_gate(request: TrustGateRequest) -> TrustGateResponse:
    v = request.verification

    if not v.verified:
        if not v.original_vulnerability_fixed:
            reason = "Rejected: original vulnerability was not fixed."
        elif v.regression_detected:
            reason = "Rejected: remediation introduced a new vulnerability (regression)."
        elif not v.functional_equivalent:
            reason = "Rejected: remediation changed the code's functional behavior."
        else:
            reason = "Rejected: verification failed for an unrecognized reason."

        return TrustGateResponse(
            decision=TrustDecision.REJECT,
            reason=reason,
            risk_score=v.original_finding.risk_score,
            verification=v,
            remediation_attempt=request.remediation_attempt,
        )

    risk_score = v.original_finding.risk_score

    if risk_score is None:
        decision = TrustDecision.HUMAN_REVIEW
        reason = "Human review required: verification passed, but no risk score is available."
    elif risk_score >= HIGH_RISK_THRESHOLD:
        decision = TrustDecision.HUMAN_REVIEW
        reason = f"Human review required: verification passed, but residual risk score ({risk_score:.1f}) meets or exceeds the High-severity threshold ({HIGH_RISK_THRESHOLD:.1f})."
    else:
        decision = TrustDecision.ACCEPT
        reason = f"Accepted: verification passed and residual risk score ({risk_score:.1f}) is below the High-severity threshold ({HIGH_RISK_THRESHOLD:.1f})."

    return TrustGateResponse(
        decision=decision,
        reason=reason,
        risk_score=risk_score,
        verification=v,
        remediation_attempt=request.remediation_attempt,
    )