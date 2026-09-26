
from typing import Any, Dict

from agents.base_agent import BaseAgent
from agents.contracts import AgentResult
from agents.analysis_agent import AnalysisAgent
from agents.risk_agent import RiskAgent
from agents.remediation_agent import RemediationAgent
from agents.verification_agent import VerificationAgent
from agents.trust_gate_agent import TrustGateAgent


class OrchestratorAgent(BaseAgent):

    def __init__(self):
        super().__init__("OrchestratorAgent")

        self.analysis_agent = AnalysisAgent()
        self.risk_agent = RiskAgent()
        self.remediation_agent = RemediationAgent()
        self.verification_agent = VerificationAgent()
        self.trust_gate_agent = TrustGateAgent()

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:

        code = input_data.get("code")
        filename = input_data.get(
            "filename",
            "submitted_code.py"
        )
        functional_tests = input_data.get(
            "functional_tests"
        )
        dry_run = input_data.get(
            "dry_run",
            False
        )
        max_attempts = input_data.get(
            "max_attempts",
            2
        )

        if not code:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No source code was provided."
            )
            return result.__dict__

        if max_attempts < 1:
            max_attempts = 1

        try:

            # 1. Security Analysis
            analysis = self.analysis_agent.run({
                "code": code,
                "filename": filename,
            })

            if not analysis["success"]:
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    data={
                        "analysis": analysis
                    },
                    message="Workflow stopped: AnalysisAgent failed."
                ).__dict__

            findings = analysis["data"]["findings"]

            if not findings:
                return AgentResult(
                    agent_name=self.name,
                    success=True,
                    data={
                        "analysis": analysis,
                        "findings": [],
                    },
                    message="No security findings detected."
                ).__dict__

            # 2. Risk Scoring
            risk = self.risk_agent.run({
                "findings": findings,
                "code": code,
            })

            if not risk["success"]:
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    data={
                        "analysis": analysis,
                        "risk": risk,
                    },
                    message="Workflow stopped: RiskAgent failed."
                ).__dict__

            scored_findings = risk["data"]["findings"]

            # Dry-run stops before Gemini remediation.
            if dry_run:
                return AgentResult(
                    agent_name=self.name,
                    success=True,
                    data={
                        "analysis": analysis,
                        "risk": risk,
                        "findings": scored_findings,
                    },
                    message=(
                        "Dry run completed: remediation and "
                        "verification were skipped."
                    )
                ).__dict__

            # 3. Select highest-risk finding
            target_finding = max(
                scored_findings,
                key=lambda finding: (
                    finding.risk_score
                    if finding.risk_score is not None
                    else -1
                )
            )

            current_code = code
            current_finding = target_finding
            remediation_history = []
            verification_history = []
            reanalysis_history = []

            # 4. Closed-loop remediation
            for attempt in range(1, max_attempts + 1):

                remediation = self.remediation_agent.run({
                    "code": current_code,
                    "finding": current_finding,
                })

                remediation_history.append({
                    "attempt": attempt,
                    "result": remediation,
                })

                if not remediation["success"]:
                    return AgentResult(
                        agent_name=self.name,
                        success=False,
                        data={
                            "analysis": analysis,
                            "risk": risk,
                            "selected_finding": current_finding,
                            "remediation_history": remediation_history,
                            "verification_history": verification_history,
                            "reanalysis_history": reanalysis_history,
                        },
                        message=(
                            f"Workflow stopped: RemediationAgent "
                            f"failed on attempt {attempt}."
                        )
                    ).__dict__

                fixed_code = remediation["data"]["fixed_code"]

                # 5. Verification
                verification = self.verification_agent.run({
                    "original_code": code,
                    "fixed_code": fixed_code,
                    "original_finding": current_finding,
                    "filename": filename,
                    "functional_tests": functional_tests,
                })

                verification_history.append({
                    "attempt": attempt,
                    "result": verification,
                })

                if not verification["success"]:
                    return AgentResult(
                        agent_name=self.name,
                        success=False,
                        data={
                            "analysis": analysis,
                            "risk": risk,
                            "selected_finding": current_finding,
                            "remediation_history": remediation_history,
                            "verification_history": verification_history,
                            "reanalysis_history": reanalysis_history,
                        },
                        message=(
                            f"Workflow stopped: VerificationAgent "
                            f"failed on attempt {attempt}."
                        )
                    ).__dict__

                verification_data = verification["data"]["verification"]

                # Successful verification exits the remediation loop.
                if verification_data["verified"]:
                    break

                # Failed verification: only re-analyze if another
                # remediation attempt is available.
                if attempt >= max_attempts:
                    return AgentResult(
                        agent_name=self.name,
                        success=True,
                        data={
                            "analysis": analysis,
                            "risk": risk,
                            "selected_finding": current_finding,
                            "remediation_history": remediation_history,
                            "verification_history": verification_history,
                            "reanalysis_history": reanalysis_history,
                        },
                        message=(
                            "Remediation loop exhausted: "
                            "maximum attempts reached without "
                            "successful verification."
                        )
                    ).__dict__

                current_code = fixed_code

                # Re-analyze the failed fix so the next attempt
                # targets an accurate, up-to-date finding instead
                # of stale metadata from before the fix.
                reanalysis = self.analysis_agent.run({
                    "code": current_code,
                    "filename": filename,
                })

                reanalysis_history.append({
                    "attempt": attempt,
                    "result": reanalysis,
                })

                if not reanalysis["success"]:
                    return AgentResult(
                        agent_name=self.name,
                        success=False,
                        data={
                            "analysis": analysis,
                            "risk": risk,
                            "selected_finding": current_finding,
                            "remediation_history": remediation_history,
                            "verification_history": verification_history,
                            "reanalysis_history": reanalysis_history,
                        },
                        message=(
                            f"Workflow stopped: re-analysis failed "
                            f"after attempt {attempt}."
                        )
                    ).__dict__

                new_findings = reanalysis["data"]["findings"]

                if not new_findings:
                    # Static analysis is clean, so verification must have
                    # failed for a non-security reason (e.g. a functional
                    # regression). There is no remaining security finding
                    # to remediate, so retrying further would not help.
                    return AgentResult(
                        agent_name=self.name,
                        success=True,
                        data={
                            "analysis": analysis,
                            "risk": risk,
                            "selected_finding": current_finding,
                            "remediation_history": remediation_history,
                            "verification_history": verification_history,
                            "reanalysis_history": reanalysis_history,
                        },
                        message=(
                            "Remediation loop stopped: no security "
                            "findings remain after the fix, but "
                            "verification still failed (likely a "
                            "functional regression). Requires human "
                            "review."
                        )
                    ).__dict__

                # Re-score the current findings so the next attempt
                # targets whatever is now the highest-risk issue.
                new_risk = self.risk_agent.run({
                    "findings": new_findings,
                    "code": current_code,
                })

                if not new_risk["success"]:
                    return AgentResult(
                        agent_name=self.name,
                        success=False,
                        data={
                            "analysis": analysis,
                            "risk": risk,
                            "selected_finding": current_finding,
                            "remediation_history": remediation_history,
                            "verification_history": verification_history,
                            "reanalysis_history": reanalysis_history,
                        },
                        message=(
                            f"Workflow stopped: RiskAgent failed during "
                            f"retry re-analysis after attempt {attempt}."
                        )
                    ).__dict__

                current_finding = max(
                    new_risk["data"]["findings"],
                    key=lambda finding: (
                        finding.risk_score
                        if finding.risk_score is not None
                        else -1
                    )
                )

            # This branch is retained as a defensive fallback.
            # Normal exhaustion is handled by the explicit return
            # inside the failed-verification path above.
            else:
                return AgentResult(
                    agent_name=self.name,
                    success=True,
                    data={
                        "analysis": analysis,
                        "risk": risk,
                        "selected_finding": current_finding,
                        "remediation_history": remediation_history,
                        "verification_history": verification_history,
                        "reanalysis_history": reanalysis_history,
                    },
                    message=(
                        "Remediation loop exhausted: "
                        "maximum attempts reached without "
                        "successful verification."
                    )
                ).__dict__

            # 6. Trust Gate
            trust_gate = self.trust_gate_agent.run({
                "verification": verification_data,
                "remediation_attempt": len(verification_history),
            })

            if not trust_gate["success"]:
                return AgentResult(
                    agent_name=self.name,
                    success=False,
                    data={
                        "analysis": analysis,
                        "risk": risk,
                        "selected_finding": current_finding,
                        "remediation_history": remediation_history,
                        "verification_history": verification_history,
                        "reanalysis_history": reanalysis_history,
                        "trust_gate": trust_gate,
                    },
                    message="Workflow stopped: TrustGateAgent failed."
                ).__dict__

            # 7. Final result
            result = AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "analysis": analysis,
                    "risk": risk,
                    "selected_finding": current_finding,
                    "remediation_history": remediation_history,
                    "verification_history": verification_history,
                    "reanalysis_history": reanalysis_history,
                    "trust_gate": trust_gate,
                },
                message=(
                    "Complete CodeShield-X closed-loop "
                    "agent workflow executed successfully."
                )
            )

            return result.__dict__

        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message=f"Orchestration failed: {e}"
            )
