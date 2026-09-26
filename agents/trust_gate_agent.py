from typing import Any, Dict

from agents.base_agent import BaseAgent
from agents.contracts import AgentResult
from models import TrustGateRequest, VerificationResponse
from trustgate import evaluate_trust_gate


class TrustGateAgent(BaseAgent):
    """
    Agent responsible for the final trust decision.
    """

    def __init__(self):
        super().__init__("TrustGateAgent")

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate the verification result and make a trust decision.
        """

        verification = input_data.get("verification")
        remediation_attempt = input_data.get(
            "remediation_attempt",
            1
        )

        if verification is None:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No verification result was provided."
            )
            return result.__dict__

        try:
            if isinstance(verification, dict):
                verification = VerificationResponse(**verification)

            request = TrustGateRequest(
                verification=verification,
                remediation_attempt=remediation_attempt
            )

            decision = evaluate_trust_gate(request)

            result = AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "decision": decision
                },
                message=(
                    f"Trust decision generated: "
                    f"{decision.decision.value}"
                )
            )

            return result.__dict__

        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message=f"Trust Gate evaluation failed: {e}"
            )
            return result.__dict__