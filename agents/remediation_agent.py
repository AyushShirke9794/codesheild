from typing import Any, Dict

from agents.base_agent import BaseAgent
from agents.contracts import AgentResult
from remediation_engine import RemediationEngine


class RemediationAgent(BaseAgent):
    """
    Agent responsible for secure-code remediation.
    """

    def __init__(self):
        super().__init__("RemediationAgent")
        self.remediation_engine = RemediationEngine()

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a secure fix for a security finding.
        """

        code = input_data.get("code")
        finding = input_data.get("finding")

        if not code:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No source code was provided for remediation."
            )
            return result.__dict__

        if finding is None:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No security finding was provided."
            )
            return result.__dict__

        try:
            remediation = self.remediation_engine.generate_fix(
                code=code,
                finding=finding
            )

            result = AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "explanation": remediation["explanation"],
                    "secure_fix": remediation["secure_fix"],
                    "fixed_code": remediation["fixed_code"],
                    "finding": finding,
                },
                message="Secure remediation generated successfully."
            )

            return result.__dict__

        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message=f"Remediation failed: {e}"
            )
            return result.__dict__