from typing import Any, Dict

from agents.base_agent import BaseAgent
from agents.contracts import AgentResult
from verification_engine import VerificationEngine


class VerificationAgent(BaseAgent):
    """
    Agent responsible for verifying remediated code.
    """

    def __init__(self):
        super().__init__("VerificationAgent")
        self.verification_engine = VerificationEngine()

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify the remediated code for security regressions
        and functional equivalence.
        """

        original_code = input_data.get("original_code")
        fixed_code = input_data.get("fixed_code")
        original_finding = input_data.get("original_finding")
        filename = input_data.get(
            "filename",
            "submitted_code.py"
        )
        functional_tests = input_data.get(
            "functional_tests"
        )

        if not original_code:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No original code was provided."
            )
            return result.__dict__

        if not fixed_code:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No fixed code was provided."
            )
            return result.__dict__

        if original_finding is None:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No original security finding was provided."
            )
            return result.__dict__

        try:
            verification = self.verification_engine.verify(
                original_code=original_code,
                fixed_code=fixed_code,
                original_finding=original_finding,
                filename=filename,
                functional_tests=functional_tests
            )

            result = AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "verification": verification,
                },
                message="Remediated code verification completed."
            )

            return result.__dict__

        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message=f"Verification failed: {e}"
            )
            return result.__dict__