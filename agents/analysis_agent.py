from typing import Any, Dict

from agents.base_agent import BaseAgent
from agents.contracts import AgentResult
from scanner import run_analysis


class AnalysisAgent(BaseAgent):
    """
    Agent responsible for security analysis of submitted code.
    """

    def __init__(self):
        super().__init__("AnalysisAgent")

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run Semgrep and Bandit analysis through the existing scanner.
        """

        code = input_data.get("code")
        filename = input_data.get(
            "filename",
            "submitted_code.py"
        )

        if not code:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No code was provided for analysis."
            )
            return result.__dict__

        try:
            findings = run_analysis(
                code=code,
                filename=filename
            )

            result = AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "findings": findings,
                    "filename": filename,
                    "finding_count": len(findings),
                },
                message=(
                    "Security analysis completed "
                    "using Semgrep and Bandit."
                )
            )

            return result.__dict__

        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message=f"Security analysis failed: {e}"
            )
            return result.__dict__