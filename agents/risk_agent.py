from typing import Any, Dict

from agents.base_agent import BaseAgent
from agents.contracts import AgentResult
from finding_features import extract_features
from risk_engine import RiskEngine


class RiskAgent(BaseAgent):
    """
    Agent responsible for risk scoring and security explanation.
    """

    def __init__(self):
        super().__init__("RiskAgent")
        self.risk_engine = RiskEngine()

    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate risk scores for security findings.
        """

        findings = input_data.get("findings")
        code = input_data.get("code")

        if findings is None:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No security findings were provided."
            )
            return result.__dict__

        if code is None:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message="No source code was provided."
            )
            return result.__dict__

        try:
            scored_findings = []

            for finding in findings:
                features = extract_features(
                    finding,
                    code
                )

                risk_score = self.risk_engine.predict(
                    **features
                )

                finding.risk_score = risk_score
                scored_findings.append(finding)

            result = AgentResult(
                agent_name=self.name,
                success=True,
                data={
                    "findings": scored_findings,
                    "finding_count": len(scored_findings),
                },
                message="Risk scoring completed using XGBoost."
            )

            return result.__dict__

        except Exception as e:
            result = AgentResult(
                agent_name=self.name,
                success=False,
                message=f"Risk scoring failed: {e}"
            )
            return result.__dict__