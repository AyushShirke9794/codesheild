from typing import List, Tuple

from models import Finding
from scanner import run_analysis


class VerificationEngine:

    def verify(
        self,
        original_code: str,
        fixed_code: str,
        original_finding: Finding,
        filename: str = "submitted_code.py"
    ):

        # Scan both versions independently.
        original_findings: List[Finding] = run_analysis(
            original_code,
            filename
        )

        fixed_findings: List[Finding] = run_analysis(
            fixed_code,
            filename
        )

        # Check whether the exact original scanner finding
        # still exists after remediation.
        original_remaining = [
            finding
            for finding in fixed_findings
            if self._matches_original_finding(
                finding,
                original_finding
            )
        ]

        original_vulnerability_fixed = (
            len(original_remaining) == 0
        )

        # Compare signatures before and after remediation.
        original_signatures = {
            self._signature(finding)
            for finding in original_findings
        }

        fixed_signatures = {
            self._signature(finding)
            for finding in fixed_findings
        }

        # Findings appearing only after remediation are
        # genuinely newly introduced findings.
        new_signatures = (
            fixed_signatures - original_signatures
        )

        new_findings = [
            finding
            for finding in fixed_findings
            if self._signature(finding) in new_signatures
        ]

        regression_detected = len(new_findings) > 0

        verified = (
            original_vulnerability_fixed
            and not regression_detected
        )

        status = "PASS" if verified else "FAIL"

        return {
            "verified": verified,
            "original_vulnerability_fixed":
                original_vulnerability_fixed,
            "regression_detected":
                regression_detected,
            "original_finding":
                original_finding,
            "remaining_findings":
                original_remaining,
            "new_findings":
                new_findings,
            "status":
                status
        }

    @staticmethod
    def _matches_original_finding(
        finding: Finding,
        original_finding: Finding
    ) -> bool:

        return (
            finding.tool == original_finding.tool
            and finding.rule_id == original_finding.rule_id
        )

    @staticmethod
    def _signature(
        finding: Finding
    ) -> Tuple[str, str, int | None]:

        return (
            finding.tool,
            finding.rule_id,
            finding.cwe_id
        )