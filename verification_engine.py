from typing import List, Tuple, Any
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from models import Finding, FunctionalTestCase
from scanner import run_analysis


class VerificationEngine:

    # =============================================================
    # Execution security limits
    # =============================================================

    EXECUTION_TIMEOUT_SECONDS = 3
    MAX_OUTPUT_BYTES = 64 * 1024

    def verify(
        self,
        original_code: str,
        fixed_code: str,
        original_finding: Finding,
        filename: str = "submitted_code.py",
        functional_tests: List[FunctionalTestCase] | None = None
    ):

        # ---------------------------------------------------------
        # 1. Static analysis of original and fixed code
        # ---------------------------------------------------------

        original_findings: List[Finding] = run_analysis(
            original_code,
            filename
        )

        fixed_findings: List[Finding] = run_analysis(
            fixed_code,
            filename
        )

        # ---------------------------------------------------------
        # 2. Check whether the original vulnerability remains
        # ---------------------------------------------------------

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

        # ---------------------------------------------------------
        # 3. Detect newly introduced security findings
        # ---------------------------------------------------------

        original_signatures = {
            self._signature(finding)
            for finding in original_findings
        }

        fixed_signatures = {
            self._signature(finding)
            for finding in fixed_findings
        }

        new_signatures = (
            fixed_signatures - original_signatures
        )

        new_findings = [
            finding
            for finding in fixed_findings
            if self._signature(finding) in new_signatures
        ]

        regression_detected = len(new_findings) > 0

        # ---------------------------------------------------------
        # 4. Functional-equivalence testing
        # ---------------------------------------------------------

        if functional_tests is None:
            functional_tests = []

        functional_equivalent = True
        functional_tests_passed = 0
        functional_tests_failed = 0

        if functional_tests:

            functional_result = self._run_functional_tests(
                original_code=original_code,
                fixed_code=fixed_code,
                functional_tests=functional_tests,
                filename=filename
            )

            functional_equivalent = functional_result[
                "functional_equivalent"
            ]

            functional_tests_passed = functional_result[
                "functional_tests_passed"
            ]

            functional_tests_failed = functional_result[
                "functional_tests_failed"
            ]

        # ---------------------------------------------------------
        # 5. Final verification decision
        # ---------------------------------------------------------

        verified = (
            original_vulnerability_fixed
            and not regression_detected
            and functional_equivalent
        )

        status = "PASS" if verified else "FAIL"

        return {
            "verified": verified,
            "original_vulnerability_fixed":
                original_vulnerability_fixed,
            "regression_detected":
                regression_detected,
            "functional_equivalent":
                functional_equivalent,
            "functional_tests_passed":
                functional_tests_passed,
            "functional_tests_failed":
                functional_tests_failed,
            "original_finding":
                original_finding,
            "remaining_findings":
                original_remaining,
            "new_findings":
                new_findings,
            "status":
                status
        }

    # =============================================================
    # Functional testing
    # =============================================================

    def _run_functional_tests(
        self,
        original_code: str,
        fixed_code: str,
        functional_tests: List[FunctionalTestCase],
        filename: str
    ):

        passed = 0
        failed = 0

        for test_case in functional_tests:

            original_output = self._execute_test_case(
                code=original_code,
                test_case=test_case,
                filename=filename
            )

            fixed_output = self._execute_test_case(
                code=fixed_code,
                test_case=test_case,
                filename=filename
            )

            expected_output = test_case.expected_output

            original_matches = (
                original_output == expected_output
            )

            fixed_matches = (
                fixed_output == expected_output
            )

            # The fixed implementation must preserve
            # the expected behavior.
            if original_matches and fixed_matches:
                passed += 1
            else:
                failed += 1

        return {
            "functional_equivalent": failed == 0,
            "functional_tests_passed": passed,
            "functional_tests_failed": failed
        }

    # =============================================================
    # Execute one functional test
    # =============================================================

    def _execute_test_case(
        self,
        code: str,
        test_case: FunctionalTestCase,
        filename: str
    ) -> Any:

        # ---------------------------------------------------------
        # Experimental execution contract:
        #
        # Submitted code must expose:
        #
        #     def main(**input_data):
        #         ...
        #
        # The verifier calls:
        #
        #     main(**input_data)
        #
        # ---------------------------------------------------------

        runner_code = """
import json
import sys

{code}

input_data = json.loads(sys.argv[1])

result = main(**input_data)

print(json.dumps(result))
""".format(
            code=code
        )

        # ---------------------------------------------------------
        # Create isolated temporary execution directory
        # ---------------------------------------------------------

        with tempfile.TemporaryDirectory(
            prefix="codeshield_verify_"
        ) as temp_dir:

            temp_path = Path(temp_dir) / filename

            temp_path.write_text(
                runner_code,
                encoding="utf-8"
            )

            input_json = json.dumps(
                test_case.input_data
            )

            # -----------------------------------------------------
            # Minimal subprocess environment
            # -----------------------------------------------------

            execution_env = {
                "PYTHONIOENCODING": "utf-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
                "PATH": os.environ.get("PATH", "")
            }

            try:

                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(temp_path),
                        input_json
                    ],

                    # Never execute with the CodeShield
                    # project directory as the working directory.
                    cwd=temp_dir,

                    # Do not inherit the complete parent environment.
                    env=execution_env,

                    # Capture output so we can validate it.
                    capture_output=True,

                    text=True,

                    # Prevent infinite loops / hanging code.
                    timeout=self.EXECUTION_TIMEOUT_SECONDS,

                    # Prevent a huge output from becoming
                    # part of the verification pipeline.
                    check=False
                )

            except subprocess.TimeoutExpired:

                print(
                    "[CodeShield-X] Functional test timed out."
                )

                return None

            except Exception as exc:

                print(
                    "[CodeShield-X] Functional execution "
                    f"failed: {exc}"
                )

                return None

            # -----------------------------------------------------
            # Output-size protection
            # -----------------------------------------------------

            stdout = completed.stdout or ""
            stderr = completed.stderr or ""

            if len(stdout.encode("utf-8")) > self.MAX_OUTPUT_BYTES:
                print(
                    "[CodeShield-X] Functional test produced "
                    "excessive stdout."
                )
                return None

            if len(stderr.encode("utf-8")) > self.MAX_OUTPUT_BYTES:
                print(
                    "[CodeShield-X] Functional test produced "
                    "excessive stderr."
                )
                return None

            # -----------------------------------------------------
            # Process failure
            # -----------------------------------------------------

            if completed.returncode != 0:
                return None

            output = stdout.strip()

            if not output:
                return None

            # -----------------------------------------------------
            # JSON output
            # -----------------------------------------------------

            try:

                return json.loads(output)

            except json.JSONDecodeError:

                return output

    # =============================================================
    # Security finding helpers
    # =============================================================

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