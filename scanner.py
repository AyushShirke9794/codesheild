import subprocess
import json
import tempfile
import os
from typing import List
from models import Finding
from parsers import parse_semgrep_output, parse_bandit_output


def run_analysis(code: str, filename: str = "submitted_code.py") -> List[Finding]:
    with tempfile.TemporaryDirectory() as tmp_dir:
        code_path = os.path.join(tmp_dir, filename)
        with open(code_path, "w") as f:
            f.write(code)

        semgrep_json_path = os.path.join(tmp_dir, "semgrep_output.json")
        subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json",
             "--output", semgrep_json_path, code_path],
            capture_output=True,
            timeout=60
        )

        bandit_json_path = os.path.join(tmp_dir, "bandit_output.json")
        subprocess.run(
            ["bandit", "-f", "json", "-o", bandit_json_path, code_path],
            capture_output=True,
            timeout=60
        )

        findings = []
        if os.path.exists(semgrep_json_path):
            findings.extend(parse_semgrep_output(semgrep_json_path))
        if os.path.exists(bandit_json_path):
            findings.extend(parse_bandit_output(bandit_json_path))

        return findings
