import json
import re
from typing import List
from models import Finding


def parse_semgrep_output(json_path: str) -> List[Finding]:
    with open(json_path, "r") as f:
        data = json.load(f)

    findings = []
    for result in data.get("results", []):
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_list = metadata.get("cwe", [])

        cwe_id = None
        if cwe_list:
            match = re.search(r"CWE-(\d+)", cwe_list[0])
            if match:
                cwe_id = int(match.group(1))

        findings.append(Finding(
            tool="semgrep",
            rule_id=result.get("check_id", "unknown"),
            cwe_id=cwe_id,
            severity_raw=result.get("extra", {}).get("severity", "UNKNOWN"),
            confidence=metadata.get("confidence"),
            message=result.get("extra", {}).get("message", ""),
            file_path=result.get("path", ""),
            line_number=result.get("start", {}).get("line", 0),
        ))
    return findings


def parse_bandit_output(json_path: str) -> List[Finding]:
    with open(json_path, "r") as f:
        data = json.load(f)

    findings = []
    for result in data.get("results", []):
        cwe_obj = result.get("issue_cwe")
        cwe_id = cwe_obj.get("id") if cwe_obj else None

        findings.append(Finding(
            tool="bandit",
            rule_id=result.get("test_id", "unknown"),
            cwe_id=cwe_id,
            severity_raw=result.get("issue_severity", "UNKNOWN"),
            confidence=result.get("issue_confidence"),
            message=result.get("issue_text", ""),
            file_path=result.get("filename", ""),
            line_number=result.get("line_number", 0),
        ))
    return findings
