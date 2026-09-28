import json
from typing import List
from models import Finding


def parse_devaic_output(json_path: str) -> List[Finding]:
    with open(json_path, "r") as f:
        data = json.load(f)

    findings = []

    for result in data:
        if not result.get("vulnerable", False):
            continue

        details = result.get("details", [])

        for detail in details:
            rule_id = detail.get("rule_id", "unknown")

            vulnerabilities = detail.get("vulnerabilities", [])
            vulnerability_text = ", ".join(vulnerabilities)

            comment = detail.get("comment", "")
            message = vulnerability_text

            if comment and comment != "NULL":
                message = f"{vulnerability_text}: {comment}"

            findings.append(
                Finding(
                    tool="devaic",
                    rule_id=rule_id,
                    cwe_id=None,
                    severity_raw="UNKNOWN",
                    confidence=None,
                    message=message,
                    file_path="",
                    line_number=0,
                )
            )

    return findings