from models import Finding
from remediation_engine import RemediationEngine


code = """import subprocess
subprocess.run(user_input, shell=True)
"""


finding = Finding(
    tool="semgrep",
    rule_id="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
    cwe_id=78,
    severity_raw="ERROR",
    confidence="MEDIUM",
    message="subprocess call with shell=True identified, security issue.",
    file_path="test.py",
    line_number=2
)


engine = RemediationEngine()

result = engine.generate_fix(
    code=code,
    finding=finding
)

print("\n=== EXPLANATION ===")
print(result["explanation"])

print("\n=== SECURE FIX ===")
print(result["secure_fix"])

print("\n=== FIXED CODE ===")
print(result["fixed_code"])