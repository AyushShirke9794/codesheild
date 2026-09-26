from verification_engine import VerificationEngine
from models import Finding

original = """import subprocess
subprocess.run(user_input, shell=True)
"""

fixed = """def safe_message():
    return "hello"

print(safe_message())
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

result = VerificationEngine().verify(
    original,
    fixed,
    finding,
    "test.py"
)

print(result)
