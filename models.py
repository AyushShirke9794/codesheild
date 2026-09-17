from pydantic import BaseModel
from typing import Optional

class Finding(BaseModel):
    tool: str              # "semgrep" or "bandit"
    rule_id: str            # tool-specific rule identifier
    cwe_id: Optional[int]   # numeric CWE, e.g. 78 (None if a tool reports no CWE)
    severity_raw: str       # the tool's own severity label, unmodified
    confidence: Optional[str]
    message: str
    file_path: str
    line_number: int
