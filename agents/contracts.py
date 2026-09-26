from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class AgentResult:
    """
    Standard output returned by every CodeShield-X agent.
    """

    agent_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""