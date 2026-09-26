from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseAgent(ABC):
    """
    Base contract for every CodeShield-X agent.
    """

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's responsibility.

        Every agent must implement this method.
        """
        pass