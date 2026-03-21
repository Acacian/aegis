"""Action model for AI agent operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Action:
    """Represents a single operation an AI agent wants to perform.

    Args:
        type: The kind of operation (e.g. "read", "write", "delete", "bulk_update").
        target: The system being acted upon (e.g. "salesforce", "stripe").
        params: Arbitrary parameters for the operation.
        description: Optional human-readable description of what the action does.
    """

    type: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    agent_id: str = ""
    parent_agent_id: str = ""
    chain_id: str = ""
    chain_depth: int = 0

    def __str__(self) -> str:
        desc = f" - {self.description}" if self.description else ""
        agent = f" [agent={self.agent_id}]" if self.agent_id else ""
        return f"Action({self.type} -> {self.target}{desc}{agent})"
