"""Execution result model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from aegis.core.action import Action


class ResultStatus(StrEnum):
    """Status of an action execution."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"  # Blocked by policy
    DENIED = "denied"  # Denied by human operator
    SKIPPED = "skipped"  # Skipped due to prior failure


@dataclass
class Result:
    """Result of executing a single action.

    Contains the action, its final status, any returned data,
    and timing information for audit purposes.
    """

    action: Action
    status: ResultStatus
    data: Any = None
    error: str | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    @property
    def ok(self) -> bool:
        """Whether the action completed successfully."""
        return self.status == ResultStatus.SUCCESS

    def __str__(self) -> str:
        status_icon = {
            ResultStatus.SUCCESS: "[OK]",
            ResultStatus.FAILED: "[FAIL]",
            ResultStatus.BLOCKED: "[BLOCK]",
            ResultStatus.DENIED: "[DENY]",
            ResultStatus.SKIPPED: "[SKIP]",
        }
        return f"{status_icon[self.status]} {self.action.type} -> {self.action.target}"
