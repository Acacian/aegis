"""Retry and rollback policy for action execution.

Configurable retry strategies with exponential backoff and
optional rollback actions when retries are exhausted.

Example::

    from aegis.core.retry import RetryPolicy

    # Retry up to 3 times with exponential backoff
    retry = RetryPolicy(max_retries=3, backoff_base=1.0)

    # With rollback action
    retry = RetryPolicy(
        max_retries=2,
        rollback_action_type="undo_write",
    )
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RetryPolicy:
    """Configuration for retry behavior on failed actions.

    Args:
        max_retries: Maximum number of retry attempts. 0 means no retries.
        backoff_base: Base delay in seconds for exponential backoff.
            Delay = backoff_base * (2 ** attempt). Set to 0 for immediate retries.
        backoff_max: Maximum delay in seconds between retries.
        retryable_errors: If set, only retry when the error message contains
            one of these substrings. Empty list means retry on any failure.
        rollback_action_type: If set, execute a rollback action with this type
            when all retries are exhausted. The rollback action inherits
            the original action's target and params.
        rollback_params: Extra params to merge into the rollback action.
    """

    max_retries: int = 0
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    retryable_errors: list[str] = field(default_factory=list)
    rollback_action_type: str = ""
    rollback_params: dict[str, Any] = field(default_factory=dict)

    def should_retry(self, attempt: int, error: str | None = None) -> bool:
        """Check if the action should be retried."""
        if attempt >= self.max_retries:
            return False
        if self.retryable_errors and error:
            return any(e in error for e in self.retryable_errors)
        return True

    def get_delay(self, attempt: int) -> float:
        """Calculate backoff delay for a given attempt number."""
        if self.backoff_base <= 0:
            return 0.0
        delay = self.backoff_base * (2**attempt)
        return float(min(delay, self.backoff_max))

    async def wait(self, attempt: int) -> None:
        """Wait for the backoff delay."""
        delay = self.get_delay(attempt)
        if delay > 0:
            await asyncio.sleep(delay)

    @property
    def has_rollback(self) -> bool:
        """Whether a rollback action is configured."""
        return bool(self.rollback_action_type)
