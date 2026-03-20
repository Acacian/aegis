"""Risk level classification for agent actions."""

from __future__ import annotations

from enum import IntEnum


class RiskLevel(IntEnum):
    """Risk level for agent actions, ordered by severity.

    Used by the policy engine to determine approval requirements.
    Higher values indicate greater potential impact.
    """

    LOW = 1  # Read-only, no side effects
    MEDIUM = 2  # Single write, generally reversible
    HIGH = 3  # Bulk operations, hard to reverse
    CRITICAL = 4  # Destructive or irreversible operations
