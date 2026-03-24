"""Protocol definitions for pluggable audit backends.

Allows swapping the default SQLite audit logger for Redis, PostgreSQL,
or any other storage backend that satisfies the protocol.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result


@runtime_checkable
class AuditBackend(Protocol):
    """Synchronous audit backend protocol.

    Any class implementing these methods can be used as a drop-in
    replacement for :class:`~aegis.runtime.audit.AuditLogger`.
    """

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Write one audit entry. Returns the row/entry ID."""
        ...

    def get_log(
        self,
        session_id: str | None = None,
        *,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        agent_id: str | None = None,
        chain_id: str | None = None,
    ) -> list[dict[str, object]]:
        """Retrieve audit entries with flexible filtering."""
        ...

    def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        """Count audit entries matching the given filters."""
        ...

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Register a callback to receive new audit entries."""
        ...

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Remove a previously registered callback."""
        ...

    def close(self) -> None:
        """Release resources held by the backend."""
        ...


@runtime_checkable
class AsyncAuditBackend(Protocol):
    """Asynchronous audit backend protocol.

    For backends that require async I/O (e.g. asyncpg for PostgreSQL).
    """

    async def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Write one audit entry. Returns the row/entry ID."""
        ...

    async def get_log(
        self,
        session_id: str | None = None,
        *,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        agent_id: str | None = None,
        chain_id: str | None = None,
    ) -> list[dict[str, object]]:
        """Retrieve audit entries with flexible filtering."""
        ...

    async def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        """Count audit entries matching the given filters."""
        ...

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Register a callback to receive new audit entries."""
        ...

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Remove a previously registered callback."""
        ...

    async def close(self) -> None:
        """Release resources held by the backend."""
        ...
