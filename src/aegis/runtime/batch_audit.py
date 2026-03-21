"""Batched audit logger for high-throughput scenarios.

Reduces SQLite write overhead by accumulating entries and flushing
them in a single transaction. Drop-in replacement for
:class:`~aegis.runtime.audit.AuditLogger` in hot paths.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result
from aegis.runtime.audit import AuditLogger

_INSERT_SQL = """\
INSERT INTO audit_log
    (session_id, timestamp, action_type, action_target, action_params,
     action_desc, risk_level, approval, matched_rule, human_decision,
     result_status, result_data, result_error,
     agent_id, parent_agent_id, chain_id, chain_depth)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class BatchAuditLogger(AuditLogger):
    """AuditLogger that batches writes for better performance.

    Reduces SQLite write overhead by accumulating entries and
    flushing them in a single transaction. Useful when processing
    many actions per second.

    Args:
        db_path: Path to SQLite database.
        batch_size: Flush after this many entries. Default 50.
        flush_interval: Flush after this many seconds. Default 5.0.
    """

    def __init__(
        self,
        db_path: str | Path = "aegis_audit.db",
        batch_size: int = 50,
        flush_interval: float = 5.0,
    ) -> None:
        super().__init__(db_path)
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._buffer: list[tuple[object, ...]] = []
        self._lock = threading.Lock()
        self._last_flush = time.monotonic()

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Buffer an audit entry instead of writing immediately.

        The entry is appended to an internal buffer and flushed when
        ``batch_size`` is reached or ``flush_interval`` seconds have
        elapsed since the last flush.

        Returns:
            ``0`` as a placeholder row ID (actual IDs are assigned at
            flush time).
        """
        row = (
            session_id,
            datetime.now(UTC).isoformat(),
            decision.action.type,
            decision.action.target,
            json.dumps(decision.action.params, default=str),
            decision.action.description or None,
            decision.risk_level.name,
            decision.approval.value,
            decision.matched_rule,
            human_decision,
            result.status.value if result else None,
            json.dumps(result.data, default=str) if result and result.data else None,
            result.error if result else None,
            decision.action.agent_id or None,
            decision.action.parent_agent_id or None,
            decision.action.chain_id or None,
            decision.action.chain_depth,
        )
        with self._lock:
            self._buffer.append(row)
            should_flush = (
                len(self._buffer) >= self.batch_size
                or (time.monotonic() - self._last_flush) >= self.flush_interval
            )
        if should_flush:
            self.flush()
        return 0

    def flush(self) -> int:
        """Flush buffered entries to SQLite in a single transaction.

        Returns:
            Number of entries flushed.
        """
        with self._lock:
            to_write = list(self._buffer)
            self._buffer.clear()
            self._last_flush = time.monotonic()

        if not to_write:
            return 0

        self._conn.executemany(_INSERT_SQL, to_write)
        self._conn.commit()
        return len(to_write)

    @property
    def pending(self) -> int:
        """Number of entries waiting in the buffer."""
        with self._lock:
            return len(self._buffer)

    def close(self) -> None:
        """Flush remaining entries and close the database connection."""
        self.flush()
        super().close()
