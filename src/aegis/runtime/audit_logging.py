"""Python logging-based audit backend.

Alternative to the SQLite-backed :class:`AuditLogger` for environments
where structured logging to stdout/log aggregators is preferred.

Example::

    import logging
    from aegis.runtime.audit_logging import LoggingAuditLogger

    logging.basicConfig(level=logging.DEBUG)
    audit = LoggingAuditLogger()
    runtime = Runtime(executor=..., policy=..., audit_logger=audit)
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result
from aegis.core.risk import RiskLevel

_RISK_TO_LEVEL = {
    RiskLevel.LOW: logging.DEBUG,
    RiskLevel.MEDIUM: logging.INFO,
    RiskLevel.HIGH: logging.WARNING,
    RiskLevel.CRITICAL: logging.ERROR,
}


class LoggingAuditLogger:
    """Audit logger that writes structured JSON to Python logging.

    Each :meth:`log` call emits a structured log record at a level
    determined by the action's risk level:

    - LOW → DEBUG
    - MEDIUM → INFO
    - HIGH → WARNING
    - CRITICAL → ERROR

    Args:
        logger: Python logger instance. Defaults to ``aegis.audit``.
    """

    _DEFAULT_MAX_ENTRIES = 10_000

    def __init__(
        self, logger: logging.Logger | None = None, max_entries: int | None = None
    ) -> None:
        self._logger = logger or logging.getLogger("aegis.audit")
        self._entries: list[dict[str, Any]] = []
        self._max_entries = max_entries if max_entries is not None else self._DEFAULT_MAX_ENTRIES

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Write one audit entry to the Python logger.

        Returns:
            Sequential entry number (1-based).
        """
        entry = {
            "session_id": session_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "action_type": decision.action.type,
            "action_target": decision.action.target,
            "action_params": decision.action.params,
            "risk_level": decision.risk_level.name,
            "approval": decision.approval.value,
            "matched_rule": decision.matched_rule,
            "human_decision": human_decision,
            "result_status": result.status.value if result else None,
            "result_error": result.error if result else None,
        }

        self._entries.append(entry)
        if len(self._entries) > self._max_entries:
            self._entries = self._entries[-self._max_entries :]
        level = _RISK_TO_LEVEL.get(decision.risk_level, logging.INFO)
        self._logger.log(level, json.dumps(entry))

        return len(self._entries)

    def get_log(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Retrieve in-memory audit entries, optionally filtered by session."""
        if session_id:
            return [e for e in self._entries if e["session_id"] == session_id]
        return list(self._entries)

    def export_jsonl(self, path: str | Path, session_id: str | None = None) -> int:
        """Export entries as JSON Lines."""
        entries = self.get_log(session_id=session_id)
        out = Path(path)
        with out.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
        return len(entries)

    def close(self) -> None:
        """No-op (no resources to close)."""
