"""SQLite-backed audit logger.

Records every policy decision and execution result for
post-hoc review, compliance, and debugging.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result

logger = logging.getLogger("aegis.runtime.audit")

_SENSITIVE_KEY_RE = re.compile(
    r"(password|secret|token|api_key|apikey|authorization|credential|private_key|access_key)",
    re.IGNORECASE,
)


def _sanitize_params(data: Any) -> Any:
    """Recursively redact values for keys matching sensitive patterns."""
    if isinstance(data, dict):
        return {
            k: "[REDACTED]" if _SENSITIVE_KEY_RE.search(k) else _sanitize_params(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_sanitize_params(item) for item in data]
    return data

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,
    action_type     TEXT    NOT NULL,
    action_target   TEXT    NOT NULL,
    action_params   TEXT,
    action_desc     TEXT,
    risk_level      TEXT    NOT NULL,
    approval        TEXT    NOT NULL,
    matched_rule    TEXT,
    human_decision  TEXT,
    result_status   TEXT,
    result_data     TEXT,
    result_error    TEXT,
    agent_id        TEXT,
    parent_agent_id TEXT,
    chain_id        TEXT,
    chain_depth     INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_action_type ON audit_log(action_type);
"""

_MIGRATE_AGENT_COLUMNS = [
    ("agent_id", "TEXT"),
    ("parent_agent_id", "TEXT"),
    ("chain_id", "TEXT"),
    ("chain_depth", "INTEGER DEFAULT 0"),
]


class AuditLogger:
    """Persists action decisions and results to a local SQLite database.

    Each call to :meth:`log` writes one row capturing the full lifecycle
    of a single action: policy decision, optional human decision, and result.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str | Path = "aegis_audit.db") -> None:
        self._db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate()
        self._init_tenure()
        self._subscribers: list[Callable[[dict[str, Any]], Any]] = []

    def _migrate(self) -> None:
        """Add agent context columns to existing databases if missing."""
        cursor = self._conn.execute("PRAGMA table_info(audit_log)")
        existing = {row[1] for row in cursor.fetchall()}
        for col_name, col_type in _MIGRATE_AGENT_COLUMNS:
            if col_name not in existing:
                self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col_name} {col_type}")
        self._conn.commit()

    def _init_tenure(self) -> None:
        """Create governance_tenure table if missing and seed the first row."""
        self._conn.execute(
            """\
            CREATE TABLE IF NOT EXISTS governance_tenure (
                first_activated  TEXT,
                total_actions    INTEGER DEFAULT 0,
                threats_blocked  INTEGER DEFAULT 0
            )"""
        )
        row = self._conn.execute("SELECT COUNT(*) FROM governance_tenure").fetchone()
        if row[0] == 0:
            self._conn.execute(
                "INSERT INTO governance_tenure (first_activated, total_actions, threats_blocked) "
                "VALUES (?, 0, 0)",
                (datetime.now(UTC).isoformat(),),
            )
        self._conn.commit()

    def _update_tenure(self, decision: PolicyDecision, result: Result | None) -> None:
        """Increment tenure counters after each log() call."""
        is_blocked = decision.approval.value in ("block",) or (
            result is not None and result.status.value in ("blocked", "denied")
        )
        if is_blocked:
            self._conn.execute(
                "UPDATE governance_tenure "
                "SET total_actions = total_actions + 1, threats_blocked = threats_blocked + 1"
            )
        else:
            self._conn.execute("UPDATE governance_tenure SET total_actions = total_actions + 1")

    def get_tenure_summary(self) -> dict[str, object]:
        """Return governance tenure statistics."""
        row = self._conn.execute(
            "SELECT first_activated, total_actions, threats_blocked FROM governance_tenure"
        ).fetchone()
        if row is None:
            return {
                "first_activated": None,
                "days_active": 0,
                "total_actions": 0,
                "threats_blocked": 0,
            }
        first_activated = row[0]
        activated_dt = datetime.fromisoformat(first_activated)
        days_active = (datetime.now(UTC) - activated_dt).days
        return {
            "first_activated": first_activated,
            "days_active": days_active,
            "total_actions": row[1],
            "threats_blocked": row[2],
        }

    def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Write one audit entry.

        Returns:
            The row ID of the inserted entry.
        """
        cursor = self._conn.execute(
            """
            INSERT INTO audit_log
                (session_id, timestamp, action_type, action_target, action_params,
                 action_desc, risk_level, approval, matched_rule, human_decision,
                 result_status, result_data, result_error,
                 agent_id, parent_agent_id, chain_id, chain_depth)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                datetime.now(UTC).isoformat(),
                decision.action.type,
                decision.action.target,
                json.dumps(_sanitize_params(decision.action.params), default=str),
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
            ),
        )
        self._update_tenure(decision, result)
        self._conn.commit()
        row_id: int = cursor.lastrowid  # type: ignore[assignment]

        if self._subscribers:
            entry: dict[str, Any] = {
                "id": row_id,
                "session_id": session_id,
                "action_type": decision.action.type,
                "action_target": decision.action.target,
                "risk_level": decision.risk_level.name,
                "approval": decision.approval.value,
                "matched_rule": decision.matched_rule,
                "result_status": result.status.value if result else None,
                "agent_id": decision.action.agent_id or None,
            }
            for cb in self._subscribers:
                try:
                    cb(entry)
                except Exception:
                    logger.warning(
                        "Audit subscriber %s failed", cb, exc_info=True
                    )

        return row_id

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
        """Retrieve audit log entries with flexible filtering.

        Args:
            session_id: Filter by session.
            action_type: Filter by action type (exact match).
            risk_level: Filter by risk level name (e.g. "HIGH").
            result_status: Filter by result status (e.g. "blocked").
            since: Only entries after this timestamp.
            until: Only entries before this timestamp.
            limit: Maximum number of entries to return.
            agent_id: Filter by agent ID (exact match).
            chain_id: Filter by chain ID (exact match).
        """
        clauses: list[str] = []
        params: list[object] = []

        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if action_type:
            clauses.append("action_type = ?")
            params.append(action_type)
        if risk_level:
            clauses.append("risk_level = ?")
            params.append(risk_level.upper())
        if result_status:
            clauses.append("result_status = ?")
            params.append(result_status)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since.isoformat())
        if until:
            clauses.append("timestamp <= ?")
            params.append(until.isoformat())
        if agent_id:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if chain_id:
            clauses.append("chain_id = ?")
            params.append(chain_id)

        query = "SELECT * FROM audit_log"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id"
        if limit is not None:
            query += " LIMIT ?"
            params.append(int(limit))

        cursor = self._conn.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

    def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        """Count audit entries matching the given filters.

        Useful for monitoring and dashboards without loading full records.
        """
        clauses: list[str] = []
        params: list[object] = []

        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if action_type:
            clauses.append("action_type = ?")
            params.append(action_type)
        if risk_level:
            clauses.append("risk_level = ?")
            params.append(risk_level.upper())
        if result_status:
            clauses.append("result_status = ?")
            params.append(result_status)

        query = "SELECT COUNT(*) FROM audit_log"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        cursor = self._conn.execute(query, params)
        row = cursor.fetchone()
        return int(row[0]) if row else 0

    def export_jsonl(self, path: str | Path, session_id: str | None = None) -> int:
        """Export audit entries as JSON Lines (one JSON object per line).

        Args:
            path: Output file path.
            session_id: Optional session filter.

        Returns:
            Number of entries exported.
        """
        entries = self.get_log(session_id=session_id)
        out = Path(path)
        with out.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")
        return len(entries)

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Register a callback to receive new audit entries."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Remove a previously registered callback."""
        with contextlib.suppress(ValueError):
            self._subscribers.remove(callback)

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
