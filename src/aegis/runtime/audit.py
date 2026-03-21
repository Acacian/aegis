"""SQLite-backed audit logger.

Records every policy decision and execution result for
post-hoc review, compliance, and debugging.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result

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
        self._conn.execute(_SCHEMA)
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Add agent context columns to existing databases if missing."""
        cursor = self._conn.execute("PRAGMA table_info(audit_log)")
        existing = {row[1] for row in cursor.fetchall()}
        for col_name, col_type in _MIGRATE_AGENT_COLUMNS:
            if col_name not in existing:
                self._conn.execute(
                    f"ALTER TABLE audit_log ADD COLUMN {col_name} {col_type}"
                )
        self._conn.commit()

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
            ),
        )
        self._conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

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

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()
