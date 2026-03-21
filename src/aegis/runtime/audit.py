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
    result_error    TEXT
);
"""


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
                 result_status, result_data, result_error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                datetime.now(UTC).isoformat(),
                decision.action.type,
                decision.action.target,
                json.dumps(decision.action.params),
                decision.action.description or None,
                decision.risk_level.name,
                decision.approval.value,
                decision.matched_rule,
                human_decision,
                result.status.value if result else None,
                json.dumps(result.data) if result and result.data else None,
                result.error if result else None,
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

        query = "SELECT * FROM audit_log"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id"
        if limit:
            query += f" LIMIT {limit}"

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
