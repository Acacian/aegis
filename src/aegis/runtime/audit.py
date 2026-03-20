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
        self._conn = sqlite3.connect(str(self._db_path))
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

    def get_log(self, session_id: str | None = None) -> list[dict]:
        """Retrieve audit log entries, optionally filtered by session."""
        if session_id:
            cursor = self._conn.execute(
                "SELECT * FROM audit_log WHERE session_id = ? ORDER BY id",
                (session_id,),
            )
        else:
            cursor = self._conn.execute("SELECT * FROM audit_log ORDER BY id")

        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

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
