"""PostgreSQL-backed async audit logger.

Uses asyncpg for high-performance async access to PostgreSQL,
with connection pooling and automatic schema creation.

Requires the ``asyncpg`` package::

    pip install agent-aegis[postgres]
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from aegis.core.policy import PolicyDecision
from aegis.core.result import Result

_CREATE_TABLE = """\
CREATE TABLE IF NOT EXISTS audit_log (
    id              BIGSERIAL PRIMARY KEY,
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

_CREATE_INDEX_SESSION = "CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_log (session_id);"
_CREATE_INDEX_TIMESTAMP = (
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log (timestamp);"
)


class PostgresAuditLogger:
    """Async audit logger backed by PostgreSQL via asyncpg.

    Uses connection pooling for efficient concurrent access. The
    schema is auto-created on first use via :meth:`ensure_table`.

    Args:
        dsn: PostgreSQL connection string.
        min_pool_size: Minimum number of connections in the pool.
        max_pool_size: Maximum number of connections in the pool.
    """

    def __init__(
        self,
        dsn: str = "postgresql://localhost/aegis",
        *,
        min_pool_size: int = 2,
        max_pool_size: int = 10,
    ) -> None:
        self._dsn = dsn
        self._min_pool_size = min_pool_size
        self._max_pool_size = max_pool_size
        self._pool: Any | None = None
        self._table_created = False
        self._subscribers: list[Callable[[dict[str, Any]], Any]] = []

    async def _get_pool(self) -> Any:
        """Lazily create the connection pool."""
        if self._pool is None:
            import asyncpg

            self._pool = await asyncpg.create_pool(
                self._dsn,
                min_size=self._min_pool_size,
                max_size=self._max_pool_size,
            )
        return self._pool

    async def ensure_table(self) -> None:
        """Create the audit_log table and indexes if they do not exist."""
        if self._table_created:
            return
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(_CREATE_TABLE)
            await conn.execute(_CREATE_INDEX_SESSION)
            await conn.execute(_CREATE_INDEX_TIMESTAMP)
        self._table_created = True

    # ------------------------------------------------------------------
    # Core methods (AsyncAuditBackend protocol)
    # ------------------------------------------------------------------

    async def log(
        self,
        session_id: str,
        decision: PolicyDecision,
        *,
        result: Result | None = None,
        human_decision: str | None = None,
    ) -> int:
        """Write one audit entry. Returns the row ID."""
        await self.ensure_table()
        pool = await self._get_pool()

        ts_iso = datetime.now(UTC).isoformat()

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO audit_log
                    (session_id, timestamp, action_type, action_target,
                     action_params, action_desc, risk_level, approval,
                     matched_rule, human_decision, result_status,
                     result_data, result_error, agent_id,
                     parent_agent_id, chain_id, chain_depth)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13, $14, $15, $16, $17)
                RETURNING id
                """,
                session_id,
                ts_iso,
                decision.action.type,
                decision.action.target,
                json.dumps(decision.action.params, default=str),
                decision.action.description or None,
                decision.risk_level.name,
                decision.approval.value,
                decision.matched_rule,
                human_decision,
                result.status.value if result else None,
                (json.dumps(result.data, default=str) if result and result.data else None),
                result.error if result else None,
                decision.action.agent_id or None,
                decision.action.parent_agent_id or None,
                decision.action.chain_id or None,
                decision.action.chain_depth,
            )

        row_id: int = row["id"]  # type: ignore[index]

        # Notify in-process subscribers
        if self._subscribers:
            summary: dict[str, Any] = {
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
                with contextlib.suppress(Exception):
                    cb(summary)

        return row_id

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
        await self.ensure_table()
        pool = await self._get_pool()

        clauses: list[str] = []
        params: list[object] = []
        idx = 1

        if session_id:
            clauses.append(f"session_id = ${idx}")
            params.append(session_id)
            idx += 1
        if action_type:
            clauses.append(f"action_type = ${idx}")
            params.append(action_type)
            idx += 1
        if risk_level:
            clauses.append(f"risk_level = ${idx}")
            params.append(risk_level.upper())
            idx += 1
        if result_status:
            clauses.append(f"result_status = ${idx}")
            params.append(result_status)
            idx += 1
        if since:
            clauses.append(f"timestamp >= ${idx}")
            params.append(since.isoformat())
            idx += 1
        if until:
            clauses.append(f"timestamp <= ${idx}")
            params.append(until.isoformat())
            idx += 1
        if agent_id:
            clauses.append(f"agent_id = ${idx}")
            params.append(agent_id)
            idx += 1
        if chain_id:
            clauses.append(f"chain_id = ${idx}")
            params.append(chain_id)
            idx += 1

        query = "SELECT * FROM audit_log"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id"
        if limit is not None:
            query += f" LIMIT ${idx}"
            params.append(int(limit))

        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [dict(row) for row in rows]

    async def count(
        self,
        *,
        session_id: str | None = None,
        action_type: str | None = None,
        risk_level: str | None = None,
        result_status: str | None = None,
    ) -> int:
        """Count audit entries matching the given filters."""
        await self.ensure_table()
        pool = await self._get_pool()

        clauses: list[str] = []
        params: list[object] = []
        idx = 1

        if session_id:
            clauses.append(f"session_id = ${idx}")
            params.append(session_id)
            idx += 1
        if action_type:
            clauses.append(f"action_type = ${idx}")
            params.append(action_type)
            idx += 1
        if risk_level:
            clauses.append(f"risk_level = ${idx}")
            params.append(risk_level.upper())
            idx += 1
        if result_status:
            clauses.append(f"result_status = ${idx}")
            params.append(result_status)
            idx += 1

        query = "SELECT COUNT(*) FROM audit_log"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        async with pool.acquire() as conn:
            row = await conn.fetchval(query, *params)

        return int(row) if row else 0

    def subscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Register a callback to receive new audit entries."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[dict[str, Any]], Any]) -> None:
        """Remove a previously registered callback."""
        with contextlib.suppress(ValueError):
            self._subscribers.remove(callback)

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
