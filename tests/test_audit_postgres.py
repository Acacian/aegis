"""Tests for the PostgreSQL async audit logger.

Uses mocked asyncpg so tests run without a real PostgreSQL server.
"""

from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("asyncpg", reason="asyncpg not installed")

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_decision(
    action_type: str = "read",
    target: str = "salesforce",
    risk: RiskLevel = RiskLevel.LOW,
    approval: Approval = Approval.AUTO,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=risk,
        approval=approval,
        matched_rule="test_rule",
    )


class FakeRecord(dict[str, Any]):
    """Behaves like an asyncpg Record: dict-like access."""

    pass


class FakeConnection:
    """Fake asyncpg connection supporting context-manager protocol."""

    def __init__(self, store: _FakeStore) -> None:
        self._store = store

    async def execute(self, query: str, *args: Any) -> str:
        return "OK"

    async def fetchrow(self, query: str, *args: Any) -> FakeRecord:
        row_id = self._store.next_id()
        entry: dict[str, Any] = {}
        cols = [
            "id",
            "session_id",
            "timestamp",
            "action_type",
            "action_target",
            "action_params",
            "action_desc",
            "risk_level",
            "approval",
            "matched_rule",
            "human_decision",
            "result_status",
            "result_data",
            "result_error",
            "agent_id",
            "parent_agent_id",
            "chain_id",
            "chain_depth",
        ]
        entry["id"] = row_id
        for i, col in enumerate(cols[1:], start=1):
            entry[col] = args[i - 1] if i - 1 < len(args) else None
        self._store.rows.append(entry)
        return FakeRecord(entry)

    async def fetch(self, query: str, *args: Any) -> list[FakeRecord]:
        # Simple filter: parse WHERE clauses from stored rows
        return [FakeRecord(r) for r in self._store.filter(query, args)]

    async def fetchval(self, query: str, *args: Any) -> int:
        rows = self._store.filter(query, args)
        return len(rows)


class _FakeStore:
    """Shared row storage for fake connections."""

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._id_seq = 0

    def next_id(self) -> int:
        self._id_seq += 1
        return self._id_seq

    def filter(self, query: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        """Very basic filter implementation for test assertions."""
        results = list(self.rows)

        # Parse simple WHERE clauses from the query
        query_upper = query.upper()
        if "WHERE" not in query_upper:
            if "LIMIT" in query_upper:
                # Extract limit value from the last arg
                limit_val = int(args[-1]) if args else len(results)
                return results[:limit_val]
            return results

        where_part = query.split("WHERE", 1)[1].split("ORDER BY")[0].strip()
        conditions = [c.strip() for c in where_part.split("AND")]

        param_idx = 0
        filtered = results

        for cond in conditions:
            # Handle LIMIT separately
            if "LIMIT" in cond.upper():
                continue

            # Parse "column = $N"
            if "=" not in cond:
                continue
            col_part = cond.split("=")[0].strip()
            if param_idx < len(args):
                val = args[param_idx]
                param_idx += 1
                filtered = [r for r in filtered if r.get(col_part) == val]

        # Handle LIMIT
        if "LIMIT" in query_upper:
            limit_val = int(args[-1]) if args and isinstance(args[-1], int) else len(filtered)
            filtered = filtered[:limit_val]

        return filtered


class FakePool:
    """Fake asyncpg pool with context-manager connection support."""

    def __init__(self, store: _FakeStore) -> None:
        self._store = store
        self._closed = False

    def acquire(self) -> _FakePoolAcquire:
        return _FakePoolAcquire(self._store)

    async def close(self) -> None:
        self._closed = True


class _FakePoolAcquire:
    """Context manager returned by FakePool.acquire()."""

    def __init__(self, store: _FakeStore) -> None:
        self._store = store

    async def __aenter__(self) -> FakeConnection:
        return FakeConnection(self._store)

    async def __aexit__(self, *exc: object) -> None:
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_store() -> _FakeStore:
    return _FakeStore()


@pytest.fixture()
def logger(fake_store: _FakeStore) -> Any:
    from aegis.runtime.audit_postgres import PostgresAuditLogger

    pg = PostgresAuditLogger(dsn="postgresql://fake/aegis")
    # Inject fake pool directly, bypassing asyncpg.create_pool
    pg._pool = FakePool(fake_store)
    return pg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPostgresAuditLog:
    async def test_log_returns_incrementing_ids(self, logger: Any) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS, data={"k": "v"})
        id1 = await logger.log("s1", decision, result=result)
        id2 = await logger.log("s1", decision, result=result)
        assert id1 == 1
        assert id2 == 2

    async def test_log_and_get_log(self, logger: Any, fake_store: _FakeStore) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        await logger.log("session-1", decision, result=result)

        entries = await logger.get_log(session_id="session-1")
        assert len(entries) == 1
        assert entries[0]["session_id"] == "session-1"
        assert entries[0]["action_type"] == "read"
        assert entries[0]["result_status"] == "success"

    async def test_get_log_all_entries(self, logger: Any) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write")

        await logger.log("sa", d1)
        await logger.log("sb", d2)

        entries = await logger.get_log()
        assert len(entries) == 2

    async def test_get_log_filters_by_session(self, logger: Any) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write", risk=RiskLevel.MEDIUM)

        await logger.log("sa", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        await logger.log("sb", d2, result=Result(action=d2.action, status=ResultStatus.DENIED))

        sa = await logger.get_log(session_id="sa")
        assert len(sa) == 1
        assert sa[0]["action_type"] == "read"

    async def test_log_without_result(self, logger: Any) -> None:
        decision = _make_decision("delete", risk=RiskLevel.CRITICAL)
        await logger.log("s1", decision, human_decision="blocked")

        entries = await logger.get_log(session_id="s1")
        assert len(entries) == 1
        assert entries[0]["result_status"] is None
        assert entries[0]["human_decision"] == "blocked"

    async def test_log_with_human_decision(self, logger: Any) -> None:
        decision = _make_decision("write", risk=RiskLevel.MEDIUM)
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        await logger.log("s1", decision, result=result, human_decision="approved")

        entries = await logger.get_log(session_id="s1")
        assert entries[0]["human_decision"] == "approved"


class TestPostgresAuditCount:
    async def test_count_all(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d)
        await logger.log("s2", d)
        await logger.log("s3", d)

        assert await logger.count() == 3

    async def test_count_with_session_filter(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d)
        await logger.log("s1", d)
        await logger.log("s2", d)

        assert await logger.count(session_id="s1") == 2


class TestPostgresAuditSubscription:
    async def test_subscribe_notifies(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        await logger.log("s1", decision, result=result)

        assert len(received) == 1
        assert received[0]["action_type"] == "read"
        assert received[0]["risk_level"] == "LOW"

    async def test_unsubscribe_stops_notifications(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        cb = lambda entry: received.append(entry)  # noqa: E731
        logger.subscribe(cb)

        decision = _make_decision()
        await logger.log("s1", decision)
        assert len(received) == 1

        logger.unsubscribe(cb)
        await logger.log("s2", decision)
        assert len(received) == 1

    async def test_subscriber_exception_does_not_break_log(self, logger: Any) -> None:
        def bad_cb(entry: dict[str, Any]) -> None:
            raise RuntimeError("boom")

        logger.subscribe(bad_cb)
        decision = _make_decision()
        row_id = await logger.log("s1", decision)
        assert row_id == 1


class TestPostgresAuditClose:
    async def test_close_closes_pool(self, logger: Any) -> None:
        # Force pool creation
        await logger.ensure_table()
        pool = logger._pool
        await logger.close()
        assert pool._closed is True
        assert logger._pool is None

    async def test_close_without_pool(self, logger: Any) -> None:
        # Should not raise when pool was never created
        await logger.close()


class TestPostgresEnsureTable:
    async def test_ensure_table_idempotent(self, logger: Any) -> None:
        await logger.ensure_table()
        await logger.ensure_table()  # second call is a no-op
        assert logger._table_created is True
