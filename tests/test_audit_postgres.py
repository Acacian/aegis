"""Tests for the PostgreSQL async audit logger.

Uses mocked asyncpg so tests run without a real PostgreSQL server.
The asyncpg import is lazy (inside _get_pool), so we bypass it by
injecting a fake pool directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

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
    *,
    agent_id: str | None = None,
    parent_agent_id: str | None = None,
    chain_id: str | None = None,
    chain_depth: int = 0,
    description: str | None = None,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(
            action_type,
            target,
            agent_id=agent_id,
            parent_agent_id=parent_agent_id,
            chain_id=chain_id,
            chain_depth=chain_depth,
            description=description,
        ),
        risk_level=risk,
        approval=approval,
        matched_rule="test_rule",
    )


class FakeRecord(dict):
    """Behaves like an asyncpg Record: dict-like access."""

    pass


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

        query_upper = query.upper()
        if "WHERE" not in query_upper:
            if "LIMIT" in query_upper:
                limit_val = int(args[-1]) if args else len(results)
                return results[:limit_val]
            return results

        where_part = query.split("WHERE", 1)[1].split("ORDER BY")[0].strip()
        conditions = [c.strip() for c in where_part.split("AND")]

        param_idx = 0
        filtered = results

        for cond in conditions:
            if "LIMIT" in cond.upper():
                continue
            if ">=" in cond:
                col_part = cond.split(">=")[0].strip()
                if param_idx < len(args):
                    val = args[param_idx]
                    param_idx += 1
                    filtered = [r for r in filtered if r.get(col_part, "") >= val]
                continue
            if "<=" in cond:
                col_part = cond.split("<=")[0].strip()
                if param_idx < len(args):
                    val = args[param_idx]
                    param_idx += 1
                    filtered = [r for r in filtered if r.get(col_part, "") <= val]
                continue
            if "=" not in cond:
                continue
            col_part = cond.split("=")[0].strip()
            if param_idx < len(args):
                val = args[param_idx]
                param_idx += 1
                filtered = [r for r in filtered if r.get(col_part) == val]

        if "LIMIT" in query_upper:
            limit_val = int(args[-1]) if args and isinstance(args[-1], int) else len(filtered)
            filtered = filtered[:limit_val]

        return filtered


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
        return [FakeRecord(r) for r in self._store.filter(query, args)]

    async def fetchval(self, query: str, *args: Any) -> int:
        rows = self._store.filter(query, args)
        return len(rows)


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
# Tests — logging
# ---------------------------------------------------------------------------


class TestPostgresAuditLog:
    async def test_log_returns_incrementing_ids(self, logger: Any) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS, data={"k": "v"})
        id1 = await logger.log("s1", decision, result=result)
        id2 = await logger.log("s1", decision, result=result)
        assert id1 == 1
        assert id2 == 2

    async def test_log_and_get_log(self, logger: Any) -> None:
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

    async def test_log_with_result_data(self, logger: Any) -> None:
        decision = _make_decision()
        result = Result(
            action=decision.action,
            status=ResultStatus.SUCCESS,
            data={"records": [1, 2, 3]},
        )
        row_id = await logger.log("s1", decision, result=result)
        assert row_id == 1

    async def test_log_with_result_error(self, logger: Any) -> None:
        decision = _make_decision("write")
        result = Result(
            action=decision.action,
            status=ResultStatus.FAILED,
            error="Connection timeout",
        )
        row_id = await logger.log("s1", decision, result=result)
        assert row_id == 1

    async def test_log_with_agent_metadata(self, logger: Any) -> None:
        decision = _make_decision(
            "read",
            agent_id="agent-1",
            parent_agent_id="parent-1",
            chain_id="chain-abc",
            chain_depth=2,
        )
        row_id = await logger.log("s1", decision)
        assert row_id == 1

        entries = await logger.get_log(session_id="s1")
        assert entries[0]["agent_id"] == "agent-1"
        assert entries[0]["parent_agent_id"] == "parent-1"
        assert entries[0]["chain_id"] == "chain-abc"
        assert entries[0]["chain_depth"] == 2

    async def test_log_with_action_description(self, logger: Any) -> None:
        decision = _make_decision("write", description="Update customer record")
        row_id = await logger.log("s1", decision)
        assert row_id == 1

        entries = await logger.get_log(session_id="s1")
        assert entries[0]["action_desc"] == "Update customer record"

    async def test_log_without_description_stores_none(self, logger: Any) -> None:
        decision = _make_decision("read")
        await logger.log("s1", decision)

        entries = await logger.get_log(session_id="s1")
        assert entries[0]["action_desc"] is None


# ---------------------------------------------------------------------------
# Tests — get_log filtering
# ---------------------------------------------------------------------------


class TestPostgresGetLog:
    async def test_filter_by_action_type(self, logger: Any) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write")

        await logger.log("s1", d1)
        await logger.log("s1", d2)

        entries = await logger.get_log(action_type="write")
        assert len(entries) == 1
        assert entries[0]["action_type"] == "write"

    async def test_filter_by_risk_level(self, logger: Any) -> None:
        d_low = _make_decision("read", risk=RiskLevel.LOW)
        d_high = _make_decision("delete", risk=RiskLevel.HIGH)

        await logger.log("s1", d_low)
        await logger.log("s1", d_high)

        entries = await logger.get_log(risk_level="HIGH")
        assert len(entries) == 1
        assert entries[0]["risk_level"] == "HIGH"

    async def test_filter_by_result_status(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
        await logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.FAILED))

        entries = await logger.get_log(result_status="failed")
        assert len(entries) == 1
        assert entries[0]["result_status"] == "failed"

    async def test_filter_by_agent_id(self, logger: Any) -> None:
        d1 = _make_decision("read", agent_id="a1")
        d2 = _make_decision("write", agent_id="a2")

        await logger.log("s1", d1)
        await logger.log("s1", d2)

        entries = await logger.get_log(agent_id="a1")
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "a1"

    async def test_filter_by_chain_id(self, logger: Any) -> None:
        d1 = _make_decision("read", chain_id="ch-1")
        d2 = _make_decision("write", chain_id="ch-2")

        await logger.log("s1", d1)
        await logger.log("s1", d2)

        entries = await logger.get_log(chain_id="ch-1")
        assert len(entries) == 1
        assert entries[0]["chain_id"] == "ch-1"

    async def test_get_log_with_limit(self, logger: Any) -> None:
        d = _make_decision()
        for _ in range(5):
            await logger.log("s1", d)

        entries = await logger.get_log(limit=3)
        assert len(entries) == 3

    async def test_get_log_with_since_filter(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d)

        since = datetime.now(UTC) - timedelta(hours=1)
        entries = await logger.get_log(since=since)
        # Our fake store doesn't deeply filter by timestamp in WHERE,
        # but this exercises the parameter-building code path
        assert isinstance(entries, list)

    async def test_get_log_with_until_filter(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d)

        until = datetime.now(UTC) + timedelta(hours=1)
        entries = await logger.get_log(until=until)
        assert isinstance(entries, list)

    async def test_get_log_combined_filters(self, logger: Any) -> None:
        d1 = _make_decision("read", risk=RiskLevel.LOW)
        d2 = _make_decision("write", risk=RiskLevel.HIGH)
        d3 = _make_decision("read", risk=RiskLevel.HIGH)

        await logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        await logger.log("s2", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))
        await logger.log("s1", d3, result=Result(action=d3.action, status=ResultStatus.FAILED))

        entries = await logger.get_log(
            session_id="s1",
            action_type="read",
            risk_level="HIGH",
        )
        assert len(entries) == 1
        assert entries[0]["risk_level"] == "HIGH"
        assert entries[0]["action_type"] == "read"


# ---------------------------------------------------------------------------
# Tests — count
# ---------------------------------------------------------------------------


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

    async def test_count_with_action_type_filter(self, logger: Any) -> None:
        d_read = _make_decision("read")
        d_write = _make_decision("write")

        await logger.log("s1", d_read)
        await logger.log("s1", d_write)
        await logger.log("s1", d_write)

        assert await logger.count(action_type="write") == 2

    async def test_count_with_risk_level_filter(self, logger: Any) -> None:
        d_low = _make_decision("read", risk=RiskLevel.LOW)
        d_high = _make_decision("delete", risk=RiskLevel.HIGH)

        await logger.log("s1", d_low)
        await logger.log("s1", d_high)

        assert await logger.count(risk_level="HIGH") == 1

    async def test_count_with_result_status_filter(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
        await logger.log("s1", d, result=Result(action=d.action, status=ResultStatus.FAILED))

        assert await logger.count(result_status="success") == 1

    async def test_count_no_matches(self, logger: Any) -> None:
        d = _make_decision()
        await logger.log("s1", d)

        assert await logger.count(session_id="nonexistent") == 0


# ---------------------------------------------------------------------------
# Tests — subscribe / unsubscribe
# ---------------------------------------------------------------------------


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
        assert received[0]["session_id"] == "s1"
        assert received[0]["approval"] == "auto"
        assert received[0]["matched_rule"] == "test_rule"

    async def test_subscribe_includes_result_status(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.FAILED)
        await logger.log("s1", decision, result=result)

        assert received[0]["result_status"] == "failed"

    async def test_subscribe_without_result(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        await logger.log("s1", decision)

        assert received[0]["result_status"] is None

    async def test_subscribe_with_agent_id(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision(agent_id="agent-x")
        await logger.log("s1", decision)

        assert received[0]["agent_id"] == "agent-x"

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

    async def test_unsubscribe_nonexistent_callback_is_safe(self, logger: Any) -> None:
        def some_cb(entry: dict[str, Any]) -> None:
            pass

        # Should not raise even though never subscribed
        logger.unsubscribe(some_cb)

    async def test_subscriber_exception_does_not_break_log(self, logger: Any) -> None:
        def bad_cb(entry: dict[str, Any]) -> None:
            raise RuntimeError("boom")

        logger.subscribe(bad_cb)
        decision = _make_decision()
        row_id = await logger.log("s1", decision)
        assert row_id == 1

    async def test_multiple_subscribers(self, logger: Any) -> None:
        received_a: list[dict[str, Any]] = []
        received_b: list[dict[str, Any]] = []
        logger.subscribe(lambda e: received_a.append(e))
        logger.subscribe(lambda e: received_b.append(e))

        decision = _make_decision()
        await logger.log("s1", decision)

        assert len(received_a) == 1
        assert len(received_b) == 1


# ---------------------------------------------------------------------------
# Tests — close
# ---------------------------------------------------------------------------


class TestPostgresAuditClose:
    async def test_close_closes_pool(self, logger: Any) -> None:
        await logger.ensure_table()
        pool = logger._pool
        await logger.close()
        assert pool._closed is True
        assert logger._pool is None

    async def test_close_without_pool(self) -> None:
        from aegis.runtime.audit_postgres import PostgresAuditLogger

        pg = PostgresAuditLogger(dsn="postgresql://fake/aegis")
        # Pool never created — should not raise
        await pg.close()
        assert pg._pool is None


# ---------------------------------------------------------------------------
# Tests — ensure_table
# ---------------------------------------------------------------------------


class TestPostgresEnsureTable:
    async def test_ensure_table_idempotent(self, logger: Any) -> None:
        await logger.ensure_table()
        await logger.ensure_table()  # second call is a no-op
        assert logger._table_created is True

    async def test_ensure_table_sets_flag(self, logger: Any) -> None:
        assert logger._table_created is False
        await logger.ensure_table()
        assert logger._table_created is True


# ---------------------------------------------------------------------------
# Tests — constructor
# ---------------------------------------------------------------------------


class TestPostgresConstructor:
    def test_default_dsn(self) -> None:
        from aegis.runtime.audit_postgres import PostgresAuditLogger

        pg = PostgresAuditLogger()
        assert pg._dsn == "postgresql://localhost/aegis"
        assert pg._min_pool_size == 2
        assert pg._max_pool_size == 10
        assert pg._pool is None
        assert pg._table_created is False
        assert pg._subscribers == []

    def test_custom_pool_sizes(self) -> None:
        from aegis.runtime.audit_postgres import PostgresAuditLogger

        pg = PostgresAuditLogger(
            dsn="postgresql://custom/db",
            min_pool_size=5,
            max_pool_size=20,
        )
        assert pg._dsn == "postgresql://custom/db"
        assert pg._min_pool_size == 5
        assert pg._max_pool_size == 20


# ---------------------------------------------------------------------------
# Tests — _get_pool (lazy pool creation)
# ---------------------------------------------------------------------------


class TestPostgresGetPool:
    async def test_get_pool_creates_pool_via_asyncpg(self) -> None:
        """Test that _get_pool calls asyncpg.create_pool with correct args."""
        import sys
        from unittest.mock import AsyncMock, MagicMock

        # Create a fake asyncpg module
        fake_asyncpg = MagicMock()
        fake_pool = MagicMock()
        fake_asyncpg.create_pool = AsyncMock(return_value=fake_pool)

        # Temporarily inject fake asyncpg into sys.modules
        old = sys.modules.get("asyncpg")
        sys.modules["asyncpg"] = fake_asyncpg
        try:
            from aegis.runtime.audit_postgres import PostgresAuditLogger

            pg = PostgresAuditLogger(
                dsn="postgresql://test/db",
                min_pool_size=3,
                max_pool_size=15,
            )
            pool = await pg._get_pool()

            assert pool is fake_pool
            fake_asyncpg.create_pool.assert_awaited_once_with(
                "postgresql://test/db",
                min_size=3,
                max_size=15,
            )

            # Second call returns cached pool
            pool2 = await pg._get_pool()
            assert pool2 is fake_pool
            # create_pool should still have been called only once
            assert fake_asyncpg.create_pool.await_count == 1
        finally:
            if old is not None:
                sys.modules["asyncpg"] = old
            else:
                sys.modules.pop("asyncpg", None)
