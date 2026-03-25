"""Tests for the Redis audit logger.

Uses a fake Redis module injected into sys.modules so tests run
without the real ``redis`` package installed.
"""

from __future__ import annotations

import fnmatch
import json
import sys
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from threading import Thread
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis.core.action import Action
from aegis.core.policy import Approval, PolicyDecision
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Fake Redis implementation
# ---------------------------------------------------------------------------


class FakeRedis:
    """Minimal in-memory fake of redis.Redis for testing."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._hashes: dict[str, dict[str, str]] = defaultdict(dict)
        self._zsets: dict[str, dict[str, float]] = defaultdict(dict)
        self._counters: dict[str, int] = defaultdict(int)
        self._published: list[tuple[str, str]] = []

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> FakeRedis:
        return _current_fake_redis

    def incr(self, key: str) -> int:
        self._counters[key] += 1
        return self._counters[key]

    def hset(self, name: str, key: str, value: str) -> int:
        self._hashes[name][key] = value
        return 1

    def hmget(self, name: str, *keys: str) -> list[str | None]:
        h = self._hashes.get(name, {})
        return [h.get(k) for k in keys]

    def zadd(self, name: str, mapping: dict[str, float]) -> int:
        self._zsets[name].update(mapping)
        return len(mapping)

    def zrangebyscore(self, name: str, min_score: Any, max_score: Any) -> list[str]:
        zset = self._zsets.get(name, {})
        results: list[tuple[str, float]] = []
        for member, score in zset.items():
            low_ok = min_score == "-inf" or score >= float(min_score)
            high_ok = max_score == "+inf" or score <= float(max_score)
            if low_ok and high_ok:
                results.append((member, score))
        results.sort(key=lambda x: x[1])
        return [m for m, _ in results]

    def scan(
        self, cursor: int = 0, match: str = "*", count: int = 100
    ) -> tuple[int, list[str]]:
        all_keys: list[str] = []
        for k in self._zsets:
            if fnmatch.fnmatch(k, match):
                all_keys.append(k)
        return (0, all_keys)

    def publish(self, channel: str, message: str) -> int:
        self._published.append((channel, message))
        return 0

    def pipeline(self) -> FakePipeline:
        return FakePipeline(self)

    def pubsub(self) -> FakePubSub:
        return FakePubSub()

    def close(self) -> None:
        pass


class FakePipeline:
    """Fake pipeline that executes commands immediately."""

    def __init__(self, client: FakeRedis) -> None:
        self._client = client
        self._commands: list[tuple[str, tuple[Any, ...]]] = []

    def hset(self, name: str, key: str, value: str) -> FakePipeline:
        self._commands.append(("hset", (name, key, value)))
        return self

    def zadd(self, name: str, mapping: dict[str, float]) -> FakePipeline:
        self._commands.append(("zadd", (name, mapping)))
        return self

    def execute(self) -> list[Any]:
        results: list[Any] = []
        for cmd, args in self._commands:
            if cmd == "hset":
                results.append(self._client.hset(*args))
            elif cmd == "zadd":
                results.append(self._client.zadd(*args))
        self._commands.clear()
        return results


class FakePubSub:
    """Fake PubSub object."""

    def __init__(self) -> None:
        self._subscribed = False
        self._closed = False

    def subscribe(self, **kwargs: Any) -> None:
        self._subscribed = True

    def unsubscribe(self) -> None:
        self._subscribed = False

    def close(self) -> None:
        self._closed = True

    def run_in_thread(self, sleep_time: float = 0.1) -> Thread:
        t = Thread(target=lambda: None, daemon=True)
        t.start()
        return t


# Global reference so from_url can return the right instance
_current_fake_redis: FakeRedis = FakeRedis()


# ---------------------------------------------------------------------------
# Inject fake redis module into sys.modules
# ---------------------------------------------------------------------------

_fake_redis_module = MagicMock()
_fake_redis_module.Redis = FakeRedis

_original_redis = sys.modules.get("redis")
sys.modules["redis"] = _fake_redis_module

from aegis.runtime.audit_redis import RedisAuditLogger  # noqa: E402

# Restore original module (or remove fake) after import
if _original_redis is not None:
    sys.modules["redis"] = _original_redis
else:
    sys.modules.pop("redis", None)


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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_client() -> FakeRedis:
    global _current_fake_redis
    client = FakeRedis()
    _current_fake_redis = client
    return client


@pytest.fixture()
def logger(fake_client: FakeRedis) -> RedisAuditLogger:
    lg = RedisAuditLogger.__new__(RedisAuditLogger)
    lg._client = fake_client
    lg._subscribers = []
    lg._pubsub = None
    lg._pubsub_thread = None
    return lg


# ---------------------------------------------------------------------------
# Tests — log
# ---------------------------------------------------------------------------


class TestRedisAuditLog:
    def test_log_returns_incrementing_ids(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS, data={"k": "v"})
        id1 = logger.log("s1", decision, result=result)
        id2 = logger.log("s1", decision, result=result)
        assert id1 == 1
        assert id2 == 2

    def test_log_and_get_log(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("session-1", decision, result=result)

        entries = logger.get_log(session_id="session-1")
        assert len(entries) == 1
        assert entries[0]["session_id"] == "session-1"
        assert entries[0]["action_type"] == "read"
        assert entries[0]["result_status"] == "success"

    def test_log_without_result(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision("delete", risk=RiskLevel.CRITICAL)
        logger.log("s1", decision, human_decision="blocked")

        entries = logger.get_log(session_id="s1")
        assert len(entries) == 1
        assert entries[0]["result_status"] is None
        assert entries[0]["result_error"] is None
        assert entries[0]["result_data"] is None
        assert entries[0]["human_decision"] == "blocked"

    def test_log_with_human_decision(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision("write", risk=RiskLevel.MEDIUM)
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("s1", decision, result=result, human_decision="approved")

        entries = logger.get_log(session_id="s1")
        assert entries[0]["human_decision"] == "approved"

    def test_log_with_result_data(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        result = Result(
            action=decision.action,
            status=ResultStatus.SUCCESS,
            data={"records": [1, 2, 3]},
        )
        row_id = logger.log("s1", decision, result=result)
        assert row_id == 1

        entries = logger.get_log(session_id="s1")
        assert entries[0]["result_data"] is not None

    def test_log_with_result_error(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision("write")
        result = Result(
            action=decision.action,
            status=ResultStatus.FAILED,
            error="Connection timeout",
        )
        row_id = logger.log("s1", decision, result=result)
        assert row_id == 1

        entries = logger.get_log(session_id="s1")
        assert entries[0]["result_error"] == "Connection timeout"

    def test_log_with_agent_metadata(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision(
            "read",
            agent_id="agent-1",
            parent_agent_id="parent-1",
            chain_id="chain-abc",
            chain_depth=2,
        )
        row_id = logger.log("s1", decision)
        assert row_id == 1

        entries = logger.get_log(session_id="s1")
        assert entries[0]["agent_id"] == "agent-1"
        assert entries[0]["parent_agent_id"] == "parent-1"
        assert entries[0]["chain_id"] == "chain-abc"
        assert entries[0]["chain_depth"] == 2

    def test_log_with_action_description(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision("write", description="Update customer record")
        row_id = logger.log("s1", decision)
        assert row_id == 1

        entries = logger.get_log(session_id="s1")
        assert entries[0]["action_desc"] == "Update customer record"

    def test_log_without_description_stores_none(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision("read")
        logger.log("s1", decision)

        entries = logger.get_log(session_id="s1")
        assert entries[0]["action_desc"] is None

    def test_log_stores_entry_in_hash_and_zset(
        self, logger: RedisAuditLogger, fake_client: FakeRedis
    ) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        # Check hash has the entry
        from aegis.runtime.audit_redis import _ENTRY_HASH

        assert "1" in fake_client._hashes[_ENTRY_HASH]

        # Check zset has the member
        from aegis.runtime.audit_redis import _session_key

        assert "1" in fake_client._zsets[_session_key("s1")]

    def test_log_publishes_to_channel(
        self, logger: RedisAuditLogger, fake_client: FakeRedis
    ) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        assert len(fake_client._published) == 1
        channel, message = fake_client._published[0]
        assert "aegis:audit:notifications" in channel
        parsed = json.loads(message)
        assert parsed["session_id"] == "s1"


# ---------------------------------------------------------------------------
# Tests — get_log filtering
# ---------------------------------------------------------------------------


class TestRedisGetLog:
    def test_get_log_filters_by_session(self, logger: RedisAuditLogger) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write", risk=RiskLevel.MEDIUM)

        logger.log("sa", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        logger.log("sb", d2, result=Result(action=d2.action, status=ResultStatus.DENIED))

        sa = logger.get_log(session_id="sa")
        assert len(sa) == 1
        assert sa[0]["action_type"] == "read"

        sb = logger.get_log(session_id="sb")
        assert len(sb) == 1
        assert sb[0]["result_status"] == "denied"

    def test_get_log_filter_by_action_type(self, logger: RedisAuditLogger) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write")

        logger.log("s", d1)
        logger.log("s", d2)

        entries = logger.get_log(session_id="s", action_type="write")
        assert len(entries) == 1
        assert entries[0]["action_type"] == "write"

    def test_get_log_filter_by_risk_level(self, logger: RedisAuditLogger) -> None:
        d_low = _make_decision("read", risk=RiskLevel.LOW)
        d_high = _make_decision("delete", risk=RiskLevel.HIGH)

        logger.log("s", d_low)
        logger.log("s", d_high)

        entries = logger.get_log(session_id="s", risk_level="HIGH")
        assert len(entries) == 1
        assert entries[0]["risk_level"] == "HIGH"

    def test_get_log_filter_by_result_status(self, logger: RedisAuditLogger) -> None:
        d = _make_decision()
        logger.log("s", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
        logger.log("s", d, result=Result(action=d.action, status=ResultStatus.FAILED))

        entries = logger.get_log(session_id="s", result_status="failed")
        assert len(entries) == 1
        assert entries[0]["result_status"] == "failed"

    def test_get_log_filter_by_agent_id(self, logger: RedisAuditLogger) -> None:
        d1 = _make_decision("read", agent_id="a1")
        d2 = _make_decision("write", agent_id="a2")

        logger.log("s", d1)
        logger.log("s", d2)

        entries = logger.get_log(session_id="s", agent_id="a1")
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "a1"

    def test_get_log_filter_by_chain_id(self, logger: RedisAuditLogger) -> None:
        d1 = _make_decision("read", chain_id="ch-1")
        d2 = _make_decision("write", chain_id="ch-2")

        logger.log("s", d1)
        logger.log("s", d2)

        entries = logger.get_log(session_id="s", chain_id="ch-1")
        assert len(entries) == 1
        assert entries[0]["chain_id"] == "ch-1"

    def test_get_log_with_limit(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        for _ in range(5):
            logger.log("s", decision)

        entries = logger.get_log(session_id="s", limit=3)
        assert len(entries) == 3

    def test_get_log_all_sessions(self, logger: RedisAuditLogger) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write")

        logger.log("sa", d1)
        logger.log("sb", d2)

        # No session_id — should return all entries from all sessions
        entries = logger.get_log()
        assert len(entries) == 2

    def test_get_log_empty_session(self, logger: RedisAuditLogger) -> None:
        entries = logger.get_log(session_id="nonexistent")
        assert entries == []

    def test_get_log_with_since_filter(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        since = datetime.now(UTC) - timedelta(hours=1)
        entries = logger.get_log(session_id="s1", since=since)
        assert len(entries) == 1

    def test_get_log_with_until_filter(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        until = datetime.now(UTC) + timedelta(hours=1)
        entries = logger.get_log(session_id="s1", until=until)
        assert len(entries) == 1

    def test_get_log_since_excludes_old_entries(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        # since is in the future — should exclude all entries
        since = datetime.now(UTC) + timedelta(hours=1)
        entries = logger.get_log(session_id="s1", since=since)
        assert len(entries) == 0

    def test_get_log_until_excludes_future_entries(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        # until is in the past — should exclude all entries
        until = datetime.now(UTC) - timedelta(hours=1)
        entries = logger.get_log(session_id="s1", until=until)
        assert len(entries) == 0

    def test_get_log_combined_filters(self, logger: RedisAuditLogger) -> None:
        d1 = _make_decision("read", risk=RiskLevel.LOW)
        d2 = _make_decision("write", risk=RiskLevel.HIGH)
        d3 = _make_decision("read", risk=RiskLevel.HIGH)

        logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        logger.log("s2", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))
        logger.log("s1", d3, result=Result(action=d3.action, status=ResultStatus.FAILED))

        entries = logger.get_log(
            session_id="s1",
            action_type="read",
            risk_level="HIGH",
        )
        assert len(entries) == 1
        assert entries[0]["risk_level"] == "HIGH"
        assert entries[0]["action_type"] == "read"

    def test_get_log_hmget_returns_none_entries(
        self, logger: RedisAuditLogger, fake_client: FakeRedis
    ) -> None:
        """Test that None entries from hmget are skipped gracefully."""
        decision = _make_decision()
        logger.log("s1", decision)

        # Inject a None value by removing the entry from the hash but keeping zset reference
        from aegis.runtime.audit_redis import _ENTRY_HASH

        fake_client._hashes[_ENTRY_HASH].pop("1", None)

        entries = logger.get_log(session_id="s1")
        assert entries == []


# ---------------------------------------------------------------------------
# Tests — count
# ---------------------------------------------------------------------------


class TestRedisAuditCount:
    def test_count_all(self, logger: RedisAuditLogger) -> None:
        d = _make_decision()
        logger.log("s1", d)
        logger.log("s2", d)
        logger.log("s3", d)

        assert logger.count() == 3

    def test_count_with_session_filter(self, logger: RedisAuditLogger) -> None:
        d = _make_decision()
        logger.log("s1", d)
        logger.log("s1", d)
        logger.log("s2", d)

        assert logger.count(session_id="s1") == 2

    def test_count_with_action_type_filter(self, logger: RedisAuditLogger) -> None:
        d_read = _make_decision("read")
        d_write = _make_decision("write")

        logger.log("s", d_read)
        logger.log("s", d_write)
        logger.log("s", d_write)

        assert logger.count(action_type="write") == 2

    def test_count_with_risk_level_filter(self, logger: RedisAuditLogger) -> None:
        d_low = _make_decision("read", risk=RiskLevel.LOW)
        d_high = _make_decision("delete", risk=RiskLevel.HIGH)

        logger.log("s", d_low)
        logger.log("s", d_high)

        assert logger.count(risk_level="HIGH") == 1

    def test_count_with_result_status_filter(self, logger: RedisAuditLogger) -> None:
        d = _make_decision()
        logger.log("s", d, result=Result(action=d.action, status=ResultStatus.SUCCESS))
        logger.log("s", d, result=Result(action=d.action, status=ResultStatus.FAILED))

        assert logger.count(result_status="success") == 1

    def test_count_no_matches(self, logger: RedisAuditLogger) -> None:
        d = _make_decision()
        logger.log("s1", d)

        assert logger.count(session_id="nonexistent") == 0


# ---------------------------------------------------------------------------
# Tests — subscribe / unsubscribe
# ---------------------------------------------------------------------------


class TestRedisAuditSubscription:
    def test_subscribe_notifies(self, logger: RedisAuditLogger) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("s1", decision, result=result)

        assert len(received) == 1
        assert received[0]["action_type"] == "read"
        assert received[0]["risk_level"] == "LOW"
        assert received[0]["session_id"] == "s1"
        assert received[0]["approval"] == "auto"
        assert received[0]["matched_rule"] == "test_rule"

    def test_subscribe_includes_result_status(self, logger: RedisAuditLogger) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.FAILED)
        logger.log("s1", decision, result=result)

        assert received[0]["result_status"] == "failed"

    def test_subscribe_without_result(self, logger: RedisAuditLogger) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        logger.log("s1", decision)

        assert received[0]["result_status"] is None

    def test_subscribe_with_agent_id(self, logger: RedisAuditLogger) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision(agent_id="agent-x")
        logger.log("s1", decision)

        assert received[0]["agent_id"] == "agent-x"

    def test_unsubscribe_stops_notifications(self, logger: RedisAuditLogger) -> None:
        received: list[dict[str, Any]] = []
        cb = lambda entry: received.append(entry)  # noqa: E731
        logger.subscribe(cb)

        decision = _make_decision()
        logger.log("s1", decision)
        assert len(received) == 1

        logger.unsubscribe(cb)
        logger.log("s2", decision)
        assert len(received) == 1

    def test_unsubscribe_nonexistent_callback_is_safe(
        self, logger: RedisAuditLogger
    ) -> None:
        def some_cb(entry: dict[str, Any]) -> None:
            pass

        # Should not raise even though never subscribed
        logger.unsubscribe(some_cb)

    def test_subscriber_exception_does_not_break_log(
        self, logger: RedisAuditLogger
    ) -> None:
        def bad_cb(entry: dict[str, Any]) -> None:
            raise RuntimeError("boom")

        logger.subscribe(bad_cb)
        decision = _make_decision()
        row_id = logger.log("s1", decision)
        assert row_id == 1

    def test_multiple_subscribers(self, logger: RedisAuditLogger) -> None:
        received_a: list[dict[str, Any]] = []
        received_b: list[dict[str, Any]] = []
        logger.subscribe(lambda e: received_a.append(e))
        logger.subscribe(lambda e: received_b.append(e))

        decision = _make_decision()
        logger.log("s1", decision)

        assert len(received_a) == 1
        assert len(received_b) == 1


# ---------------------------------------------------------------------------
# Tests — close
# ---------------------------------------------------------------------------


class TestRedisAuditClose:
    def test_close_without_pubsub(self, logger: RedisAuditLogger) -> None:
        # _pubsub is None — should not raise
        logger.close()

    def test_close_with_pubsub(self, logger: RedisAuditLogger) -> None:
        fake_ps = FakePubSub()
        logger._pubsub = fake_ps
        fake_thread = Thread(target=lambda: None, daemon=True)
        fake_thread.start()
        fake_thread.join()  # ensure it's done before we set it
        logger._pubsub_thread = fake_thread

        logger.close()

        assert fake_ps._closed is True
        assert logger._pubsub is None
        assert logger._pubsub_thread is None

    def test_close_with_pubsub_no_thread(self, logger: RedisAuditLogger) -> None:
        fake_ps = FakePubSub()
        logger._pubsub = fake_ps
        logger._pubsub_thread = None

        logger.close()

        assert fake_ps._closed is True
        assert logger._pubsub is None


# ---------------------------------------------------------------------------
# Tests — _matches_filters static method
# ---------------------------------------------------------------------------


class TestMatchesFilters:
    def test_no_filters_returns_true(self) -> None:
        entry = {"action_type": "read", "risk_level": "LOW"}
        assert RedisAuditLogger._matches_filters(entry) is True

    def test_action_type_match(self) -> None:
        entry = {"action_type": "read"}
        assert RedisAuditLogger._matches_filters(entry, action_type="read") is True

    def test_action_type_mismatch(self) -> None:
        entry = {"action_type": "read"}
        assert RedisAuditLogger._matches_filters(entry, action_type="write") is False

    def test_risk_level_case_insensitive(self) -> None:
        entry = {"risk_level": "HIGH"}
        assert RedisAuditLogger._matches_filters(entry, risk_level="high") is True

    def test_risk_level_mismatch(self) -> None:
        entry = {"risk_level": "LOW"}
        assert RedisAuditLogger._matches_filters(entry, risk_level="HIGH") is False

    def test_result_status_match(self) -> None:
        entry = {"result_status": "success"}
        assert RedisAuditLogger._matches_filters(entry, result_status="success") is True

    def test_result_status_mismatch(self) -> None:
        entry = {"result_status": "success"}
        assert RedisAuditLogger._matches_filters(entry, result_status="failed") is False

    def test_agent_id_match(self) -> None:
        entry = {"agent_id": "agent-1"}
        assert RedisAuditLogger._matches_filters(entry, agent_id="agent-1") is True

    def test_agent_id_mismatch(self) -> None:
        entry = {"agent_id": "agent-1"}
        assert RedisAuditLogger._matches_filters(entry, agent_id="agent-2") is False

    def test_chain_id_match(self) -> None:
        entry = {"chain_id": "ch-1"}
        assert RedisAuditLogger._matches_filters(entry, chain_id="ch-1") is True

    def test_chain_id_mismatch(self) -> None:
        entry = {"chain_id": "ch-1"}
        assert RedisAuditLogger._matches_filters(entry, chain_id="ch-2") is False

    def test_since_filter(self) -> None:
        now = datetime.now(UTC)
        entry = {"timestamp": now.isoformat()}
        past = now - timedelta(hours=1)
        assert RedisAuditLogger._matches_filters(entry, since=past) is True

    def test_since_filter_excludes(self) -> None:
        now = datetime.now(UTC)
        entry = {"timestamp": now.isoformat()}
        future = now + timedelta(hours=1)
        assert RedisAuditLogger._matches_filters(entry, since=future) is False

    def test_until_filter(self) -> None:
        now = datetime.now(UTC)
        entry = {"timestamp": now.isoformat()}
        future = now + timedelta(hours=1)
        assert RedisAuditLogger._matches_filters(entry, until=future) is True

    def test_until_filter_excludes(self) -> None:
        now = datetime.now(UTC)
        entry = {"timestamp": now.isoformat()}
        past = now - timedelta(hours=1)
        assert RedisAuditLogger._matches_filters(entry, until=past) is False

    def test_no_timestamp_with_time_filters(self) -> None:
        entry = {"action_type": "read"}
        now = datetime.now(UTC)
        # Entry has no timestamp — time filters are skipped
        assert RedisAuditLogger._matches_filters(entry, since=now) is True


# ---------------------------------------------------------------------------
# Tests — _collect_entry_ids
# ---------------------------------------------------------------------------


class TestCollectEntryIds:
    def test_collect_with_session(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        ids = logger._collect_entry_ids("s1", None, None)
        assert ids == ["1"]

    def test_collect_without_session_scans_all(self, logger: RedisAuditLogger) -> None:
        d = _make_decision()
        logger.log("sa", d)
        logger.log("sb", d)

        ids = logger._collect_entry_ids(None, None, None)
        assert len(ids) == 2

    def test_collect_with_since_until(self, logger: RedisAuditLogger) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        now = datetime.now(UTC)
        past = now - timedelta(hours=1)
        future = now + timedelta(hours=1)

        ids = logger._collect_entry_ids("s1", past, future)
        assert len(ids) == 1

    def test_collect_empty(self, logger: RedisAuditLogger) -> None:
        ids = logger._collect_entry_ids("nonexistent", None, None)
        assert ids == []


# ---------------------------------------------------------------------------
# Tests — constructor (__init__)
# ---------------------------------------------------------------------------


class TestRedisAuditConstructor:
    def test_init_via_fake_redis_module(self) -> None:
        """Test __init__ by injecting a fake redis module into sys.modules."""
        fake_client = FakeRedis()

        fake_redis_mod = MagicMock()
        fake_redis_mod.Redis = MagicMock()
        fake_redis_mod.Redis.from_url = MagicMock(return_value=fake_client)

        old = sys.modules.get("redis")
        sys.modules["redis"] = fake_redis_mod
        try:
            lg = RedisAuditLogger(redis_url="redis://test:6379/0")

            fake_redis_mod.Redis.from_url.assert_called_once_with(
                "redis://test:6379/0", decode_responses=True
            )
            assert lg._client is fake_client
            assert lg._subscribers == []
            assert lg._pubsub is None
            assert lg._pubsub_thread is None
        finally:
            if old is not None:
                sys.modules["redis"] = old
            else:
                sys.modules.pop("redis", None)

    def test_init_default_url(self) -> None:
        """Test __init__ with default URL."""
        fake_client = FakeRedis()

        fake_redis_mod = MagicMock()
        fake_redis_mod.Redis = MagicMock()
        fake_redis_mod.Redis.from_url = MagicMock(return_value=fake_client)

        old = sys.modules.get("redis")
        sys.modules["redis"] = fake_redis_mod
        try:
            lg = RedisAuditLogger()

            fake_redis_mod.Redis.from_url.assert_called_once_with(
                "redis://localhost:6379/0", decode_responses=True
            )
            assert lg._client is fake_client
        finally:
            if old is not None:
                sys.modules["redis"] = old
            else:
                sys.modules.pop("redis", None)


# ---------------------------------------------------------------------------
# Tests — helper functions at module level
# ---------------------------------------------------------------------------


class TestModuleHelpers:
    def test_session_key(self) -> None:
        from aegis.runtime.audit_redis import _session_key

        assert _session_key("abc") == "aegis:audit:session:abc"

    def test_all_sessions_pattern(self) -> None:
        from aegis.runtime.audit_redis import _all_sessions_pattern

        assert _all_sessions_pattern() == "aegis:audit:session:*"

    def test_constants(self) -> None:
        from aegis.runtime.audit_redis import (
            _ENTRY_HASH,
            _ID_SEQ,
            _PREFIX,
            _PUBSUB_CHANNEL,
        )

        assert _PREFIX == "aegis:audit"
        assert _ID_SEQ == "aegis:audit:id_seq"
        assert _ENTRY_HASH == "aegis:audit:entries"
        assert _PUBSUB_CHANNEL == "aegis:audit:notifications"
