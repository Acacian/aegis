"""Tests for the Redis audit logger.

Uses mocked Redis client so tests run without a real Redis server.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("redis", reason="redis not installed")

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


class FakeRedis:
    """Minimal in-memory fake of redis.Redis for testing."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._hashes: dict[str, dict[str, str]] = defaultdict(dict)
        self._zsets: dict[str, dict[str, float]] = defaultdict(dict)
        self._counters: dict[str, int] = defaultdict(int)
        self._published: list[tuple[str, str]] = []

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

    def scan(self, cursor: int = 0, match: str = "*", count: int = 100) -> tuple[int, list[str]]:
        import fnmatch

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

    def close(self) -> None:
        pass


class FakePipeline:
    """Fake pipeline that executes commands immediately."""

    def __init__(self, client: FakeRedis) -> None:
        self._client = client
        self._results: list[Any] = []
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


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture()
def logger(fake_redis: FakeRedis) -> Any:
    with patch("redis.Redis.from_url", return_value=fake_redis):
        from aegis.runtime.audit_redis import RedisAuditLogger

        return RedisAuditLogger(redis_url="redis://fake:6379/0")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRedisAuditLog:
    def test_log_returns_incrementing_ids(self, logger: Any) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS, data={"k": "v"})
        id1 = logger.log("s1", decision, result=result)
        id2 = logger.log("s1", decision, result=result)
        assert id1 == 1
        assert id2 == 2

    def test_log_and_get_log(self, logger: Any) -> None:
        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("session-1", decision, result=result)

        entries = logger.get_log(session_id="session-1")
        assert len(entries) == 1
        assert entries[0]["session_id"] == "session-1"
        assert entries[0]["action_type"] == "read"
        assert entries[0]["result_status"] == "success"

    def test_get_log_filters_by_session(self, logger: Any) -> None:
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

    def test_get_log_filter_by_action_type(self, logger: Any) -> None:
        d1 = _make_decision("read")
        d2 = _make_decision("write")

        logger.log("s", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        logger.log("s", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))

        entries = logger.get_log(session_id="s", action_type="write")
        assert len(entries) == 1
        assert entries[0]["action_type"] == "write"

    def test_get_log_filter_by_risk_level(self, logger: Any) -> None:
        d_low = _make_decision("read", risk=RiskLevel.LOW)
        d_high = _make_decision("delete", risk=RiskLevel.HIGH)

        logger.log("s", d_low)
        logger.log("s", d_high)

        entries = logger.get_log(session_id="s", risk_level="HIGH")
        assert len(entries) == 1
        assert entries[0]["risk_level"] == "HIGH"

    def test_get_log_with_limit(self, logger: Any) -> None:
        decision = _make_decision()
        for _ in range(5):
            logger.log("s", decision)

        entries = logger.get_log(session_id="s", limit=3)
        assert len(entries) == 3

    def test_log_without_result(self, logger: Any) -> None:
        decision = _make_decision("delete", risk=RiskLevel.CRITICAL)
        logger.log("s1", decision, human_decision="blocked")

        entries = logger.get_log(session_id="s1")
        assert len(entries) == 1
        assert entries[0]["result_status"] is None
        assert entries[0]["human_decision"] == "blocked"

    def test_log_with_human_decision(self, logger: Any) -> None:
        decision = _make_decision("write", risk=RiskLevel.MEDIUM)
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("s1", decision, result=result, human_decision="approved")

        entries = logger.get_log(session_id="s1")
        assert entries[0]["human_decision"] == "approved"


class TestRedisAuditCount:
    def test_count_all(self, logger: Any) -> None:
        d = _make_decision()
        logger.log("s1", d)
        logger.log("s2", d)
        logger.log("s3", d)

        assert logger.count() == 3

    def test_count_with_session_filter(self, logger: Any) -> None:
        d = _make_decision()
        logger.log("s1", d)
        logger.log("s1", d)
        logger.log("s2", d)

        assert logger.count(session_id="s1") == 2

    def test_count_with_action_type_filter(self, logger: Any) -> None:
        d_read = _make_decision("read")
        d_write = _make_decision("write")

        logger.log("s", d_read)
        logger.log("s", d_write)
        logger.log("s", d_write)

        assert logger.count(action_type="write") == 2


class TestRedisAuditSubscription:
    def test_subscribe_notifies(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        logger.subscribe(lambda entry: received.append(entry))

        decision = _make_decision()
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("s1", decision, result=result)

        assert len(received) == 1
        assert received[0]["action_type"] == "read"
        assert received[0]["risk_level"] == "LOW"

    def test_unsubscribe_stops_notifications(self, logger: Any) -> None:
        received: list[dict[str, Any]] = []
        cb = lambda entry: received.append(entry)  # noqa: E731
        logger.subscribe(cb)

        decision = _make_decision()
        logger.log("s1", decision)
        assert len(received) == 1

        logger.unsubscribe(cb)
        logger.log("s2", decision)
        assert len(received) == 1  # no new notification

    def test_subscriber_exception_does_not_break_log(self, logger: Any) -> None:
        def bad_cb(entry: dict[str, Any]) -> None:
            raise RuntimeError("boom")

        logger.subscribe(bad_cb)
        decision = _make_decision()
        # Should not raise
        row_id = logger.log("s1", decision)
        assert row_id == 1


class TestRedisAuditPubSub:
    def test_log_publishes_to_channel(self, logger: Any, fake_redis: FakeRedis) -> None:
        decision = _make_decision()
        logger.log("s1", decision)

        assert len(fake_redis._published) == 1
        channel, message = fake_redis._published[0]
        assert "aegis:audit:notifications" in channel
        parsed = json.loads(message)
        assert parsed["session_id"] == "s1"


class TestRedisAuditClose:
    def test_close_does_not_raise(self, logger: Any) -> None:
        logger.close()
