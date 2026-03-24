"""Tests for the Redis-backed distributed rate limiter.

Uses a mocked Redis client so tests run without a real Redis server.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from unittest.mock import patch

import pytest

pytest.importorskip("redis", reason="redis not installed")

from aegis.core.action import Action
from aegis.core.rate_limiter import RateLimitRule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action(type_: str = "write", target: str = "crm") -> Action:
    return Action(type=type_, target=target)


def _write_rule(
    name: str = "write_limit",
    max_requests: int = 3,
    window: float = 60.0,
    action: str = "block",
    **kw: object,
) -> RateLimitRule:
    return RateLimitRule(
        name=name,
        match_type="write*",
        max_requests=max_requests,
        window_seconds=window,
        action_on_limit=action,
        **kw,  # type: ignore[arg-type]
    )


class FakeRedis:
    """Minimal in-memory fake of redis.Redis for rate limiter testing."""

    def __init__(self) -> None:
        self._zsets: dict[str, dict[str, float]] = defaultdict(dict)
        self._counters: dict[str, int] = defaultdict(int)

    def incr(self, key: str) -> int:
        self._counters[key] += 1
        return self._counters[key]

    def zadd(self, name: str, mapping: dict[str, float]) -> int:
        self._zsets[name].update(mapping)
        return len(mapping)

    def zremrangebyscore(self, name: str, min_score: Any, max_score: Any) -> int:
        zset = self._zsets.get(name, {})
        to_remove = []
        for member, score in zset.items():
            rm_low = True if min_score == "-inf" else score >= float(min_score)
            rm_high = True if max_score == "+inf" else score <= float(max_score)
            if rm_low and rm_high:
                to_remove.append(member)
        for m in to_remove:
            del zset[m]
        return len(to_remove)

    def zcard(self, name: str) -> int:
        return len(self._zsets.get(name, {}))

    def zrange(self, name: str, start: int, end: int, withscores: bool = False) -> list[Any]:
        zset = self._zsets.get(name, {})
        items = sorted(zset.items(), key=lambda x: x[1])
        # Handle end=-1 as "to the end"
        end = len(items) + end + 1 if end < 0 else end + 1
        sliced = items[start:end]
        if withscores:
            return sliced
        return [m for m, _ in sliced]

    def expire(self, name: str, seconds: int) -> bool:
        return True

    def delete(self, *names: str) -> int:
        count = 0
        for name in names:
            if name in self._zsets:
                del self._zsets[name]
                count += 1
            if name in self._counters:
                del self._counters[name]
                count += 1
        return count

    def scan(self, cursor: int = 0, match: str = "*", count: int = 100) -> tuple[int, list[str]]:
        import fnmatch

        all_keys: list[str] = []
        for k in list(self._zsets.keys()) + list(self._counters.keys()):
            if fnmatch.fnmatch(k, match) and k not in all_keys:
                all_keys.append(k)
        return (0, all_keys)

    def pipeline(self) -> FakePipeline:
        return FakePipeline(self)

    def close(self) -> None:
        pass


class FakePipeline:
    """Fake pipeline that records commands and executes them on execute()."""

    def __init__(self, client: FakeRedis) -> None:
        self._client = client
        self._commands: list[tuple[str, tuple[Any, ...]]] = []

    def zremrangebyscore(self, name: str, min_s: Any, max_s: Any) -> FakePipeline:
        self._commands.append(("zremrangebyscore", (name, min_s, max_s)))
        return self

    def zadd(self, name: str, mapping: dict[str, float]) -> FakePipeline:
        self._commands.append(("zadd", (name, mapping)))
        return self

    def zcard(self, name: str) -> FakePipeline:
        self._commands.append(("zcard", (name,)))
        return self

    def expire(self, name: str, seconds: int) -> FakePipeline:
        self._commands.append(("expire", (name, seconds)))
        return self

    def execute(self) -> list[Any]:
        results: list[Any] = []
        for cmd, args in self._commands:
            if cmd == "zremrangebyscore":
                results.append(self._client.zremrangebyscore(*args))
            elif cmd == "zadd":
                results.append(self._client.zadd(*args))
            elif cmd == "zcard":
                results.append(self._client.zcard(*args))
            elif cmd == "expire":
                results.append(self._client.expire(*args))
        self._commands.clear()
        return results


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_redis() -> FakeRedis:
    return FakeRedis()


@pytest.fixture()
def limiter(fake_redis: FakeRedis) -> Any:
    with patch("redis.Redis.from_url", return_value=fake_redis):
        from aegis.core.rate_limiter_redis import RedisRateLimiter

        return RedisRateLimiter(
            redis_url="redis://fake:6379/0",
            rules=[_write_rule(max_requests=3)],
        )


# ---------------------------------------------------------------------------
# Basic limiting
# ---------------------------------------------------------------------------


class TestBasicLimiting:
    def test_under_limit(self, limiter: Any) -> None:
        for _ in range(3):
            res = limiter.record(_action(), "a1")
            assert res.allowed is True
            assert res.action == "allowed"

    def test_over_limit(self, limiter: Any) -> None:
        for _ in range(3):
            limiter.record(_action(), "a1")
        res = limiter.record(_action(), "a1")
        assert res.allowed is False
        assert res.action == "blocked"
        assert res.current_count == 4
        assert res.max_requests == 3

    def test_no_matching_rule(self, limiter: Any) -> None:
        res = limiter.record(_action("read"), "a1")
        assert res.allowed is True
        assert res.rule_name is None

    def test_check_does_not_record(self, limiter: Any) -> None:
        limiter.check(_action(), "a1")
        limiter.check(_action(), "a1")
        res = limiter.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 1


# ---------------------------------------------------------------------------
# Action modes
# ---------------------------------------------------------------------------


class TestActionModes:
    def test_block_denies(self, fake_redis: FakeRedis) -> None:
        with patch("redis.Redis.from_url", return_value=fake_redis):
            from aegis.core.rate_limiter_redis import RedisRateLimiter

            rl = RedisRateLimiter(rules=[_write_rule(max_requests=1, action="block")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is False
        assert res.action == "blocked"

    def test_throttle_denies(self, fake_redis: FakeRedis) -> None:
        with patch("redis.Redis.from_url", return_value=fake_redis):
            from aegis.core.rate_limiter_redis import RedisRateLimiter

            rl = RedisRateLimiter(rules=[_write_rule(max_requests=1, action="throttle")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is False
        assert res.action == "throttled"

    def test_warn_allows(self, fake_redis: FakeRedis) -> None:
        with patch("redis.Redis.from_url", return_value=fake_redis):
            from aegis.core.rate_limiter_redis import RedisRateLimiter

            rl = RedisRateLimiter(rules=[_write_rule(max_requests=1, action="warn")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.action == "warned"


# ---------------------------------------------------------------------------
# Per-agent vs global
# ---------------------------------------------------------------------------


class TestPerAgentVsGlobal:
    def test_per_agent_independent(self, limiter: Any) -> None:
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        # Agent a2 is independent
        res = limiter.record(_action(), "a2")
        assert res.allowed is True
        assert res.current_count == 1

    def test_global_shared(self, fake_redis: FakeRedis) -> None:
        rule = RateLimitRule(
            name="global_limit",
            match_type="write*",
            max_requests=3,
            window_seconds=60.0,
            per_agent=False,
            action_on_limit="block",
        )
        with patch("redis.Redis.from_url", return_value=fake_redis):
            from aegis.core.rate_limiter_redis import RedisRateLimiter

            rl = RedisRateLimiter(rules=[rule])
        rl.record(_action(), "a1")
        rl.record(_action(), "a2")
        rl.record(_action(), "a3")
        res = rl.record(_action(), "a4")
        assert res.allowed is False
        assert res.action == "blocked"


# ---------------------------------------------------------------------------
# add_rule
# ---------------------------------------------------------------------------


class TestAddRule:
    def test_add_rule(self, limiter: Any) -> None:
        new_rule = RateLimitRule(
            name="delete_limit",
            match_type="delete*",
            max_requests=1,
            window_seconds=60.0,
        )
        limiter.add_rule(new_rule)
        limiter.record(_action("delete_row"), "a1")
        res = limiter.record(_action("delete_row"), "a1")
        assert res.allowed is False
        assert res.rule_name == "delete_limit"


# ---------------------------------------------------------------------------
# get_usage
# ---------------------------------------------------------------------------


class TestGetUsage:
    def test_usage_for_agent(self, limiter: Any) -> None:
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        usage = limiter.get_usage("a1")
        assert len(usage) == 1
        key = next(iter(usage))
        info = usage[key]
        assert info["current_count"] == 2  # type: ignore[index]
        assert info["rule_name"] == "write_limit"  # type: ignore[index]

    def test_usage_empty(self, limiter: Any) -> None:
        usage = limiter.get_usage("nobody")
        # Either empty or has zero count
        for v in usage.values():
            assert v["current_count"] == 0  # type: ignore[index]


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_single_agent(self, limiter: Any) -> None:
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        limiter.reset("a1")
        res = limiter.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 1

    def test_reset_all(self, limiter: Any) -> None:
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        limiter.record(_action(), "a1")
        limiter.reset()
        res = limiter.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 1


# ---------------------------------------------------------------------------
# retry_after
# ---------------------------------------------------------------------------


class TestRetryAfter:
    def test_retry_after_present_when_blocked(self, limiter: Any) -> None:
        for _ in range(3):
            limiter.record(_action(), "a1")
        res = limiter.record(_action(), "a1")
        assert res.retry_after_seconds is not None
        assert res.retry_after_seconds >= 0.0

    def test_retry_after_none_when_under_limit(self, limiter: Any) -> None:
        res = limiter.record(_action(), "a1")
        assert res.retry_after_seconds is None


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_does_not_raise(self, limiter: Any) -> None:
        limiter.close()
