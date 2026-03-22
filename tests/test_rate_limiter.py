"""Tests for the Rate Limiter engine."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.action import Action
from aegis.core.rate_limiter import (
    RateLimiter,
    RateLimitResult,
    RateLimitRule,
    from_policy_dict,
)

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


# ---------------------------------------------------------------------------
# RateLimitRule dataclass
# ---------------------------------------------------------------------------


class TestRateLimitRule:
    def test_defaults(self) -> None:
        r = RateLimitRule(name="r", match_type="*")
        assert r.match_target == "*"
        assert r.per_agent is True
        assert r.action_on_limit == "block"
        assert r.max_requests == 100
        assert r.window_seconds == 60.0

    def test_invalid_action_on_limit(self) -> None:
        with pytest.raises(ValueError, match="action_on_limit"):
            RateLimitRule(name="r", match_type="*", action_on_limit="explode")

    def test_negative_max_requests(self) -> None:
        with pytest.raises(ValueError, match="max_requests"):
            RateLimitRule(name="r", match_type="*", max_requests=-1)

    def test_zero_window(self) -> None:
        with pytest.raises(ValueError, match="window_seconds"):
            RateLimitRule(name="r", match_type="*", window_seconds=0)

    def test_matches_type_glob(self) -> None:
        r = RateLimitRule(name="r", match_type="write*")
        assert r.matches(_action("write_file"))
        assert r.matches(_action("write"))
        assert not r.matches(_action("read"))

    def test_matches_target_glob(self) -> None:
        r = RateLimitRule(name="r", match_type="*", match_target="prod*")
        assert r.matches(_action("write", "production"))
        assert not r.matches(_action("write", "staging"))

    def test_matches_both_type_and_target(self) -> None:
        r = RateLimitRule(name="r", match_type="delete*", match_target="db*")
        assert r.matches(_action("delete_row", "db_users"))
        assert not r.matches(_action("delete_row", "cache"))
        assert not r.matches(_action("read", "db_users"))

    def test_frozen(self) -> None:
        r = RateLimitRule(name="r", match_type="*")
        with pytest.raises(AttributeError):
            r.name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RateLimitResult dataclass
# ---------------------------------------------------------------------------


class TestRateLimitResult:
    def test_defaults(self) -> None:
        r = RateLimitResult(allowed=True)
        assert r.rule_name is None
        assert r.current_count == 0
        assert r.max_requests == 0
        assert r.retry_after_seconds is None
        assert r.action == "allowed"

    def test_frozen(self) -> None:
        r = RateLimitResult(allowed=True)
        with pytest.raises(AttributeError):
            r.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# RateLimiter — basic limiting
# ---------------------------------------------------------------------------


class TestBasicLimiting:
    def test_under_limit(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=5)])
        for _ in range(5):
            res = rl.record(_action(), "a1")
            assert res.allowed is True
            assert res.action == "allowed"

    def test_at_limit(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=3)])
        for _ in range(3):
            res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 3

    def test_over_limit(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=3)])
        for _ in range(3):
            rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is False
        assert res.action == "blocked"
        assert res.current_count == 4
        assert res.max_requests == 3

    def test_no_matching_rule_allows(self) -> None:
        rl = RateLimiter([_write_rule()])
        res = rl.record(_action("read"), "a1")
        assert res.allowed is True
        assert res.rule_name is None

    def test_check_does_not_record(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=2)])
        # Check twice — neither should increment the counter.
        rl.check(_action(), "a1")
        rl.check(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 1


# ---------------------------------------------------------------------------
# Sliding window
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_old_requests_expire(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=2, window=0.1)])
        rl.record(_action(), "a1")
        rl.record(_action(), "a1")
        # Window expires.
        time.sleep(0.15)
        res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 1

    def test_partial_expiry(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=2, window=0.2)])
        rl.record(_action(), "a1")
        time.sleep(0.12)
        rl.record(_action(), "a1")
        # First request expired, second still alive.
        time.sleep(0.12)
        res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 2


# ---------------------------------------------------------------------------
# Per-agent vs global
# ---------------------------------------------------------------------------


class TestPerAgentVsGlobal:
    def test_per_agent_independent(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=2)])
        rl.record(_action(), "a1")
        rl.record(_action(), "a1")
        # Agent a2 is independent.
        res = rl.record(_action(), "a2")
        assert res.allowed is True
        assert res.current_count == 1

    def test_global_shared(self) -> None:
        rule = RateLimitRule(
            name="global_limit",
            match_type="write*",
            max_requests=3,
            window_seconds=60.0,
            per_agent=False,
            action_on_limit="block",
        )
        rl = RateLimiter([rule])
        rl.record(_action(), "a1")
        rl.record(_action(), "a2")
        rl.record(_action(), "a3")
        res = rl.record(_action(), "a4")
        assert res.allowed is False
        assert res.action == "blocked"


# ---------------------------------------------------------------------------
# Glob pattern matching
# ---------------------------------------------------------------------------


class TestGlobPatterns:
    def test_wildcard_type(self) -> None:
        rule = RateLimitRule(name="all", match_type="*", max_requests=1, window_seconds=60)
        rl = RateLimiter([rule])
        rl.record(_action("anything"), "a1")
        res = rl.record(_action("something_else"), "a1")
        assert res.allowed is False

    def test_prefix_type(self) -> None:
        rule = RateLimitRule(name="del", match_type="delete*", max_requests=1, window_seconds=60)
        rl = RateLimiter([rule])
        rl.record(_action("delete_row"), "a1")
        res = rl.record(_action("delete_table"), "a1")
        assert res.allowed is False
        # Non-delete is unaffected.
        res2 = rl.record(_action("read"), "a1")
        assert res2.allowed is True

    def test_target_pattern(self) -> None:
        rule = RateLimitRule(
            name="prod", match_type="*", match_target="prod_*", max_requests=1, window_seconds=60
        )
        rl = RateLimiter([rule])
        rl.record(_action("write", "prod_db"), "a1")
        res = rl.record(_action("write", "prod_cache"), "a1")
        assert res.allowed is False
        # Different target namespace is unaffected.
        res2 = rl.record(_action("write", "dev_db"), "a1")
        assert res2.allowed is True

    def test_question_mark_pattern(self) -> None:
        rule = RateLimitRule(name="qm", match_type="log?", max_requests=1, window_seconds=60)
        rl = RateLimiter([rule])
        rl.record(_action("logs"), "a1")
        res = rl.record(_action("logi"), "a1")
        assert res.allowed is False
        # "logging" has more than one char after "log" → no match.
        res2 = rl.record(_action("logging"), "a1")
        assert res2.allowed is True


# ---------------------------------------------------------------------------
# Multiple rules — first match wins
# ---------------------------------------------------------------------------


class TestMultipleRules:
    def test_first_matching_rule_wins(self) -> None:
        strict = RateLimitRule(
            name="strict_delete",
            match_type="delete*",
            max_requests=1,
            window_seconds=60,
        )
        lenient = RateLimitRule(
            name="lenient_all",
            match_type="*",
            max_requests=100,
            window_seconds=60,
        )
        rl = RateLimiter([strict, lenient])
        rl.record(_action("delete_row"), "a1")
        res = rl.record(_action("delete_row"), "a1")
        assert res.allowed is False
        assert res.rule_name == "strict_delete"

    def test_later_rule_applies_when_first_does_not_match(self) -> None:
        write_rule = RateLimitRule(
            name="w", match_type="write*", max_requests=1, window_seconds=60
        )
        read_rule = RateLimitRule(name="r", match_type="read*", max_requests=2, window_seconds=60)
        rl = RateLimiter([write_rule, read_rule])
        rl.record(_action("read"), "a1")
        rl.record(_action("read"), "a1")
        res = rl.record(_action("read"), "a1")
        assert res.allowed is False
        assert res.rule_name == "r"


# ---------------------------------------------------------------------------
# Action modes: block / throttle / warn
# ---------------------------------------------------------------------------


class TestActionModes:
    def test_block_denies(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1, action="block")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is False
        assert res.action == "blocked"

    def test_throttle_denies_with_label(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1, action="throttle")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is False
        assert res.action == "throttled"

    def test_warn_allows(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1, action="warn")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.action == "warned"

    def test_warn_still_tracks_count(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1, action="warn")])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.current_count == 2
        assert res.max_requests == 1


# ---------------------------------------------------------------------------
# retry_after calculation
# ---------------------------------------------------------------------------


class TestRetryAfter:
    def test_retry_after_present_when_blocked(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1, window=1.0)])
        rl.record(_action(), "a1")
        res = rl.record(_action(), "a1")
        assert res.retry_after_seconds is not None
        assert 0 < res.retry_after_seconds <= 1.0

    def test_retry_after_none_when_under_limit(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=5)])
        res = rl.record(_action(), "a1")
        assert res.retry_after_seconds is None

    def test_retry_after_decreases_over_time(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1, window=0.5)])
        rl.record(_action(), "a1")
        res1 = rl.record(_action(), "a1")
        time.sleep(0.15)
        res2 = rl.check(_action(), "a1")
        assert res2.retry_after_seconds is not None
        assert res1.retry_after_seconds is not None
        assert res2.retry_after_seconds < res1.retry_after_seconds


# ---------------------------------------------------------------------------
# get_usage
# ---------------------------------------------------------------------------


class TestGetUsage:
    def test_usage_for_agent(self) -> None:
        rl = RateLimiter([_write_rule()])
        rl.record(_action(), "a1")
        rl.record(_action(), "a1")
        usage = rl.get_usage("a1")
        assert len(usage) == 1
        key = next(iter(usage))
        info = usage[key]
        assert info["current_count"] == 2  # type: ignore[index]
        assert info["rule_name"] == "write_limit"  # type: ignore[index]

    def test_usage_all(self) -> None:
        rl = RateLimiter([_write_rule()])
        rl.record(_action(), "a1")
        rl.record(_action(), "a2")
        usage = rl.get_usage()
        assert len(usage) == 2

    def test_usage_empty(self) -> None:
        rl = RateLimiter([_write_rule()])
        assert rl.get_usage() == {}

    def test_usage_excludes_other_agent(self) -> None:
        rl = RateLimiter([_write_rule()])
        rl.record(_action(), "a1")
        rl.record(_action(), "a2")
        usage = rl.get_usage("a1")
        assert len(usage) == 1


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_single_agent(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=2)])
        rl.record(_action(), "a1")
        rl.record(_action(), "a1")
        rl.reset("a1")
        res = rl.record(_action(), "a1")
        assert res.allowed is True
        assert res.current_count == 1

    def test_reset_all(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1)])
        rl.record(_action(), "a1")
        rl.record(_action(), "a2")
        rl.reset()
        res1 = rl.record(_action(), "a1")
        res2 = rl.record(_action(), "a2")
        assert res1.allowed is True
        assert res2.allowed is True

    def test_reset_preserves_other_agents(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=2)])
        rl.record(_action(), "a1")
        rl.record(_action(), "a2")
        rl.record(_action(), "a2")
        rl.reset("a1")
        # a2 unaffected.
        res = rl.record(_action(), "a2")
        assert res.allowed is False


# ---------------------------------------------------------------------------
# from_policy_dict
# ---------------------------------------------------------------------------


class TestFromPolicyDict:
    def test_basic_config(self) -> None:
        cfg = {
            "rate_limits": [
                {
                    "name": "write_limit",
                    "match": {"type": "write*"},
                    "max_requests": 10,
                    "window": 30,
                    "action": "block",
                }
            ]
        }
        rl = from_policy_dict(cfg)
        assert len(rl._rules) == 1
        assert rl._rules[0].name == "write_limit"
        assert rl._rules[0].match_type == "write*"
        assert rl._rules[0].max_requests == 10
        assert rl._rules[0].window_seconds == 30.0

    def test_global_rule(self) -> None:
        cfg = {
            "rate_limits": [
                {
                    "name": "global_delete",
                    "match": {"type": "delete*"},
                    "max_requests": 5,
                    "window": 300,
                    "per_agent": False,
                    "action": "block",
                }
            ]
        }
        rl = from_policy_dict(cfg)
        assert rl._rules[0].per_agent is False

    def test_target_in_match(self) -> None:
        cfg = {
            "rate_limits": [
                {
                    "name": "prod_write",
                    "match": {"type": "write*", "target": "production"},
                    "max_requests": 1,
                    "window": 60,
                    "action": "block",
                }
            ]
        }
        rl = from_policy_dict(cfg)
        assert rl._rules[0].match_target == "production"

    def test_multiple_rules(self) -> None:
        cfg = {
            "rate_limits": [
                {
                    "name": "r1",
                    "match": {"type": "a*"},
                    "max_requests": 1,
                    "window": 10,
                    "action": "block",
                },
                {
                    "name": "r2",
                    "match": {"type": "b*"},
                    "max_requests": 2,
                    "window": 20,
                    "action": "warn",
                },
            ]
        }
        rl = from_policy_dict(cfg)
        assert len(rl._rules) == 2
        assert rl._rules[1].action_on_limit == "warn"

    def test_defaults_applied(self) -> None:
        cfg = {"rate_limits": [{"name": "default", "match": {"type": "*"}}]}
        rl = from_policy_dict(cfg)
        assert rl._rules[0].max_requests == 100
        assert rl._rules[0].window_seconds == 60.0
        assert rl._rules[0].action_on_limit == "block"

    def test_empty_config(self) -> None:
        rl = from_policy_dict({})
        assert len(rl._rules) == 0

    def test_functional_integration(self) -> None:
        """Round-trip: config → limiter → record → verify limit."""
        cfg = {
            "rate_limits": [
                {
                    "name": "w",
                    "match": {"type": "write*"},
                    "max_requests": 2,
                    "window": 60,
                    "action": "block",
                }
            ]
        }
        rl = from_policy_dict(cfg)
        rl.record(_action("write_file"), "agent-x")
        rl.record(_action("write_db"), "agent-x")
        res = rl.record(_action("write_log"), "agent-x")
        assert res.allowed is False
        assert res.rule_name == "w"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_records(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1000, window=10.0)])
        errors: list[Exception] = []

        def _worker(agent: str) -> None:
            try:
                for _ in range(100):
                    rl.record(_action(), agent)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(f"a{i}",)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_concurrent_same_agent(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=500, window=10.0)])
        blocked_count = 0
        lock = threading.Lock()
        errors: list[Exception] = []

        def _worker() -> None:
            nonlocal blocked_count
            try:
                for _ in range(100):
                    res = rl.record(_action(), "shared")
                    if not res.allowed:
                        with lock:
                            blocked_count += 1
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # 1000 total records, 500 allowed → 500 blocked
        assert blocked_count == 500

    def test_concurrent_check_and_record(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=100, window=10.0)])
        errors: list[Exception] = []

        def _recorder() -> None:
            try:
                for _ in range(50):
                    rl.record(_action(), "a1")
            except Exception as exc:
                errors.append(exc)

        def _checker() -> None:
            try:
                for _ in range(50):
                    rl.check(_action(), "a1")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_recorder) for _ in range(5)]
        threads += [threading.Thread(target=_checker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# Action model integration
# ---------------------------------------------------------------------------


class TestActionIntegration:
    def test_with_full_action_object(self) -> None:
        rule = RateLimitRule(name="r", match_type="write*", max_requests=1, window_seconds=60)
        rl = RateLimiter([rule])
        action = Action(
            type="write_record",
            target="salesforce",
            params={"id": "123"},
            description="Update contact",
            agent_id="bot-1",
        )
        res = rl.record(action, "bot-1")
        assert res.allowed is True
        res2 = rl.record(action, "bot-1")
        assert res2.allowed is False

    def test_default_agent_id(self) -> None:
        rl = RateLimiter([_write_rule(max_requests=1)])
        rl.record(_action())
        res = rl.record(_action())
        assert res.allowed is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_max_requests_blocks_immediately(self) -> None:
        rule = RateLimitRule(name="zero", match_type="*", max_requests=0, window_seconds=60)
        rl = RateLimiter([rule])
        res = rl.record(_action(), "a1")
        assert res.allowed is False

    def test_empty_rules_allows_everything(self) -> None:
        rl = RateLimiter([])
        res = rl.record(_action(), "a1")
        assert res.allowed is True

    def test_none_rules_allows_everything(self) -> None:
        rl = RateLimiter(None)
        res = rl.record(_action(), "a1")
        assert res.allowed is True
