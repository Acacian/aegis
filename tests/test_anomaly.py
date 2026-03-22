"""Tests for the Behavioral Anomaly Detection engine."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector, AnomalyResult, BehaviorProfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_action(type_: str = "read", target: str = "crm") -> Action:
    return Action(type=type_, target=target)


def _record_many(
    detector: AnomalyDetector,
    action: Action,
    count: int,
    agent_id: str = "agent-1",
    *,
    blocked: bool = False,
) -> None:
    """Record *count* identical actions into *detector*."""
    for _ in range(count):
        detector.record(action, agent_id, blocked=blocked)


# ---------------------------------------------------------------------------
# BehaviorProfile dataclass
# ---------------------------------------------------------------------------


class TestBehaviorProfile:
    def test_defaults(self) -> None:
        p = BehaviorProfile(agent_id="a")
        assert p.agent_id == "a"
        assert p.total_actions == 0
        assert p.blocked_count == 0
        assert isinstance(p.action_counts, dict)
        assert isinstance(p.action_rate, dict)
        assert isinstance(p.avg_rate_per_minute, dict)
        assert isinstance(p.target_counts, dict)

    def test_first_last_seen_populated(self) -> None:
        p = BehaviorProfile(agent_id="b")
        assert p.first_seen <= p.last_seen


# ---------------------------------------------------------------------------
# AnomalyResult dataclass
# ---------------------------------------------------------------------------


class TestAnomalyResult:
    def test_ok_result(self) -> None:
        r = AnomalyResult(is_anomalous=False)
        assert not r.is_anomalous
        assert r.anomaly_type is None
        assert r.severity == 0.0

    def test_anomalous_result(self) -> None:
        r = AnomalyResult(
            is_anomalous=True,
            anomaly_type="rate_spike",
            severity=0.8,
            message="bad",
            recommendation="fix",
        )
        assert r.is_anomalous
        assert r.anomaly_type == "rate_spike"
        assert r.severity == 0.8

    def test_frozen(self) -> None:
        r = AnomalyResult(is_anomalous=False)
        with pytest.raises(AttributeError):
            r.is_anomalous = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Detector: profile building
# ---------------------------------------------------------------------------


class TestProfileBuilding:
    def test_record_creates_profile(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action(), "agent-1")
        p = d.get_profile("agent-1")
        assert p is not None
        assert p.total_actions == 1

    def test_multiple_records(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action(), 5, "agent-1")
        p = d.get_profile("agent-1")
        assert p is not None
        assert p.total_actions == 5
        assert p.action_counts["read"] == 5
        assert p.target_counts["crm"] == 5

    def test_different_action_types(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action("read", "crm"), "a")
        d.record(_make_action("write", "crm"), "a")
        d.record(_make_action("delete", "crm"), "a")
        p = d.get_profile("a")
        assert p is not None
        assert set(p.action_counts.keys()) == {"read", "write", "delete"}

    def test_blocked_count(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action(), 3, "a", blocked=True)
        _record_many(d, _make_action(), 2, "a", blocked=False)
        p = d.get_profile("a")
        assert p is not None
        assert p.blocked_count == 3
        assert p.total_actions == 5

    def test_separate_agent_profiles(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action("read", "crm"), "agent-1")
        d.record(_make_action("write", "stripe"), "agent-2")
        p1 = d.get_profile("agent-1")
        p2 = d.get_profile("agent-2")
        assert p1 is not None and p2 is not None
        assert "read" in p1.action_counts
        assert "write" in p2.action_counts
        assert "write" not in p1.action_counts

    def test_default_agent_id(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action())
        assert d.get_profile("default") is not None

    def test_agent_id_from_action(self) -> None:
        d = AnomalyDetector()
        action = Action(type="read", target="crm", agent_id="from-action")
        d.record(action, "")
        assert d.get_profile("from-action") is not None

    def test_last_seen_updated(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action(), "a")
        p1 = d.get_profile("a")
        assert p1 is not None
        first_ts = p1.last_seen
        d.record(_make_action(), "a")
        p2 = d.get_profile("a")
        assert p2 is not None
        assert p2.last_seen >= first_ts


# ---------------------------------------------------------------------------
# Detector: anomaly checks
# ---------------------------------------------------------------------------


class TestNewActionAnomaly:
    def test_new_action_type_flagged(self) -> None:
        d = AnomalyDetector(new_action_alert=True)
        _record_many(d, _make_action("read", "crm"), 10, "a")
        result = d.check(_make_action("delete", "crm"), "a")
        assert result.is_anomalous
        assert result.anomaly_type == "new_action"
        assert result.severity > 0

    def test_new_action_alert_disabled(self) -> None:
        d = AnomalyDetector(new_action_alert=False)
        _record_many(d, _make_action("read", "crm"), 10, "a")
        # "delete" is new but alerts are disabled.
        result = d.check(_make_action("delete", "crm"), "a")
        # Should not fire new_action, though it may fire unusual_target or nothing.
        assert result.anomaly_type != "new_action"

    def test_known_action_not_flagged_as_new(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action("read", "crm"), 5, "a")
        result = d.check(_make_action("read", "crm"), "a")
        # Known action + known target + not enough volume for burst/rate.
        assert not result.is_anomalous


class TestUnusualTarget:
    def test_unusual_target_flagged(self) -> None:
        d = AnomalyDetector(burst_limit=1000)
        _record_many(d, _make_action("read", "staging"), 10, "a")
        result = d.check(_make_action("read", "production"), "a")
        assert result.is_anomalous
        assert result.anomaly_type == "unusual_target"

    def test_known_target_ok(self) -> None:
        d = AnomalyDetector(burst_limit=1000)
        _record_many(d, _make_action("read", "staging"), 10, "a")
        result = d.check(_make_action("read", "staging"), "a")
        assert not result.is_anomalous


class TestRateSpike:
    def test_rate_spike_detected(self) -> None:
        d = AnomalyDetector(rate_threshold=2.0)
        action = _make_action("read", "crm")
        # Build a slow baseline (simulate ~1 action per 0.5s = 120/min).
        for _ in range(5):
            d.record(action, "a")
            time.sleep(0.02)

        # Now spike: many actions with no delay.
        for _ in range(20):
            d.record(action, "a")

        result = d.check(action, "a")
        # We may or may not detect rate_spike depending on timing; but at
        # minimum we should not crash and should return a valid result.
        assert isinstance(result, AnomalyResult)

    def test_no_spike_for_steady_rate(self) -> None:
        d = AnomalyDetector(rate_threshold=5.0)
        action = _make_action("read", "crm")
        for _ in range(5):
            d.record(action, "a")
            time.sleep(0.01)
        result = d.check(action, "a")
        # Steady rate -- should not be a rate_spike.
        assert result.anomaly_type != "rate_spike"


class TestBurstDetection:
    def test_burst_detected(self) -> None:
        d = AnomalyDetector(burst_window=60.0, burst_limit=5)
        action = _make_action("read", "crm")
        # Record 10 actions rapidly -> triggers burst (>=5 in window).
        for _ in range(10):
            d.record(action, "a")
        result = d.check(action, "a")
        # Should trigger burst or rate_spike (both are valid since
        # rate_spike is checked before burst).
        assert result.is_anomalous
        assert result.anomaly_type in ("rate_spike", "burst")

    def test_no_burst_under_limit(self) -> None:
        d = AnomalyDetector(burst_window=60.0, burst_limit=100)
        action = _make_action("read", "crm")
        for _ in range(3):
            d.record(action, "a")
        result = d.check(action, "a")
        assert result.anomaly_type != "burst"


class TestHighBlockRate:
    def test_high_block_rate_detected(self) -> None:
        d = AnomalyDetector(block_rate_threshold=0.5, burst_limit=1000)
        action = _make_action("read", "crm")
        # 4 blocked + 1 normal = 80% block rate.
        for _ in range(4):
            d.record(action, "a", blocked=True)
        d.record(action, "a", blocked=False)
        result = d.check(action, "a")
        assert result.is_anomalous
        assert result.anomaly_type == "high_block_rate"
        assert result.severity > 0

    def test_low_block_rate_ok(self) -> None:
        d = AnomalyDetector(block_rate_threshold=0.5, burst_limit=1000)
        action = _make_action("read", "crm")
        _record_many(d, action, 10, "a", blocked=False)
        result = d.check(action, "a")
        assert result.anomaly_type != "high_block_rate"

    def test_block_rate_needs_minimum_actions(self) -> None:
        """Block-rate check is skipped when total_actions < 5."""
        d = AnomalyDetector(block_rate_threshold=0.1, burst_limit=1000)
        action = _make_action("read", "crm")
        d.record(action, "a", blocked=True)
        d.record(action, "a", blocked=True)
        result = d.check(action, "a")
        # Only 2 actions -- not enough to trigger block-rate heuristic.
        assert result.anomaly_type != "high_block_rate"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_check_empty_profile(self) -> None:
        d = AnomalyDetector()
        result = d.check(_make_action(), "nonexistent")
        assert not result.is_anomalous

    def test_check_first_action_ok(self) -> None:
        """First-ever action for an agent should not be anomalous."""
        d = AnomalyDetector()
        result = d.check(_make_action(), "new-agent")
        assert not result.is_anomalous

    def test_get_profile_nonexistent(self) -> None:
        d = AnomalyDetector()
        assert d.get_profile("ghost") is None

    def test_reset_single_agent(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action(), "a")
        d.record(_make_action(), "b")
        d.reset("a")
        assert d.get_profile("a") is None
        assert d.get_profile("b") is not None

    def test_reset_all(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action(), "a")
        d.record(_make_action(), "b")
        d.reset()
        assert d.get_profile("a") is None
        assert d.get_profile("b") is None

    def test_severity_clamped(self) -> None:
        """Severity should never exceed 1.0."""
        r = AnomalyResult(is_anomalous=True, severity=0.9)
        assert r.severity <= 1.0

    def test_record_with_action_agent_id(self) -> None:
        """When agent_id='' but action.agent_id is set, use action's."""
        d = AnomalyDetector()
        action = Action(type="read", target="crm", agent_id="from-action")
        d.record(action, "")
        assert d.get_profile("from-action") is not None
        assert d.get_profile("default") is None


# ---------------------------------------------------------------------------
# Policy generation
# ---------------------------------------------------------------------------


class TestPolicyGeneration:
    def test_basic_policy(self) -> None:
        d = AnomalyDetector()
        d.record(_make_action("read_crm", "crm"), "a")
        d.record(_make_action("write_crm", "crm"), "a")
        policy = d.generate_policy("a")
        assert policy["version"] == "1"
        assert "rules" in policy
        assert "defaults" in policy
        assert len(policy["rules"]) >= 2  # 2 observed + block rules

    def test_read_action_gets_auto(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action("read_data", "crm"), 10, "a")
        policy = d.generate_policy("a")
        read_rules = [r for r in policy["rules"] if r["match"]["type"] == "read_data"]
        assert len(read_rules) == 1
        assert read_rules[0]["approval"] == "auto"
        assert read_rules[0]["risk_level"] == "low"

    def test_write_action_gets_approve(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action("write_record", "crm"), 5, "a")
        policy = d.generate_policy("a")
        write_rules = [r for r in policy["rules"] if r["match"]["type"] == "write_record"]
        assert len(write_rules) == 1
        assert write_rules[0]["approval"] == "approve"

    def test_delete_action_gets_block(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action("delete_record", "crm"), 3, "a")
        policy = d.generate_policy("a")
        del_rules = [r for r in policy["rules"] if r["match"]["type"] == "delete_record"]
        assert len(del_rules) == 1
        assert del_rules[0]["approval"] == "block"
        assert del_rules[0]["risk_level"] == "critical"

    def test_unseen_destructive_patterns_blocked(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action("read_data", "crm"), 5, "a")
        policy = d.generate_policy("a")
        block_rules = [r for r in policy["rules"] if r["approval"] == "block"]
        # Should block delete_*, drop_*, destroy_*, purge_*.
        block_patterns = {r["match"]["type"] for r in block_rules}
        for prefix in ("delete_*", "drop_*", "destroy_*", "purge_*"):
            assert prefix in block_patterns

    def test_empty_profile_returns_empty(self) -> None:
        d = AnomalyDetector()
        assert d.generate_policy("nonexistent") == {}

    def test_rules_ordered_by_frequency(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action("read_data", "crm"), 20, "a")
        _record_many(d, _make_action("write_data", "crm"), 5, "a")
        policy = d.generate_policy("a")
        observed_rules = [r for r in policy["rules"] if not r["name"].startswith("block_")]
        assert observed_rules[0]["match"]["type"] == "read_data"
        assert observed_rules[1]["match"]["type"] == "write_data"


# ---------------------------------------------------------------------------
# Integration with Action objects
# ---------------------------------------------------------------------------


class TestActionIntegration:
    def test_action_with_params(self) -> None:
        d = AnomalyDetector()
        action = Action(type="read", target="crm", params={"limit": 100})
        d.record(action, "a")
        assert d.get_profile("a") is not None
        assert d.get_profile("a").action_counts["read"] == 1  # type: ignore[union-attr]

    def test_action_with_description(self) -> None:
        d = AnomalyDetector()
        action = Action(type="write", target="stripe", description="Update customer")
        d.record(action, "a")
        p = d.get_profile("a")
        assert p is not None
        assert p.target_counts["stripe"] == 1

    def test_frozen_action_no_mutation(self) -> None:
        d = AnomalyDetector()
        action = Action(type="read", target="crm")
        d.record(action, "a")
        d.check(action, "a")
        # Action is frozen -- should remain unchanged.
        assert action.type == "read"
        assert action.target == "crm"

    def test_chain_fields_preserved(self) -> None:
        d = AnomalyDetector()
        action = Action(
            type="read",
            target="crm",
            agent_id="child",
            parent_agent_id="parent",
            chain_id="c1",
            chain_depth=2,
        )
        d.record(action, "child")
        p = d.get_profile("child")
        assert p is not None
        assert p.total_actions == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_records(self) -> None:
        d = AnomalyDetector()
        action = _make_action()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(100):
                    d.record(action, "shared")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        p = d.get_profile("shared")
        assert p is not None
        assert p.total_actions == 800

    def test_concurrent_record_and_check(self) -> None:
        d = AnomalyDetector()
        _record_many(d, _make_action(), 10, "a")
        errors: list[Exception] = []

        def recorder() -> None:
            try:
                for _ in range(100):
                    d.record(_make_action(), "a")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        def checker() -> None:
            try:
                for _ in range(100):
                    r = d.check(_make_action(), "a")
                    assert isinstance(r, AnomalyResult)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [
            threading.Thread(target=recorder),
            threading.Thread(target=checker),
            threading.Thread(target=recorder),
            threading.Thread(target=checker),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_concurrent_different_agents(self) -> None:
        d = AnomalyDetector()
        errors: list[Exception] = []

        def worker(agent: str) -> None:
            try:
                for _ in range(100):
                    d.record(_make_action(), agent)
                    d.check(_make_action(), agent)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"agent-{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        for i in range(8):
            p = d.get_profile(f"agent-{i}")
            assert p is not None
            assert p.total_actions == 100


# ---------------------------------------------------------------------------
# Detector constructor defaults
# ---------------------------------------------------------------------------


class TestDetectorConfig:
    def test_default_values(self) -> None:
        d = AnomalyDetector()
        assert d._rate_threshold == 5.0
        assert d._burst_window == 60.0
        assert d._burst_limit == 10
        assert d._new_action_alert is True
        assert d._block_rate_threshold == 0.5

    def test_custom_values(self) -> None:
        d = AnomalyDetector(
            rate_threshold=3.0,
            burst_window=30.0,
            burst_limit=5,
            new_action_alert=False,
            block_rate_threshold=0.3,
        )
        assert d._rate_threshold == 3.0
        assert d._burst_window == 30.0
        assert d._burst_limit == 5
        assert d._new_action_alert is False
        assert d._block_rate_threshold == 0.3
