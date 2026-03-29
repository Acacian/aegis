"""Tests for the Behavioral Drift Detection engine and drift policy rules."""

from __future__ import annotations

import math
import threading
from datetime import UTC, datetime, timedelta

import pytest

from aegis.config import AegisConfig, DriftConfig
from aegis.core.action import Action
from aegis.core.anomaly import AnomalyDetector
from aegis.core.drift import (
    DriftAction,
    DriftBaseline,
    DriftDetector,
    DriftMetricConfig,
    DriftResult,
    DriftSeverity,
    DriftType,
    HistoricalSnapshot,
    _kl_divergence,
    _normalize,
    _parse_window,
    _severity_from_deviation,
)
from aegis.core.drift_policy import (
    DriftPolicyDecision,
    DriftPolicyEvaluator,
    DriftPolicyRule,
)
from aegis.core.policy import Approval
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_action(type_: str = "read", target: str = "crm", agent_id: str = "") -> Action:
    return Action(type=type_, target=target, agent_id=agent_id)


def _make_snapshots(
    agent_id: str,
    count: int,
    *,
    action_counts: dict[str, int] | None = None,
    total_actions: int = 100,
    blocked_count: int = 5,
    avg_latency_ms: float = 50.0,
    total_tokens: int = 1000,
    period_minutes: float = 60.0,
    days_back: int = 30,
) -> list[HistoricalSnapshot]:
    """Create *count* historical snapshots spread across *days_back* days."""
    now = datetime.now(UTC)
    snapshots = []
    for i in range(count):
        ts = now - timedelta(days=days_back * (count - i) / count)
        snapshots.append(
            HistoricalSnapshot(
                agent_id=agent_id,
                timestamp=ts,
                action_counts=action_counts or {"read": 80, "write": 20},
                total_actions=total_actions,
                blocked_count=blocked_count,
                avg_latency_ms=avg_latency_ms,
                total_tokens=total_tokens,
                period_minutes=period_minutes,
            )
        )
    return snapshots


# ---------------------------------------------------------------------------
# DriftResult dataclass
# ---------------------------------------------------------------------------


class TestDriftResult:
    def test_no_drift(self) -> None:
        r = DriftResult(drifted=False, drift_type=DriftType.ERROR_RATE)
        assert not r.drifted
        assert r.severity == DriftSeverity.LOW

    def test_drift_detected(self) -> None:
        r = DriftResult(
            drifted=True,
            drift_type=DriftType.TOOL_DISTRIBUTION,
            severity=DriftSeverity.HIGH,
            baseline_value=0.5,
            current_value=0.9,
            deviation_pct=0.8,
            message="drift found",
            action=DriftAction.BLOCK,
        )
        assert r.drifted
        assert r.severity == DriftSeverity.HIGH
        assert r.deviation_pct == 0.8
        assert r.action == DriftAction.BLOCK

    def test_frozen(self) -> None:
        r = DriftResult(drifted=False, drift_type=DriftType.ERROR_RATE)
        with pytest.raises(AttributeError):
            r.drifted = True  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DriftBaseline dataclass
# ---------------------------------------------------------------------------


class TestDriftBaseline:
    def test_defaults(self) -> None:
        b = DriftBaseline(
            agent_id="a",
            metric_name="error_rate",
            window_days=30,
            baseline_value=0.05,
            stddev=0.01,
            sample_count=100,
        )
        assert b.agent_id == "a"
        assert b.window_days == 30
        assert b.baseline_value == 0.05
        assert b.computed_at is not None


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


class TestUtilities:
    def test_parse_window_days(self) -> None:
        assert _parse_window("30d") == 30
        assert _parse_window("7d") == 7
        assert _parse_window("14D") == 14

    def test_parse_window_plain_int(self) -> None:
        assert _parse_window("30") == 30

    def test_normalize(self) -> None:
        dist = _normalize({"a": 3, "b": 7})
        assert abs(dist["a"] - 0.3) < 1e-9
        assert abs(dist["b"] - 0.7) < 1e-9

    def test_normalize_empty(self) -> None:
        assert _normalize({}) == {}

    def test_kl_divergence_identical(self) -> None:
        p = {"a": 0.5, "b": 0.5}
        assert _kl_divergence(p, p) < 1e-9

    def test_kl_divergence_different(self) -> None:
        p = {"a": 0.9, "b": 0.1}
        q = {"a": 0.5, "b": 0.5}
        assert _kl_divergence(p, q) > 0

    def test_severity_from_deviation_low(self) -> None:
        assert _severity_from_deviation(0.1, 0.2) == DriftSeverity.LOW

    def test_severity_from_deviation_medium(self) -> None:
        assert _severity_from_deviation(0.3, 0.2) == DriftSeverity.MEDIUM

    def test_severity_from_deviation_high(self) -> None:
        assert _severity_from_deviation(0.7, 0.2) == DriftSeverity.HIGH

    def test_severity_from_deviation_critical(self) -> None:
        assert _severity_from_deviation(1.0, 0.2) == DriftSeverity.CRITICAL


# ---------------------------------------------------------------------------
# Baseline computation from snapshots
# ---------------------------------------------------------------------------


class TestBaselineComputation:
    def test_compute_baseline_error_rate(self) -> None:
        detector = DriftDetector()
        snapshots = _make_snapshots("a", 10, blocked_count=5, total_actions=100)
        baseline = detector.compute_baseline("a", "error_rate", snapshots)
        assert baseline.agent_id == "a"
        assert baseline.metric_name == "error_rate"
        assert abs(baseline.baseline_value - 0.05) < 1e-9
        # At least most snapshots should be included (boundary timing can exclude one).
        assert baseline.sample_count >= 9

    def test_compute_baseline_action_frequency(self) -> None:
        detector = DriftDetector()
        snapshots = _make_snapshots("a", 5, total_actions=120, period_minutes=60.0)
        baseline = detector.compute_baseline("a", "action_frequency", snapshots)
        # 120 actions / 60 min = 2.0 per minute
        assert abs(baseline.baseline_value - 2.0) < 1e-9

    def test_compute_baseline_response_latency(self) -> None:
        detector = DriftDetector()
        snapshots = _make_snapshots("a", 5, avg_latency_ms=100.0)
        baseline = detector.compute_baseline("a", "response_latency", snapshots)
        assert abs(baseline.baseline_value - 100.0) < 1e-9

    def test_compute_baseline_token_usage(self) -> None:
        detector = DriftDetector()
        snapshots = _make_snapshots("a", 5, total_tokens=2000)
        baseline = detector.compute_baseline("a", "token_usage", snapshots)
        assert abs(baseline.baseline_value - 2000.0) < 1e-9

    def test_compute_baseline_tool_distribution(self) -> None:
        detector = DriftDetector()
        snapshots = _make_snapshots("a", 5, action_counts={"read": 80, "write": 20})
        baseline = detector.compute_baseline("a", "tool_distribution", snapshots)
        # Entropy of {0.8, 0.2} = -(0.8*ln(0.8) + 0.2*ln(0.2))
        expected = -(0.8 * math.log(0.8) + 0.2 * math.log(0.2))
        assert abs(baseline.baseline_value - expected) < 1e-6

    def test_compute_baseline_stddev(self) -> None:
        detector = DriftDetector()
        # Create snapshots with varying error rates.
        now = datetime.now(UTC)
        snapshots = [
            HistoricalSnapshot(
                agent_id="a",
                timestamp=now - timedelta(days=i),
                total_actions=100,
                blocked_count=i * 2,  # 0%, 2%, 4%, 6%, 8%
            )
            for i in range(5)
        ]
        baseline = detector.compute_baseline("a", "error_rate", snapshots)
        assert baseline.stddev > 0

    def test_compute_baseline_empty_snapshots(self) -> None:
        detector = DriftDetector()
        baseline = detector.compute_baseline("a", "error_rate", [])
        assert baseline.baseline_value == 0.0
        assert baseline.sample_count == 0

    def test_time_window_filtering(self) -> None:
        detector = DriftDetector(
            metric_configs=[DriftMetricConfig(name="error_rate", window_days=7)]
        )
        now = datetime.now(UTC)
        # 5 recent snapshots + 5 old ones outside window.
        recent = [
            HistoricalSnapshot(
                agent_id="a",
                timestamp=now - timedelta(days=i),
                total_actions=100,
                blocked_count=10,
            )
            for i in range(5)
        ]
        old = [
            HistoricalSnapshot(
                agent_id="a",
                timestamp=now - timedelta(days=30 + i),
                total_actions=100,
                blocked_count=50,  # Very high error rate.
            )
            for i in range(5)
        ]
        baseline = detector.compute_baseline("a", "error_rate", recent + old)
        # Should only use the 5 recent snapshots (error_rate = 0.1).
        assert abs(baseline.baseline_value - 0.1) < 1e-9
        assert baseline.sample_count == 5


# ---------------------------------------------------------------------------
# Baseline from BehaviorProfile
# ---------------------------------------------------------------------------


class TestBaselineFromProfile:
    def test_compute_from_profile_error_rate(self) -> None:
        ad = AnomalyDetector()
        action = _make_action()
        for _ in range(8):
            ad.record(action, "a")
        for _ in range(2):
            ad.record(action, "a", blocked=True)

        detector = DriftDetector(anomaly_detector=ad)
        baseline = detector.compute_baseline_from_profile("a", "error_rate")
        assert baseline is not None
        assert abs(baseline.baseline_value - 0.2) < 1e-9

    def test_compute_from_profile_no_profile(self) -> None:
        ad = AnomalyDetector()
        detector = DriftDetector(anomaly_detector=ad)
        assert detector.compute_baseline_from_profile("ghost", "error_rate") is None

    def test_compute_from_profile_no_detector(self) -> None:
        detector = DriftDetector()
        assert detector.compute_baseline_from_profile("a", "error_rate") is None


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


class TestDriftDetection:
    def test_no_baseline_no_drift(self) -> None:
        detector = DriftDetector()
        result = detector.check("a", "error_rate")
        assert not result.drifted
        assert "No baseline" in result.message

    def test_error_rate_drift_detected(self) -> None:
        ad = AnomalyDetector()
        # Build a profile with high error rate.
        action = _make_action()
        for _ in range(5):
            ad.record(action, "a")
        for _ in range(5):
            ad.record(action, "a", blocked=True)

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1, action=DriftAction.BLOCK)
            ],
        )
        # Set baseline with low error rate.
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=100,
            )
        )

        result = detector.check("a", "error_rate")
        assert result.drifted
        assert result.drift_type == DriftType.ERROR_RATE
        assert result.action == DriftAction.BLOCK
        assert result.deviation_pct > 0.1

    def test_error_rate_within_threshold(self) -> None:
        ad = AnomalyDetector()
        action = _make_action()
        for _ in range(95):
            ad.record(action, "a")
        for _ in range(5):
            ad.record(action, "a", blocked=True)

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.5, action=DriftAction.WARN)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=100,
            )
        )

        result = detector.check("a", "error_rate")
        # 5% current vs 5% baseline = 0% deviation, within 50% threshold.
        assert not result.drifted

    def test_response_latency_drift(self) -> None:
        detector = DriftDetector(
            metric_configs=[
                DriftMetricConfig(name="response_latency", threshold=2.0, action=DriftAction.BLOCK)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="response_latency",
                window_days=7,
                baseline_value=50.0,
                stddev=5.0,
                sample_count=100,
            )
        )
        # Record high latency samples.
        for _ in range(10):
            detector.record_latency("a", 200.0)

        result = detector.check("a", "response_latency")
        assert result.drifted
        assert result.drift_type == DriftType.RESPONSE_LATENCY
        assert result.current_value > 150.0

    def test_token_usage_drift(self) -> None:
        detector = DriftDetector(
            metric_configs=[
                DriftMetricConfig(name="token_usage", threshold=0.5, action=DriftAction.ALERT)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="token_usage",
                window_days=30,
                baseline_value=1000.0,
                stddev=50.0,
                sample_count=100,
            )
        )
        # Record high token usage.
        for _ in range(10):
            detector.record_tokens("a", 3000)

        result = detector.check("a", "token_usage")
        assert result.drifted
        assert result.drift_type == DriftType.TOKEN_USAGE

    def test_action_frequency_drift(self) -> None:
        ad = AnomalyDetector()
        action = _make_action()
        # Build a profile with a certain rate.
        for _ in range(50):
            ad.record(action, "a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="action_frequency", threshold=0.3, action=DriftAction.WARN)
            ],
        )
        # Set a very different baseline.
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="action_frequency",
                window_days=30,
                baseline_value=0.001,  # Very low baseline.
                stddev=0.0001,
                sample_count=100,
            )
        )

        result = detector.check("a", "action_frequency")
        # Current rate should be much higher than 0.001.
        assert result.drifted

    def test_check_all_metrics(self) -> None:
        ad = AnomalyDetector()
        action = _make_action()
        for _ in range(10):
            ad.record(action, "a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1),
                DriftMetricConfig(name="action_frequency", threshold=0.1),
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=100,
            )
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="action_frequency",
                window_days=30,
                baseline_value=0.001,
                stddev=0.0001,
                sample_count=100,
            )
        )

        results = detector.check_all("a")
        assert len(results) == 2
        assert all(isinstance(r, DriftResult) for r in results)

    def test_check_from_snapshot(self) -> None:
        detector = DriftDetector(
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.2, action=DriftAction.WARN)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=100,
            )
        )

        snap = HistoricalSnapshot(
            agent_id="a",
            timestamp=datetime.now(UTC),
            total_actions=100,
            blocked_count=30,  # 30% error rate vs 5% baseline.
        )
        result = detector.check_from_snapshot(snap, "error_rate")
        assert result.drifted
        assert result.deviation_pct > 0.2


# ---------------------------------------------------------------------------
# Drift severity levels
# ---------------------------------------------------------------------------


class TestDriftSeverity:
    def test_severity_escalation(self) -> None:
        ad = AnomalyDetector()
        action = _make_action()
        for _ in range(50):
            ad.record(action, "a", blocked=True)
        for _ in range(50):
            ad.record(action, "a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1, action=DriftAction.BLOCK)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.01,
                stddev=0.005,
                sample_count=100,
            )
        )

        result = detector.check("a", "error_rate")
        assert result.drifted
        # 50% error rate vs 1% baseline = huge deviation.
        assert result.severity in (DriftSeverity.HIGH, DriftSeverity.CRITICAL)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestDriftConfig:
    def test_from_config_dict(self) -> None:
        config = {
            "enabled": True,
            "baselines": [
                {"name": "tool_distribution", "window": "30d", "threshold": 0.2, "action": "warn"},
                {"name": "error_rate", "window": "14d", "threshold": 0.5, "action": "block"},
            ],
        }
        detector = DriftDetector.from_config(config)
        assert "tool_distribution" in detector._metric_configs
        assert "error_rate" in detector._metric_configs
        assert detector._metric_configs["error_rate"].window_days == 14
        assert detector._metric_configs["error_rate"].threshold == 0.5
        assert detector._metric_configs["error_rate"].action == DriftAction.BLOCK

    def test_aegis_config_drift_parsing(self) -> None:
        data = {
            "drift": {
                "enabled": True,
                "baselines": [
                    {
                        "name": "tool_distribution",
                        "window": "30d",
                        "threshold": 0.2,
                        "action": "warn",
                    },
                    {
                        "name": "response_latency",
                        "window": "7d",
                        "threshold": 2.0,
                        "action": "block",
                    },
                ],
            }
        }
        cfg = AegisConfig.from_dict(data)
        assert cfg.drift is not None
        assert cfg.drift.enabled is True
        assert len(cfg.drift.baselines) == 2
        assert cfg.drift.baselines[0]["name"] == "tool_distribution"
        assert cfg.drift.baselines[1]["action"] == "block"

    def test_aegis_config_drift_none(self) -> None:
        cfg = AegisConfig.from_dict({})
        assert cfg.drift is None

    def test_aegis_config_drift_disabled(self) -> None:
        cfg = AegisConfig.from_dict({"drift": {"enabled": False}})
        assert cfg.drift is not None
        assert cfg.drift.enabled is False

    def test_drift_config_defaults(self) -> None:
        dc = DriftConfig()
        assert dc.enabled is False
        assert dc.baselines == []


# ---------------------------------------------------------------------------
# DriftPolicyRule
# ---------------------------------------------------------------------------


class TestDriftPolicyRule:
    def test_rule_triggers_on_drift(self) -> None:
        ad = AnomalyDetector()
        action = _make_action(agent_id="a")
        for _ in range(5):
            ad.record(action, "a")
        for _ in range(5):
            ad.record(action, "a", blocked=True)

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1, action=DriftAction.BLOCK)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.01,
                stddev=0.005,
                sample_count=100,
            )
        )

        rule = DriftPolicyRule(
            name="drift_error",
            metric=DriftType.ERROR_RATE,
            action_on_drift=DriftAction.BLOCK,
            risk_level=RiskLevel.CRITICAL,
        )

        decision = rule.evaluate(action, detector)
        assert decision is not None
        assert decision.approval == Approval.BLOCK
        assert decision.risk_level == RiskLevel.CRITICAL
        assert decision.drift_result is not None
        assert decision.drift_result.drifted

    def test_rule_no_drift_no_decision(self) -> None:
        ad = AnomalyDetector()
        action = _make_action(agent_id="a")
        for _ in range(100):
            ad.record(action, "a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.5, action=DriftAction.WARN)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.0,
                stddev=0.0,
                sample_count=100,
            )
        )

        rule = DriftPolicyRule(
            name="drift_error",
            metric=DriftType.ERROR_RATE,
            action_on_drift=DriftAction.WARN,
        )

        decision = rule.evaluate(action, detector)
        assert decision is None

    def test_rule_agent_matching(self) -> None:
        ad = AnomalyDetector()
        action_a = _make_action(agent_id="agent-a")
        action_b = _make_action(agent_id="agent-b")
        for _ in range(5):
            ad.record(action_a, "agent-a", blocked=True)
            ad.record(action_a, "agent-a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1, action=DriftAction.WARN)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="agent-a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.01,
                stddev=0.005,
                sample_count=100,
            )
        )

        rule = DriftPolicyRule(
            name="drift_error_agent_a",
            metric=DriftType.ERROR_RATE,
            action_on_drift=DriftAction.WARN,
            match_agent="agent-a",
        )

        # Should match agent-a.
        decision_a = rule.evaluate(action_a, detector)
        assert decision_a is not None

        # Should not match agent-b.
        decision_b = rule.evaluate(action_b, detector)
        assert decision_b is None

    def test_warn_action_maps_to_approve(self) -> None:
        ad = AnomalyDetector()
        action = _make_action(agent_id="a")
        for _ in range(5):
            ad.record(action, "a", blocked=True)
        for _ in range(5):
            ad.record(action, "a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1, action=DriftAction.WARN)
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.01,
                stddev=0.005,
                sample_count=100,
            )
        )

        rule = DriftPolicyRule(
            name="drift_warn",
            metric=DriftType.ERROR_RATE,
            action_on_drift=DriftAction.WARN,
        )
        decision = rule.evaluate(action, detector)
        assert decision is not None
        assert decision.approval == Approval.APPROVE


# ---------------------------------------------------------------------------
# DriftPolicyEvaluator
# ---------------------------------------------------------------------------


class TestDriftPolicyEvaluator:
    def test_evaluator_with_multiple_rules(self) -> None:
        ad = AnomalyDetector()
        action = _make_action(agent_id="a")
        for _ in range(5):
            ad.record(action, "a", blocked=True)
        for _ in range(5):
            ad.record(action, "a")

        detector = DriftDetector(
            anomaly_detector=ad,
            metric_configs=[
                DriftMetricConfig(name="error_rate", threshold=0.1, action=DriftAction.WARN),
                DriftMetricConfig(
                    name="action_frequency",
                    threshold=0.1,
                    action=DriftAction.BLOCK,
                ),
            ],
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.01,
                stddev=0.005,
                sample_count=100,
            )
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="action_frequency",
                window_days=30,
                baseline_value=0.001,
                stddev=0.0001,
                sample_count=100,
            )
        )

        evaluator = DriftPolicyEvaluator(
            drift_detector=detector,
            rules=[
                DriftPolicyRule(
                    name="drift_error",
                    metric=DriftType.ERROR_RATE,
                    action_on_drift=DriftAction.WARN,
                    risk_level=RiskLevel.MEDIUM,
                ),
                DriftPolicyRule(
                    name="drift_freq",
                    metric=DriftType.ACTION_FREQUENCY,
                    action_on_drift=DriftAction.BLOCK,
                    risk_level=RiskLevel.CRITICAL,
                ),
            ],
        )

        decision = evaluator.evaluate(action)
        assert decision is not None
        # Should pick the most severe (BLOCK > WARN).
        assert decision.approval == Approval.BLOCK
        assert decision.risk_level == RiskLevel.CRITICAL

    def test_evaluator_no_drift(self) -> None:
        ad = AnomalyDetector()
        action = _make_action(agent_id="a")
        for _ in range(100):
            ad.record(action, "a")

        detector = DriftDetector(anomaly_detector=ad)
        evaluator = DriftPolicyEvaluator(drift_detector=detector)
        evaluator.add_rule(
            DriftPolicyRule(
                name="drift_error",
                metric=DriftType.ERROR_RATE,
                action_on_drift=DriftAction.WARN,
            )
        )

        decision = evaluator.evaluate(action)
        # No baselines set = no drift.
        assert decision is None

    def test_evaluator_from_config(self) -> None:
        config = {
            "baselines": [
                {"name": "error_rate", "threshold": 0.2, "action": "warn"},
                {"name": "response_latency", "threshold": 2.0, "action": "block"},
            ],
        }
        detector = DriftDetector()
        evaluator = DriftPolicyEvaluator.from_config(config, detector)
        assert len(evaluator._rules) == 2
        assert evaluator._rules[0].name == "drift_error_rate"
        assert evaluator._rules[1].name == "drift_response_latency"

    def test_drift_policy_decision_summary(self) -> None:
        drift_result = DriftResult(
            drifted=True,
            drift_type=DriftType.ERROR_RATE,
            severity=DriftSeverity.HIGH,
            deviation_pct=0.8,
        )
        decision = DriftPolicyDecision(
            action=_make_action(),
            risk_level=RiskLevel.HIGH,
            approval=Approval.BLOCK,
            matched_rule="test",
            drift_result=drift_result,
            all_drift_results=[drift_result],
        )
        summary = decision.drift_summary
        assert "1 metrics" in summary
        assert "error_rate" in summary


# ---------------------------------------------------------------------------
# Integration with AnomalyDetector
# ---------------------------------------------------------------------------


class TestAnomalyDetectorIntegration:
    def test_drift_builds_on_anomaly_profile(self) -> None:
        """DriftDetector consumes BehaviorProfile from AnomalyDetector."""
        ad = AnomalyDetector()
        action = _make_action()
        for _ in range(20):
            ad.record(action, "agent-1")
        for _ in range(5):
            ad.record(action, "agent-1", blocked=True)

        detector = DriftDetector(anomaly_detector=ad)
        baseline = detector.compute_baseline_from_profile("agent-1", "error_rate")
        assert baseline is not None
        assert baseline.baseline_value == 5 / 25  # 5 blocked / 25 total

    def test_drift_uses_profile_action_counts(self) -> None:
        """Tool distribution baseline uses action_counts from profile."""
        ad = AnomalyDetector()
        for _ in range(80):
            ad.record(_make_action("read", "crm"), "a")
        for _ in range(20):
            ad.record(_make_action("write", "crm"), "a")

        detector = DriftDetector(anomaly_detector=ad)
        baseline = detector.compute_baseline_from_profile("a", "tool_distribution")
        assert baseline is not None
        # Should have entropy of {0.8, 0.2} distribution.
        expected = -(0.8 * math.log(0.8) + 0.2 * math.log(0.2))
        assert abs(baseline.baseline_value - expected) < 1e-6


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_single_agent(self) -> None:
        detector = DriftDetector()
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=10,
            )
        )
        detector.set_baseline(
            DriftBaseline(
                agent_id="b",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=10,
            )
        )
        detector.reset("a")
        assert detector.get_baseline("a", "error_rate") is None
        assert detector.get_baseline("b", "error_rate") is not None

    def test_reset_all(self) -> None:
        detector = DriftDetector()
        detector.set_baseline(
            DriftBaseline(
                agent_id="a",
                metric_name="error_rate",
                window_days=30,
                baseline_value=0.05,
                stddev=0.01,
                sample_count=10,
            )
        )
        detector.reset()
        assert detector.get_baseline("a", "error_rate") is None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_baseline_operations(self) -> None:
        detector = DriftDetector()
        errors: list[Exception] = []

        def worker(agent: str) -> None:
            try:
                for i in range(50):
                    detector.set_baseline(
                        DriftBaseline(
                            agent_id=agent,
                            metric_name="error_rate",
                            window_days=30,
                            baseline_value=i * 0.01,
                            stddev=0.01,
                            sample_count=10,
                        )
                    )
                    detector.get_baseline(agent, "error_rate")
                    detector.record_latency(agent, float(i))
                    detector.record_tokens(agent, i * 100)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"agent-{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
