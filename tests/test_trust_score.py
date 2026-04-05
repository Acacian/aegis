"""Tests for the Trust Score module."""

from __future__ import annotations

import threading

import pytest

from aegis.core.trust_score import (
    TrustEvent,
    TrustEventType,
    TrustLevel,
    TrustScore,
    TrustScorer,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_scorer(**kwargs) -> TrustScorer:
    return TrustScorer(**kwargs)


def _record_compliance(scorer: TrustScorer, agent: str, n: int = 1) -> TrustScore:
    result = None
    for _ in range(n):
        result = scorer.record_event(agent, TrustEventType.COMPLIANCE)
    assert result is not None
    return result


def _record_violation(scorer: TrustScorer, agent: str, n: int = 1) -> TrustScore:
    result = None
    for _ in range(n):
        result = scorer.record_event(agent, TrustEventType.VIOLATION)
    assert result is not None
    return result


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestTrustLevel:
    def test_five_levels(self) -> None:
        levels = list(TrustLevel)
        assert len(levels) == 5

    def test_values(self) -> None:
        assert TrustLevel.UNTRUSTED == "untrusted"
        assert TrustLevel.LOW == "low"
        assert TrustLevel.MODERATE == "moderate"
        assert TrustLevel.HIGH == "high"
        assert TrustLevel.VERIFIED == "verified"


class TestTrustEventType:
    def test_five_types(self) -> None:
        types = list(TrustEventType)
        assert len(types) == 5

    def test_values(self) -> None:
        assert TrustEventType.COMPLIANCE == "compliance"
        assert TrustEventType.VIOLATION == "violation"
        assert TrustEventType.ESCALATION == "escalation"
        assert TrustEventType.AUDIT_PASS == "audit_pass"
        assert TrustEventType.AUDIT_FAIL == "audit_fail"


# ---------------------------------------------------------------------------
# Frozen dataclass tests
# ---------------------------------------------------------------------------


class TestTrustEventDataclass:
    def test_frozen(self) -> None:
        event = TrustEvent(
            agent_id="a",
            event_type=TrustEventType.COMPLIANCE,
            weight=0.05,
            timestamp=1.0,
            description="test",
        )
        with pytest.raises(AttributeError):
            event.weight = 0.1  # type: ignore[misc]

    def test_fields(self) -> None:
        event = TrustEvent(
            agent_id="a",
            event_type=TrustEventType.VIOLATION,
            weight=-0.15,
            timestamp=2.0,
            description="bad action",
        )
        assert event.agent_id == "a"
        assert event.event_type == TrustEventType.VIOLATION
        assert event.weight == -0.15
        assert event.description == "bad action"


class TestTrustScoreDataclass:
    def test_frozen(self) -> None:
        score = TrustScore(
            agent_id="a",
            score=0.5,
            level=TrustLevel.MODERATE,
            history_size=0,
            last_updated=1.0,
        )
        with pytest.raises(AttributeError):
            score.score = 0.9  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TrustScorer: basic operations
# ---------------------------------------------------------------------------


class TestTrustScorerBasic:
    def test_new_agent_starts_at_neutral(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        score = scorer.get_score("agent-1")
        assert score.score == pytest.approx(0.5, abs=0.01)
        assert score.level == TrustLevel.MODERATE

    def test_compliance_increases_trust(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        before = scorer.get_score("a").score
        _record_compliance(scorer, "a", 5)
        after = scorer.get_score("a").score
        assert after > before

    def test_violation_decreases_trust(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a", 5)
        before = scorer.get_score("a").score
        _record_violation(scorer, "a", 3)
        after = scorer.get_score("a").score
        assert after < before

    def test_score_clamped_at_zero(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_violation(scorer, "a", 50)
        score = scorer.get_score("a")
        assert score.score >= 0.0

    def test_score_clamped_at_one(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a", 100)
        score = scorer.get_score("a")
        assert score.score <= 1.0

    def test_history_size_tracked(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a", 3)
        _record_violation(scorer, "a", 2)
        score = scorer.get_score("a")
        assert score.history_size == 5

    def test_max_history_enforced(self) -> None:
        scorer = _build_scorer(max_history=5, decay_rate=0.0)
        _record_compliance(scorer, "a", 10)
        score = scorer.get_score("a")
        assert score.history_size == 5


# ---------------------------------------------------------------------------
# Trust levels
# ---------------------------------------------------------------------------


class TestTrustLevels:
    def test_untrusted_level(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_violation(scorer, "a", 20)
        score = scorer.get_score("a")
        assert score.level == TrustLevel.UNTRUSTED

    def test_low_level(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        # Start at 0.5, one violation brings it to 0.35 (LOW range: 0.25-0.44)
        _record_violation(scorer, "a", 1)
        score = scorer.get_score("a")
        assert score.level == TrustLevel.LOW

    def test_high_level(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a", 10)
        score = scorer.get_score("a")
        assert score.level in (TrustLevel.HIGH, TrustLevel.VERIFIED)

    def test_verified_level(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        for _ in range(10):
            scorer.record_event("a", TrustEventType.AUDIT_PASS)
        score = scorer.get_score("a")
        assert score.level == TrustLevel.VERIFIED


# ---------------------------------------------------------------------------
# Severity weighting
# ---------------------------------------------------------------------------


class TestSeverityWeighting:
    def test_high_severity_violation_more_impactful(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        score_low = scorer.record_event("a", TrustEventType.VIOLATION, severity=0.5)
        scorer2 = _build_scorer(decay_rate=0.0)
        score_high = scorer2.record_event("b", TrustEventType.VIOLATION, severity=2.0)
        assert score_low.score > score_high.score

    def test_zero_severity_no_impact(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        before = scorer.get_score("a").score
        scorer.record_event("a", TrustEventType.VIOLATION, severity=0.0)
        after = scorer.get_score("a").score
        assert before == pytest.approx(after, abs=0.001)


# ---------------------------------------------------------------------------
# Decay
# ---------------------------------------------------------------------------


class TestDecay:
    def test_decay_toward_neutral_from_high(self) -> None:
        scorer = _build_scorer(decay_rate=0.01)
        _record_compliance(scorer, "a", 10)
        before = scorer.get_score("a").score
        result = scorer.decay("a", 10.0)
        assert result.score < before
        assert result.score >= 0.5  # should not cross neutral

    def test_decay_toward_neutral_from_low(self) -> None:
        scorer = _build_scorer(decay_rate=0.01)
        _record_violation(scorer, "a", 5)
        before = scorer.get_score("a").score
        assert before < 0.5
        result = scorer.decay("a", 10.0)
        assert result.score > before
        assert result.score <= 0.5

    def test_zero_decay_rate_no_change(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a", 5)
        before = scorer.get_score("a").score
        scorer.decay("a", 1000.0)
        after = scorer.get_score("a").score
        assert before == pytest.approx(after, abs=0.001)


# ---------------------------------------------------------------------------
# Threshold policies
# ---------------------------------------------------------------------------


class TestThresholdPolicies:
    def test_low_risk_always_passes(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_violation(scorer, "a", 20)
        assert scorer.check_threshold("a", "low") is True

    def test_critical_risk_requires_high_trust(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        assert scorer.check_threshold("a", "critical") is False

    def test_critical_risk_passes_with_high_trust(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        for _ in range(10):
            scorer.record_event("a", TrustEventType.AUDIT_PASS)
        assert scorer.check_threshold("a", "critical") is True

    def test_unknown_risk_denied(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        assert scorer.check_threshold("a", "unknown_level") is False


# ---------------------------------------------------------------------------
# Events retrieval
# ---------------------------------------------------------------------------


class TestEventRetrieval:
    def test_get_events_empty(self) -> None:
        scorer = _build_scorer()
        assert scorer.get_events("nonexistent") == []

    def test_get_events_returns_recorded(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        scorer.record_event("a", TrustEventType.COMPLIANCE, description="good")
        scorer.record_event("a", TrustEventType.VIOLATION, description="bad")
        events = scorer.get_events("a")
        assert len(events) == 2
        assert events[0].event_type == TrustEventType.COMPLIANCE
        assert events[1].event_type == TrustEventType.VIOLATION


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class TestReport:
    def test_empty_report(self) -> None:
        scorer = _build_scorer()
        report = scorer.report()
        assert report.total_agents == 0
        assert report.total_events == 0

    def test_report_counts_agents(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a")
        _record_compliance(scorer, "b")
        _record_violation(scorer, "c")
        report = scorer.report()
        assert report.total_agents == 3
        assert report.total_events == 3

    def test_report_level_distribution(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        _record_compliance(scorer, "a")
        report = scorer.report()
        total = sum(report.level_distribution.values())
        assert total == 1


# ---------------------------------------------------------------------------
# Custom weights
# ---------------------------------------------------------------------------


class TestCustomWeights:
    def test_custom_event_weights(self) -> None:
        custom = {
            TrustEventType.COMPLIANCE: 0.2,
            TrustEventType.VIOLATION: -0.4,
        }
        scorer = _build_scorer(event_weights=custom, decay_rate=0.0)
        scorer.record_event("a", TrustEventType.COMPLIANCE)
        score = scorer.get_score("a").score
        assert score == pytest.approx(0.7, abs=0.01)

    def test_custom_weight_override(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        scorer.record_event("a", TrustEventType.COMPLIANCE, weight=0.3)
        score = scorer.get_score("a").score
        assert score == pytest.approx(0.8, abs=0.01)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_events(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        errors: list[Exception] = []

        def worker(agent_id: str) -> None:
            try:
                for _ in range(100):
                    scorer.record_event(agent_id, TrustEventType.COMPLIANCE)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(f"agent-{i}",)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        report = scorer.report()
        assert report.total_agents == 4
        assert report.total_events == 400

    def test_concurrent_mixed_operations(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        errors: list[Exception] = []

        def writer() -> None:
            try:
                for _ in range(50):
                    scorer.record_event("shared", TrustEventType.COMPLIANCE)
                    scorer.record_event("shared", TrustEventType.VIOLATION)
            except Exception as e:
                errors.append(e)

        def reader() -> None:
            try:
                for _ in range(50):
                    scorer.get_score("shared")
                    scorer.report()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(2)]
        threads += [threading.Thread(target=reader) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_description(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        result = scorer.record_event("a", TrustEventType.COMPLIANCE, description="")
        assert result.score > 0.0

    def test_very_large_severity(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        result = scorer.record_event("a", TrustEventType.VIOLATION, severity=100.0)
        assert result.score == 0.0  # clamped at 0

    def test_negative_weight(self) -> None:
        scorer = _build_scorer(decay_rate=0.0)
        result = scorer.record_event("a", TrustEventType.COMPLIANCE, weight=-0.1)
        assert result.score < 0.5  # negative weight reduces trust
