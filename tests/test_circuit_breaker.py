"""Tests for the Circuit Breaker engine."""

from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass

import pytest

from aegis.core.circuit_breaker import (
    AnomalyCircuitBridge,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitState,
    QDVMetric,
    QualityLevel,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_breaker(
    name: str = "test",
    failure_threshold: int = 3,
    recovery_timeout_s: float = 1.0,
    success_threshold: int = 2,
    half_open_max_calls: int = 3,
    window_s: float = 120.0,
    on_state_change=None,
) -> CircuitBreaker:
    config = CircuitBreakerConfig(
        failure_threshold=failure_threshold,
        recovery_timeout_s=recovery_timeout_s,
        half_open_max_calls=half_open_max_calls,
        success_threshold=success_threshold,
        window_s=window_s,
    )
    return CircuitBreaker(name=name, config=config, on_state_change=on_state_change)


@dataclass(frozen=True)
class FakeAnomalyResult:
    """Lightweight stand-in for AnomalyResult to avoid importing the full module."""

    is_anomalous: bool


# ---------------------------------------------------------------------------
# CircuitState enum
# ---------------------------------------------------------------------------


class TestCircuitState:
    def test_values(self) -> None:
        assert CircuitState.CLOSED == "closed"
        assert CircuitState.OPEN == "open"
        assert CircuitState.HALF_OPEN == "half_open"


# ---------------------------------------------------------------------------
# QualityLevel enum
# ---------------------------------------------------------------------------


class TestQualityLevel:
    def test_ordering(self) -> None:
        assert QualityLevel.NOMINAL < QualityLevel.DEGRADED
        assert QualityLevel.DEGRADED < QualityLevel.CRITICAL

    def test_int_values(self) -> None:
        assert int(QualityLevel.NOMINAL) == 0
        assert int(QualityLevel.DEGRADED) == 1
        assert int(QualityLevel.CRITICAL) == 2


# ---------------------------------------------------------------------------
# CircuitOpenError
# ---------------------------------------------------------------------------


class TestCircuitOpenError:
    def test_is_exception(self) -> None:
        err = CircuitOpenError("breaker tripped")
        assert isinstance(err, Exception)
        assert "breaker tripped" in str(err)


# ---------------------------------------------------------------------------
# CircuitBreaker: initial state
# ---------------------------------------------------------------------------


class TestCircuitBreakerInitialState:
    def test_starts_closed(self) -> None:
        cb = _make_breaker()
        assert cb.state == CircuitState.CLOSED

    def test_check_allowed_returns_true(self) -> None:
        cb = _make_breaker()
        assert cb.check_allowed() is True

    def test_quality_level_nominal(self) -> None:
        cb = _make_breaker()
        assert cb.quality_level == QualityLevel.NOMINAL


# ---------------------------------------------------------------------------
# State transitions: CLOSED -> OPEN
# ---------------------------------------------------------------------------


class TestClosedToOpen:
    def test_failures_below_threshold_stay_closed(self) -> None:
        cb = _make_breaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    def test_failures_at_threshold_opens(self) -> None:
        cb = _make_breaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_open_raises_circuit_open_error(self) -> None:
        cb = _make_breaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            cb.check_allowed()

    def test_quality_level_critical_when_open(self) -> None:
        cb = _make_breaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.quality_level == QualityLevel.CRITICAL


# ---------------------------------------------------------------------------
# State transitions: OPEN -> HALF_OPEN (recovery after timeout)
# ---------------------------------------------------------------------------


class TestOpenToHalfOpen:
    def test_recovery_after_timeout(self) -> None:
        cb = _make_breaker(failure_threshold=2, recovery_timeout_s=0.05)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        time.sleep(0.1)
        assert cb.state == CircuitState.HALF_OPEN

    def test_recovery_with_mocked_time(self) -> None:
        cb = _make_breaker(failure_threshold=2, recovery_timeout_s=60.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # Simulate time passing by manipulating _opened_at
        cb._opened_at = time.monotonic() - 61.0
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_allows_limited_calls(self) -> None:
        cb = _make_breaker(
            failure_threshold=2,
            recovery_timeout_s=0.01,
            half_open_max_calls=2,
        )
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.05)

        assert cb.state == CircuitState.HALF_OPEN
        assert cb.check_allowed() is True
        assert cb.check_allowed() is True
        with pytest.raises(CircuitOpenError, match="half-open quota"):
            cb.check_allowed()

    def test_quality_level_degraded_when_half_open(self) -> None:
        cb = _make_breaker(failure_threshold=2, recovery_timeout_s=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.05)
        assert cb.quality_level == QualityLevel.DEGRADED


# ---------------------------------------------------------------------------
# State transitions: HALF_OPEN -> CLOSED
# ---------------------------------------------------------------------------


class TestHalfOpenToClosed:
    def test_successes_close_breaker(self) -> None:
        cb = _make_breaker(
            failure_threshold=2,
            recovery_timeout_s=0.01,
            success_threshold=2,
        )
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.05)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_success()
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_failure_in_half_open_reopens(self) -> None:
        cb = _make_breaker(failure_threshold=2, recovery_timeout_s=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.05)
        assert cb.state == CircuitState.HALF_OPEN

        cb.record_failure()
        assert cb.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# Full cycle: CLOSED -> OPEN -> HALF_OPEN -> CLOSED
# ---------------------------------------------------------------------------


class TestFullCycle:
    def test_complete_state_machine_cycle(self) -> None:
        transitions = []

        def on_change(name, old, new):
            transitions.append((old, new))

        cb = _make_breaker(
            failure_threshold=2,
            recovery_timeout_s=0.01,
            success_threshold=2,
            on_state_change=on_change,
        )

        # CLOSED -> OPEN
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # OPEN -> HALF_OPEN
        time.sleep(0.05)
        assert cb.state == CircuitState.HALF_OPEN

        # HALF_OPEN -> CLOSED
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

        assert (CircuitState.CLOSED, CircuitState.OPEN) in transitions
        assert (CircuitState.OPEN, CircuitState.HALF_OPEN) in transitions
        assert (CircuitState.HALF_OPEN, CircuitState.CLOSED) in transitions


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_from_open(self) -> None:
        cb = _make_breaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb.check_allowed() is True

    def test_reset_clears_failures(self) -> None:
        cb = _make_breaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.reset()

        # One more failure should not trip (threshold is 3)
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED


# ---------------------------------------------------------------------------
# Sliding window
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_old_failures_expire(self) -> None:
        cb = _make_breaker(failure_threshold=3, window_s=0.05)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.1)
        # Old failures expired
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    def test_failures_within_window_accumulate(self) -> None:
        cb = _make_breaker(failure_threshold=3, window_s=10.0)
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


# ---------------------------------------------------------------------------
# Quality level: degraded near threshold
# ---------------------------------------------------------------------------


class TestQualityDegradedNearThreshold:
    def test_quality_degrades_near_threshold(self) -> None:
        cb = _make_breaker(failure_threshold=10, window_s=60.0)
        # Record 8 failures (80% of threshold=10 > 70% cutoff)
        for _ in range(8):
            cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.quality_level == QualityLevel.DEGRADED


# ---------------------------------------------------------------------------
# QDVMetric
# ---------------------------------------------------------------------------


class TestQDVMetric:
    def test_empty_is_perfect(self) -> None:
        m = QDVMetric()
        assert m.score == pytest.approx(1.0)

    def test_all_nominal(self) -> None:
        m = QDVMetric(
            component_scores={
                "a": QualityLevel.NOMINAL,
                "b": QualityLevel.NOMINAL,
            }
        )
        assert m.score == pytest.approx(1.0)

    def test_all_critical(self) -> None:
        m = QDVMetric(
            component_scores={
                "a": QualityLevel.CRITICAL,
                "b": QualityLevel.CRITICAL,
            }
        )
        assert m.score == pytest.approx(0.0)

    def test_mixed_scores(self) -> None:
        m = QDVMetric(
            component_scores={
                "a": QualityLevel.NOMINAL,
                "b": QualityLevel.CRITICAL,
            }
        )
        # NOMINAL=1.0, CRITICAL=0.0, avg=0.5
        assert m.score == pytest.approx(0.5)

    def test_degraded_level(self) -> None:
        m = QDVMetric(
            component_scores={
                "a": QualityLevel.DEGRADED,
            }
        )
        # DEGRADED => 1 - (1/2) = 0.5
        assert m.score == pytest.approx(0.5)

    def test_worst_component_none(self) -> None:
        m = QDVMetric()
        assert m.worst_component is None

    def test_worst_component(self) -> None:
        m = QDVMetric(
            component_scores={
                "healthy": QualityLevel.NOMINAL,
                "broken": QualityLevel.CRITICAL,
                "degraded": QualityLevel.DEGRADED,
            }
        )
        name, level = m.worst_component
        assert name == "broken"
        assert level == QualityLevel.CRITICAL


# ---------------------------------------------------------------------------
# CircuitBreakerRegistry
# ---------------------------------------------------------------------------


class TestCircuitBreakerRegistry:
    def test_register_creates_breaker(self) -> None:
        reg = CircuitBreakerRegistry()
        cb = reg.register("test")
        assert isinstance(cb, CircuitBreaker)
        assert cb.name == "test"

    def test_register_idempotent(self) -> None:
        reg = CircuitBreakerRegistry()
        cb1 = reg.register("test")
        cb2 = reg.register("test")
        assert cb1 is cb2

    def test_register_with_config(self) -> None:
        reg = CircuitBreakerRegistry()
        config = CircuitBreakerConfig(failure_threshold=10)
        cb = reg.register("custom", config=config)
        assert cb._config.failure_threshold == 10

    def test_get_existing(self) -> None:
        reg = CircuitBreakerRegistry()
        cb = reg.register("test")
        assert reg.get("test") is cb

    def test_get_nonexistent(self) -> None:
        reg = CircuitBreakerRegistry()
        assert reg.get("ghost") is None

    def test_get_qdv(self) -> None:
        reg = CircuitBreakerRegistry()
        reg.register("a")
        reg.register("b")
        qdv = reg.get_qdv()
        assert isinstance(qdv, QDVMetric)
        assert "a" in qdv.component_scores
        assert "b" in qdv.component_scores

    def test_get_qdv_reflects_state(self) -> None:
        reg = CircuitBreakerRegistry()
        cb = reg.register("tripped", CircuitBreakerConfig(failure_threshold=1))
        cb.record_failure()
        qdv = reg.get_qdv()
        assert qdv.component_scores["tripped"] == QualityLevel.CRITICAL

    def test_multiple_breakers(self) -> None:
        reg = CircuitBreakerRegistry()
        cb1 = reg.register("alpha")
        cb2 = reg.register("beta")
        assert cb1 is not cb2
        assert reg.get("alpha") is cb1
        assert reg.get("beta") is cb2


# ---------------------------------------------------------------------------
# AnomalyCircuitBridge
# ---------------------------------------------------------------------------


class TestAnomalyCircuitBridge:
    def test_consecutive_anomalies_trigger_failure(self) -> None:
        cb = _make_breaker(failure_threshold=1)
        bridge = AnomalyCircuitBridge(breaker=cb, anomaly_threshold=3)

        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        assert cb.state == CircuitState.CLOSED

        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        # 3 consecutive anomalies -> 1 failure recorded -> trips breaker
        assert cb.state == CircuitState.OPEN

    def test_non_anomalous_resets_counter(self) -> None:
        cb = _make_breaker(failure_threshold=1)
        bridge = AnomalyCircuitBridge(breaker=cb, anomaly_threshold=3)

        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=False))  # reset
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))

        assert cb.state == CircuitState.CLOSED  # never reached 3 consecutive

    def test_non_anomalous_records_success(self) -> None:
        cb = _make_breaker(
            failure_threshold=2,
            recovery_timeout_s=0.01,
            success_threshold=1,
        )
        # Trip the breaker
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.05)
        assert cb.state == CircuitState.HALF_OPEN

        bridge = AnomalyCircuitBridge(breaker=cb, anomaly_threshold=3)
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=False))
        # Success recorded -> HALF_OPEN -> CLOSED
        assert cb.state == CircuitState.CLOSED

    def test_counter_resets_after_triggering_failure(self) -> None:
        cb = _make_breaker(failure_threshold=10)
        bridge = AnomalyCircuitBridge(breaker=cb, anomaly_threshold=2)

        # First batch: 2 anomalies -> 1 failure, counter resets
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        # Second batch: 2 more anomalies -> 1 more failure
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        bridge.on_anomaly(FakeAnomalyResult(is_anomalous=True))
        # Total: 2 failures recorded, breaker still closed (threshold=10)
        assert cb.state == CircuitState.CLOSED


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestCircuitBreakerThreadSafety:
    def test_concurrent_record_and_check(self) -> None:
        cb = _make_breaker(failure_threshold=50, window_s=60.0)
        errors: list[Exception] = []

        def recorder():
            try:
                for _ in range(100):
                    cb.record_failure()
            except Exception as exc:
                errors.append(exc)

        def checker():
            try:
                for _ in range(100):
                    with contextlib.suppress(CircuitOpenError):
                        cb.check_allowed()
            except Exception as exc:
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

    def test_concurrent_registry_register(self) -> None:
        reg = CircuitBreakerRegistry()
        errors: list[Exception] = []

        def worker(name: str):
            try:
                for _ in range(50):
                    reg.register(name)
                    reg.get(name)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(f"cb-{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
