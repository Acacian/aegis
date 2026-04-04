"""Circuit Breaker -- fail-loud governance with quality degradation visibility.

Implements a per-component circuit breaker pattern that makes failures
*loud* instead of silent.  When a component degrades beyond its failure
threshold the breaker opens and subsequent calls raise
:class:`CircuitOpenError` immediately, forcing callers to handle the
outage explicitly rather than silently degrading.

State machine::

    CLOSED  ──(failures >= threshold)──►  OPEN
      ▲                                     │
      │                          (recovery_timeout_s elapsed)
      │                                     ▼
      └──(successes >= threshold)───  HALF_OPEN

Thread-safe: every mutation is guarded by a per-breaker or per-registry
:class:`threading.Lock`.

Usage::

    from aegis.core.circuit_breaker import (
        CircuitBreaker,
        CircuitBreakerConfig,
        CircuitBreakerRegistry,
        CircuitOpenError,
    )

    registry = CircuitBreakerRegistry()
    breaker = registry.register(
        "policy_evaluator",
        CircuitBreakerConfig(failure_threshold=3, recovery_timeout_s=30),
    )

    try:
        breaker.check_allowed()
        result = do_work()
        breaker.record_success()
    except CircuitOpenError:
        # Component is down -- fail loudly
        ...
    except Exception:
        breaker.record_failure()
        raise
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.anomaly import AnomalyResult

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class QualityLevel(IntEnum):
    """Component quality signal.

    NOMINAL: normal operation.
    DEGRADED: performance degradation or intermittent errors (warning).
    CRITICAL: severe failure requiring automatic intervention.
    """

    NOMINAL = 0
    DEGRADED = 1
    CRITICAL = 2


class CircuitState(StrEnum):
    """Circuit breaker state machine.

    CLOSED: normal -- all requests pass through.
    OPEN: tripped -- all requests rejected immediately (fail-loud).
    HALF_OPEN: recovery probe -- limited requests allowed through.
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class CircuitOpenError(Exception):
    """Raised when a call is attempted on an OPEN circuit (fail-loud)."""


# ---------------------------------------------------------------------------
# QDV Metric
# ---------------------------------------------------------------------------


@dataclass
class QDVMetric:
    """Quality Degradation Visibility -- system-wide quality indicator.

    Collapses per-component quality levels into a single score:

    * ``1.0`` -- all components NOMINAL
    * ``0.0`` -- all components CRITICAL
    """

    component_scores: dict[str, QualityLevel] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def score(self) -> float:
        """Compute overall QDV score (0.0--1.0)."""
        if not self.component_scores:
            return 1.0
        total = sum(
            1.0 - (level.value / QualityLevel.CRITICAL.value)
            for level in self.component_scores.values()
        )
        return total / len(self.component_scores)

    @property
    def worst_component(self) -> tuple[str, QualityLevel] | None:
        """Return the component with the worst quality level."""
        if not self.component_scores:
            return None
        return max(
            self.component_scores.items(),
            key=lambda x: x[1].value,
        )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class CircuitBreakerConfig:
    """Configuration for a single circuit breaker.

    Attributes:
        failure_threshold: Number of failures within *window_s* that
            trigger the CLOSED -> OPEN transition.
        recovery_timeout_s: Seconds the breaker stays OPEN before
            transitioning to HALF_OPEN.
        half_open_max_calls: Maximum probe calls allowed in HALF_OPEN
            before the quota is exhausted.
        success_threshold: Consecutive successes in HALF_OPEN needed
            to transition back to CLOSED.
        window_s: Sliding window (seconds) for counting failures.
    """

    failure_threshold: int = 5
    recovery_timeout_s: float = 60.0
    half_open_max_calls: int = 3
    success_threshold: int = 2
    window_s: float = 120.0


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Per-component circuit breaker with fail-loud semantics.

    When the breaker is OPEN, :meth:`check_allowed` raises
    :class:`CircuitOpenError` instead of silently failing -- callers
    must handle the outage explicitly.

    Args:
        name: Human-readable component identifier.
        config: Tuning knobs; ``None`` uses defaults.
        on_state_change: Optional callback ``(name, old, new) -> None``
            invoked on every state transition.
    """

    def __init__(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
        on_state_change: Any = None,
    ) -> None:
        self.name = name
        self._config = config or CircuitBreakerConfig()
        self._on_state_change = on_state_change
        self._state = CircuitState.CLOSED
        self._failure_times: deque[float] = deque()
        self._success_count = 0
        self._half_open_calls = 0
        self._opened_at: float = 0.0
        self._lock = threading.Lock()

    # -- public properties ---------------------------------------------------

    @property
    def state(self) -> CircuitState:
        """Current state (may trigger OPEN -> HALF_OPEN recovery check)."""
        with self._lock:
            self._check_recovery()
            return self._state

    @property
    def quality_level(self) -> QualityLevel:
        """Current quality level derived from circuit state."""
        state = self.state
        if state == CircuitState.CLOSED:
            recent = self._count_recent_failures()
            if recent > self._config.failure_threshold * 0.7:
                return QualityLevel.DEGRADED
            return QualityLevel.NOMINAL
        if state == CircuitState.HALF_OPEN:
            return QualityLevel.DEGRADED
        return QualityLevel.CRITICAL  # OPEN

    # -- recording -----------------------------------------------------------

    def record_success(self) -> None:
        """Record a successful call.

        In HALF_OPEN state, once *success_threshold* consecutive
        successes are recorded the breaker transitions back to CLOSED.
        """
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self._config.success_threshold:
                    self._transition(CircuitState.CLOSED)
                    self._failure_times.clear()
                    self._success_count = 0
                    self._half_open_calls = 0

    def record_failure(self) -> None:
        """Record a failed call.

        In HALF_OPEN state, any failure immediately reopens the breaker.
        In CLOSED state, if failures within the sliding window reach the
        threshold, the breaker opens.
        """
        with self._lock:
            now = time.monotonic()
            self._failure_times.append(now)
            self._trim_window(now)

            if self._state == CircuitState.HALF_OPEN:
                self._transition(CircuitState.OPEN)
                self._opened_at = now
                self._success_count = 0
                self._half_open_calls = 0
                return

            if (
                self._state == CircuitState.CLOSED
                and self._count_recent_failures() >= self._config.failure_threshold
            ):
                self._transition(CircuitState.OPEN)
                self._opened_at = now

    # -- gating --------------------------------------------------------------

    def check_allowed(self) -> bool:
        """Check whether a call is allowed through the breaker.

        Returns:
            ``True`` when the call may proceed.

        Raises:
            CircuitOpenError: When the breaker is OPEN or the HALF_OPEN
                probe quota is exhausted.
        """
        with self._lock:
            self._check_recovery()

            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls < self._config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                raise CircuitOpenError(f"Circuit '{self.name}' half-open quota exceeded")

            # OPEN
            raise CircuitOpenError(
                f"Circuit '{self.name}' is OPEN "
                f"(failures={self._count_recent_failures()}, "
                f"recovery in {self._time_to_recovery():.0f}s)"
            )

    # -- reset ---------------------------------------------------------------

    def reset(self) -> None:
        """Manually reset the breaker to CLOSED state."""
        with self._lock:
            self._transition(CircuitState.CLOSED)
            self._failure_times.clear()
            self._success_count = 0
            self._half_open_calls = 0
            self._opened_at = 0.0

    # -- internals -----------------------------------------------------------

    def _check_recovery(self) -> None:
        """Transition OPEN -> HALF_OPEN when the recovery timeout expires."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self._config.recovery_timeout_s:
                self._transition(CircuitState.HALF_OPEN)
                self._success_count = 0
                self._half_open_calls = 0

    def _count_recent_failures(self) -> int:
        now = time.monotonic()
        self._trim_window(now)
        return len(self._failure_times)

    def _trim_window(self, now: float) -> None:
        cutoff = now - self._config.window_s
        while self._failure_times and self._failure_times[0] < cutoff:
            self._failure_times.popleft()

    def _time_to_recovery(self) -> float:
        elapsed = time.monotonic() - self._opened_at
        return max(0.0, self._config.recovery_timeout_s - elapsed)

    def _transition(self, new_state: CircuitState) -> None:
        old_state = self._state
        self._state = new_state
        if self._on_state_change and old_state != new_state:
            self._on_state_change(self.name, old_state, new_state)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class CircuitBreakerRegistry:
    """Central registry for all circuit breakers.

    Manages per-component breakers and provides a system-wide
    :class:`QDVMetric` aggregation.
    """

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    def register(
        self,
        name: str,
        config: CircuitBreakerConfig | None = None,
    ) -> CircuitBreaker:
        """Register (or return existing) breaker for *name*."""
        with self._lock:
            if name in self._breakers:
                return self._breakers[name]
            breaker = CircuitBreaker(
                name=name,
                config=config,
                on_state_change=self._on_state_change,
            )
            self._breakers[name] = breaker
            return breaker

    def get(self, name: str) -> CircuitBreaker | None:
        """Return the breaker for *name*, or ``None``."""
        with self._lock:
            return self._breakers.get(name)

    def get_qdv(self) -> QDVMetric:
        """Compute system-wide QDV metric from all registered breakers."""
        with self._lock:
            scores = {name: breaker.quality_level for name, breaker in self._breakers.items()}
            return QDVMetric(component_scores=scores)

    # -- internal callback ---------------------------------------------------

    @staticmethod
    def _on_state_change(
        name: str,
        old_state: CircuitState,
        new_state: CircuitState,
    ) -> None:
        logger = logging.getLogger("aegis.circuit_breaker")

        if new_state == CircuitState.OPEN:
            logger.error(
                "CIRCUIT OPEN: %s (%s -> %s). All requests to this component will be rejected.",
                name,
                old_state,
                new_state,
            )
        elif new_state == CircuitState.HALF_OPEN:
            logger.warning(
                "CIRCUIT HALF-OPEN: %s -- attempting recovery",
                name,
            )
        elif new_state == CircuitState.CLOSED:
            logger.info(
                "CIRCUIT CLOSED: %s -- recovered from %s",
                name,
                old_state,
            )


# ---------------------------------------------------------------------------
# Anomaly bridge
# ---------------------------------------------------------------------------


class AnomalyCircuitBridge:
    """Bridge between :class:`~aegis.core.anomaly.AnomalyDetector` and :class:`CircuitBreaker`.

    Converts consecutive anomaly detections into circuit breaker failure
    signals.  When *anomaly_threshold* consecutive anomalies are observed
    the bridge records a single failure on the associated breaker; a
    non-anomalous result resets the counter and records a success.

    Args:
        breaker: The circuit breaker to drive.
        anomaly_threshold: Consecutive anomalies required before
            recording a failure on the breaker.
    """

    def __init__(
        self,
        breaker: CircuitBreaker,
        anomaly_threshold: int = 3,
    ) -> None:
        self._breaker = breaker
        self._threshold = anomaly_threshold
        self._consecutive_anomalies = 0

    def on_anomaly(self, result: AnomalyResult) -> None:
        """Process an anomaly result from the detector.

        Args:
            result: The :class:`~aegis.core.anomaly.AnomalyResult` to
                evaluate.
        """
        if result.is_anomalous:
            self._consecutive_anomalies += 1
            if self._consecutive_anomalies >= self._threshold:
                self._breaker.record_failure()
                self._consecutive_anomalies = 0
        else:
            self._consecutive_anomalies = 0
            self._breaker.record_success()
