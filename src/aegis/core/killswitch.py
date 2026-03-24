"""Runtime kill switch for AI agents.

A non-bypassable circuit breaker that lives outside the agent reasoning
path.  When triggered, it blocks ALL further agent actions until manually
reset by a human operator.

Triggers:
- Cost threshold exceeded
- Error rate spike
- Anomaly detection alert
- Forbidden action attempted
- Manual activation
- Time-based auto-shutdown

Usage::

    from aegis.core.killswitch import KillSwitch

    ks = KillSwitch(
        max_cost_usd=100.0,
        max_error_rate=0.5,
        max_actions_per_minute=60,
        forbidden_actions=["delete_database", "rm_rf"],
    )

    # Before every agent action:
    ks.check_or_raise(action_type="read_file", cost_usd=0.01)

    # Manual trigger:
    ks.trigger("Suspicious behavior detected by operator")

    # Reset (requires explicit human action):
    ks.reset()
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field

logger = logging.getLogger("aegis.killswitch")


class KillSwitchTriggered(Exception):
    """Raised when the kill switch has been activated."""

    def __init__(self, reason: str, triggered_at: float) -> None:
        self.reason = reason
        self.triggered_at = triggered_at
        super().__init__(f"Kill switch triggered: {reason}")


@dataclass(frozen=True)
class KillSwitchStatus:
    """Current state of the kill switch."""

    triggered: bool
    reason: str | None
    triggered_at: float | None
    total_actions: int
    total_cost_usd: float
    total_errors: int
    actions_last_minute: int


class KillSwitch:
    """Runtime kill switch — the last line of defense.

    Once triggered, ALL actions are blocked until :meth:`reset` is called
    explicitly.  The kill switch cannot be bypassed by the agent.

    Args:
        max_cost_usd: Maximum cumulative cost before auto-trigger.
            ``None`` disables cost-based triggering.
        max_error_rate: Maximum error ratio (0.0-1.0) over the last
            ``error_window`` actions before auto-trigger.  ``None``
            disables error-rate triggering.
        error_window: Number of recent actions to consider for error
            rate calculation.
        max_actions_per_minute: Maximum actions per rolling minute.
            ``None`` disables rate-based triggering.
        forbidden_actions: Action types that trigger the kill switch
            immediately when attempted.
        auto_shutdown_after: Automatically trigger after this many
            seconds of runtime.  ``None`` disables.
        on_trigger: Optional callback invoked when the switch trips.
            Receives ``(reason: str, status: KillSwitchStatus)``.
    """

    def __init__(
        self,
        *,
        max_cost_usd: float | None = None,
        max_error_rate: float | None = None,
        error_window: int = 20,
        max_actions_per_minute: int | None = None,
        forbidden_actions: list[str] | None = None,
        auto_shutdown_after: float | None = None,
        on_trigger: object | None = None,
    ) -> None:
        self._max_cost = max_cost_usd
        self._max_error_rate = max_error_rate
        self._error_window = max(error_window, 1)
        self._max_actions_per_minute = max_actions_per_minute
        self._forbidden: frozenset[str] = frozenset(forbidden_actions or [])
        self._auto_shutdown_after = auto_shutdown_after
        self._on_trigger = on_trigger

        # State (all guarded by _lock)
        self._lock = threading.Lock()
        self._triggered = False
        self._trigger_reason: str | None = None
        self._triggered_at: float | None = None

        # Counters
        self._total_actions = 0
        self._total_cost = 0.0
        self._total_errors = 0
        self._error_history: deque[bool] = deque(maxlen=self._error_window)
        self._action_timestamps: deque[float] = deque()

        self._start_time = time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_or_raise(
        self,
        *,
        action_type: str = "",
        cost_usd: float = 0.0,
        is_error: bool = False,
    ) -> None:
        """Check all triggers and raise if the kill switch is active.

        Call this before every agent action.  It is designed to be fast
        (~microseconds when not triggered).

        Args:
            action_type: The action being attempted.
            cost_usd: Cost of this action (added to cumulative total).
            is_error: Whether this action resulted in an error.

        Raises:
            KillSwitchTriggered: If the kill switch is active or gets
                triggered by this check.
        """
        with self._lock:
            # Already triggered — fast path
            if self._triggered:
                raise KillSwitchTriggered(
                    self._trigger_reason or "unknown",
                    self._triggered_at or 0.0,
                )

            now = time.monotonic()

            # Update counters
            self._total_actions += 1
            self._total_cost += cost_usd
            self._error_history.append(is_error)
            if is_error:
                self._total_errors += 1
            self._action_timestamps.append(now)

            # Prune old timestamps (older than 60s)
            cutoff = now - 60.0
            while self._action_timestamps and self._action_timestamps[0] < cutoff:
                self._action_timestamps.popleft()

            # --- Check triggers ---

            # 1. Forbidden action
            if action_type and action_type in self._forbidden:
                self._do_trigger(f"Forbidden action attempted: {action_type}")

            # 2. Cost threshold
            if self._max_cost is not None and self._total_cost > self._max_cost:
                self._do_trigger(
                    f"Cost threshold exceeded: ${self._total_cost:.2f} > ${self._max_cost:.2f}"
                )

            # 3. Error rate
            if (
                self._max_error_rate is not None
                and len(self._error_history) >= self._error_window
            ):
                error_rate = sum(self._error_history) / len(self._error_history)
                if error_rate > self._max_error_rate:
                    self._do_trigger(
                        f"Error rate exceeded: {error_rate:.1%} > {self._max_error_rate:.1%}"
                    )

            # 4. Actions per minute
            if self._max_actions_per_minute is not None:
                if len(self._action_timestamps) > self._max_actions_per_minute:
                    self._do_trigger(
                        f"Rate exceeded: {len(self._action_timestamps)}/min "
                        f"> {self._max_actions_per_minute}/min"
                    )

            # 5. Auto-shutdown timeout
            if self._auto_shutdown_after is not None:
                elapsed = now - self._start_time
                if elapsed > self._auto_shutdown_after:
                    self._do_trigger(
                        f"Auto-shutdown after {elapsed:.0f}s "
                        f"(limit: {self._auto_shutdown_after:.0f}s)"
                    )

            # If any trigger fired, raise
            if self._triggered:
                raise KillSwitchTriggered(
                    self._trigger_reason or "unknown",
                    self._triggered_at or 0.0,
                )

    def trigger(self, reason: str = "Manual activation") -> None:
        """Manually activate the kill switch.

        Args:
            reason: Human-readable reason for activation.
        """
        with self._lock:
            self._do_trigger(reason)

    def reset(self) -> None:
        """Reset the kill switch.  Requires explicit human action.

        Clears the triggered state and all counters.
        """
        with self._lock:
            self._triggered = False
            self._trigger_reason = None
            self._triggered_at = None
            self._total_actions = 0
            self._total_cost = 0.0
            self._total_errors = 0
            self._error_history.clear()
            self._action_timestamps.clear()
            self._start_time = time.monotonic()
            logger.info("Kill switch reset")

    @property
    def is_triggered(self) -> bool:
        """Whether the kill switch is currently active."""
        with self._lock:
            return self._triggered

    @property
    def status(self) -> KillSwitchStatus:
        """Current kill switch status snapshot."""
        with self._lock:
            now = time.monotonic()
            cutoff = now - 60.0
            recent = sum(1 for t in self._action_timestamps if t >= cutoff)
            return KillSwitchStatus(
                triggered=self._triggered,
                reason=self._trigger_reason,
                triggered_at=self._triggered_at,
                total_actions=self._total_actions,
                total_cost_usd=self._total_cost,
                total_errors=self._total_errors,
                actions_last_minute=recent,
            )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _do_trigger(self, reason: str) -> None:
        """Activate the kill switch (must hold _lock)."""
        if self._triggered:
            return  # Already triggered
        self._triggered = True
        self._trigger_reason = reason
        self._triggered_at = time.monotonic()
        logger.critical("KILL SWITCH TRIGGERED: %s", reason)

        if self._on_trigger is not None:
            try:
                self._on_trigger(reason, self.status)  # type: ignore[operator]
            except Exception:
                logger.warning("Kill switch on_trigger callback failed", exc_info=True)
