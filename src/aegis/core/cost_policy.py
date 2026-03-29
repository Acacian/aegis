"""Cost governance as a policy dimension.

Integrates cost tracking with the policy engine so that budget limits
are enforced alongside security guardrails in a single governance
pipeline.

The :class:`CostPolicyEnforcer` evaluates every LLM call against
multiple cost dimensions (per-call, per-session, daily, per-minute
tokens) and returns a :class:`CostDecision` that mirrors the
policy engine's ALLOW/BLOCK/WARN pattern.

Thread-safe: all mutable state is guarded by the same locking pattern
used in :mod:`aegis.core.budget`.

Example::

    from aegis.config import CostConfig
    from aegis.core.cost_policy import CostPolicyEnforcer

    enforcer = CostPolicyEnforcer(CostConfig(
        budget_usd=100.0,
        per_session_limit_usd=5.0,
        daily_budget_usd=50.0,
        per_minute_tokens=100_000,
        on_exceed="block",
    ))

    decision = enforcer.check_and_record(usage)
    if decision.blocked:
        raise RuntimeError(decision.reason)
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aegis.config import CostConfig
from aegis.core.budget import (
    BudgetExhausted,
    CostTracker,
    ModelPricing,
    TokenUsage,
)

logger = logging.getLogger("aegis.cost_policy")


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------


class CostAction(StrEnum):
    """Action resulting from cost policy evaluation."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class CostDecision:
    """Result of a cost policy check.

    Attributes:
        action: Whether the call is allowed, warned, or blocked.
        reason: Human-readable explanation of the decision.
        dimension: Which limit was hit (e.g. ``"per_call"``, ``"daily"``).
        cost_usd: Dollar cost of the evaluated call.
        cumulative_usd: Total session spend after this call.
    """

    action: CostAction
    reason: str = ""
    dimension: str = ""
    cost_usd: float = 0.0
    cumulative_usd: float = 0.0

    @property
    def allowed(self) -> bool:
        """Whether the call should proceed."""
        return self.action != CostAction.BLOCK

    @property
    def blocked(self) -> bool:
        """Whether the call should be stopped."""
        return self.action == CostAction.BLOCK


# ---------------------------------------------------------------------------
# Token-rate tracker (rolling-window)
# ---------------------------------------------------------------------------


class _TokenRateTracker:
    """Tracks token consumption in a rolling 60-second window.

    Thread-safety is provided by the caller (CostPolicyEnforcer._lock).
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        self._window = window_seconds
        self._entries: deque[tuple[float, int]] = deque()

    def add(self, tokens: int, now: float | None = None) -> None:
        """Record *tokens* consumed at the current time."""
        ts = now if now is not None else time.time()
        self._entries.append((ts, tokens))

    def total_in_window(self, now: float | None = None) -> int:
        """Return total tokens consumed in the last *window_seconds*."""
        ts = now if now is not None else time.time()
        cutoff = ts - self._window
        # Prune old entries
        while self._entries and self._entries[0][0] < cutoff:
            self._entries.popleft()
        return sum(t for _, t in self._entries)


# ---------------------------------------------------------------------------
# Daily tracker
# ---------------------------------------------------------------------------


class _DailyTracker:
    """Tracks daily cost accumulation, resetting at midnight UTC.

    Thread-safety is provided by the caller (CostPolicyEnforcer._lock).
    """

    def __init__(self) -> None:
        self._day_key: str = ""
        self._spent: float = 0.0

    def _current_day(self, now: float | None = None) -> str:
        ts = now if now is not None else time.time()
        return time.strftime("%Y-%m-%d", time.gmtime(ts))

    def add(self, cost: float, now: float | None = None) -> float:
        """Record *cost* and return the new daily total."""
        day = self._current_day(now)
        if day != self._day_key:
            self._day_key = day
            self._spent = 0.0
        self._spent += cost
        return self._spent

    @property
    def spent_today(self) -> float:
        """Current day's accumulated spend."""
        day = self._current_day()
        if day != self._day_key:
            return 0.0
        return self._spent


# ---------------------------------------------------------------------------
# CostPolicyEnforcer
# ---------------------------------------------------------------------------


class CostPolicyEnforcer:
    """Evaluates LLM calls against cost policy dimensions.

    Wraps an existing :class:`CostTracker` and adds per-session,
    daily, and per-minute-token enforcement on top of the tracker's
    built-in budget.

    Args:
        config: Cost configuration from ``aegis.yaml``.
        pricing: Optional custom pricing instance.
        session_id: Session identifier for audit correlation.
    """

    def __init__(
        self,
        config: CostConfig,
        *,
        pricing: ModelPricing | None = None,
        session_id: str = "",
    ) -> None:
        self._config = config
        self._pricing = pricing or ModelPricing()
        self._session_id = session_id
        self._lock = threading.Lock()

        # Core tracker with overall budget
        self._tracker = CostTracker(
            max_budget=config.budget_usd or 0.0,
            warn_threshold=config.alert_threshold,
            session_id=session_id,
            pricing=self._pricing,
        )

        # Per-minute token rate tracker
        self._token_rate = _TokenRateTracker(window_seconds=60.0)

        # Daily spend tracker
        self._daily = _DailyTracker()

        # Resolve on_exceed action
        self._on_exceed = self._resolve_action(config.on_exceed)

    # -- Public interface ---------------------------------------------------

    @property
    def config(self) -> CostConfig:
        """The cost configuration."""
        return self._config

    @property
    def tracker(self) -> CostTracker:
        """The underlying CostTracker."""
        return self._tracker

    @property
    def session_spent(self) -> float:
        """Total dollars spent in this session."""
        return self._tracker.spent

    @property
    def daily_spent(self) -> float:
        """Total dollars spent today (UTC)."""
        with self._lock:
            return self._daily.spent_today

    def estimate_cost(self, usage: TokenUsage) -> float:
        """Estimate the dollar cost of a token usage without recording."""
        return self._pricing.cost(usage)

    def pre_check(self, usage: TokenUsage) -> CostDecision:
        """Check cost limits *before* executing a call.

        Does not record the cost. Use this for pre-flight checks.
        """
        cost = self._pricing.cost(usage)
        total_tokens = usage.input_tokens + usage.output_tokens
        now = time.time()

        with self._lock:
            return self._evaluate(cost, total_tokens, now, record=False)

    def check_and_record(
        self,
        usage: TokenUsage,
        *,
        agent_id: str = "",
        action_type: str = "",
    ) -> CostDecision:
        """Check cost limits and record the usage if allowed.

        This is the main entry point for the cost governance pipeline.
        Returns a :class:`CostDecision` indicating whether the call
        should proceed.

        If ``on_exceed`` is ``block`` and a limit is hit, the usage is
        **not** recorded (the call should not have happened).

        If ``on_exceed`` is ``warn`` or ``log``, the usage is recorded
        regardless, but the decision carries a warning.
        """
        cost = self._pricing.cost(usage)
        total_tokens = usage.input_tokens + usage.output_tokens
        now = time.time()

        with self._lock:
            decision = self._evaluate(cost, total_tokens, now, record=False)

            if decision.blocked:
                # Blocked: do not record
                return decision

            # Record the cost
            try:
                record = self._tracker.record(
                    usage,
                    agent_id=agent_id,
                    action_type=action_type,
                )
            except BudgetExhausted as exc:
                return CostDecision(
                    action=CostAction.BLOCK,
                    reason=str(exc),
                    dimension="budget",
                    cost_usd=cost,
                    cumulative_usd=self._tracker.spent,
                )

            # Update auxiliary trackers
            self._token_rate.add(total_tokens, now)
            self._daily.add(cost, now)

            if decision.action == CostAction.WARN:
                return CostDecision(
                    action=CostAction.WARN,
                    reason=decision.reason,
                    dimension=decision.dimension,
                    cost_usd=cost,
                    cumulative_usd=record.cumulative,
                )

            return CostDecision(
                action=CostAction.ALLOW,
                reason="",
                cost_usd=cost,
                cumulative_usd=record.cumulative,
            )

    def get_report(self) -> dict[str, Any]:
        """Generate a cost governance report."""
        base = self._tracker.get_report()
        with self._lock:
            base["daily_spent"] = round(self._daily.spent_today, 6)
            base["tokens_last_minute"] = self._token_rate.total_in_window()
            base["limits"] = {
                "budget_usd": self._config.budget_usd,
                "per_call_limit_usd": self._config.per_call_limit_usd,
                "per_session_limit_usd": self._config.per_session_limit_usd,
                "daily_budget_usd": self._config.daily_budget_usd,
                "per_minute_tokens": self._config.per_minute_tokens,
                "on_exceed": self._config.on_exceed,
            }
        return base

    # -- Internal -----------------------------------------------------------

    def _evaluate(
        self,
        cost: float,
        total_tokens: int,
        now: float,
        *,
        record: bool = False,
    ) -> CostDecision:
        """Evaluate all cost dimensions (caller must hold _lock).

        Returns the most restrictive decision across all dimensions.
        """
        cfg = self._config

        # 1. Per-call limit
        if cfg.per_call_limit_usd is not None and cost > cfg.per_call_limit_usd:
            return self._make_decision(
                dimension="per_call",
                reason=(
                    f"Call cost ${cost:.4f} exceeds per-call limit ${cfg.per_call_limit_usd:.4f}"
                ),
                cost_usd=cost,
            )

        # 2. Per-session limit
        if cfg.per_session_limit_usd is not None:
            projected = self._tracker.spent + cost
            if projected > cfg.per_session_limit_usd:
                return self._make_decision(
                    dimension="per_session",
                    reason=(
                        f"Session spend ${projected:.4f} would exceed "
                        f"per-session limit ${cfg.per_session_limit_usd:.4f}"
                    ),
                    cost_usd=cost,
                )

        # 3. Daily budget
        if cfg.daily_budget_usd is not None:
            projected_daily = self._daily.spent_today + cost
            if projected_daily > cfg.daily_budget_usd:
                return self._make_decision(
                    dimension="daily",
                    reason=(
                        f"Daily spend ${projected_daily:.4f} would exceed "
                        f"daily budget ${cfg.daily_budget_usd:.4f}"
                    ),
                    cost_usd=cost,
                )

        # 4. Per-minute token rate
        if cfg.per_minute_tokens is not None:
            current_rate = self._token_rate.total_in_window(now)
            projected_rate = current_rate + total_tokens
            if projected_rate > cfg.per_minute_tokens:
                return self._make_decision(
                    dimension="per_minute_tokens",
                    reason=(
                        f"Token rate {projected_rate} would exceed "
                        f"per-minute limit {cfg.per_minute_tokens}"
                    ),
                    cost_usd=cost,
                )

        # 5. Overall budget (via alert_threshold for warn)
        if cfg.budget_usd is not None and cfg.budget_usd > 0:
            projected = self._tracker.spent + cost
            utilization = projected / cfg.budget_usd
            if projected > cfg.budget_usd:
                return self._make_decision(
                    dimension="budget",
                    reason=(
                        f"Total spend ${projected:.4f} would exceed budget ${cfg.budget_usd:.4f}"
                    ),
                    cost_usd=cost,
                )
            if utilization >= cfg.alert_threshold:
                return CostDecision(
                    action=CostAction.WARN,
                    reason=(
                        f"Budget utilization {utilization:.0%} exceeds "
                        f"alert threshold {cfg.alert_threshold:.0%}"
                    ),
                    dimension="budget_alert",
                    cost_usd=cost,
                    cumulative_usd=projected,
                )

        return CostDecision(
            action=CostAction.ALLOW,
            cost_usd=cost,
            cumulative_usd=self._tracker.spent + cost,
        )

    def _make_decision(
        self,
        *,
        dimension: str,
        reason: str,
        cost_usd: float,
    ) -> CostDecision:
        """Create a decision based on the on_exceed policy."""
        return CostDecision(
            action=self._on_exceed,
            reason=reason,
            dimension=dimension,
            cost_usd=cost_usd,
            cumulative_usd=self._tracker.spent,
        )

    @staticmethod
    def _resolve_action(on_exceed: str) -> CostAction:
        """Map config string to CostAction."""
        mapping = {
            "block": CostAction.BLOCK,
            "warn": CostAction.WARN,
            "log": CostAction.WARN,  # log is treated as warn (non-blocking)
        }
        return mapping.get(on_exceed, CostAction.BLOCK)
