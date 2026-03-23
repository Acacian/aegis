"""Cost circuit breaker for AI agent sessions.

Tracks dollar-denominated costs across LLM calls and enforces budget
limits with configurable thresholds. Designed as a pre-execution gate
that integrates with the Aegis policy engine.

Thread-safe: all balance mutations are guarded by a lock.

Example::

    tracker = CostTracker(max_budget=5.00)
    tracker.record(TokenUsage(model="gpt-4o", input_tokens=1000, output_tokens=200))
    print(tracker.spent)       # 0.00575
    print(tracker.remaining)   # 4.99425

    # With thresholds
    tracker = CostTracker(
        max_budget=10.00,
        warn_threshold=0.8,     # warn at 80%
        soft_threshold=0.9,     # soft limit at 90%
    )
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class BudgetExhausted(RuntimeError):
    """Raised when a cost tracker's budget has been exceeded."""

    def __init__(
        self,
        budget: float,
        spent: float,
        *,
        model: str = "",
        session_id: str = "",
    ) -> None:
        self.budget = budget
        self.spent = spent
        self.model = model
        self.session_id = session_id
        super().__init__(
            f"Budget exhausted: spent ${spent:.4f} of ${budget:.2f}"
            f"{f' (model={model})' if model else ''}"
        )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class BudgetAction(StrEnum):
    """Action to take when a budget threshold is reached."""

    OK = "ok"
    WARN = "warn"
    SOFT_LIMIT = "soft_limit"
    HARD_LIMIT = "hard_limit"
    LOOP_DETECTED = "loop_detected"


@dataclass(frozen=True)
class TokenUsage:
    """Token usage from a single LLM call.

    Attributes:
        model: Model identifier (e.g. ``"gpt-4o"``, ``"claude-sonnet-4-20250514"``).
        input_tokens: Number of input/prompt tokens.
        output_tokens: Number of output/completion tokens.
        cached_tokens: Number of cached input tokens (lower cost).
        reasoning_tokens: Number of reasoning tokens (if applicable).
    """

    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    reasoning_tokens: int = 0


@dataclass(frozen=True)
class CostRecord:
    """A single cost event in the tracker's ledger."""

    timestamp: float
    model: str
    input_tokens: int
    output_tokens: int
    cost: float
    cumulative: float
    agent_id: str = ""
    action_type: str = ""
    session_id: str = ""


# ---------------------------------------------------------------------------
# Model pricing table (per million tokens, March 2026)
# ---------------------------------------------------------------------------

# Format: "model_prefix": (input_per_million, output_per_million, cached_per_million)
_PRICING: dict[str, tuple[float, float, float]] = {
    # OpenAI
    "gpt-4o": (2.50, 10.00, 1.25),
    "gpt-4o-mini": (0.15, 0.60, 0.075),
    "gpt-4-turbo": (10.00, 30.00, 5.00),
    "gpt-4.1": (2.00, 8.00, 0.50),
    "gpt-4.1-mini": (0.40, 1.60, 0.10),
    "gpt-4.1-nano": (0.10, 0.40, 0.025),
    "o1": (15.00, 60.00, 7.50),
    "o1-mini": (1.10, 4.40, 0.55),
    "o3": (10.00, 40.00, 2.50),
    "o3-mini": (1.10, 4.40, 0.55),
    "o4-mini": (1.10, 4.40, 0.55),
    # Anthropic
    "claude-opus-4": (15.00, 75.00, 1.50),
    "claude-sonnet-4": (3.00, 15.00, 0.30),
    "claude-haiku-3.5": (0.80, 4.00, 0.08),
    # Google
    "gemini-2.0-flash": (0.10, 0.40, 0.025),
    "gemini-2.5-pro": (1.25, 10.00, 0.3125),
    "gemini-2.5-flash": (0.15, 0.60, 0.0375),
}


class ModelPricing:
    """Model pricing lookup with user override support."""

    def __init__(self) -> None:
        self._table: dict[str, tuple[float, float, float]] = dict(_PRICING)

    def register(
        self,
        model: str,
        input_per_million: float,
        output_per_million: float,
        cached_per_million: float = 0.0,
    ) -> None:
        """Register or override pricing for a model."""
        self._table[model] = (
            input_per_million,
            output_per_million,
            cached_per_million,
        )

    def cost(self, usage: TokenUsage) -> float:
        """Calculate the dollar cost for a token usage record.

        Uses longest-prefix matching to find the pricing entry.
        Falls back to gpt-4o pricing if no match is found.
        """
        rate = self._resolve(usage.model)
        input_rate, output_rate, cached_rate = rate

        regular_input = max(0, usage.input_tokens - usage.cached_tokens)
        cost = (
            regular_input * input_rate / 1_000_000
            + usage.cached_tokens * (cached_rate or input_rate) / 1_000_000
            + usage.output_tokens * output_rate / 1_000_000
        )
        return cost

    def _resolve(self, model: str) -> tuple[float, float, float]:
        """Resolve pricing for a model using longest-prefix matching."""
        if model in self._table:
            return self._table[model]

        # Longest prefix match
        best_key = ""
        for key in self._table:
            if model.startswith(key) and len(key) > len(best_key):
                best_key = key
        if best_key:
            return self._table[best_key]

        # Fallback
        return self._table.get("gpt-4o", (2.50, 10.00, 1.25))


# ---------------------------------------------------------------------------
# Loop detector
# ---------------------------------------------------------------------------

_LOOP_WINDOW = 60.0  # seconds
_LOOP_THRESHOLD = 5  # identical calls within window


@dataclass
class _LoopEntry:
    """Tracks repeated identical calls."""

    key: str
    timestamps: list[float] = field(default_factory=list)


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------


class CostTracker:
    """Tracks cumulative costs and enforces budget limits.

    Args:
        max_budget: Maximum allowed spend in dollars. ``0`` = unlimited.
        warn_threshold: Fraction (0-1) of budget that triggers a warning.
        soft_threshold: Fraction (0-1) of budget that triggers soft limit.
        session_id: Optional session identifier for audit correlation.
        pricing: Optional custom pricing instance.
        on_warn: Callback invoked when warn threshold is reached.
        on_soft_limit: Callback invoked when soft threshold is reached.
        loop_window: Seconds for loop detection window.
        loop_threshold: Number of identical calls to trigger loop detection.
    """

    def __init__(
        self,
        max_budget: float = 0.0,
        *,
        warn_threshold: float = 0.8,
        soft_threshold: float = 0.9,
        session_id: str = "",
        pricing: ModelPricing | None = None,
        on_warn: Callable[[CostRecord], Any] | None = None,
        on_soft_limit: Callable[[CostRecord], Any] | None = None,
        loop_window: float = _LOOP_WINDOW,
        loop_threshold: int = _LOOP_THRESHOLD,
    ) -> None:
        self.max_budget = max_budget
        self.warn_threshold = warn_threshold
        self.soft_threshold = soft_threshold
        self.session_id = session_id
        self._pricing = pricing or ModelPricing()
        self._on_warn = on_warn
        self._on_soft_limit = on_soft_limit
        self._loop_window = loop_window
        self._loop_threshold = loop_threshold

        self._spent: float = 0.0
        self._records: list[CostRecord] = []
        self._loop_entries: dict[str, _LoopEntry] = {}
        self._lock = threading.Lock()

    # -- Public properties --------------------------------------------------

    @property
    def spent(self) -> float:
        """Total dollars spent so far."""
        return self._spent

    @property
    def remaining(self) -> float:
        """Dollars remaining in budget. ``float('inf')`` if unlimited."""
        if self.max_budget <= 0:
            return float("inf")
        return max(0.0, self.max_budget - self._spent)

    @property
    def utilization(self) -> float:
        """Budget utilization as a fraction (0-1). ``0`` if unlimited."""
        if self.max_budget <= 0:
            return 0.0
        return min(1.0, self._spent / self.max_budget)

    @property
    def records(self) -> list[CostRecord]:
        """Copy of all cost records."""
        return list(self._records)

    # -- Core methods -------------------------------------------------------

    def check_budget(self, estimated_cost: float = 0.0) -> BudgetAction:
        """Check budget status without recording anything.

        Args:
            estimated_cost: Estimated cost of the next call.

        Returns:
            The action that would be taken.
        """
        if self.max_budget <= 0:
            return BudgetAction.OK

        projected = self._spent + estimated_cost
        if projected >= self.max_budget:
            return BudgetAction.HARD_LIMIT
        if self.max_budget > 0 and projected / self.max_budget >= self.soft_threshold:
            return BudgetAction.SOFT_LIMIT
        if self.max_budget > 0 and projected / self.max_budget >= self.warn_threshold:
            return BudgetAction.WARN
        return BudgetAction.OK

    def record(
        self,
        usage: TokenUsage,
        *,
        agent_id: str = "",
        action_type: str = "",
    ) -> CostRecord:
        """Record a token usage and enforce budget limits.

        Args:
            usage: Token usage from an LLM call.
            agent_id: Optional agent identifier.
            action_type: Optional action type for audit.

        Returns:
            The recorded cost entry.

        Raises:
            BudgetExhausted: If the hard budget limit is exceeded.
        """
        cost = self._pricing.cost(usage)

        with self._lock:
            # Loop detection
            loop_key = f"{usage.model}:{agent_id}:{action_type}"
            self._check_loop(loop_key)

            self._spent += cost
            record = CostRecord(
                timestamp=time.time(),
                model=usage.model,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cost=cost,
                cumulative=self._spent,
                agent_id=agent_id,
                action_type=action_type,
                session_id=self.session_id,
            )
            self._records.append(record)

            # Check thresholds
            self._evaluate_thresholds(record)
            return record

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate the cost of a hypothetical call."""
        usage = TokenUsage(model=model, input_tokens=input_tokens, output_tokens=output_tokens)
        return self._pricing.cost(usage)

    def get_report(self) -> dict[str, Any]:
        """Generate a structured cost report."""
        by_model: dict[str, float] = {}
        by_agent: dict[str, float] = {}

        for r in self._records:
            by_model[r.model] = by_model.get(r.model, 0.0) + r.cost
            if r.agent_id:
                by_agent[r.agent_id] = by_agent.get(r.agent_id, 0.0) + r.cost

        return {
            "session_id": self.session_id,
            "max_budget": self.max_budget,
            "spent": round(self._spent, 6),
            "remaining": round(self.remaining, 6) if self.remaining != float("inf") else None,
            "utilization": round(self.utilization, 4),
            "call_count": len(self._records),
            "by_model": {k: round(v, 6) for k, v in sorted(by_model.items())},
            "by_agent": {k: round(v, 6) for k, v in sorted(by_agent.items())},
        }

    def child(self, max_budget: float, *, session_id: str = "") -> CostTracker:
        """Create a child tracker whose costs roll up to this parent.

        The child's budget cannot exceed this tracker's remaining budget.
        """
        effective = min(max_budget, self.remaining) if self.max_budget > 0 else max_budget
        child = CostTracker(
            max_budget=effective,
            warn_threshold=self.warn_threshold,
            soft_threshold=self.soft_threshold,
            session_id=session_id or self.session_id,
            pricing=self._pricing,
        )
        child._parent = self  # type: ignore[attr-defined]
        return child

    # -- Internal -----------------------------------------------------------

    def _evaluate_thresholds(self, record: CostRecord) -> BudgetAction:
        """Evaluate thresholds and fire callbacks / raise exceptions."""
        if self.max_budget <= 0:
            return BudgetAction.OK

        util = self.utilization

        if util >= 1.0:
            raise BudgetExhausted(
                self.max_budget,
                self._spent,
                model=record.model,
                session_id=self.session_id,
            )

        if util >= self.soft_threshold:
            if self._on_soft_limit:
                self._on_soft_limit(record)
            # Also propagate to parent if exists
            parent = getattr(self, "_parent", None)
            if parent is not None:
                parent.record(
                    TokenUsage(
                        model=record.model,
                        input_tokens=record.input_tokens,
                        output_tokens=record.output_tokens,
                    ),
                    agent_id=record.agent_id,
                    action_type=record.action_type,
                )
            return BudgetAction.SOFT_LIMIT

        if util >= self.warn_threshold:
            if self._on_warn:
                self._on_warn(record)
            return BudgetAction.WARN

        # Propagate cost to parent
        parent = getattr(self, "_parent", None)
        if parent is not None:
            parent.record(
                TokenUsage(
                    model=record.model,
                    input_tokens=record.input_tokens,
                    output_tokens=record.output_tokens,
                ),
                agent_id=record.agent_id,
                action_type=record.action_type,
            )

        return BudgetAction.OK

    def _check_loop(self, key: str) -> None:
        """Detect repeated identical calls within the loop window."""
        now = time.time()
        entry = self._loop_entries.get(key)
        if entry is None:
            entry = _LoopEntry(key=key)
            self._loop_entries[key] = entry

        # Prune old timestamps
        cutoff = now - self._loop_window
        entry.timestamps = [t for t in entry.timestamps if t > cutoff]
        entry.timestamps.append(now)

        if len(entry.timestamps) >= self._loop_threshold:
            raise BudgetExhausted(
                self.max_budget,
                self._spent,
                model=key.split(":")[0],
                session_id=self.session_id,
            )
