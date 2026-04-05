"""Resource contracts for AI agent operations.

Inspired by the Agent Contracts framework (arXiv:2601.08815) -- formal
specifications of resource bounds that agents must obey during execution.

A contract declares the maximum resources an operation may consume
(LLM calls, tokens, cost, wall-clock time, tool invocations).  The
``@resource_contract`` decorator enforces these bounds at runtime,
raising :class:`ContractViolation` when a limit is breached.

Contracts compose: a parent contract's limits propagate to child
operations via ``child()`` (monotone constraint — children cannot
exceed the parent's remaining budget).

No external dependencies.  Thread-safe.

Reference:
    Agent Contracts: Verifiable Resource Bounds for AI Agents.
    arXiv:2601.08815 (2025).

Example::

    @resource_contract(max_calls=10, max_cost_usd=1.0, max_duration_s=30)
    async def research_task(query: str):
        ...

    monitor = ContractMonitor(ResourceContract(max_calls=100))
    monitor.record_call()
    assert monitor.remaining_calls == 99
"""

from __future__ import annotations

import asyncio
import functools
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ContractViolation(RuntimeError):
    """Raised when an agent operation breaches its resource contract.

    Attributes:
        contract_name: Name of the violated contract.
        dimension: Which limit was breached (e.g. ``"max_calls"``).
        limit: The configured limit.
        actual: The actual value at violation time.
    """

    def __init__(
        self,
        contract_name: str,
        dimension: str,
        limit: float,
        actual: float,
    ) -> None:
        self.contract_name = contract_name
        self.dimension = dimension
        self.limit = limit
        self.actual = actual
        super().__init__(
            f"Contract '{contract_name}' violated: {dimension} (limit={limit}, actual={actual})"
        )


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceContract:
    """Formal specification of resource bounds for an agent operation.

    All limits are optional — ``None`` means unconstrained.

    Attributes:
        name: Contract identifier.
        max_calls: Maximum number of LLM/tool calls.
        max_tokens: Maximum total tokens (input + output).
        max_cost_usd: Maximum dollar spend.
        max_duration_s: Maximum wall-clock seconds.
        max_tool_invocations: Maximum tool/function invocations.
        max_retries: Maximum retry attempts.
        on_violation: ``"raise"`` (default), ``"warn"``, or ``"log"``.
    """

    name: str = "default"
    max_calls: int | None = None
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    max_duration_s: float | None = None
    max_tool_invocations: int | None = None
    max_retries: int | None = None
    on_violation: str = "raise"


@dataclass(frozen=True)
class ContractStatus:
    """Snapshot of contract enforcement state.

    Attributes:
        contract_name: The contract being monitored.
        calls_used: LLM/tool calls consumed.
        tokens_used: Total tokens consumed.
        cost_used_usd: Dollar cost consumed.
        elapsed_s: Wall-clock seconds elapsed.
        tool_invocations_used: Tool invocations consumed.
        retries_used: Retry attempts consumed.
        violations: List of violation descriptions.
        exhausted: Whether any hard limit has been reached.
    """

    contract_name: str
    calls_used: int = 0
    tokens_used: int = 0
    cost_used_usd: float = 0.0
    elapsed_s: float = 0.0
    tool_invocations_used: int = 0
    retries_used: int = 0
    violations: list[str] = field(default_factory=list)
    exhausted: bool = False


# ---------------------------------------------------------------------------
# Contract monitor
# ---------------------------------------------------------------------------


class ContractMonitor:
    """Runtime monitor that enforces a :class:`ResourceContract`.

    Thread-safe: all mutations are guarded by an internal lock.

    Args:
        contract: The contract to enforce.
    """

    def __init__(self, contract: ResourceContract) -> None:
        self._contract = contract
        self._calls = 0
        self._tokens = 0
        self._cost_usd = 0.0
        self._tool_invocations = 0
        self._retries = 0
        self._start_time = time.monotonic()
        self._violations: list[str] = []
        self._lock = threading.Lock()

    # -- recording -----------------------------------------------------------

    def record_call(self, tokens: int = 0, cost_usd: float = 0.0) -> None:
        """Record an LLM call.

        Args:
            tokens: Tokens consumed by this call.
            cost_usd: Dollar cost of this call.

        Raises:
            ContractViolation: If ``on_violation == "raise"`` and a
                limit is breached.
        """
        with self._lock:
            self._calls += 1
            self._tokens += tokens
            self._cost_usd += cost_usd
            self._check_limits()

    def record_tool_invocation(self) -> None:
        """Record a tool/function invocation.

        Raises:
            ContractViolation: If tool invocation limit is breached.
        """
        with self._lock:
            self._tool_invocations += 1
            self._check_limits()

    def record_retry(self) -> None:
        """Record a retry attempt.

        Raises:
            ContractViolation: If retry limit is breached.
        """
        with self._lock:
            self._retries += 1
            self._check_limits()

    # -- queries -------------------------------------------------------------

    @property
    def remaining_calls(self) -> int | None:
        """Remaining LLM calls, or ``None`` if unconstrained."""
        if self._contract.max_calls is None:
            return None
        return max(0, self._contract.max_calls - self._calls)

    @property
    def remaining_tokens(self) -> int | None:
        """Remaining tokens, or ``None`` if unconstrained."""
        if self._contract.max_tokens is None:
            return None
        return max(0, self._contract.max_tokens - self._tokens)

    @property
    def remaining_cost_usd(self) -> float | None:
        """Remaining budget in USD, or ``None`` if unconstrained."""
        if self._contract.max_cost_usd is None:
            return None
        return max(0.0, self._contract.max_cost_usd - self._cost_usd)

    @property
    def remaining_duration_s(self) -> float | None:
        """Remaining wall-clock seconds, or ``None`` if unconstrained."""
        if self._contract.max_duration_s is None:
            return None
        elapsed = time.monotonic() - self._start_time
        return max(0.0, self._contract.max_duration_s - elapsed)

    @property
    def elapsed_s(self) -> float:
        """Wall-clock seconds since monitoring started."""
        return time.monotonic() - self._start_time

    def status(self) -> ContractStatus:
        """Return a snapshot of current enforcement state."""
        with self._lock:
            elapsed = time.monotonic() - self._start_time
            exhausted = False
            c = self._contract
            if c.max_calls is not None and self._calls >= c.max_calls:
                exhausted = True
            if c.max_tokens is not None and self._tokens >= c.max_tokens:
                exhausted = True
            if c.max_cost_usd is not None and self._cost_usd >= c.max_cost_usd:
                exhausted = True
            if c.max_duration_s is not None and elapsed >= c.max_duration_s:
                exhausted = True
            if (
                c.max_tool_invocations is not None
                and self._tool_invocations >= c.max_tool_invocations
            ):
                exhausted = True
            if c.max_retries is not None and self._retries >= c.max_retries:
                exhausted = True

            return ContractStatus(
                contract_name=c.name,
                calls_used=self._calls,
                tokens_used=self._tokens,
                cost_used_usd=round(self._cost_usd, 6),
                elapsed_s=round(elapsed, 3),
                tool_invocations_used=self._tool_invocations,
                retries_used=self._retries,
                violations=list(self._violations),
                exhausted=exhausted,
            )

    # -- child contracts -----------------------------------------------------

    def child(self, name: str = "", **overrides: Any) -> ContractMonitor:
        """Create a child monitor with monotone-constrained limits.

        The child's limits are capped at the parent's remaining budget.
        This enforces the monotone constraint from delegation chains.

        Args:
            name: Name for the child contract.
            **overrides: Override specific limits (capped by parent remaining).

        Returns:
            A new :class:`ContractMonitor`.
        """
        c = self._contract
        elapsed = time.monotonic() - self._start_time

        def _cap(limit: int | float | None, remaining: int | float | None, override: Any) -> Any:
            if override is not None and remaining is not None:
                return min(override, remaining)
            if override is not None:
                return override
            return remaining

        child_contract = ResourceContract(
            name=name or f"{c.name}.child",
            max_calls=_cap(c.max_calls, self.remaining_calls, overrides.get("max_calls")),
            max_tokens=_cap(c.max_tokens, self.remaining_tokens, overrides.get("max_tokens")),
            max_cost_usd=_cap(
                c.max_cost_usd, self.remaining_cost_usd, overrides.get("max_cost_usd")
            ),
            max_duration_s=_cap(
                c.max_duration_s,
                max(0.0, c.max_duration_s - elapsed) if c.max_duration_s else None,
                overrides.get("max_duration_s"),
            ),
            max_tool_invocations=_cap(
                c.max_tool_invocations,
                (
                    max(0, c.max_tool_invocations - self._tool_invocations)
                    if c.max_tool_invocations is not None
                    else None
                ),
                overrides.get("max_tool_invocations"),
            ),
            max_retries=overrides.get("max_retries", c.max_retries),
            on_violation=overrides.get("on_violation", c.on_violation),
        )
        return ContractMonitor(child_contract)

    # -- internal ------------------------------------------------------------

    def _check_limits(self) -> None:
        """Check all limits and handle violations (caller holds lock)."""
        c = self._contract
        elapsed = time.monotonic() - self._start_time

        checks: list[tuple[str, float | None, float]] = [
            ("max_calls", c.max_calls, self._calls),
            ("max_tokens", c.max_tokens, self._tokens),
            ("max_cost_usd", c.max_cost_usd, self._cost_usd),
            ("max_duration_s", c.max_duration_s, elapsed),
            ("max_tool_invocations", c.max_tool_invocations, self._tool_invocations),
            ("max_retries", c.max_retries, self._retries),
        ]

        for dimension, limit, actual in checks:
            if limit is not None and actual > limit:
                msg = f"{dimension}: limit={limit}, actual={actual}"
                self._violations.append(msg)
                if c.on_violation == "raise":
                    raise ContractViolation(c.name, dimension, limit, actual)


# ---------------------------------------------------------------------------
# Decorator
# ---------------------------------------------------------------------------


def resource_contract(
    *,
    name: str = "",
    max_calls: int | None = None,
    max_tokens: int | None = None,
    max_cost_usd: float | None = None,
    max_duration_s: float | None = None,
    max_tool_invocations: int | None = None,
    max_retries: int | None = None,
    on_violation: str = "raise",
) -> Callable[[F], F]:
    """Decorator that wraps a function with resource contract enforcement.

    The decorated function receives an injected ``_contract_monitor``
    keyword argument (a :class:`ContractMonitor`) that it can use to
    record resource consumption.

    If the function is async, it is wrapped with async support.

    Args:
        name: Contract name (defaults to function name).
        max_calls: Maximum LLM calls.
        max_tokens: Maximum tokens.
        max_cost_usd: Maximum USD spend.
        max_duration_s: Maximum wall-clock seconds.
        max_tool_invocations: Maximum tool invocations.
        max_retries: Maximum retries.
        on_violation: ``"raise"``, ``"warn"``, or ``"log"``.

    Example::

        @resource_contract(max_calls=5, max_cost_usd=0.50)
        async def my_agent_task(query: str, _contract_monitor=None):
            monitor = _contract_monitor
            # ... do work, call monitor.record_call() ...
    """

    def decorator(fn: F) -> F:
        contract = ResourceContract(
            name=name or fn.__name__,
            max_calls=max_calls,
            max_tokens=max_tokens,
            max_cost_usd=max_cost_usd,
            max_duration_s=max_duration_s,
            max_tool_invocations=max_tool_invocations,
            max_retries=max_retries,
            on_violation=on_violation,
        )

        if asyncio.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                monitor = ContractMonitor(contract)
                kwargs["_contract_monitor"] = monitor
                # Duration check via timeout
                if contract.max_duration_s is not None:
                    try:
                        return await asyncio.wait_for(
                            fn(*args, **kwargs),
                            timeout=contract.max_duration_s,
                        )
                    except TimeoutError:
                        raise ContractViolation(
                            contract.name,
                            "max_duration_s",
                            contract.max_duration_s,
                            monitor.elapsed_s,
                        ) from None
                return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            monitor = ContractMonitor(contract)
            kwargs["_contract_monitor"] = monitor
            result = fn(*args, **kwargs)
            # Post-execution duration check for sync functions
            if contract.max_duration_s is not None and monitor.elapsed_s > contract.max_duration_s:
                raise ContractViolation(
                    contract.name,
                    "max_duration_s",
                    contract.max_duration_s,
                    monitor.elapsed_s,
                )
            return result

        return sync_wrapper  # type: ignore[return-value]

    return decorator
