"""Configurable per-agent rate limiting engine for AI agent actions.

Provides a sliding-window rate limiter that integrates with the policy
engine via glob-based action type and target matching.  Supports per-agent
and global limits with block / throttle / warn responses.

Thread-safe: all bucket mutations are guarded by per-key locks.
"""

from __future__ import annotations

import fnmatch
import threading
import time
from dataclasses import dataclass

from aegis.core.action import Action

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

_VALID_ACTIONS: frozenset[str] = frozenset({"block", "throttle", "warn"})


@dataclass(frozen=True)
class RateLimitRule:
    """Declarative rate-limit rule.

    Attributes:
        name: Unique identifier for this rule.
        match_type: Glob pattern matched against ``Action.type``.
        match_target: Glob pattern matched against ``Action.target``.
        max_requests: Maximum number of actions allowed within *window_seconds*.
        window_seconds: Sliding window duration in seconds.
        per_agent: If ``True`` the limit applies independently per agent;
            otherwise a single global counter is shared.
        action_on_limit: Behaviour when the limit is exceeded —
            ``"block"`` (reject), ``"throttle"`` (reject with retry hint),
            or ``"warn"`` (allow but flag).
    """

    name: str
    match_type: str
    match_target: str = "*"
    max_requests: int = 100
    window_seconds: float = 60.0
    per_agent: bool = True
    action_on_limit: str = "block"

    def __post_init__(self) -> None:
        if self.action_on_limit not in _VALID_ACTIONS:
            msg = (
                f"action_on_limit must be one of {sorted(_VALID_ACTIONS)}, "
                f"got {self.action_on_limit!r}"
            )
            raise ValueError(msg)
        if self.max_requests < 0:
            raise ValueError("max_requests must be non-negative")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

    def matches(self, action: Action) -> bool:
        """Return ``True`` when *action* matches this rule's patterns."""
        return fnmatch.fnmatch(action.type, self.match_type) and fnmatch.fnmatch(
            action.target, self.match_target
        )


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate-limit check.

    Attributes:
        allowed: ``True`` when the action may proceed.
        rule_name: Name of the triggered rule, or ``None`` if no rule matched.
        current_count: Number of requests in the current window.
        max_requests: The limit defined by the rule.
        retry_after_seconds: Seconds until the oldest request in the window
            expires (``None`` when not applicable).
        action: Human-readable outcome label.
    """

    allowed: bool
    rule_name: str | None = None
    current_count: int = 0
    max_requests: int = 0
    retry_after_seconds: float | None = None
    action: str = "allowed"


_ALLOWED = RateLimitResult(allowed=True, action="allowed")

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class RateLimiter:
    """Sliding-window rate limiter with glob-based rule matching.

    Rules are evaluated in declaration order; the **first** matching rule
    determines the outcome.

    Parameters:
        rules: Ordered list of :class:`RateLimitRule` instances.
    """

    def __init__(self, rules: list[RateLimitRule] | None = None) -> None:
        self._rules: list[RateLimitRule] = list(rules or [])
        # Buckets keyed by (rule_name, bucket_key) → list of timestamps.
        self._buckets: dict[tuple[str, str], list[float]] = {}
        # Per-key locks to minimise contention.
        self._locks: dict[tuple[str, str], threading.Lock] = {}
        # Global lock only for creating new entries.
        self._global_lock = threading.Lock()

    # -- internal helpers ---------------------------------------------------

    def _get_lock(self, key: tuple[str, str]) -> threading.Lock:
        lock = self._locks.get(key)
        if lock is not None:
            return lock
        with self._global_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def _bucket_key(self, rule: RateLimitRule, agent_id: str) -> str:
        return agent_id if rule.per_agent else "__global__"

    @staticmethod
    def _prune(timestamps: list[float], window: float, now: float) -> list[float]:
        cutoff = now - window
        return [t for t in timestamps if t > cutoff]

    def _matching_rule(self, action: Action) -> RateLimitRule | None:
        for rule in self._rules:
            if rule.matches(action):
                return rule
        return None

    # -- public API ---------------------------------------------------------

    def check(self, action: Action, agent_id: str = "default") -> RateLimitResult:
        """Check whether *action* is within rate limits **without** recording it.

        Returns :class:`RateLimitResult` describing the outcome.
        """
        rule = self._matching_rule(action)
        if rule is None:
            return _ALLOWED

        bkey = self._bucket_key(rule, agent_id)
        key = (rule.name, bkey)
        lock = self._get_lock(key)
        now = time.monotonic()

        with lock:
            timestamps = self._buckets.get(key, [])
            timestamps = self._prune(timestamps, rule.window_seconds, now)
            self._buckets[key] = timestamps
            count = len(timestamps)

            if count < rule.max_requests:
                return RateLimitResult(
                    allowed=True,
                    rule_name=rule.name,
                    current_count=count,
                    max_requests=rule.max_requests,
                    retry_after_seconds=None,
                    action="allowed",
                )

            # Limit reached / exceeded.
            retry_after = (timestamps[0] + rule.window_seconds - now) if timestamps else 0.0
            retry_after = max(retry_after, 0.0)

            if rule.action_on_limit == "warn":
                return RateLimitResult(
                    allowed=True,
                    rule_name=rule.name,
                    current_count=count,
                    max_requests=rule.max_requests,
                    retry_after_seconds=retry_after,
                    action="warned",
                )

            action_label = "throttled" if rule.action_on_limit == "throttle" else "blocked"
            return RateLimitResult(
                allowed=False,
                rule_name=rule.name,
                current_count=count,
                max_requests=rule.max_requests,
                retry_after_seconds=retry_after,
                action=action_label,
            )

    def record(self, action: Action, agent_id: str = "default") -> RateLimitResult:
        """Record *action* and check rate limits in a single atomic call.

        The action is always recorded (even when the limit is exceeded) so
        that subsequent checks remain accurate.
        """
        rule = self._matching_rule(action)
        if rule is None:
            return _ALLOWED

        bkey = self._bucket_key(rule, agent_id)
        key = (rule.name, bkey)
        lock = self._get_lock(key)
        now = time.monotonic()

        with lock:
            timestamps = self._buckets.get(key, [])
            timestamps = self._prune(timestamps, rule.window_seconds, now)
            timestamps.append(now)
            self._buckets[key] = timestamps
            count = len(timestamps)

            if count <= rule.max_requests:
                return RateLimitResult(
                    allowed=True,
                    rule_name=rule.name,
                    current_count=count,
                    max_requests=rule.max_requests,
                    retry_after_seconds=None,
                    action="allowed",
                )

            retry_after = (timestamps[0] + rule.window_seconds - now) if timestamps else 0.0
            retry_after = max(retry_after, 0.0)

            if rule.action_on_limit == "warn":
                return RateLimitResult(
                    allowed=True,
                    rule_name=rule.name,
                    current_count=count,
                    max_requests=rule.max_requests,
                    retry_after_seconds=retry_after,
                    action="warned",
                )

            action_label = "throttled" if rule.action_on_limit == "throttle" else "blocked"
            return RateLimitResult(
                allowed=False,
                rule_name=rule.name,
                current_count=count,
                max_requests=rule.max_requests,
                retry_after_seconds=retry_after,
                action=action_label,
            )

    def get_usage(self, agent_id: str | None = None) -> dict[str, object]:
        """Return current usage statistics.

        When *agent_id* is provided only that agent's buckets are included;
        otherwise all buckets are returned.

        Returns a mapping of ``rule_name`` to usage dicts.
        """
        now = time.monotonic()
        result: dict[str, object] = {}

        for (rule_name, bkey), timestamps in list(self._buckets.items()):
            if agent_id is not None and bkey != agent_id:
                continue
            # Find the rule to get window info.
            rule = next((r for r in self._rules if r.name == rule_name), None)
            if rule is None:
                continue
            lock = self._get_lock((rule_name, bkey))
            with lock:
                pruned = self._prune(timestamps, rule.window_seconds, now)
                self._buckets[(rule_name, bkey)] = pruned
                entry_key = f"{rule_name}:{bkey}"
                result[entry_key] = {
                    "rule_name": rule_name,
                    "agent_id": bkey,
                    "current_count": len(pruned),
                    "max_requests": rule.max_requests,
                    "window_seconds": rule.window_seconds,
                }
        return result

    def reset(self, agent_id: str | None = None) -> None:
        """Clear rate-limit state.

        When *agent_id* is given only that agent's buckets are removed;
        otherwise all state is cleared.
        """
        if agent_id is not None:
            keys_to_remove = [k for k in list(self._buckets.keys()) if k[1] == agent_id]
            for key in keys_to_remove:
                lock = self._get_lock(key)
                with lock:
                    self._buckets.pop(key, None)
        else:
            with self._global_lock:
                self._buckets.clear()
                self._locks.clear()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def from_policy_dict(config: dict[str, object]) -> RateLimiter:
    """Create a :class:`RateLimiter` from a policy-style configuration dict.

    Expected schema::

        rate_limits:
          - name: write_limit
            match: { type: "write*" }
            max_requests: 100
            window: 60
            action: block
          - name: global_delete
            match: { type: "delete*", target: "production" }
            max_requests: 5
            window: 300
            per_agent: false
            action: block
    """
    raw_rules: list[dict[str, object]] = config.get("rate_limits", [])  # type: ignore[assignment]
    rules: list[RateLimitRule] = []

    for entry in raw_rules:
        match_cfg: dict[str, str] = entry.get("match", {})  # type: ignore[assignment]
        match_type = match_cfg.get("type", "*")
        match_target = match_cfg.get("target", "*")

        raw_max: int = entry.get("max_requests", 100)  # type: ignore[assignment]
        raw_window: float = float(str(entry.get("window", 60)))

        rule = RateLimitRule(
            name=str(entry.get("name", f"rule_{len(rules)}")),
            match_type=match_type,
            match_target=match_target,
            max_requests=int(raw_max),
            window_seconds=raw_window,
            per_agent=bool(entry.get("per_agent", True)),
            action_on_limit=str(entry.get("action", "block")),
        )
        rules.append(rule)

    return RateLimiter(rules)
