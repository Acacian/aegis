"""Redis-backed distributed rate limiter.

Uses Redis Sorted Sets for sliding-window rate limiting, enabling
distributed rate limiting across multiple processes and hosts.

Requires the ``redis`` package::

    pip install agent-aegis[redis]
"""

from __future__ import annotations

import time
from typing import Any

from aegis.core.action import Action
from aegis.core.rate_limiter import RateLimitResult, RateLimitRule

# Redis key prefixes
_PREFIX = "aegis:ratelimit"
_ALLOWED = RateLimitResult(allowed=True, action="allowed")


def _bucket_redis_key(rule_name: str, bucket_key: str) -> str:
    return f"{_PREFIX}:{rule_name}:{bucket_key}"


class RedisRateLimiter:
    """Distributed sliding-window rate limiter backed by Redis.

    Provides the same public API as :class:`~aegis.core.rate_limiter.RateLimiter`
    but stores state in Redis, enabling rate limiting across processes.

    Args:
        redis_url: Redis connection URL.
        rules: Ordered list of :class:`RateLimitRule` instances.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        rules: list[RateLimitRule] | None = None,
    ) -> None:
        import redis

        self._client: redis.Redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self._rules: list[RateLimitRule] = list(rules or [])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_rule(self, rule: RateLimitRule) -> None:
        """Append a rate-limit rule.

        Rules are evaluated in declaration order; the first matching
        rule determines the outcome.
        """
        self._rules.append(rule)

    def check(self, action: Action, agent_id: str = "default") -> RateLimitResult:
        """Check whether *action* is within rate limits without recording.

        Returns :class:`RateLimitResult` describing the outcome.
        """
        rule = self._matching_rule(action)
        if rule is None:
            return _ALLOWED

        bkey = self._bucket_key(rule, agent_id)
        redis_key = _bucket_redis_key(rule.name, bkey)
        now = time.time()

        # Remove expired entries and count
        cutoff = now - rule.window_seconds
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        pipe.zcard(redis_key)
        results = pipe.execute()
        count: int = int(results[1])

        if count < rule.max_requests:
            return RateLimitResult(
                allowed=True,
                rule_name=rule.name,
                current_count=count,
                max_requests=rule.max_requests,
                retry_after_seconds=None,
                action="allowed",
            )

        # Limit reached
        retry_after = self._calc_retry_after(redis_key, rule.window_seconds, now)

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
        """Record *action* and check rate limits atomically.

        The action is always recorded (even when the limit is exceeded)
        so that subsequent checks remain accurate.
        """
        rule = self._matching_rule(action)
        if rule is None:
            return _ALLOWED

        bkey = self._bucket_key(rule, agent_id)
        redis_key = _bucket_redis_key(rule.name, bkey)
        now = time.time()
        cutoff = now - rule.window_seconds

        # Atomic: prune, add, count, set TTL
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(redis_key, "-inf", cutoff)
        # Use timestamp + counter as unique member to avoid collisions
        member = f"{now}:{self._client.incr(f'{redis_key}:seq')}"
        pipe.zadd(redis_key, {member: now})
        pipe.zcard(redis_key)
        # Auto-expire the key after the window passes
        pipe.expire(redis_key, int(rule.window_seconds) + 1)
        results = pipe.execute()
        count: int = int(results[2])

        if count <= rule.max_requests:
            return RateLimitResult(
                allowed=True,
                rule_name=rule.name,
                current_count=count,
                max_requests=rule.max_requests,
                retry_after_seconds=None,
                action="allowed",
            )

        # Limit exceeded
        retry_after = self._calc_retry_after(redis_key, rule.window_seconds, now)

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
        """
        now = time.time()
        result: dict[str, object] = {}

        for rule in self._rules:
            if agent_id is not None:
                bkeys = [self._bucket_key(rule, agent_id)]
            else:
                # Scan for all bucket keys matching this rule
                bkeys = self._scan_bucket_keys(rule.name)

            for bkey in bkeys:
                redis_key = _bucket_redis_key(rule.name, bkey)
                cutoff = now - rule.window_seconds
                self._client.zremrangebyscore(redis_key, "-inf", cutoff)
                count = int(self._client.zcard(redis_key))  # type: ignore[arg-type]
                if count == 0 and agent_id is None:
                    continue

                entry_key = f"{rule.name}:{bkey}"
                result[entry_key] = {
                    "rule_name": rule.name,
                    "agent_id": bkey,
                    "current_count": count,
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
            for rule in self._rules:
                bkey = self._bucket_key(rule, agent_id)
                redis_key = _bucket_redis_key(rule.name, bkey)
                seq_key = f"{redis_key}:seq"
                self._client.delete(redis_key, seq_key)
        else:
            # Delete all aegis rate-limit keys
            cursor: int = 0
            while True:
                cursor, keys = self._client.scan(  # type: ignore[misc]
                    cursor=cursor, match=f"{_PREFIX}:*", count=100
                )
                if keys:
                    self._client.delete(*keys)
                if cursor == 0:
                    break

    def close(self) -> None:
        """Close the Redis connection."""
        self._client.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _matching_rule(self, action: Action) -> RateLimitRule | None:
        for rule in self._rules:
            if rule.matches(action):
                return rule
        return None

    @staticmethod
    def _bucket_key(rule: RateLimitRule, agent_id: str) -> str:
        return agent_id if rule.per_agent else "__global__"

    def _calc_retry_after(self, redis_key: str, window_seconds: float, now: float) -> float:
        """Calculate seconds until the oldest entry in the window expires."""
        oldest: list[Any] = self._client.zrange(  # type: ignore[assignment]
            redis_key, 0, 0, withscores=True
        )
        if oldest:
            oldest_score = float(oldest[0][1])
            retry = oldest_score + window_seconds - now
            return max(retry, 0.0)
        return 0.0

    def _scan_bucket_keys(self, rule_name: str) -> list[str]:
        """Scan Redis for all bucket keys under a given rule name."""
        prefix = f"{_PREFIX}:{rule_name}:"
        bucket_keys: list[str] = []
        cursor: int = 0
        while True:
            cursor, keys = self._client.scan(  # type: ignore[misc]
                cursor=cursor, match=f"{prefix}*", count=100
            )
            for key in keys:
                # Skip sequence keys
                if key.endswith(":seq"):
                    continue
                # Extract the bucket key (agent_id or __global__)
                bkey = key[len(prefix) :]
                if bkey and bkey not in bucket_keys:
                    bucket_keys.append(bkey)
            if cursor == 0:
                break
        return bucket_keys
