"""MCP-specific rate limiter with per-server and per-tool granularity.

Provides sliding-window rate limiting designed specifically for MCP tool
calls.  Supports hierarchical config (tool > server > global > default),
burst detection with cooldown, and per-session isolation.

Thread-safe: all bucket mutations are guarded by a single lock to avoid
deadlocks between the multiple windows that must be checked atomically.

Example::

    limiter = MCPRateLimiter(
        server_configs={"filesystem": RateLimitConfig(requests_per_minute=30)},
        tool_configs={"filesystem.write_file": RateLimitConfig(requests_per_minute=10)},
    )
    result = limiter.check("read_file", "filesystem")
    if not result.allowed:
        print(f"Denied: {result.reason}, retry in {result.retry_after_seconds}s")
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

_DEFAULT_RPM = 60
_DEFAULT_RPH = 1000
_DEFAULT_BURST = 10
_DEFAULT_COOLDOWN = 60.0


@dataclass
class RateLimitConfig:
    """Rate limit configuration for a server or tool."""

    requests_per_minute: int = _DEFAULT_RPM
    requests_per_hour: int = _DEFAULT_RPH
    burst_limit: int = _DEFAULT_BURST  # max calls in a 1-second window
    cooldown_seconds: float = _DEFAULT_COOLDOWN  # cooldown after burst detection


@dataclass(frozen=True)
class MCPRateLimitResult:
    """Result of a rate limit check."""

    allowed: bool
    reason: str  # "" if allowed, explanation if denied
    current_rpm: int  # current requests per minute
    current_rph: int  # current requests per hour
    burst_detected: bool
    retry_after_seconds: float  # 0 if allowed, suggested wait time if denied
    server_name: str
    tool_name: str


# ---------------------------------------------------------------------------
# Sliding window
# ---------------------------------------------------------------------------


class _SlidingWindow:
    """Sliding window counter using timestamp deque."""

    __slots__ = ("_window", "_timestamps")

    def __init__(self, window_seconds: float) -> None:
        self._window = window_seconds
        self._timestamps: deque[float] = deque()

    def add(self, now: float | None = None) -> None:
        """Record a timestamp."""
        self._timestamps.append(now if now is not None else time.monotonic())
        self._prune(now)

    def count(self, now: float | None = None) -> int:
        """Return current count within the window."""
        self._prune(now)
        return len(self._timestamps)

    def oldest(self) -> float | None:
        """Return the oldest timestamp, or None if empty."""
        return self._timestamps[0] if self._timestamps else None

    def clear(self) -> None:
        """Reset all recorded timestamps."""
        self._timestamps.clear()

    def _prune(self, now: float | None = None) -> None:
        cutoff = (now if now is not None else time.monotonic()) - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()


# ---------------------------------------------------------------------------
# Per-key state
# ---------------------------------------------------------------------------


@dataclass
class _BucketState:
    """Rate limit state for a single (session, server, tool) key."""

    minute_window: _SlidingWindow = field(default_factory=lambda: _SlidingWindow(60.0))
    hour_window: _SlidingWindow = field(default_factory=lambda: _SlidingWindow(3600.0))
    burst_window: _SlidingWindow = field(default_factory=lambda: _SlidingWindow(1.0))
    cooldown_until: float = 0.0  # monotonic time when cooldown expires


# ---------------------------------------------------------------------------
# MCP Rate Limiter
# ---------------------------------------------------------------------------


class MCPRateLimiter:
    """Rate limiter for MCP tool calls with per-server and per-tool granularity.

    Uses a sliding window algorithm.  Supports:

    - Global limits (across all servers)
    - Per-server limits
    - Per-tool limits (most specific wins)
    - Burst detection (rapid calls in short window)
    - Cooldown after burst
    """

    def __init__(
        self,
        *,
        global_config: RateLimitConfig | None = None,
        server_configs: dict[str, RateLimitConfig] | None = None,
        tool_configs: dict[str, RateLimitConfig] | None = None,
        default_config: RateLimitConfig | None = None,
    ) -> None:
        self._global_config = global_config
        self._server_configs: dict[str, RateLimitConfig] = dict(server_configs or {})
        self._tool_configs: dict[str, RateLimitConfig] = dict(tool_configs or {})
        self._default_config = default_config or RateLimitConfig()

        # Keyed by (session_id, server_name, tool_name).
        self._buckets: dict[tuple[str, str, str], _BucketState] = {}
        # Single lock for all mutations — simple and deadlock-free.
        self._lock = threading.Lock()

    # -- config resolution --------------------------------------------------

    def _resolve_config(self, tool_name: str, server_name: str) -> RateLimitConfig:
        """Resolve the effective config using the hierarchy.

        Priority: tool_configs > server_configs > global_config > default.
        """
        tool_key = f"{server_name}.{tool_name}"
        if tool_key in self._tool_configs:
            return self._tool_configs[tool_key]
        if server_name in self._server_configs:
            return self._server_configs[server_name]
        if self._global_config is not None:
            return self._global_config
        return self._default_config

    # -- bucket access ------------------------------------------------------

    def _get_bucket(self, session_id: str, server_name: str, tool_name: str) -> _BucketState:
        """Return the bucket for a key, creating it if necessary.

        Caller must hold ``self._lock``.
        """
        key = (session_id, server_name, tool_name)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _BucketState()
            self._buckets[key] = bucket
        return bucket

    # -- public API ---------------------------------------------------------

    def check(
        self,
        tool_name: str,
        server_name: str,
        *,
        session_id: str = "default",
    ) -> MCPRateLimitResult:
        """Check if a tool call is allowed and record it.

        Returns a result with allowed/denied status.  If allowed, the call
        is recorded automatically so callers only need a single method.
        """
        config = self._resolve_config(tool_name, server_name)
        now = time.monotonic()

        with self._lock:
            bucket = self._get_bucket(session_id, server_name, tool_name)

            # 1. Cooldown check
            if bucket.cooldown_until > now:
                remaining = bucket.cooldown_until - now
                return MCPRateLimitResult(
                    allowed=False,
                    reason=(
                        f"Burst cooldown active for {server_name}.{tool_name}; "
                        f"{remaining:.1f}s remaining"
                    ),
                    current_rpm=bucket.minute_window.count(now),
                    current_rph=bucket.hour_window.count(now),
                    burst_detected=True,
                    retry_after_seconds=remaining,
                    server_name=server_name,
                    tool_name=tool_name,
                )

            # 1b. Cooldown just expired — clear burst window so it does
            #     not immediately re-trigger on stale timestamps.
            if bucket.cooldown_until > 0:
                bucket.burst_window.clear()
                bucket.cooldown_until = 0.0

            # 2. Per-minute check
            rpm = bucket.minute_window.count(now)
            if rpm >= config.requests_per_minute:
                oldest = bucket.minute_window.oldest()
                retry = (oldest + 60.0 - now) if oldest is not None else 60.0
                retry = max(retry, 0.0)
                return MCPRateLimitResult(
                    allowed=False,
                    reason=(
                        f"Per-minute limit ({config.requests_per_minute} rpm) "
                        f"exceeded for {server_name}.{tool_name}"
                    ),
                    current_rpm=rpm,
                    current_rph=bucket.hour_window.count(now),
                    burst_detected=False,
                    retry_after_seconds=retry,
                    server_name=server_name,
                    tool_name=tool_name,
                )

            # 3. Per-hour check
            rph = bucket.hour_window.count(now)
            if rph >= config.requests_per_hour:
                oldest = bucket.hour_window.oldest()
                retry = (oldest + 3600.0 - now) if oldest is not None else 3600.0
                retry = max(retry, 0.0)
                return MCPRateLimitResult(
                    allowed=False,
                    reason=(
                        f"Per-hour limit ({config.requests_per_hour} rph) "
                        f"exceeded for {server_name}.{tool_name}"
                    ),
                    current_rpm=rpm,
                    current_rph=rph,
                    burst_detected=False,
                    retry_after_seconds=retry,
                    server_name=server_name,
                    tool_name=tool_name,
                )

            # 4. Burst check (before recording, check if adding would exceed)
            burst_count = bucket.burst_window.count(now)
            if burst_count >= config.burst_limit:
                # Burst detected — enter cooldown
                bucket.cooldown_until = now + config.cooldown_seconds
                return MCPRateLimitResult(
                    allowed=False,
                    reason=(
                        f"Burst detected ({burst_count + 1} calls/sec) for "
                        f"{server_name}.{tool_name}; entering "
                        f"{config.cooldown_seconds}s cooldown"
                    ),
                    current_rpm=rpm,
                    current_rph=rph,
                    burst_detected=True,
                    retry_after_seconds=config.cooldown_seconds,
                    server_name=server_name,
                    tool_name=tool_name,
                )

            # 5. Allowed — record the call
            bucket.minute_window.add(now)
            bucket.hour_window.add(now)
            bucket.burst_window.add(now)

            return MCPRateLimitResult(
                allowed=True,
                reason="",
                current_rpm=bucket.minute_window.count(now),
                current_rph=bucket.hour_window.count(now),
                burst_detected=False,
                retry_after_seconds=0.0,
                server_name=server_name,
                tool_name=tool_name,
            )

    def record(
        self,
        tool_name: str,
        server_name: str,
        *,
        session_id: str = "default",
    ) -> None:
        """Record a tool call without checking limits (for tracking only)."""
        now = time.monotonic()

        with self._lock:
            bucket = self._get_bucket(session_id, server_name, tool_name)
            bucket.minute_window.add(now)
            bucket.hour_window.add(now)
            bucket.burst_window.add(now)

    def get_stats(
        self,
        server_name: str | None = None,
        tool_name: str | None = None,
        session_id: str = "default",
    ) -> dict[str, Any]:
        """Get current rate stats.

        Returns a dict keyed by ``"server.tool"`` with usage information.
        When *server_name* or *tool_name* are provided, results are filtered.
        """
        now = time.monotonic()
        result: dict[str, Any] = {}

        with self._lock:
            for (sid, srv, tl), bucket in self._buckets.items():
                if sid != session_id:
                    continue
                if server_name is not None and srv != server_name:
                    continue
                if tool_name is not None and tl != tool_name:
                    continue

                key = f"{srv}.{tl}"
                in_cooldown = bucket.cooldown_until > now
                result[key] = {
                    "server_name": srv,
                    "tool_name": tl,
                    "current_rpm": bucket.minute_window.count(now),
                    "current_rph": bucket.hour_window.count(now),
                    "burst_count": bucket.burst_window.count(now),
                    "in_cooldown": in_cooldown,
                    "cooldown_remaining": (
                        max(0.0, bucket.cooldown_until - now) if in_cooldown else 0.0
                    ),
                }

        return result

    def reset(
        self,
        *,
        server_name: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Reset counters.

        - No arguments: reset everything.
        - *server_name* only: reset all tools on that server (all sessions).
        - *session_id* only: reset all buckets for that session.
        - Both: reset buckets matching both filters.
        """
        with self._lock:
            if server_name is None and session_id is None:
                self._buckets.clear()
                return

            keys_to_remove = [
                k
                for k in self._buckets
                if (server_name is None or k[1] == server_name)
                and (session_id is None or k[0] == session_id)
            ]
            for key in keys_to_remove:
                del self._buckets[key]

    def set_config(
        self,
        config: RateLimitConfig,
        *,
        server_name: str | None = None,
        tool_name: str | None = None,
    ) -> None:
        """Hot-update rate limit config.

        - Neither *server_name* nor *tool_name*: update the global config.
        - *server_name* only: update the server-level config.
        - Both *server_name* and *tool_name*: update the tool-level config.
        - *tool_name* alone without *server_name*: raises ``ValueError``.
        """
        if tool_name is not None and server_name is None:
            raise ValueError(
                "tool_name requires server_name (tool configs are keyed as 'server.tool')"
            )

        with self._lock:
            if server_name is None and tool_name is None:
                self._global_config = config
            elif tool_name is not None:
                tool_key = f"{server_name}.{tool_name}"
                self._tool_configs[tool_key] = config
            else:
                assert server_name is not None
                self._server_configs[server_name] = config
