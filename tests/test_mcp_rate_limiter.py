"""Tests for aegis.core.mcp_rate_limiter — MCP-specific rate limiting."""

from __future__ import annotations

import threading
from unittest.mock import patch

import pytest

from aegis.core.mcp_rate_limiter import (
    MCPRateLimiter,
    MCPRateLimitResult,
    RateLimitConfig,
    _SlidingWindow,
)

# ---------------------------------------------------------------------------
# _SlidingWindow
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_add_and_count(self):
        w = _SlidingWindow(10.0)
        now = 1000.0
        w.add(now)
        w.add(now + 1.0)
        assert w.count(now + 2.0) == 2

    def test_prune_removes_old(self):
        w = _SlidingWindow(5.0)
        w.add(100.0)
        w.add(103.0)
        w.add(106.0)
        # At t=106, window is [101..106], so 100.0 is pruned
        assert w.count(106.0) == 2

    def test_oldest(self):
        w = _SlidingWindow(60.0)
        assert w.oldest() is None
        w.add(50.0)
        w.add(60.0)
        assert w.oldest() == 50.0

    def test_clear(self):
        w = _SlidingWindow(60.0)
        w.add(1.0)
        w.add(2.0)
        w.clear()
        assert w.count(3.0) == 0

    def test_empty_count(self):
        w = _SlidingWindow(60.0)
        assert w.count(100.0) == 0


# ---------------------------------------------------------------------------
# Basic rate limiting
# ---------------------------------------------------------------------------


class TestBasicRateLimiting:
    def test_allows_under_limit(self):
        limiter = MCPRateLimiter(default_config=RateLimitConfig(requests_per_minute=5))
        for _ in range(5):
            result = limiter.check("read_file", "filesystem")
            assert result.allowed

    def test_denies_over_rpm(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(
                requests_per_minute=3,
                requests_per_hour=1000,
                burst_limit=100,  # high burst to not trigger it
            )
        )
        for _ in range(3):
            result = limiter.check("read_file", "filesystem")
            assert result.allowed

        result = limiter.check("read_file", "filesystem")
        assert not result.allowed
        assert "Per-minute limit" in result.reason
        assert result.current_rpm == 3

    def test_denies_over_rph(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(
                requests_per_minute=1000,
                requests_per_hour=3,
                burst_limit=1000,
            )
        )
        for _ in range(3):
            result = limiter.check("read_file", "filesystem")
            assert result.allowed

        result = limiter.check("read_file", "filesystem")
        assert not result.allowed
        assert "Per-hour limit" in result.reason
        assert result.current_rph == 3

    def test_result_fields(self):
        limiter = MCPRateLimiter()
        result = limiter.check("read_file", "filesystem")
        assert isinstance(result, MCPRateLimitResult)
        assert result.server_name == "filesystem"
        assert result.tool_name == "read_file"
        assert result.allowed is True
        assert result.reason == ""
        assert result.burst_detected is False
        assert result.retry_after_seconds == 0.0
        assert result.current_rpm == 1
        assert result.current_rph == 1

    def test_retry_after_positive_when_denied(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(
                requests_per_minute=1,
                burst_limit=100,
            )
        )
        limiter.check("read_file", "filesystem")
        result = limiter.check("read_file", "filesystem")
        assert not result.allowed
        assert result.retry_after_seconds > 0


# ---------------------------------------------------------------------------
# Burst detection
# ---------------------------------------------------------------------------


class TestBurstDetection:
    def test_burst_triggers_cooldown(self):
        """Rapid calls within 1 second should trigger burst detection."""
        config = RateLimitConfig(
            requests_per_minute=1000,
            requests_per_hour=10000,
            burst_limit=3,
            cooldown_seconds=10.0,
        )
        limiter = MCPRateLimiter(default_config=config)

        # First 3 calls are fine (burst_limit=3 means 4th triggers)
        for _ in range(3):
            result = limiter.check("read_file", "filesystem")
            assert result.allowed

        # 4th call should trigger burst
        result = limiter.check("read_file", "filesystem")
        assert not result.allowed
        assert result.burst_detected
        assert "Burst detected" in result.reason
        assert result.retry_after_seconds == 10.0

    def test_cooldown_blocks_subsequent_calls(self):
        config = RateLimitConfig(
            requests_per_minute=1000,
            burst_limit=2,
            cooldown_seconds=5.0,
        )
        limiter = MCPRateLimiter(default_config=config)

        # Trigger burst
        limiter.check("read_file", "filesystem")
        limiter.check("read_file", "filesystem")
        result = limiter.check("read_file", "filesystem")
        assert not result.allowed
        assert result.burst_detected

        # Subsequent call is also blocked (cooldown)
        result = limiter.check("read_file", "filesystem")
        assert not result.allowed
        assert result.burst_detected
        assert "cooldown active" in result.reason.lower()

    def test_cooldown_expires(self):
        """After cooldown expires, calls should be allowed again."""
        config = RateLimitConfig(
            requests_per_minute=1000,
            burst_limit=2,
            cooldown_seconds=5.0,
        )
        limiter = MCPRateLimiter(default_config=config)

        t = 1000.0
        with patch("aegis.core.mcp_rate_limiter.time") as mock_time:
            mock_time.monotonic.return_value = t
            limiter.check("t", "s")

            mock_time.monotonic.return_value = t + 0.1
            limiter.check("t", "s")

            # Burst triggered
            mock_time.monotonic.return_value = t + 0.2
            result = limiter.check("t", "s")
            assert not result.allowed
            assert result.burst_detected

            # Still in cooldown
            mock_time.monotonic.return_value = t + 3.0
            result = limiter.check("t", "s")
            assert not result.allowed

            # Cooldown expired (5s after t + 0.2 = t + 5.2)
            mock_time.monotonic.return_value = t + 6.0
            result = limiter.check("t", "s")
            assert result.allowed


# ---------------------------------------------------------------------------
# Config hierarchy
# ---------------------------------------------------------------------------


class TestConfigHierarchy:
    def test_tool_config_wins_over_server(self):
        limiter = MCPRateLimiter(
            server_configs={
                "filesystem": RateLimitConfig(requests_per_minute=100, burst_limit=1000)
            },
            tool_configs={
                "filesystem.write_file": RateLimitConfig(requests_per_minute=2, burst_limit=1000)
            },
        )
        # write_file limited to 2 rpm
        limiter.check("write_file", "filesystem")
        limiter.check("write_file", "filesystem")
        result = limiter.check("write_file", "filesystem")
        assert not result.allowed

        # read_file uses server config (100 rpm), should be fine
        result = limiter.check("read_file", "filesystem")
        assert result.allowed

    def test_server_config_wins_over_global(self):
        limiter = MCPRateLimiter(
            global_config=RateLimitConfig(requests_per_minute=100, burst_limit=1000),
            server_configs={
                "filesystem": RateLimitConfig(requests_per_minute=2, burst_limit=1000)
            },
        )
        limiter.check("read_file", "filesystem")
        limiter.check("read_file", "filesystem")
        result = limiter.check("read_file", "filesystem")
        assert not result.allowed

        # Different server falls back to global (100 rpm)
        result = limiter.check("query", "database")
        assert result.allowed

    def test_global_wins_over_default(self):
        limiter = MCPRateLimiter(
            global_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000),
            default_config=RateLimitConfig(requests_per_minute=100, burst_limit=1000),
        )
        limiter.check("read_file", "filesystem")
        limiter.check("read_file", "filesystem")
        result = limiter.check("read_file", "filesystem")
        assert not result.allowed

    def test_fallback_to_default(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        limiter.check("any_tool", "any_server")
        limiter.check("any_tool", "any_server")
        result = limiter.check("any_tool", "any_server")
        assert not result.allowed

    def test_builtin_default_when_no_config(self):
        """When no configs at all, uses built-in default (60 rpm, 10 burst)."""
        limiter = MCPRateLimiter()

        # Space calls 0.2s apart via mocking to avoid burst limit (10/sec).
        t = 1000.0
        with patch("aegis.core.mcp_rate_limiter.time") as mock_time:
            for i in range(60):
                mock_time.monotonic.return_value = t + i * 0.2
                result = limiter.check("tool", "server")
                assert result.allowed, f"Call {i + 1} denied: {result.reason}"

            mock_time.monotonic.return_value = t + 60 * 0.2
            result = limiter.check("tool", "server")
            assert not result.allowed


# ---------------------------------------------------------------------------
# Session isolation
# ---------------------------------------------------------------------------


class TestSessionIsolation:
    def test_different_sessions_independent(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        # Session A fills its quota
        limiter.check("read_file", "fs", session_id="session_a")
        limiter.check("read_file", "fs", session_id="session_a")
        result = limiter.check("read_file", "fs", session_id="session_a")
        assert not result.allowed

        # Session B is still fine
        result = limiter.check("read_file", "fs", session_id="session_b")
        assert result.allowed

    def test_default_session(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=1, burst_limit=1000)
        )
        limiter.check("t", "s")  # Uses default session_id
        result = limiter.check("t", "s")
        assert not result.allowed


# ---------------------------------------------------------------------------
# Hot-update config
# ---------------------------------------------------------------------------


class TestHotUpdate:
    def test_update_global_config(self):
        limiter = MCPRateLimiter(
            global_config=RateLimitConfig(requests_per_minute=100, burst_limit=1000)
        )
        # Initially allows many calls
        for _ in range(5):
            assert limiter.check("t", "s").allowed

        # Tighten global limit
        limiter.set_config(RateLimitConfig(requests_per_minute=2, burst_limit=1000))
        # Already recorded 5, but new limit is 2 rpm — should deny
        result = limiter.check("t", "s")
        assert not result.allowed

    def test_update_server_config(self):
        limiter = MCPRateLimiter()
        limiter.set_config(
            RateLimitConfig(requests_per_minute=1, burst_limit=1000),
            server_name="strict_server",
        )
        limiter.check("t", "strict_server")
        result = limiter.check("t", "strict_server")
        assert not result.allowed

    def test_update_tool_config(self):
        limiter = MCPRateLimiter()
        limiter.set_config(
            RateLimitConfig(requests_per_minute=1, burst_limit=1000),
            server_name="fs",
            tool_name="write",
        )
        limiter.check("write", "fs")
        result = limiter.check("write", "fs")
        assert not result.allowed

        # Other tools on same server use default (60 rpm)
        result = limiter.check("read", "fs")
        assert result.allowed

    def test_tool_without_server_raises(self):
        limiter = MCPRateLimiter()
        with pytest.raises(ValueError, match="tool_name requires server_name"):
            limiter.set_config(RateLimitConfig(), tool_name="write")


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------


class TestReset:
    def test_reset_all(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        limiter.check("t1", "s1")
        limiter.check("t1", "s1")
        result = limiter.check("t1", "s1")
        assert not result.allowed

        limiter.reset()
        result = limiter.check("t1", "s1")
        assert result.allowed

    def test_reset_by_server(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        limiter.check("t", "server_a")
        limiter.check("t", "server_a")
        limiter.check("t", "server_b")
        limiter.check("t", "server_b")

        # Reset only server_a
        limiter.reset(server_name="server_a")

        result = limiter.check("t", "server_a")
        assert result.allowed  # Reset worked

        result = limiter.check("t", "server_b")
        assert not result.allowed  # Not reset

    def test_reset_by_session(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        limiter.check("t", "s", session_id="sess_a")
        limiter.check("t", "s", session_id="sess_a")
        limiter.check("t", "s", session_id="sess_b")
        limiter.check("t", "s", session_id="sess_b")

        limiter.reset(session_id="sess_a")

        result = limiter.check("t", "s", session_id="sess_a")
        assert result.allowed

        result = limiter.check("t", "s", session_id="sess_b")
        assert not result.allowed

    def test_reset_by_server_and_session(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=1, burst_limit=1000)
        )
        limiter.check("t", "s1", session_id="a")
        limiter.check("t", "s2", session_id="a")
        limiter.check("t", "s1", session_id="b")

        limiter.reset(server_name="s1", session_id="a")

        # s1/a was reset
        assert limiter.check("t", "s1", session_id="a").allowed
        # s2/a was NOT reset
        assert not limiter.check("t", "s2", session_id="a").allowed
        # s1/b was NOT reset
        assert not limiter.check("t", "s1", session_id="b").allowed


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_basic_stats(self):
        limiter = MCPRateLimiter()
        limiter.check("read_file", "filesystem")
        limiter.check("read_file", "filesystem")
        limiter.check("write_file", "filesystem")

        stats = limiter.get_stats()
        assert "filesystem.read_file" in stats
        assert stats["filesystem.read_file"]["current_rpm"] == 2
        assert stats["filesystem.read_file"]["current_rph"] == 2
        assert "filesystem.write_file" in stats
        assert stats["filesystem.write_file"]["current_rpm"] == 1

    def test_filter_by_server(self):
        limiter = MCPRateLimiter()
        limiter.check("read", "fs")
        limiter.check("query", "db")

        stats = limiter.get_stats(server_name="fs")
        assert "fs.read" in stats
        assert "db.query" not in stats

    def test_filter_by_tool(self):
        limiter = MCPRateLimiter()
        limiter.check("read", "fs")
        limiter.check("write", "fs")

        stats = limiter.get_stats(tool_name="read")
        assert "fs.read" in stats
        assert "fs.write" not in stats

    def test_stats_for_different_session(self):
        limiter = MCPRateLimiter()
        limiter.check("t", "s", session_id="a")
        limiter.check("t", "s", session_id="b")

        stats_a = limiter.get_stats(session_id="a")
        assert stats_a["s.t"]["current_rpm"] == 1

        stats_b = limiter.get_stats(session_id="b")
        assert stats_b["s.t"]["current_rpm"] == 1

    def test_empty_stats(self):
        limiter = MCPRateLimiter()
        assert limiter.get_stats() == {}

    def test_cooldown_in_stats(self):
        config = RateLimitConfig(
            requests_per_minute=1000,
            burst_limit=1,
            cooldown_seconds=60.0,
        )
        limiter = MCPRateLimiter(default_config=config)
        limiter.check("t", "s")  # first call OK
        limiter.check("t", "s")  # triggers burst

        stats = limiter.get_stats()
        assert stats["s.t"]["in_cooldown"] is True
        assert stats["s.t"]["cooldown_remaining"] > 0


# ---------------------------------------------------------------------------
# Record (tracking only)
# ---------------------------------------------------------------------------


class TestRecord:
    def test_record_increments_counters(self):
        limiter = MCPRateLimiter()
        limiter.record("read_file", "filesystem")
        limiter.record("read_file", "filesystem")

        stats = limiter.get_stats()
        assert stats["filesystem.read_file"]["current_rpm"] == 2

    def test_record_does_not_check_limits(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=1, burst_limit=1000)
        )
        # record does not check — should not raise or return denied
        limiter.record("t", "s")
        limiter.record("t", "s")  # Over the limit, but just recording

        # But a subsequent check should see the recorded calls
        result = limiter.check("t", "s")
        assert not result.allowed


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_checks(self):
        """Multiple threads checking the same tool concurrently."""
        config = RateLimitConfig(
            requests_per_minute=1000,
            requests_per_hour=100000,
            burst_limit=1000,
        )
        limiter = MCPRateLimiter(default_config=config)
        results: list[MCPRateLimitResult] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(50):
                    r = limiter.check("read_file", "filesystem")
                    results.append(r)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        # All 500 calls should have been allowed
        assert len(results) == 500
        allowed = sum(1 for r in results if r.allowed)
        assert allowed == 500

    def test_concurrent_rate_limiting(self):
        """Concurrent threads with a tight limit — total allowed must not exceed the limit."""
        config = RateLimitConfig(
            requests_per_minute=20,
            requests_per_hour=100000,
            burst_limit=1000,
        )
        limiter = MCPRateLimiter(default_config=config)
        results: list[MCPRateLimitResult] = []
        lock = threading.Lock()

        def worker() -> None:
            for _ in range(10):
                r = limiter.check("tool", "server")
                with lock:
                    results.append(r)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed = sum(1 for r in results if r.allowed)
        # Should allow exactly 20 (the rpm limit)
        assert allowed == 20
        assert len(results) == 100


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_rpm_denies_all(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(
                requests_per_minute=0,
                burst_limit=1000,
            )
        )
        result = limiter.check("t", "s")
        assert not result.allowed

    def test_zero_burst_limit_denies_all(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(
                requests_per_minute=1000,
                burst_limit=0,
            )
        )
        result = limiter.check("t", "s")
        assert not result.allowed
        assert result.burst_detected

    def test_very_high_limits(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(
                requests_per_minute=1_000_000,
                requests_per_hour=10_000_000,
                burst_limit=100_000,
            )
        )
        for _ in range(100):
            assert limiter.check("t", "s").allowed

    def test_different_tools_independent(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        limiter.check("read_file", "fs")
        limiter.check("read_file", "fs")
        assert not limiter.check("read_file", "fs").allowed

        # Different tool has its own counter
        assert limiter.check("write_file", "fs").allowed

    def test_different_servers_independent(self):
        limiter = MCPRateLimiter(
            default_config=RateLimitConfig(requests_per_minute=2, burst_limit=1000)
        )
        limiter.check("read", "server_a")
        limiter.check("read", "server_a")
        assert not limiter.check("read", "server_a").allowed

        assert limiter.check("read", "server_b").allowed


# ---------------------------------------------------------------------------
# Sliding window accuracy with time mocking
# ---------------------------------------------------------------------------


class TestSlidingWindowAccuracy:
    def test_rpm_window_slides(self):
        """Requests should become available as the 60s window slides."""
        config = RateLimitConfig(
            requests_per_minute=2,
            requests_per_hour=10000,
            burst_limit=1000,
        )
        limiter = MCPRateLimiter(default_config=config)

        # Use time mocking for precise control
        t = 1000.0

        with patch("aegis.core.mcp_rate_limiter.time") as mock_time:
            mock_time.monotonic.return_value = t
            limiter.check("t", "s")  # t=1000

            mock_time.monotonic.return_value = t + 1.0
            limiter.check("t", "s")  # t=1001

            mock_time.monotonic.return_value = t + 2.0
            result = limiter.check("t", "s")  # t=1002 — should be denied
            assert not result.allowed

            # Advance past the first request's window expiry (1000 + 60 = 1060)
            mock_time.monotonic.return_value = t + 61.0
            result = limiter.check("t", "s")  # t=1061 — first request pruned
            assert result.allowed

    def test_rph_window_slides(self):
        config = RateLimitConfig(
            requests_per_minute=10000,
            requests_per_hour=2,
            burst_limit=1000,
        )
        limiter = MCPRateLimiter(default_config=config)

        t = 1000.0
        with patch("aegis.core.mcp_rate_limiter.time") as mock_time:
            mock_time.monotonic.return_value = t
            limiter.check("t", "s")

            mock_time.monotonic.return_value = t + 1.0
            limiter.check("t", "s")

            mock_time.monotonic.return_value = t + 2.0
            result = limiter.check("t", "s")
            assert not result.allowed

            # Advance past the first request's hour window
            mock_time.monotonic.return_value = t + 3601.0
            result = limiter.check("t", "s")
            assert result.allowed

    def test_burst_window_resets_after_1_second(self):
        config = RateLimitConfig(
            requests_per_minute=10000,
            requests_per_hour=100000,
            burst_limit=2,
            cooldown_seconds=0.05,
        )
        limiter = MCPRateLimiter(default_config=config)

        t = 1000.0
        with patch("aegis.core.mcp_rate_limiter.time") as mock_time:
            mock_time.monotonic.return_value = t
            limiter.check("t", "s")

            mock_time.monotonic.return_value = t + 0.1
            limiter.check("t", "s")

            # Third call within 1s — burst
            mock_time.monotonic.return_value = t + 0.2
            result = limiter.check("t", "s")
            assert not result.allowed
            assert result.burst_detected

            # Wait for cooldown to expire
            mock_time.monotonic.return_value = t + 0.3  # 0.2 + 0.05 cooldown
            result = limiter.check("t", "s")
            assert result.allowed


# ---------------------------------------------------------------------------
# Integration: mixed usage patterns
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_full_workflow(self):
        """Simulate a realistic MCP rate limiting scenario."""
        limiter = MCPRateLimiter(
            server_configs={
                "filesystem": RateLimitConfig(requests_per_minute=10, burst_limit=1000),
                "database": RateLimitConfig(requests_per_minute=5, burst_limit=1000),
            },
            tool_configs={
                "filesystem.delete_file": RateLimitConfig(requests_per_minute=2, burst_limit=1000),
            },
        )

        # Filesystem reads — up to 10 per minute
        for _ in range(10):
            assert limiter.check("read_file", "filesystem").allowed
        assert not limiter.check("read_file", "filesystem").allowed

        # Filesystem deletes — only 2 per minute
        assert limiter.check("delete_file", "filesystem").allowed
        assert limiter.check("delete_file", "filesystem").allowed
        assert not limiter.check("delete_file", "filesystem").allowed

        # Database queries — 5 per minute
        for _ in range(5):
            assert limiter.check("query", "database").allowed
        assert not limiter.check("query", "database").allowed

        # Check stats
        stats = limiter.get_stats()
        assert stats["filesystem.read_file"]["current_rpm"] == 10
        assert stats["filesystem.delete_file"]["current_rpm"] == 2
        assert stats["database.query"]["current_rpm"] == 5

        # Hot-update: tighten database limit
        limiter.set_config(
            RateLimitConfig(requests_per_minute=3, burst_limit=1000),
            server_name="database",
        )
        # Already at 5, new limit is 3 — still denied
        assert not limiter.check("query", "database").allowed

        # Reset database
        limiter.reset(server_name="database")
        assert limiter.check("query", "database").allowed
