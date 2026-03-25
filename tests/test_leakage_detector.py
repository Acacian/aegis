"""Tests for cross-session data leakage detection."""

from __future__ import annotations

import re

from aegis.core.leakage_detector import (
    LeakageDetector,
    LeakageFinding,
    LeakageReport,
    _extract_arg_values,
    _extract_tokens,
    _flatten_args,
)

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_flatten_args_simple(self) -> None:
        result = _flatten_args({"a": "hello", "b": "world"})
        assert "hello" in result
        assert "world" in result

    def test_flatten_args_nested(self) -> None:
        result = _flatten_args({"x": {"y": "deep_value"}})
        assert "deep_value" in result

    def test_flatten_args_depth_limit(self) -> None:
        nested: dict = {"val": "target"}
        for _ in range(15):
            nested = {"x": nested}
        result = _flatten_args(nested)
        assert isinstance(result, str)

    def test_extract_arg_values_min_length(self) -> None:
        values = _extract_arg_values({"short": "ab", "long": "abcdefgh"}, 8)
        assert "abcdefgh" in values
        assert "ab" not in values

    def test_extract_arg_values_nested(self) -> None:
        values = _extract_arg_values({"outer": {"inner": "long_enough_value"}}, 8)
        assert "long_enough_value" in values

    def test_extract_tokens(self) -> None:
        tokens = _extract_tokens("hello world, foo;bar|baz", 3)
        assert "hello" in tokens
        assert "world" in tokens
        assert "foo" in tokens
        assert "bar" in tokens
        assert "baz" in tokens


# ---------------------------------------------------------------------------
# Observation ingestion
# ---------------------------------------------------------------------------


class TestLeakageDetectorObserve:
    def test_observe_tool_call(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "test"},
        )
        report = detector.analyze()
        assert report.observations_analyzed == 1

    def test_observe_session(self) -> None:
        """Ingest from a Session-like object."""

        class _Event:
            def __init__(self, event_type: str, tool_name: str, data: dict) -> None:
                self.event_type = event_type
                self.tool_name = tool_name
                self.data = data

        class _Session:
            session_id = "sess-1"
            metadata: dict = {"tenant_id": "t1"}
            events = [
                _Event("tool_call", "search", {"arguments": {"q": "hello"}}),
                _Event("tool_result", "search", {"result": "world"}),
            ]

        detector = LeakageDetector()
        detector.observe_session(_Session())
        report = detector.analyze()
        assert report.observations_analyzed == 1
        assert report.sessions_analyzed == 1

    def test_empty_analysis(self) -> None:
        detector = LeakageDetector()
        report = detector.analyze()
        assert report.clean
        assert report.observations_analyzed == 0

    def test_reset(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="t",
            arguments={},
        )
        detector.reset()
        report = detector.analyze()
        assert report.observations_analyzed == 0


# ---------------------------------------------------------------------------
# Cross-tenant argument overlap
# ---------------------------------------------------------------------------


class TestCrossTenantOverlap:
    def test_no_overlap_clean(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "unique_query_aaa"},
        )
        detector.observe_tool_call(
            tenant_id="t2",
            session_id="s2",
            tool_name="search",
            arguments={"q": "different_bbb"},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "cross_tenant_overlap"]
        assert len(findings) == 0

    def test_overlap_detected(self) -> None:
        detector = LeakageDetector()
        shared = "shared_value_across_tenants"
        shared2 = "another_shared_value_long"
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": shared, "r": shared2},
        )
        detector.observe_tool_call(
            tenant_id="t2",
            session_id="s2",
            tool_name="search",
            arguments={"q": shared, "r": shared2},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "cross_tenant_overlap"]
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "t1" in findings[0].tenant_ids
        assert "t2" in findings[0].tenant_ids

    def test_short_values_ignored(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="t",
            arguments={"q": "short", "r": "short2"},
        )
        detector.observe_tool_call(
            tenant_id="t2",
            session_id="s2",
            tool_name="t",
            arguments={"q": "short", "r": "short2"},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "cross_tenant_overlap"]
        assert len(findings) == 0

    def test_single_tenant_no_finding(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="t",
            arguments={"q": "long_enough_value"},
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s2",
            tool_name="t",
            arguments={"q": "long_enough_value"},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "cross_tenant_overlap"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Session fingerprinting
# ---------------------------------------------------------------------------


class TestSessionFingerprinting:
    def test_single_fingerprint_no_finding(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="get_user_agent",
            arguments={},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "session_fingerprinting"]
        assert len(findings) == 0

    def test_multiple_fingerprints_flagged(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="get_user_agent",
            arguments={},
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="get_timezone",
            arguments={},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "session_fingerprinting"]
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_custom_fingerprint_patterns(self) -> None:
        custom = [("custom_probe", re.compile(r"custom_secret_tool", re.IGNORECASE))]
        detector = LeakageDetector(fingerprint_patterns=custom)
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="custom_secret_tool",
            arguments={},
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="get_user_agent",
            arguments={},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "session_fingerprinting"]
        assert len(findings) == 1
        assert "custom_probe" in findings[0].evidence["patterns"]


# ---------------------------------------------------------------------------
# Correlation probing
# ---------------------------------------------------------------------------


class TestCorrelationProbing:
    def test_no_repeated_calls_clean(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "query_one_long"},
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s2",
            tool_name="search",
            arguments={"q": "query_two_long"},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "correlation_probing"]
        assert len(findings) == 0

    def test_repeated_calls_across_sessions(self) -> None:
        detector = LeakageDetector()
        args1 = {"q": "same_query_value_long"}
        args2 = {"x": "another_same_value_long"}
        for sid in ("s1", "s2"):
            detector.observe_tool_call(
                tenant_id="t1",
                session_id=sid,
                tool_name="search",
                arguments=args1,
            )
            detector.observe_tool_call(
                tenant_id="t1",
                session_id=sid,
                tool_name="lookup",
                arguments=args2,
            )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "correlation_probing"]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_single_session_no_finding(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "same_query_value_long"},
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "same_query_value_long"},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "correlation_probing"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Exfiltration via tool args
# ---------------------------------------------------------------------------


class TestExfiltrationViaArgs:
    def test_no_result_reuse_clean(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "query_text_long"},
            result="some result text long enough",
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="process",
            arguments={"x": "unrelated_value_long"},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "exfiltration_via_args"]
        assert len(findings) == 0

    def test_result_embedded_in_args(self) -> None:
        detector = LeakageDetector()
        secret_result = "secret_token_from_server_response"
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="get_token",
            arguments={"a": "request_data"},
            result=secret_result,
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="send_data",
            arguments={"token": secret_result},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "exfiltration_via_args"]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_same_tool_result_in_own_args_ignored(self) -> None:
        detector = LeakageDetector()
        value = "long_value_repeated_in_same_tool"
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="tool_a",
            arguments={"x": "init"},
            result=value,
        )
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="tool_a",
            arguments={"x": value},
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "exfiltration_via_args"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Profile accumulation
# ---------------------------------------------------------------------------


class TestProfileAccumulation:
    def test_no_cross_tenant_leak_clean(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": "tenant_one_query_value"},
            result="normal result for t1",
        )
        detector.observe_tool_call(
            tenant_id="t2",
            session_id="s2",
            tool_name="search",
            arguments={"q": "tenant_two_query_value"},
            result="normal result for t2",
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "profile_accumulation"]
        assert len(findings) == 0

    def test_result_contains_other_tenant_data(self) -> None:
        detector = LeakageDetector()
        tenant1_secret = "tenant_one_secret_query_value"
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="search",
            arguments={"q": tenant1_secret},
            result="normal",
        )
        # t2's result contains t1's argument value = leakage
        detector.observe_tool_call(
            tenant_id="t2",
            session_id="s2",
            tool_name="search",
            arguments={"q": "something_different_long"},
            result=f"profile data: {tenant1_secret}",
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "profile_accumulation"]
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "t1" in findings[0].tenant_ids
        assert "t2" in findings[0].tenant_ids

    def test_single_tenant_no_finding(self) -> None:
        detector = LeakageDetector()
        detector.observe_tool_call(
            tenant_id="t1",
            session_id="s1",
            tool_name="t",
            arguments={"q": "long_value_here_test"},
            result="long_value_here_test",
        )
        report = detector.analyze()
        findings = [f for f in report.findings if f.category == "profile_accumulation"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


class TestLeakageReport:
    def test_clean_report(self) -> None:
        report = LeakageReport()
        assert report.clean

    def test_report_with_findings(self) -> None:
        report = LeakageReport(
            findings=[
                LeakageFinding(
                    category="test",
                    severity="high",
                    description="test finding",
                )
            ]
        )
        assert not report.clean

    def test_format_report(self) -> None:
        detector = LeakageDetector()
        report = detector.analyze()
        text = detector.format_report(report)
        assert "Cross-Session Leakage Report" in text
        assert "No leakage detected" in text
