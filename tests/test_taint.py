"""Tests for aegis.core.taint — data taint tracking."""

from __future__ import annotations

import pytest

from aegis.core.taint import (
    TaintAction,
    TaintedValue,
    TaintLabel,
    TaintPolicy,
    TaintPolicyRule,
    TaintReport,
    TaintSeverity,
    TaintTracker,
)

# ---------------------------------------------------------------------------
# TaintedValue
# ---------------------------------------------------------------------------


class TestTaintedValue:
    def test_creation(self) -> None:
        tv = TaintedValue(
            taint_id="t-1",
            labels=frozenset({TaintLabel.USER_INPUT}),
            source="user",
            payload_hash="abc123",
            created_at=1000.0,
        )
        assert tv.taint_id == "t-1"
        assert TaintLabel.USER_INPUT in tv.labels
        assert tv.source == "user"

    def test_frozen(self) -> None:
        tv = TaintedValue(
            taint_id="t-1",
            labels=frozenset({TaintLabel.USER_INPUT}),
            source="user",
            payload_hash="abc",
            created_at=1000.0,
        )
        with pytest.raises(AttributeError):
            tv.source = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TaintPolicy
# ---------------------------------------------------------------------------


class TestTaintPolicy:
    def test_default_policy_blocks_untrusted_to_exec(self) -> None:
        policy = TaintPolicy()
        tv = TaintedValue(
            taint_id="t-1",
            labels=frozenset({TaintLabel.UNTRUSTED}),
            source="web",
            payload_hash="h",
            created_at=0,
        )
        finding = policy.evaluate(tv, "code_execution")
        assert finding is not None
        assert finding.action == TaintAction.BLOCK
        assert finding.severity == TaintSeverity.CRITICAL

    def test_default_policy_allows_sanitised(self) -> None:
        policy = TaintPolicy()
        tv = TaintedValue(
            taint_id="t-1",
            labels=frozenset({TaintLabel.SANITISED}),
            source="sanitiser",
            payload_hash="h",
            created_at=0,
        )
        finding = policy.evaluate(tv, "code_execution")
        assert finding is None

    def test_no_match_returns_none(self) -> None:
        policy = TaintPolicy()
        tv = TaintedValue(
            taint_id="t-1",
            labels=frozenset({TaintLabel.MODEL_OUTPUT}),
            source="llm",
            payload_hash="h",
            created_at=0,
        )
        assert policy.evaluate(tv, "unknown_sink") is None

    def test_custom_rule(self) -> None:
        rule = TaintPolicyRule(
            name="custom",
            source_labels=frozenset({TaintLabel.FILE_SYSTEM}),
            sink_pattern="network",
            action=TaintAction.WARN,
            severity=TaintSeverity.MEDIUM,
        )
        policy = TaintPolicy(rules=[rule])
        tv = TaintedValue(
            taint_id="t-1",
            labels=frozenset({TaintLabel.FILE_SYSTEM}),
            source="fs",
            payload_hash="h",
            created_at=0,
        )
        finding = policy.evaluate(tv, "network")
        assert finding is not None
        assert finding.action == TaintAction.WARN

    def test_add_rule(self) -> None:
        policy = TaintPolicy(rules=[])
        assert len(policy.rules) == 0
        policy.add_rule(
            TaintPolicyRule(
                name="new",
                source_labels=frozenset({TaintLabel.DATABASE}),
                sink_pattern="external_api",
                action=TaintAction.LOG,
            )
        )
        assert len(policy.rules) == 1


# ---------------------------------------------------------------------------
# TaintTracker
# ---------------------------------------------------------------------------


class TestTaintTracker:
    def test_tag_creates_tainted_value(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("user-input", TaintLabel.USER_INPUT, payload="hello")
        assert tv.taint_id.startswith("taint-")
        assert TaintLabel.USER_INPUT in tv.labels
        assert len(tv.propagation_chain) == 1

    def test_propagate_extends_chain(self) -> None:
        tracker = TaintTracker()
        tv1 = tracker.tag("source", TaintLabel.EXTERNAL_API)
        tv2 = tracker.propagate(tv1, "processor", TaintLabel.TOOL_OUTPUT)
        assert len(tv2.propagation_chain) == 2
        assert TaintLabel.EXTERNAL_API in tv2.labels
        assert TaintLabel.TOOL_OUTPUT in tv2.labels

    def test_propagate_without_new_label(self) -> None:
        tracker = TaintTracker()
        tv1 = tracker.tag("source", TaintLabel.USER_INPUT)
        tv2 = tracker.propagate(tv1, "step2")
        assert tv2.labels == tv1.labels
        assert len(tv2.propagation_chain) == 2

    def test_sanitise_clears_labels(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("source", TaintLabel.UNTRUSTED)
        sanitised = tracker.sanitise(tv)
        assert sanitised.labels == frozenset({TaintLabel.SANITISED})
        assert len(sanitised.propagation_chain) == 2

    def test_check_sink_with_violation(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("web", TaintLabel.UNTRUSTED)
        finding = tracker.check_sink(tv, "code_execution")
        assert finding is not None
        assert finding.action == TaintAction.BLOCK

    def test_check_sink_clean(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("model", TaintLabel.MODEL_OUTPUT)
        finding = tracker.check_sink(tv, "display")
        assert finding is None

    def test_analyze_report(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("web", TaintLabel.UNTRUSTED)
        tracker.propagate(tv, "handler")
        tracker.check_sink(tv, "code_execution")
        report = tracker.analyze()
        assert isinstance(report, TaintReport)
        assert report.total_tracked == 1  # same taint_id, updated
        assert report.sinks_reached == 1
        assert not report.clean

    def test_analyze_clean_report(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("safe", TaintLabel.MODEL_OUTPUT)
        tracker.check_sink(tv, "display")
        report = tracker.analyze()
        assert report.clean

    def test_get_chain(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("a", TaintLabel.USER_INPUT)
        tv2 = tracker.propagate(tv, "b", TaintLabel.TOOL_OUTPUT)
        chain = tracker.get_chain(tv2.taint_id)
        assert chain is not None
        assert len(chain) == 2

    def test_get_tainted_sinks(self) -> None:
        tracker = TaintTracker()
        tv = tracker.tag("src", TaintLabel.UNTRUSTED)
        tracker.check_sink(tv, "code_execution")
        tracker.check_sink(tv, "database")
        sinks = tracker.get_tainted_sinks()
        assert "code_execution" in sinks
        assert "database" in sinks

    def test_reset(self) -> None:
        tracker = TaintTracker()
        tracker.tag("src", TaintLabel.USER_INPUT)
        tracker.reset()
        report = tracker.analyze()
        assert report.total_tracked == 0

    def test_end_to_end_flow(self) -> None:
        """Full taint flow: tag → propagate → check → sanitise → check."""
        tracker = TaintTracker()

        # User input tagged
        tv = tracker.tag("user", TaintLabel.USER_INPUT, payload="SELECT * FROM users")

        # Flows through SQL builder
        tv = tracker.propagate(tv, "sql_builder", TaintLabel.TOOL_OUTPUT)

        # Would be blocked at database sink
        finding = tracker.check_sink(tv, "file_write")
        assert finding is not None
        assert finding.action == TaintAction.WARN

        # Sanitise
        tv = tracker.sanitise(tv)

        # Now clean at the same sink
        finding = tracker.check_sink(tv, "file_write")
        assert finding is None
