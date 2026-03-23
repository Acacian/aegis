"""Tests for OpenTelemetry export module."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any
from unittest.mock import MagicMock

from aegis.core.otel_export import AegisEvent, AegisOTelExporter, _otel_safe

# ---------------------------------------------------------------------------
# In-memory mode (no tracer)
# ---------------------------------------------------------------------------


class TestInMemoryMode:
    def test_record_decision(self) -> None:
        exp = AegisOTelExporter()
        event = exp.record_decision(
            "read", "crm", "allow",
            risk_level="low",
            matched_rule="default-allow",
            agent_id="agent-1",
        )
        assert isinstance(event, AegisEvent)
        assert event.event_type == "policy_decision"
        assert event.attributes["aegis.action.type"] == "read"
        assert event.attributes["aegis.decision"] == "allow"
        assert exp.event_count == 1

    def test_record_cost(self) -> None:
        exp = AegisOTelExporter()
        event = exp.record_cost(
            "gpt-4o", 1000, 200, 0.0045, 0.0045,
            agent_id="agent-1",
        )
        assert event.event_type == "cost_record"
        assert event.attributes["aegis.cost.model"] == "gpt-4o"
        assert event.attributes["aegis.cost.amount"] == 0.0045
        assert event.attributes["aegis.cost.input_tokens"] == 1000

    def test_record_anomaly(self) -> None:
        exp = AegisOTelExporter()
        event = exp.record_anomaly(
            "agent-1", "burst", "read",
            severity="warning",
            details="50 actions in 10s",
        )
        assert event.event_type == "anomaly_detected"
        assert event.attributes["aegis.anomaly.type"] == "burst"

    def test_record_mcp_finding(self) -> None:
        exp = AegisOTelExporter()
        event = exp.record_mcp_finding(
            "evil_tool", "tool_poisoning", "critical",
            detail="Authority injection detected",
            trust_level="L0",
        )
        assert event.event_type == "mcp_security_finding"
        assert event.attributes["aegis.mcp.severity"] == "critical"

    def test_record_budget_alert(self) -> None:
        exp = AegisOTelExporter()
        event = exp.record_budget_alert(
            "warn", 8.0, 10.0, 0.8,
            session_id="sess-123",
        )
        assert event.event_type == "budget_alert"
        assert event.attributes["aegis.budget.utilization"] == 0.8

    def test_events_accumulate(self) -> None:
        exp = AegisOTelExporter()
        exp.record_decision("read", "x", "allow")
        exp.record_cost("gpt-4o", 100, 50, 0.001, 0.001)
        exp.record_anomaly("a", "burst", "write")
        assert exp.event_count == 3
        assert len(exp.events) == 3

    def test_events_are_copies(self) -> None:
        exp = AegisOTelExporter()
        exp.record_decision("read", "x", "allow")
        events1 = exp.events
        events2 = exp.events
        assert events1 is not events2

    def test_timestamp_populated(self) -> None:
        exp = AegisOTelExporter()
        event = exp.record_decision("read", "x", "allow")
        assert event.timestamp > 0


# ---------------------------------------------------------------------------
# OTel tracer mode (mock tracer)
# ---------------------------------------------------------------------------


class _MockSpan:
    """Minimal span mock for testing."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []
        self.attributes: dict[str, Any] = {}

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        self.events.append((name, attributes or {}))

    def __enter__(self) -> _MockSpan:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _MockTracer:
    """Minimal tracer mock for testing."""

    def __init__(self) -> None:
        self.spans: list[_MockSpan] = []

    @contextmanager
    def start_as_current_span(self, name: str, attributes: dict[str, Any] | None = None):
        span = _MockSpan()
        span.attributes = attributes or {}
        self.spans.append(span)
        yield span


class TestOTelTracerMode:
    def test_decision_creates_span(self) -> None:
        tracer = _MockTracer()
        exp = AegisOTelExporter(tracer=tracer)
        exp.record_decision("delete", "db", "block", risk_level="critical")
        assert len(tracer.spans) == 1
        span = tracer.spans[0]
        assert "aegis.action.type" in span.attributes
        assert len(span.events) == 1
        assert span.events[0][0] == "policy_decision"

    def test_cost_creates_span(self) -> None:
        tracer = _MockTracer()
        exp = AegisOTelExporter(tracer=tracer)
        exp.record_cost("gpt-4o", 1000, 200, 0.005, 0.005)
        assert len(tracer.spans) == 1
        span = tracer.spans[0]
        assert span.events[0][0] == "cost_record"

    def test_service_name_in_attributes(self) -> None:
        tracer = _MockTracer()
        exp = AegisOTelExporter(tracer=tracer, service_name="my-agent-app")
        exp.record_decision("read", "crm", "allow")
        span = tracer.spans[0]
        assert span.attributes["service.name"] == "my-agent-app"

    def test_tracer_error_does_not_break(self) -> None:
        """OTel errors must never break governance."""
        bad_tracer = MagicMock()
        bad_tracer.start_as_current_span.side_effect = RuntimeError("OTel broken")
        exp = AegisOTelExporter(tracer=bad_tracer)
        # Should not raise
        event = exp.record_decision("read", "crm", "allow")
        assert event is not None
        assert exp.event_count == 1

    def test_multiple_event_types(self) -> None:
        tracer = _MockTracer()
        exp = AegisOTelExporter(tracer=tracer)
        exp.record_decision("read", "crm", "allow")
        exp.record_cost("gpt-4o", 100, 50, 0.001, 0.001)
        exp.record_anomaly("a1", "burst", "write")
        exp.record_mcp_finding("tool", "poisoning", "high")
        exp.record_budget_alert("warn", 8.0, 10.0, 0.8)
        assert len(tracer.spans) == 5
        # Also stored in memory
        assert exp.event_count == 5


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


class TestOtelSafe:
    def test_string_passthrough(self) -> None:
        assert _otel_safe("hello") == "hello"

    def test_int_passthrough(self) -> None:
        assert _otel_safe(42) == 42

    def test_float_passthrough(self) -> None:
        assert _otel_safe(3.14) == 3.14

    def test_bool_passthrough(self) -> None:
        assert _otel_safe(True) is True

    def test_complex_type_to_string(self) -> None:
        assert _otel_safe([1, 2, 3]) == "[1, 2, 3]"
        assert _otel_safe({"key": "val"}) == "{'key': 'val'}"
        assert _otel_safe(None) == "None"
