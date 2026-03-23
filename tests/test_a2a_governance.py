"""Tests for agent-to-agent communication governance."""

from __future__ import annotations

from aegis.core.a2a_governance import (
    A2AGovernor,
    A2AMessage,
    _flatten_payload,
    redact_payload,
    scan_content,
)
from aegis.core.agent_identity import AgentIdentity, AgentRegistry


def _make_registry() -> AgentRegistry:
    """Create a test registry with two agents."""
    registry = AgentRegistry()
    orchestrator = AgentIdentity(
        agent_id="orchestrator",
        name="Orchestrator",
        capabilities=frozenset({
            "a2a_send_task",
            "a2a_respond_task",
            "a2a_delegate",
            "a2a_notify",
            "a2a_share_data",
        }),
        trust_level=90,
    )
    worker = AgentIdentity(
        agent_id="worker-1",
        name="Worker 1",
        capabilities=frozenset({
            "a2a_respond_task",
            "a2a_notify",
        }),
        trust_level=60,
    )
    registry.register(orchestrator)
    registry.register(worker)
    return registry


# ---------------------------------------------------------------------------
# A2AMessage
# ---------------------------------------------------------------------------


class TestA2AMessage:
    def test_auto_timestamp(self) -> None:
        msg = A2AMessage(
            sender_id="a", receiver_id="b", message_type="notification"
        )
        assert msg.timestamp > 0

    def test_custom_timestamp(self) -> None:
        msg = A2AMessage(
            sender_id="a",
            receiver_id="b",
            message_type="notification",
            timestamp=123.0,
        )
        assert msg.timestamp == 123.0

    def test_default_payload(self) -> None:
        msg = A2AMessage(
            sender_id="a", receiver_id="b", message_type="notification"
        )
        assert msg.payload == {}

    def test_correlation_id(self) -> None:
        msg = A2AMessage(
            sender_id="a",
            receiver_id="b",
            message_type="task_request",
            correlation_id="corr-123",
        )
        assert msg.correlation_id == "corr-123"


# ---------------------------------------------------------------------------
# Content scanning
# ---------------------------------------------------------------------------


class TestContentScanning:
    def test_clean_payload(self) -> None:
        findings = scan_content({"action": "read_file", "path": "/tmp/data.csv"})
        assert len(findings) == 0

    def test_api_key_detected(self) -> None:
        findings = scan_content({"config": "api_key=sk-123abc"})
        assert any(name == "api_key" for name, _ in findings)

    def test_password_detected(self) -> None:
        findings = scan_content({"cred": "password=hunter2"})
        assert any(name == "password" for name, _ in findings)

    def test_bearer_token_detected(self) -> None:
        findings = scan_content({"header": "Bearer eyJhbGciOiJIUzI1NiJ9"})
        assert any(name == "bearer_token" for name, _ in findings)

    def test_aws_key_detected(self) -> None:
        findings = scan_content({"key": "AKIAIOSFODNN7EXAMPLE"})
        assert any(name == "aws_key" for name, _ in findings)

    def test_email_detected(self) -> None:
        findings = scan_content({"contact": "user@example.com"})
        assert any(name == "email_address" for name, _ in findings)

    def test_ssn_detected(self) -> None:
        findings = scan_content({"data": "SSN: 123-45-6789"})
        assert any(name == "ssn" for name, _ in findings)

    def test_internal_path_detected(self) -> None:
        findings = scan_content({"path": "/etc/passwd"})
        assert any(name == "internal_path" for name, _ in findings)

    def test_nested_payload(self) -> None:
        findings = scan_content({
            "level1": {"level2": {"secret": "password=abc123"}},
        })
        assert any(name == "password" for name, _ in findings)


# ---------------------------------------------------------------------------
# Content redaction
# ---------------------------------------------------------------------------


class TestRedaction:
    def test_redact_api_key(self) -> None:
        result = redact_payload({"config": "api_key=sk-123abc"})
        assert "sk-123abc" not in result["config"]
        assert "[REDACTED]" in result["config"]

    def test_redact_nested(self) -> None:
        result = redact_payload({
            "outer": {"inner": "password=secret123"},
        })
        assert "secret123" not in str(result)
        assert "[REDACTED]" in result["outer"]["inner"]

    def test_clean_payload_unchanged(self) -> None:
        payload = {"action": "read_file", "path": "/tmp/data.csv"}
        result = redact_payload(payload)
        assert result == payload

    def test_redact_list(self) -> None:
        result = redact_payload({
            "items": ["normal", "password=secret123"],
        })
        assert "secret123" not in str(result)
        assert result["items"][0] == "normal"

    def test_redact_non_string_preserved(self) -> None:
        result = redact_payload({"count": 42, "flag": True})
        assert result["count"] == 42
        assert result["flag"] is True


# ---------------------------------------------------------------------------
# Flatten helper
# ---------------------------------------------------------------------------


class TestFlattenPayload:
    def test_simple(self) -> None:
        result = _flatten_payload({"a": "hello", "b": "world"})
        assert "hello" in result
        assert "world" in result

    def test_nested(self) -> None:
        result = _flatten_payload({"a": {"b": "deep"}})
        assert "deep" in result

    def test_list_values(self) -> None:
        result = _flatten_payload({"items": ["one", "two"]})
        assert "one" in result
        assert "two" in result

    def test_depth_limit(self) -> None:
        nested: dict = {"val": "target"}
        for _ in range(15):
            nested = {"x": nested}
        result = _flatten_payload(nested)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# A2AGovernor — registration checks
# ---------------------------------------------------------------------------


class TestGovernorRegistration:
    def test_unknown_sender_blocked(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="unknown",
            receiver_id="worker-1",
            message_type="notification",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert "unknown_sender" in decision.violations

    def test_unknown_receiver_blocked(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="unknown",
            message_type="notification",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert "unknown_receiver" in decision.violations

    def test_self_message_blocked(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="orchestrator",
            message_type="notification",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert "self_message" in decision.violations


# ---------------------------------------------------------------------------
# A2AGovernor — capability checks
# ---------------------------------------------------------------------------


class TestGovernorCapability:
    def test_allowed_with_capability(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed

    def test_blocked_missing_capability(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        # worker-1 doesn't have a2a_send_task
        msg = A2AMessage(
            sender_id="worker-1",
            receiver_id="orchestrator",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert any("missing_capability" in v for v in decision.violations)

    def test_allowed_respond_task(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="worker-1",
            receiver_id="orchestrator",
            message_type="task_response",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed

    def test_custom_message_type_no_cap_required(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        # Custom message types not in capability_map are allowed
        msg = A2AMessage(
            sender_id="worker-1",
            receiver_id="orchestrator",
            message_type="custom_type",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed


# ---------------------------------------------------------------------------
# A2AGovernor — trust level checks
# ---------------------------------------------------------------------------


class TestGovernorTrust:
    def test_trust_sufficient(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, min_trust_level=50)
        msg = A2AMessage(
            sender_id="worker-1",
            receiver_id="orchestrator",
            message_type="notification",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed

    def test_trust_insufficient(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, min_trust_level=80)
        # worker-1 has trust_level=60
        msg = A2AMessage(
            sender_id="worker-1",
            receiver_id="orchestrator",
            message_type="notification",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert any("insufficient_trust" in v for v in decision.violations)


# ---------------------------------------------------------------------------
# A2AGovernor — content filtering
# ---------------------------------------------------------------------------


class TestGovernorContentFilter:
    def test_clean_content_allowed(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
            payload={"action": "read", "path": "/tmp/data.csv"},
        )
        decision = governor.evaluate(msg)
        assert decision.allowed
        assert decision.filtered_payload is None

    def test_sensitive_content_redacted(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, block_on_sensitive=False)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
            payload={"config": "api_key=sk-123abc"},
        )
        decision = governor.evaluate(msg)
        assert decision.allowed
        assert decision.filtered_payload is not None
        assert "sk-123abc" not in str(decision.filtered_payload)

    def test_sensitive_content_blocked(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, block_on_sensitive=True)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
            payload={"config": "api_key=sk-123abc"},
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert any("sensitive_content" in v for v in decision.violations)

    def test_content_filter_disabled(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, content_filter=False)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
            payload={"config": "api_key=sk-123abc"},
        )
        decision = governor.evaluate(msg)
        assert decision.allowed
        assert decision.filtered_payload is None


# ---------------------------------------------------------------------------
# A2AGovernor — rate limiting
# ---------------------------------------------------------------------------


class TestGovernorRateLimiting:
    def test_under_limit_allowed(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            rate_limit_per_sender=5,
            rate_window_seconds=60.0,
            content_filter=False,
        )
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        for _ in range(5):
            decision = governor.evaluate(msg)
        assert decision.allowed

    def test_sender_limit_exceeded(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            rate_limit_per_sender=3,
            rate_window_seconds=60.0,
            content_filter=False,
        )
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decisions = [governor.evaluate(msg) for _ in range(4)]
        assert decisions[2].allowed  # 3rd is OK
        assert not decisions[3].allowed  # 4th exceeds
        assert "rate_limit_sender" in decisions[3].violations

    def test_pair_limit_exceeded(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            rate_limit_per_sender=100,
            rate_limit_per_pair=2,
            rate_window_seconds=60.0,
            content_filter=False,
        )
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decisions = [governor.evaluate(msg) for _ in range(3)]
        assert decisions[1].allowed
        assert not decisions[2].allowed
        assert "rate_limit_pair" in decisions[2].violations


# ---------------------------------------------------------------------------
# A2AGovernor — audit log
# ---------------------------------------------------------------------------


class TestGovernorAuditLog:
    def test_log_records_decisions(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, content_filter=False)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        governor.evaluate(msg)
        log = governor.audit_log
        assert len(log) == 1
        assert log[0].allowed is True
        assert log[0].sender_id == "orchestrator"
        assert log[0].message_type == "task_request"

    def test_log_blocked_entry(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        msg = A2AMessage(
            sender_id="unknown",
            receiver_id="worker-1",
            message_type="notification",
        )
        governor.evaluate(msg)
        log = governor.audit_log
        assert len(log) == 1
        assert log[0].allowed is False

    def test_format_audit_log_empty(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)
        text = governor.format_audit_log()
        assert "No entries" in text

    def test_format_audit_log_with_entries(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, content_filter=False)
        governor.evaluate(A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        ))
        governor.evaluate(A2AMessage(
            sender_id="unknown",
            receiver_id="worker-1",
            message_type="notification",
        ))
        text = governor.format_audit_log()
        assert "ALLOW" in text
        assert "BLOCK" in text
        assert "Total messages: 2" in text
        assert "Allowed: 1" in text
        assert "Blocked: 1" in text
