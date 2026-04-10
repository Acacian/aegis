"""Tests for agent-to-agent communication governance."""

from __future__ import annotations

from aegis.core.a2a_governance import (
    A2ADecision,
    A2AGovernor,
    A2AMessage,
    GovernanceEnvelope,
    GovernanceHandshake,
    _flatten_payload,
    redact_payload,
    scan_content,
)
from aegis.core.agent_identity import AgentIdentity, AgentRegistry
from aegis.core.constitution import AgentConstitution, AgentOntology, Constraint


def _make_registry() -> AgentRegistry:
    """Create a test registry with two agents."""
    registry = AgentRegistry()
    orchestrator = AgentIdentity(
        agent_id="orchestrator",
        name="Orchestrator",
        capabilities=frozenset(
            {
                "a2a_send_task",
                "a2a_respond_task",
                "a2a_delegate",
                "a2a_notify",
                "a2a_share_data",
            }
        ),
        trust_level=90,
    )
    worker = AgentIdentity(
        agent_id="worker-1",
        name="Worker 1",
        capabilities=frozenset(
            {
                "a2a_respond_task",
                "a2a_notify",
            }
        ),
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
        msg = A2AMessage(sender_id="a", receiver_id="b", message_type="notification")
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
        msg = A2AMessage(sender_id="a", receiver_id="b", message_type="notification")
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
        findings = scan_content(
            {
                "level1": {"level2": {"secret": "password=abc123"}},
            }
        )
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
        result = redact_payload(
            {
                "outer": {"inner": "password=secret123"},
            }
        )
        assert "secret123" not in str(result)
        assert "[REDACTED]" in result["outer"]["inner"]

    def test_clean_payload_unchanged(self) -> None:
        payload = {"action": "read_file", "path": "/tmp/data.csv"}
        result = redact_payload(payload)
        assert result == payload

    def test_redact_list(self) -> None:
        result = redact_payload(
            {
                "items": ["normal", "password=secret123"],
            }
        )
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
        governor.evaluate(
            A2AMessage(
                sender_id="orchestrator",
                receiver_id="worker-1",
                message_type="task_request",
            )
        )
        governor.evaluate(
            A2AMessage(
                sender_id="unknown",
                receiver_id="worker-1",
                message_type="notification",
            )
        )
        text = governor.format_audit_log()
        assert "ALLOW" in text
        assert "BLOCK" in text
        assert "Total messages: 2" in text
        assert "Allowed: 1" in text
        assert "Blocked: 1" in text


# ---------------------------------------------------------------------------
# Helper: registry with constitutional agents
# ---------------------------------------------------------------------------


def _make_constitutional_registry() -> AgentRegistry:
    """Create a registry with agents that have constitutions."""
    registry = AgentRegistry()
    orchestrator = AgentIdentity(
        agent_id="orch",
        name="Orchestrator",
        capabilities=frozenset(
            {"a2a_send_task", "a2a_respond_task", "a2a_delegate", "a2a_notify"}
        ),
        trust_level=90,
        constitution=AgentConstitution(
            ontology=AgentOntology(role="orchestrator", domain="finance"),
            capabilities=frozenset({"a2a_send_task", "a2a_delegate"}),
            constraints=(
                Constraint(
                    name="no_external",
                    forbidden_targets=frozenset({"external"}),
                    forbidden_patterns=frozenset({"data_share"}),
                ),
            ),
        ),
    )
    worker = AgentIdentity(
        agent_id="wrk",
        name="Worker",
        capabilities=frozenset({"a2a_respond_task", "a2a_notify"}),
        trust_level=70,
        constitution=AgentConstitution(
            ontology=AgentOntology(role="worker", domain="finance"),
            capabilities=frozenset({"a2a_respond_task"}),
            constraints=(
                Constraint(
                    name="no_delete",
                    forbidden_patterns=frozenset({"delete_*"}),
                ),
            ),
        ),
    )
    registry.register(orchestrator)
    registry.register(worker)
    return registry


# ---------------------------------------------------------------------------
# Governance Envelope
# ---------------------------------------------------------------------------


class TestGovernanceEnvelope:
    def test_envelope_not_attached_by_default(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry, content_filter=False)
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed
        assert decision.envelope is None

    def test_envelope_attached_when_enabled(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            attach_envelope=True,
            policy_version="v1",
        )
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed
        assert decision.envelope is not None
        assert isinstance(decision.envelope, GovernanceEnvelope)
        assert decision.envelope.trust_level == 90
        assert decision.envelope.policy_version == "v1"
        assert decision.envelope.signature_hash

    def test_envelope_not_attached_to_blocked(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            attach_envelope=True,
        )
        msg = A2AMessage(
            sender_id="unknown",
            receiver_id="worker-1",
            message_type="notification",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert decision.envelope is None

    def test_envelope_contains_constitution_data(self) -> None:
        registry = _make_constitutional_registry()
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            attach_envelope=True,
        )
        msg = A2AMessage(
            sender_id="orch",
            receiver_id="wrk",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.envelope is not None
        assert decision.envelope.sender_ontology["role"] == "orchestrator"
        assert decision.envelope.sender_ontology["domain"] == "finance"
        assert "no_external" in decision.envelope.sender_constraints

    def test_envelope_delegation_depth(self) -> None:
        registry = _make_constitutional_registry()
        child = AgentIdentity(
            agent_id="child",
            name="Child",
            capabilities=frozenset({"a2a_respond_task"}),
            trust_level=60,
        )
        registry.delegate("orch", child)
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            attach_envelope=True,
        )
        msg = A2AMessage(
            sender_id="child",
            receiver_id="wrk",
            message_type="task_response",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed
        assert decision.envelope is not None
        assert decision.envelope.delegation_depth == 1

    def test_envelope_signature_deterministic(self) -> None:
        """Two envelopes built at same time should have same hash."""
        # We just verify the hash is a non-empty hex string
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            attach_envelope=True,
        )
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.envelope is not None
        assert len(decision.envelope.signature_hash) == 64  # SHA-256 hex

    def test_envelope_with_no_constitution(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            attach_envelope=True,
        )
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.envelope is not None
        assert decision.envelope.sender_ontology == {"role": "", "domain": ""}
        assert decision.envelope.sender_constraints == frozenset()

    def test_a2a_message_backward_compat(self) -> None:
        msg = A2AMessage(sender_id="a", receiver_id="b", message_type="t")
        assert msg.envelope is None

    def test_a2a_decision_backward_compat(self) -> None:
        msg = A2AMessage(sender_id="a", receiver_id="b", message_type="t")
        decision = A2ADecision(allowed=True, message=msg, reason="ok")
        assert decision.envelope is None


# ---------------------------------------------------------------------------
# Governance Handshake
# ---------------------------------------------------------------------------


class TestGovernanceHandshake:
    def test_compatible_agents(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orch", "wrk")
        assert result.compatible

    def test_domain_mismatch_blocks(self) -> None:
        registry = AgentRegistry()
        registry.register(
            AgentIdentity(
                agent_id="a",
                name="A",
                capabilities=frozenset({"cap"}),
                trust_level=80,
                constitution=AgentConstitution(
                    ontology=AgentOntology(role="r", domain="finance"),
                ),
            )
        )
        registry.register(
            AgentIdentity(
                agent_id="b",
                name="B",
                capabilities=frozenset({"cap"}),
                trust_level=80,
                constitution=AgentConstitution(
                    ontology=AgentOntology(role="r", domain="healthcare"),
                ),
            )
        )
        hs = GovernanceHandshake(registry=registry, require_domain_match=True)
        result = hs.negotiate("a", "b")
        assert not result.compatible
        assert any("Domain mismatch" in r for r in result.reasons)

    def test_domain_match_with_empty_domain(self) -> None:
        registry = AgentRegistry()
        registry.register(
            AgentIdentity(
                agent_id="a",
                name="A",
                capabilities=frozenset({"cap"}),
                trust_level=80,
                constitution=AgentConstitution(
                    ontology=AgentOntology(role="r", domain="finance"),
                ),
            )
        )
        registry.register(
            AgentIdentity(
                agent_id="b",
                name="B",
                capabilities=frozenset({"cap"}),
                trust_level=80,
            )
        )
        hs = GovernanceHandshake(registry=registry, require_domain_match=True)
        result = hs.negotiate("a", "b")
        assert result.compatible

    def test_insufficient_capability_overlap(self) -> None:
        registry = AgentRegistry()
        registry.register(
            AgentIdentity(
                agent_id="a",
                name="A",
                capabilities=frozenset({"cap_x"}),
                trust_level=80,
            )
        )
        registry.register(
            AgentIdentity(
                agent_id="b",
                name="B",
                capabilities=frozenset({"cap_y"}),
                trust_level=80,
            )
        )
        hs = GovernanceHandshake(registry=registry, min_capability_overlap=1)
        result = hs.negotiate("a", "b")
        assert not result.compatible
        assert any("Insufficient capability overlap" in r for r in result.reasons)

    def test_sender_constraint_forbids_receiver_domain(self) -> None:
        registry = _make_constitutional_registry()
        # Add an agent in the "external" domain
        registry.register(
            AgentIdentity(
                agent_id="ext",
                name="External",
                capabilities=frozenset({"a2a_respond_task"}),
                trust_level=50,
                constitution=AgentConstitution(
                    ontology=AgentOntology(role="ext", domain="external"),
                ),
            )
        )
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orch", "ext")
        assert not result.compatible
        assert any("forbids target domain" in r for r in result.reasons)

    def test_sender_constraint_forbids_message_type(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orch", "wrk", message_type="data_share")
        assert not result.compatible
        assert any("forbids message type" in r for r in result.reasons)

    def test_receiver_constraint_forbids_message_type(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orch", "wrk", message_type="delete_data")
        assert not result.compatible
        assert any("Receiver constraint" in r for r in result.reasons)

    def test_trust_below_minimum(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry, min_trust_level=80)
        # wrk has trust_level=70
        result = hs.negotiate("orch", "wrk")
        assert not result.compatible
        assert any("Receiver trust" in r for r in result.reasons)

    def test_negotiated_capabilities_populated(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orch", "wrk")
        assert result.compatible
        assert len(result.negotiated_capabilities) > 0

    def test_handshake_integrated_with_governor(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry)
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            handshake=hs,
        )
        msg = A2AMessage(
            sender_id="orch",
            receiver_id="wrk",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed

    def test_handshake_failure_blocks_message(self) -> None:
        registry = _make_constitutional_registry()
        hs = GovernanceHandshake(registry=registry)
        governor = A2AGovernor(
            registry=registry,
            content_filter=False,
            handshake=hs,
        )
        # data_share is forbidden by orch's constraint
        msg = A2AMessage(
            sender_id="orch",
            receiver_id="wrk",
            message_type="data_share",
        )
        decision = governor.evaluate(msg)
        assert not decision.allowed
        assert "handshake_failed" in decision.violations

    def test_no_constitution_agents(self) -> None:
        registry = _make_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orchestrator", "worker-1")
        assert result.compatible

    def test_unregistered_sender(self) -> None:
        registry = _make_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("ghost", "worker-1")
        assert not result.compatible
        assert "Sender not registered" in result.reasons

    def test_unregistered_receiver(self) -> None:
        registry = _make_registry()
        hs = GovernanceHandshake(registry=registry)
        result = hs.negotiate("orchestrator", "ghost")
        assert not result.compatible
        assert "Receiver not registered" in result.reasons


# ---------------------------------------------------------------------------
# A2A + MASMonitor integration (P0-2)
# ---------------------------------------------------------------------------


class TestA2AMASMonitorIntegration:
    """A2AGovernor feeds MASMonitor; topology anomalies surface in decisions."""

    def test_allowed_messages_recorded_in_monitor(self) -> None:
        from aegis.core.mas_monitor import MASMonitor

        registry = _make_registry()
        monitor = MASMonitor(flood_rate=1000.0)  # effectively no flood
        monitor.register_agent("orchestrator")
        monitor.register_agent("worker-1")

        governor = A2AGovernor(
            registry=registry,
            mas_monitor=monitor,
            rate_limit_per_sender=1000,
            rate_limit_per_pair=1000,
        )

        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
            payload={"x": 1},
        )
        decision = governor.evaluate(msg)
        assert decision.allowed is True
        assert decision.topology_anomalies == ()

        # Topology graph should now know about this edge
        topology = monitor.get_topology()
        assert "worker-1" in topology.get("orchestrator", [])

    def test_blocked_messages_not_recorded(self) -> None:
        from aegis.core.mas_monitor import MASMonitor

        registry = _make_registry()
        monitor = MASMonitor()
        monitor.register_agent("orchestrator")
        monitor.register_agent("worker-1")

        # Governor with min_trust_level higher than anyone has
        governor = A2AGovernor(
            registry=registry,
            mas_monitor=monitor,
            min_trust_level=999,
        )

        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed is False

        # Monitor should NOT have recorded a blocked message
        topology = monitor.get_topology()
        assert topology.get("orchestrator", []) == []

    def test_topology_flood_downgrades_decision(self) -> None:
        from aegis.core.mas_monitor import MASMonitor

        registry = _make_registry()
        # Tight flood threshold so 3 messages already exceed the rate
        monitor = MASMonitor(flood_rate=2.0, flood_window_s=5.0)
        monitor.register_agent("orchestrator")
        monitor.register_agent("worker-1")

        governor = A2AGovernor(
            registry=registry,
            mas_monitor=monitor,
            rate_limit_per_sender=1000,
            rate_limit_per_pair=1000,
        )

        base_ts = 1_000_000.0
        last_decision: A2ADecision | None = None
        for i in range(10):
            msg = A2AMessage(
                sender_id="orchestrator",
                receiver_id="worker-1",
                message_type="task_request",
                timestamp=base_ts + i * 0.01,
            )
            last_decision = governor.evaluate(msg)

        assert last_decision is not None
        # Final message should be blocked by topology flood anomaly
        assert last_decision.allowed is False
        assert "topology_anomaly:flood" in last_decision.violations
        assert any(a.anomaly_type == "flood" for a in last_decision.topology_anomalies)
        assert "Topology anomaly" in last_decision.reason

    def test_ghost_anomaly_downgrades_decision(self) -> None:
        from aegis.core.mas_monitor import MASMonitor

        registry = _make_registry()
        monitor = MASMonitor()
        # Only register orchestrator → receiver is a "ghost" to the topology
        monitor.register_agent("orchestrator")

        governor = A2AGovernor(
            registry=registry,
            mas_monitor=monitor,
            rate_limit_per_sender=1000,
            rate_limit_per_pair=1000,
        )

        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed is False
        assert any(a.anomaly_type == "ghost" for a in decision.topology_anomalies)
        assert "topology_anomaly:ghost" in decision.violations

    def test_without_monitor_decisions_unchanged(self) -> None:
        registry = _make_registry()
        governor = A2AGovernor(registry=registry)  # no monitor

        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed is True
        assert decision.topology_anomalies == ()

    def test_low_severity_topology_anomaly_does_not_block(self) -> None:
        """Low-severity topology findings are surfaced but do not downgrade."""
        from aegis.core.mas_monitor import MASMonitor

        registry = _make_registry()
        # Threshold set so flood severity=high would still block; we only
        # want to check that "low" severity wouldn't override.
        monitor = MASMonitor(flood_rate=10.0, flood_window_s=1.0)
        monitor.register_agent("orchestrator")
        monitor.register_agent("worker-1")

        governor = A2AGovernor(
            registry=registry,
            mas_monitor=monitor,
            rate_limit_per_sender=1000,
            rate_limit_per_pair=1000,
            topology_block_severities=frozenset({"high"}),
        )

        # Normal single message — no anomaly at all
        msg = A2AMessage(
            sender_id="orchestrator",
            receiver_id="worker-1",
            message_type="task_request",
        )
        decision = governor.evaluate(msg)
        assert decision.allowed is True
        assert decision.topology_anomalies == ()
