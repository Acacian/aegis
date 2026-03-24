"""AGEF v1 schema conformance tests.

Validates that AGEF events conform to the JSON schema defined in
``specs/agef/v1/schema.json``. Tests cover all 7 event types,
required fields, enum constraints, evidence hash chains, timestamp
format, and UUID format.

No external JSON Schema validator is used; validation is done by
inspecting structure, types, and values directly.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

_SPECS_DIR = Path(__file__).resolve().parents[2] / "specs" / "agef" / "v1"
_SCHEMA_PATH = _SPECS_DIR / "schema.json"


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    """Load the AGEF v1 JSON schema."""
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Event types and their required sections (per allOf conditionals)
# ---------------------------------------------------------------------------

_EVENT_TYPE_REQUIRED_SECTIONS: dict[str, list[str]] = {
    "policy_decision": ["action", "decision"],
    "guardrail_trigger": ["guardrail"],
    "approval_request": ["action", "approval"],
    "approval_response": ["approval"],
    "cost_alert": ["cost"],
    "rate_limit": ["rate_limit"],
    "audit_entry": [],
}

_ALL_EVENT_TYPES = list(_EVENT_TYPE_REQUIRED_SECTIONS.keys())

# ---------------------------------------------------------------------------
# Enum value sets from the schema
# ---------------------------------------------------------------------------

_DECISION_OUTCOMES = {"allowed", "blocked", "masked", "warned", "escalated"}
_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
_GUARDRAIL_TYPES = {
    "pii_detection",
    "injection_detection",
    "toxicity_detection",
    "topic_restriction",
    "regex_pattern",
    "semantic_similarity",
    "custom",
}
_GUARDRAIL_ACTIONS = {"blocked", "masked", "warned", "allowed"}
_GUARDRAIL_SEVERITIES = {"low", "medium", "high", "critical"}
_APPROVAL_DECISIONS = {"approved", "denied", "timeout", None}
_RATE_LIMIT_TYPES = {
    "requests_per_minute",
    "requests_per_hour",
    "tokens_per_minute",
    "tokens_per_hour",
    "cost_per_hour",
    "custom",
}
_RATE_LIMIT_ACTIONS = {"throttled", "queued", "blocked", "warned"}

# ---------------------------------------------------------------------------
# Helpers: sample event builders
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_ISO8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"  # date + time
    r"(\.\d+)?"  # optional fractional seconds
    r"(Z|[+-]\d{2}:\d{2})$"  # timezone
)
_SHA256_HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


def _ts() -> str:
    """Return an ISO 8601 UTC timestamp."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _eid() -> str:
    """Return a UUID v4 string."""
    return str(uuid.uuid4())


def _evidence(
    seq: int = 0,
    previous_hash: str | None = None,
    session_id: str = "session-conformance",
) -> dict[str, Any]:
    """Build a valid evidence section."""
    return {
        "hash": "sha256:" + "a" * 64,  # placeholder; real hash tested separately
        "previous_hash": previous_hash,
        "session_id": session_id,
        "sequence_number": seq,
    }


def _agent(
    agent_id: str = "conformance-agent",
    chain_id: str | None = None,
    chain_depth: int = 0,
    parent_agent_id: str | None = None,
) -> dict[str, Any]:
    """Build a valid agent section."""
    d: dict[str, Any] = {
        "id": agent_id,
        "name": "Conformance Test Agent",
        "framework": "aegis",
        "model": "test-model",
    }
    if chain_id is not None:
        d["chain_id"] = chain_id
        d["chain_depth"] = chain_depth
    if parent_agent_id is not None:
        d["parent_agent_id"] = parent_agent_id
    return d


def _action_section() -> dict[str, Any]:
    return {
        "type": "api_call",
        "target": "test-service",
        "params": {"query": "SELECT 1"},
        "description": "Test action for conformance",
    }


def _build_event(event_type: str, **extra: Any) -> dict[str, Any]:
    """Build a minimal valid AGEF event for the given type."""
    event: dict[str, Any] = {
        "agef_version": "1.0.0",
        "event_id": _eid(),
        "timestamp": _ts(),
        "event_type": event_type,
        "agent": _agent(),
        "evidence": _evidence(),
    }

    if event_type == "policy_decision":
        event["action"] = _action_section()
        event["decision"] = {
            "outcome": "allowed",
            "risk_level": "LOW",
            "rule": "test-rule",
            "reason": "Conformance test",
            "approval_required": False,
        }
    elif event_type == "guardrail_trigger":
        event["guardrail"] = {
            "name": "pii-detector-test",
            "type": "pii_detection",
            "action": "masked",
            "details": "Detected PII in test content",
            "severity": "high",
        }
    elif event_type == "approval_request":
        event["action"] = _action_section()
        event["approval"] = {
            "request_id": _eid(),
            "requested_at": _ts(),
            "responded_at": None,
            "approver": None,
            "decision": None,
            "timeout_seconds": 300,
        }
    elif event_type == "approval_response":
        event["approval"] = {
            "request_id": _eid(),
            "requested_at": _ts(),
            "responded_at": _ts(),
            "approver": "admin@example.com",
            "decision": "approved",
            "reason": "Looks safe",
            "timeout_seconds": 300,
        }
    elif event_type == "cost_alert":
        event["cost"] = {
            "model": "gpt-4o",
            "input_tokens": 10000,
            "output_tokens": 2000,
            "total_tokens": 12000,
            "estimated_cost_usd": 0.045,
            "cumulative_cost_usd": 1.23,
            "budget_remaining_usd": 8.77,
            "budget_limit_usd": 10.00,
            "budget_utilization_pct": 12.3,
        }
    elif event_type == "rate_limit":
        event["rate_limit"] = {
            "limit_type": "requests_per_minute",
            "limit_value": 100,
            "current_value": 101,
            "window_seconds": 60,
            "action_taken": "throttled",
            "retry_after_seconds": 5,
        }
    elif event_type == "audit_entry":
        pass  # No additional required sections

    event.update(extra)
    return event


# ---------------------------------------------------------------------------
# Schema loading and basic structure
# ---------------------------------------------------------------------------


class TestSchemaStructure:
    """Verify the AGEF schema itself is well-formed."""

    def test_schema_file_exists(self) -> None:
        assert _SCHEMA_PATH.exists(), f"Schema not found at {_SCHEMA_PATH}"

    def test_schema_is_valid_json(self, schema: dict[str, Any]) -> None:
        assert "$schema" in schema
        assert schema["title"] == "Agent Governance Event Format (AGEF) v1"

    def test_schema_has_all_event_types(self, schema: dict[str, Any]) -> None:
        enum_values = schema["properties"]["event_type"]["enum"]
        assert set(enum_values) == set(_ALL_EVENT_TYPES)

    def test_schema_required_top_level_fields(self, schema: dict[str, Any]) -> None:
        assert set(schema["required"]) == {"agef_version", "event_id", "timestamp", "event_type"}

    def test_schema_agef_version_const(self, schema: dict[str, Any]) -> None:
        assert schema["properties"]["agef_version"]["const"] == "1.0.0"

    def test_schema_conditional_requirements(self, schema: dict[str, Any]) -> None:
        """Verify allOf conditionals define the right required sections."""
        conditionals = schema.get("allOf", [])
        found: dict[str, list[str]] = {}
        for cond in conditionals:
            if_block = cond.get("if", {})
            then_block = cond.get("then", {})
            event_type = if_block.get("properties", {}).get("event_type", {}).get("const")
            if event_type:
                found[event_type] = then_block.get("required", [])

        for etype, required in _EVENT_TYPE_REQUIRED_SECTIONS.items():
            if required:
                assert etype in found, f"Missing conditional for {etype}"
                assert set(found[etype]) == set(required), (
                    f"Wrong required sections for {etype}: "
                    f"expected {required}, got {found.get(etype)}"
                )


# ---------------------------------------------------------------------------
# Event generation and validation for all 7 types
# ---------------------------------------------------------------------------


class TestAllEventTypes:
    """Generate and validate sample events for all 7 AGEF event types."""

    @pytest.mark.parametrize("event_type", _ALL_EVENT_TYPES)
    def test_event_has_required_top_level_fields(self, event_type: str) -> None:
        event = _build_event(event_type)
        assert event["agef_version"] == "1.0.0"
        assert "event_id" in event
        assert "timestamp" in event
        assert event["event_type"] == event_type

    @pytest.mark.parametrize("event_type", _ALL_EVENT_TYPES)
    def test_event_has_required_sections(self, event_type: str) -> None:
        event = _build_event(event_type)
        for section in _EVENT_TYPE_REQUIRED_SECTIONS[event_type]:
            assert section in event, f"{event_type} missing required section: {section}"

    @pytest.mark.parametrize("event_type", _ALL_EVENT_TYPES)
    def test_event_is_json_serializable(self, event_type: str) -> None:
        event = _build_event(event_type)
        serialized = json.dumps(event)
        roundtrip = json.loads(serialized)
        assert roundtrip["event_type"] == event_type

    @pytest.mark.parametrize("event_type", _ALL_EVENT_TYPES)
    def test_event_id_is_uuid(self, event_type: str) -> None:
        event = _build_event(event_type)
        assert _UUID_RE.match(event["event_id"]), (
            f"event_id is not a valid UUID: {event['event_id']}"
        )

    @pytest.mark.parametrize("event_type", _ALL_EVENT_TYPES)
    def test_timestamp_is_iso8601(self, event_type: str) -> None:
        event = _build_event(event_type)
        assert _ISO8601_RE.match(event["timestamp"]), (
            f"timestamp is not ISO 8601: {event['timestamp']}"
        )


# ---------------------------------------------------------------------------
# Enum value validation
# ---------------------------------------------------------------------------


class TestEnumValues:
    """Verify enum fields use only schema-allowed values."""

    def test_decision_outcome_enum(self) -> None:
        event = _build_event("policy_decision")
        assert event["decision"]["outcome"] in _DECISION_OUTCOMES

    @pytest.mark.parametrize("outcome", sorted(_DECISION_OUTCOMES))
    def test_all_decision_outcomes_accepted(self, outcome: str) -> None:
        event = _build_event("policy_decision")
        event["decision"]["outcome"] = outcome
        assert event["decision"]["outcome"] in _DECISION_OUTCOMES

    def test_risk_level_enum(self) -> None:
        event = _build_event("policy_decision")
        assert event["decision"]["risk_level"] in _RISK_LEVELS

    @pytest.mark.parametrize("level", sorted(_RISK_LEVELS))
    def test_all_risk_levels_accepted(self, level: str) -> None:
        event = _build_event("policy_decision")
        event["decision"]["risk_level"] = level
        assert event["decision"]["risk_level"] in _RISK_LEVELS

    def test_guardrail_type_enum(self) -> None:
        event = _build_event("guardrail_trigger")
        assert event["guardrail"]["type"] in _GUARDRAIL_TYPES

    def test_guardrail_action_enum(self) -> None:
        event = _build_event("guardrail_trigger")
        assert event["guardrail"]["action"] in _GUARDRAIL_ACTIONS

    def test_guardrail_severity_enum(self) -> None:
        event = _build_event("guardrail_trigger")
        assert event["guardrail"]["severity"] in _GUARDRAIL_SEVERITIES

    def test_approval_decision_enum(self) -> None:
        event = _build_event("approval_response")
        assert event["approval"]["decision"] in _APPROVAL_DECISIONS

    def test_rate_limit_type_enum(self) -> None:
        event = _build_event("rate_limit")
        assert event["rate_limit"]["limit_type"] in _RATE_LIMIT_TYPES

    def test_rate_limit_action_enum(self) -> None:
        event = _build_event("rate_limit")
        assert event["rate_limit"]["action_taken"] in _RATE_LIMIT_ACTIONS


# ---------------------------------------------------------------------------
# Required field presence
# ---------------------------------------------------------------------------


class TestRequiredFields:
    """Verify that required fields are present on each event type."""

    def test_policy_decision_has_action_and_decision(self) -> None:
        event = _build_event("policy_decision")
        assert "action" in event
        assert "decision" in event
        assert "outcome" in event["decision"]

    def test_guardrail_trigger_has_guardrail(self) -> None:
        event = _build_event("guardrail_trigger")
        assert "guardrail" in event
        assert "name" in event["guardrail"]
        assert "type" in event["guardrail"]

    def test_approval_request_has_action_and_approval(self) -> None:
        event = _build_event("approval_request")
        assert "action" in event
        assert "approval" in event
        assert "request_id" in event["approval"]

    def test_approval_response_has_approval(self) -> None:
        event = _build_event("approval_response")
        assert "approval" in event
        assert "decision" in event["approval"]
        assert "approver" in event["approval"]

    def test_cost_alert_has_cost(self) -> None:
        event = _build_event("cost_alert")
        assert "cost" in event
        assert "model" in event["cost"]
        assert "input_tokens" in event["cost"]
        assert "output_tokens" in event["cost"]
        assert "total_tokens" in event["cost"]
        assert "estimated_cost_usd" in event["cost"]

    def test_rate_limit_has_rate_limit(self) -> None:
        event = _build_event("rate_limit")
        assert "rate_limit" in event
        assert "limit_type" in event["rate_limit"]
        assert "limit_value" in event["rate_limit"]
        assert "current_value" in event["rate_limit"]

    def test_audit_entry_minimal(self) -> None:
        event = _build_event("audit_entry")
        # audit_entry has no additional required sections
        assert event["event_type"] == "audit_entry"
        assert "agef_version" in event
        assert "event_id" in event
        assert "timestamp" in event


# ---------------------------------------------------------------------------
# Field type validation
# ---------------------------------------------------------------------------


class TestFieldTypes:
    """Verify field types match the schema definitions."""

    def test_agef_version_is_string(self) -> None:
        event = _build_event("policy_decision")
        assert isinstance(event["agef_version"], str)

    def test_event_id_is_string(self) -> None:
        event = _build_event("policy_decision")
        assert isinstance(event["event_id"], str)

    def test_timestamp_is_string(self) -> None:
        event = _build_event("policy_decision")
        assert isinstance(event["timestamp"], str)

    def test_agent_id_is_string(self) -> None:
        event = _build_event("policy_decision")
        assert isinstance(event["agent"]["id"], str)

    def test_chain_depth_is_integer(self) -> None:
        event = _build_event(
            "policy_decision",
            agent=_agent(chain_id="chain-1", chain_depth=2),
        )
        assert isinstance(event["agent"]["chain_depth"], int)
        assert event["agent"]["chain_depth"] >= 0

    def test_decision_approval_required_is_bool(self) -> None:
        event = _build_event("policy_decision")
        assert isinstance(event["decision"]["approval_required"], bool)

    def test_cost_tokens_are_integers(self) -> None:
        event = _build_event("cost_alert")
        cost = event["cost"]
        assert isinstance(cost["input_tokens"], int)
        assert isinstance(cost["output_tokens"], int)
        assert isinstance(cost["total_tokens"], int)
        assert cost["input_tokens"] >= 0
        assert cost["output_tokens"] >= 0
        assert cost["total_tokens"] >= 0

    def test_cost_usd_are_numbers(self) -> None:
        event = _build_event("cost_alert")
        cost = event["cost"]
        assert isinstance(cost["estimated_cost_usd"], (int, float))
        assert isinstance(cost["cumulative_cost_usd"], (int, float))
        assert cost["estimated_cost_usd"] >= 0
        assert cost["cumulative_cost_usd"] >= 0

    def test_rate_limit_window_is_positive_int(self) -> None:
        event = _build_event("rate_limit")
        rl = event["rate_limit"]
        assert isinstance(rl["window_seconds"], int)
        assert rl["window_seconds"] >= 1

    def test_evidence_sequence_is_non_negative_int(self) -> None:
        event = _build_event("policy_decision")
        assert isinstance(event["evidence"]["sequence_number"], int)
        assert event["evidence"]["sequence_number"] >= 0


# ---------------------------------------------------------------------------
# Evidence hash chain integrity
# ---------------------------------------------------------------------------


def _compute_event_hash(event: dict[str, Any]) -> str:
    """Compute SHA-256 of the event payload (excluding evidence.hash)."""
    # Create a copy without evidence.hash for hashing
    copy = json.loads(json.dumps(event))
    if "evidence" in copy:
        copy["evidence"].pop("hash", None)
    canonical = json.dumps(copy, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


class TestEvidenceHashChain:
    """Verify evidence hash chain structure and format."""

    def test_evidence_hash_format(self) -> None:
        """Evidence hash must be sha256:<64 hex chars>."""
        event = _build_event("policy_decision")
        event["evidence"]["hash"] = _compute_event_hash(event)
        assert _SHA256_HASH_RE.match(event["evidence"]["hash"])

    def test_first_event_previous_hash_is_null(self) -> None:
        """The first event in a session has previous_hash = null."""
        event = _build_event("policy_decision")
        event["evidence"]["sequence_number"] = 0
        event["evidence"]["previous_hash"] = None
        assert event["evidence"]["previous_hash"] is None

    def test_chained_events_link_correctly(self) -> None:
        """Each event's previous_hash references the preceding event's hash."""
        events: list[dict[str, Any]] = []
        for i in range(5):
            prev_hash = events[-1]["evidence"]["hash"] if events else None
            event = _build_event(
                "policy_decision",
                event_id=_eid(),
                evidence=_evidence(seq=i, previous_hash=prev_hash),
            )
            event["evidence"]["hash"] = _compute_event_hash(event)
            events.append(event)

        # Verify chain linkage
        for i in range(1, len(events)):
            assert events[i]["evidence"]["previous_hash"] == events[i - 1]["evidence"]["hash"]

        # First event has no predecessor
        assert events[0]["evidence"]["previous_hash"] is None

    def test_hash_changes_on_payload_modification(self) -> None:
        """Modifying any field in the payload changes the computed hash."""
        event = _build_event("policy_decision")
        hash1 = _compute_event_hash(event)

        modified = json.loads(json.dumps(event))
        modified["decision"]["outcome"] = "blocked"
        hash2 = _compute_event_hash(modified)

        assert hash1 != hash2

    def test_sequence_numbers_are_monotonic(self) -> None:
        """Sequence numbers in a chain must be monotonically increasing."""
        events = []
        for i in range(10):
            events.append(
                _build_event(
                    "audit_entry",
                    evidence=_evidence(seq=i),
                )
            )
        for i in range(1, len(events)):
            assert (
                events[i]["evidence"]["sequence_number"]
                > events[i - 1]["evidence"]["sequence_number"]
            )

    def test_evidence_session_id_consistent(self) -> None:
        """All events in a chain share the same session_id."""
        session = "session-chain-test"
        events = [
            _build_event(
                "audit_entry",
                evidence=_evidence(seq=i, session_id=session),
            )
            for i in range(3)
        ]
        session_ids = {e["evidence"]["session_id"] for e in events}
        assert len(session_ids) == 1
        assert session_ids.pop() == session


# ---------------------------------------------------------------------------
# UUID format validation
# ---------------------------------------------------------------------------


class TestUUIDFormat:
    """Verify UUID fields conform to the expected format."""

    def test_event_id_is_valid_uuid(self) -> None:
        event = _build_event("policy_decision")
        parsed = uuid.UUID(event["event_id"])
        assert str(parsed) == event["event_id"].lower()

    def test_approval_request_id_is_valid_uuid(self) -> None:
        event = _build_event("approval_request")
        parsed = uuid.UUID(event["approval"]["request_id"])
        assert str(parsed) == event["approval"]["request_id"].lower()

    def test_unique_event_ids_across_events(self) -> None:
        """Each generated event gets a unique event_id."""
        ids = {_build_event("audit_entry")["event_id"] for _ in range(100)}
        assert len(ids) == 100


# ---------------------------------------------------------------------------
# ISO 8601 timestamp format
# ---------------------------------------------------------------------------


class TestTimestampFormat:
    """Verify timestamp fields conform to ISO 8601."""

    @pytest.mark.parametrize("event_type", _ALL_EVENT_TYPES)
    def test_event_timestamp_format(self, event_type: str) -> None:
        event = _build_event(event_type)
        assert _ISO8601_RE.match(event["timestamp"]), event["timestamp"]

    def test_approval_timestamps_format(self) -> None:
        event = _build_event("approval_response")
        assert _ISO8601_RE.match(event["approval"]["requested_at"])
        assert _ISO8601_RE.match(event["approval"]["responded_at"])

    def test_utc_z_suffix_accepted(self) -> None:
        ts = "2026-03-24T10:30:00.000Z"
        assert _ISO8601_RE.match(ts)

    def test_offset_format_accepted(self) -> None:
        ts = "2026-03-24T10:30:00.000+09:00"
        assert _ISO8601_RE.match(ts)


# ---------------------------------------------------------------------------
# Cross-event-type section compatibility
# ---------------------------------------------------------------------------


class TestCrossEventSections:
    """Verify that optional sections can be attached to any event."""

    def test_metadata_on_any_event(self) -> None:
        for etype in _ALL_EVENT_TYPES:
            event = _build_event(etype, metadata={"custom_key": "custom_value"})
            assert event["metadata"]["custom_key"] == "custom_value"

    def test_context_on_any_event(self) -> None:
        ctx = {
            "environment": "testing",
            "service": "conformance-suite",
            "trace_id": "abc123",
        }
        for etype in _ALL_EVENT_TYPES:
            event = _build_event(etype, context=ctx)
            assert event["context"]["environment"] == "testing"

    def test_agent_section_on_all_events(self) -> None:
        for etype in _ALL_EVENT_TYPES:
            event = _build_event(etype)
            assert "agent" in event
            assert "id" in event["agent"]

    def test_evidence_section_on_all_events(self) -> None:
        for etype in _ALL_EVENT_TYPES:
            event = _build_event(etype)
            assert "evidence" in event
            assert "sequence_number" in event["evidence"]
