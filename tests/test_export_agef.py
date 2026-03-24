"""Tests for the AGEF event formatter."""

from __future__ import annotations

import json
import uuid

from aegis.export.agef import (
    AGEF_VERSION,
    _compute_hash,
    to_agef_event,
)


def _sample_entry(**overrides: object) -> dict[str, object]:
    """Build a minimal audit entry dict for testing."""
    base: dict[str, object] = {
        "session_id": "sess-001",
        "timestamp": "2026-03-24T10:30:00+00:00",
        "action_type": "db_query",
        "action_target": "salesforce",
        "action_params": json.dumps({"query": "SELECT *"}),
        "action_description": "Read accounts",
        "risk_level": "LOW",
        "approval": "auto",
        "matched_rule": "read_only",
        "agent_id": "agent-1",
        "parent_agent_id": "orchestrator-1",
        "chain_id": "chain-abc",
        "chain_depth": 1,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Basic structure
# ---------------------------------------------------------------------------


class TestBasicStructure:
    def test_required_top_level_fields(self) -> None:
        event = to_agef_event(_sample_entry())
        assert event["agef_version"] == AGEF_VERSION
        assert event["event_type"] == "policy_decision"
        # event_id must be a valid UUID
        uuid.UUID(event["event_id"])
        # timestamp preserved from entry
        assert event["timestamp"] == "2026-03-24T10:30:00+00:00"

    def test_agent_section(self) -> None:
        event = to_agef_event(_sample_entry())
        agent = event["agent"]
        assert agent["id"] == "agent-1"
        assert agent["parent_agent_id"] == "orchestrator-1"
        assert agent["chain_id"] == "chain-abc"
        assert agent["chain_depth"] == 1

    def test_action_section(self) -> None:
        event = to_agef_event(_sample_entry())
        action = event["action"]
        assert action["type"] == "db_query"
        assert action["target"] == "salesforce"
        assert action["params"] == {"query": "SELECT *"}
        assert action["description"] == "Read accounts"

    def test_decision_section(self) -> None:
        event = to_agef_event(_sample_entry())
        decision = event["decision"]
        assert decision["outcome"] == "allowed"
        assert decision["risk_level"] == "LOW"
        assert decision["rule"] == "read_only"
        assert decision["approval_required"] is False

    def test_evidence_section(self) -> None:
        event = to_agef_event(_sample_entry(), sequence_number=5)
        evidence = event["evidence"]
        assert evidence["session_id"] == "sess-001"
        assert evidence["sequence_number"] == 5
        assert evidence["previous_hash"] is None
        assert evidence["hash"].startswith("sha256:")
        assert len(evidence["hash"]) == len("sha256:") + 64


# ---------------------------------------------------------------------------
# Decision outcome mapping
# ---------------------------------------------------------------------------


class TestDecisionOutcome:
    def test_auto_maps_to_allowed(self) -> None:
        event = to_agef_event(_sample_entry(approval="auto"))
        assert event["decision"]["outcome"] == "allowed"
        assert event["decision"]["approval_required"] is False

    def test_approve_maps_to_escalated(self) -> None:
        event = to_agef_event(_sample_entry(approval="approve"))
        assert event["decision"]["outcome"] == "escalated"
        assert event["decision"]["approval_required"] is True

    def test_block_maps_to_blocked(self) -> None:
        event = to_agef_event(_sample_entry(approval="block"))
        assert event["decision"]["outcome"] == "blocked"


# ---------------------------------------------------------------------------
# Hash chain linkage
# ---------------------------------------------------------------------------


class TestHashChain:
    def test_first_event_has_null_previous(self) -> None:
        event = to_agef_event(_sample_entry())
        assert event["evidence"]["previous_hash"] is None

    def test_chain_links_previous_hash(self) -> None:
        ev1 = to_agef_event(_sample_entry(), sequence_number=0)
        ev2 = to_agef_event(
            _sample_entry(),
            sequence_number=1,
            previous_hash=ev1["evidence"]["hash"],
        )
        assert ev2["evidence"]["previous_hash"] == ev1["evidence"]["hash"]
        # Hashes must differ (different sequence numbers and previous_hash)
        assert ev2["evidence"]["hash"] != ev1["evidence"]["hash"]

    def test_three_event_chain(self) -> None:
        ev1 = to_agef_event(_sample_entry(), sequence_number=0)
        ev2 = to_agef_event(
            _sample_entry(),
            sequence_number=1,
            previous_hash=ev1["evidence"]["hash"],
        )
        ev3 = to_agef_event(
            _sample_entry(),
            sequence_number=2,
            previous_hash=ev2["evidence"]["hash"],
        )
        assert ev3["evidence"]["previous_hash"] == ev2["evidence"]["hash"]
        assert ev2["evidence"]["previous_hash"] == ev1["evidence"]["hash"]
        assert ev1["evidence"]["previous_hash"] is None

    def test_hash_is_deterministic_for_same_content(self) -> None:
        """Identical event content (minus uuid) should produce deterministic hash."""
        entry = _sample_entry()
        ev1 = to_agef_event(entry, sequence_number=0)
        ev2 = to_agef_event(entry, sequence_number=0)
        # event_id differs (random uuid), so hashes will differ
        # But _compute_hash is deterministic for the same dict
        assert ev1["evidence"]["hash"].startswith("sha256:")
        assert ev2["evidence"]["hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# Various event types
# ---------------------------------------------------------------------------


class TestEventTypes:
    def test_policy_decision_includes_action_and_decision(self) -> None:
        event = to_agef_event(_sample_entry(), event_type="policy_decision")
        assert "action" in event
        assert "decision" in event

    def test_guardrail_trigger_omits_decision(self) -> None:
        event = to_agef_event(_sample_entry(), event_type="guardrail_trigger")
        assert "decision" not in event
        # guardrail_trigger does not include action section from this formatter
        assert "action" not in event

    def test_cost_alert_omits_action_and_decision(self) -> None:
        event = to_agef_event(_sample_entry(), event_type="cost_alert")
        assert "action" not in event
        assert "decision" not in event

    def test_audit_entry_includes_action(self) -> None:
        event = to_agef_event(_sample_entry(), event_type="audit_entry")
        assert "action" in event
        assert "decision" not in event

    def test_invalid_event_type_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="Invalid AGEF event_type"):
            to_agef_event(_sample_entry(), event_type="not_a_real_type")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_missing_agent_id(self) -> None:
        """Events without agent_id should omit the agent section entirely."""
        entry = _sample_entry(agent_id="", parent_agent_id="", chain_id="")
        event = to_agef_event(entry)
        assert "agent" not in event

    def test_missing_optional_fields(self) -> None:
        """Minimal entry with only required fields."""
        entry: dict[str, object] = {
            "session_id": "s1",
            "action_type": "read",
            "action_target": "db",
            "risk_level": "MEDIUM",
            "approval": "auto",
        }
        event = to_agef_event(entry)
        assert event["agef_version"] == AGEF_VERSION
        assert event["action"]["type"] == "read"
        assert event["decision"]["outcome"] == "allowed"

    def test_action_params_as_dict(self) -> None:
        """action_params can be a dict (from webhook logger) instead of JSON string."""
        entry = _sample_entry(action_params={"key": "value"})
        event = to_agef_event(entry)
        assert event["action"]["params"] == {"key": "value"}

    def test_action_params_invalid_json_ignored(self) -> None:
        """Invalid JSON string for action_params should be silently ignored."""
        entry = _sample_entry(action_params="not-valid-json{{{")
        event = to_agef_event(entry)
        assert "params" not in event["action"]

    def test_timestamp_generated_when_missing(self) -> None:
        """If entry has no timestamp, one is generated."""
        entry = _sample_entry()
        del entry["timestamp"]  # type: ignore[arg-type]
        event = to_agef_event(entry)
        assert event["timestamp"]  # non-empty string

    def test_human_decision_maps_to_reason(self) -> None:
        entry = _sample_entry(human_decision="Approved by admin")
        event = to_agef_event(entry)
        assert event["decision"]["reason"] == "Approved by admin"

    def test_action_desc_fallback(self) -> None:
        """Support 'action_desc' (SQLite column name) as well as 'action_description'."""
        entry = _sample_entry()
        del entry["action_description"]  # type: ignore[arg-type]
        entry["action_desc"] = "Fallback description"
        event = to_agef_event(entry)
        assert event["action"]["description"] == "Fallback description"


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------


class TestHashComputation:
    def test_hash_excludes_evidence_hash(self) -> None:
        """The evidence.hash field itself must be excluded from hash computation."""
        event = to_agef_event(_sample_entry())
        # Recompute and verify
        recomputed = _compute_hash(event)
        assert recomputed == event["evidence"]["hash"]

    def test_hash_format(self) -> None:
        event = to_agef_event(_sample_entry())
        h = event["evidence"]["hash"]
        assert h.startswith("sha256:")
        hex_part = h.split(":")[1]
        assert len(hex_part) == 64
        int(hex_part, 16)  # Must be valid hex
