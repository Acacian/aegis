"""AGEF (Agent Governance Event Format) v1.0.0 event formatter.

Converts internal Aegis audit entry dicts into AGEF-compliant JSON events
for interoperable consumption by SIEM systems, dashboards, and compliance tools.

Reference: specs/agef/v1/schema.json
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# AGEF event-type constants
# ---------------------------------------------------------------------------

AGEF_VERSION = "1.0.0"

EVENT_TYPES = frozenset(
    {
        "policy_decision",
        "guardrail_trigger",
        "approval_request",
        "approval_response",
        "cost_alert",
        "rate_limit",
        "audit_entry",
    }
)

# Map Aegis approval values -> AGEF decision outcomes
_APPROVAL_TO_OUTCOME: dict[str, str] = {
    "auto": "allowed",
    "approve": "escalated",
    "block": "blocked",
}


def _compute_hash(event: dict[str, Any]) -> str:
    """Compute SHA-256 hash of the canonical event (excluding ``evidence.hash``).

    The canonical form is a JSON string with sorted keys and no extra whitespace.
    """
    # Work on a shallow copy so we don't mutate the caller's dict
    canonical = _deep_copy_without_hash(event)
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _deep_copy_without_hash(event: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *event* with ``evidence.hash`` removed."""
    out: dict[str, Any] = {}
    for k, v in event.items():
        if k == "evidence" and isinstance(v, dict):
            ev = {ek: ev for ek, ev in v.items() if ek != "hash"}
            out[k] = ev
        else:
            out[k] = v
    return out


def to_agef_event(
    entry: dict[str, Any],
    *,
    event_type: str = "policy_decision",
    previous_hash: str | None = None,
    sequence_number: int = 0,
) -> dict[str, Any]:
    """Convert an Aegis audit entry dict to an AGEF v1.0.0 event.

    Args:
        entry: Internal audit entry dict (as produced by ``AuditLogger.log`` /
            ``WebhookAuditLogger.log`` or returned by ``get_log()``).
        event_type: AGEF event type. Must be one of the spec-defined values.
        previous_hash: Hash of the immediately preceding event in the session
            chain.  ``None`` for the first event.
        sequence_number: Monotonically increasing counter within the session.

    Returns:
        A dict conforming to the AGEF v1.0.0 schema.

    Raises:
        ValueError: If *event_type* is not a valid AGEF event type.
    """
    if event_type not in EVENT_TYPES:
        msg = f"Invalid AGEF event_type: {event_type!r}. Must be one of {sorted(EVENT_TYPES)}"
        raise ValueError(msg)

    event: dict[str, Any] = {
        "agef_version": AGEF_VERSION,
        "event_id": str(uuid.uuid4()),
        "timestamp": entry.get("timestamp") or datetime.now(UTC).isoformat(),
        "event_type": event_type,
    }

    # -- agent section -------------------------------------------------------
    agent_id = entry.get("agent_id")
    if agent_id:
        agent: dict[str, Any] = {"id": agent_id}
        if entry.get("parent_agent_id"):
            agent["parent_agent_id"] = entry["parent_agent_id"]
        if entry.get("chain_id"):
            agent["chain_id"] = entry["chain_id"]
        chain_depth = entry.get("chain_depth")
        if chain_depth is not None:
            agent["chain_depth"] = int(chain_depth)
        event["agent"] = agent

    # -- action section ------------------------------------------------------
    if event_type in ("policy_decision", "approval_request", "audit_entry"):
        action: dict[str, Any] = {}
        if entry.get("action_type"):
            action["type"] = entry["action_type"]
        if entry.get("action_target"):
            action["target"] = entry["action_target"]

        # action_params may be a JSON string (from SQLite) or a dict
        params = entry.get("action_params")
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = None
        if params:
            action["params"] = params

        desc = entry.get("action_description") or entry.get("action_desc")
        if desc:
            action["description"] = desc

        if action:
            event["action"] = action

    # -- decision section ----------------------------------------------------
    if event_type == "policy_decision":
        approval_val = entry.get("approval", "")
        outcome = _APPROVAL_TO_OUTCOME.get(str(approval_val), "allowed")

        decision: dict[str, Any] = {"outcome": outcome}

        risk = entry.get("risk_level")
        if risk:
            decision["risk_level"] = str(risk).upper()

        rule = entry.get("matched_rule")
        if rule:
            decision["rule"] = str(rule)

        human = entry.get("human_decision")
        if human:
            decision["reason"] = str(human)

        decision["approval_required"] = outcome == "escalated"

        event["decision"] = decision

    # -- evidence section ----------------------------------------------------
    evidence: dict[str, Any] = {
        "previous_hash": previous_hash,
        "session_id": entry.get("session_id", ""),
        "sequence_number": sequence_number,
    }
    event["evidence"] = evidence

    # Compute the hash *after* all other fields are set
    event["evidence"]["hash"] = _compute_hash(event)

    return event
