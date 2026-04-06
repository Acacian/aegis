"""Action Replay & Simulation Engine.

Replays recorded agent actions against policies for testing, auditing,
and what-if analysis.  Think ``git rebase --onto`` for governance:
take historical decisions and see what would happen under a different
policy regime.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Policy

# Severity ordering — mirrors ``_APPROVAL_SEVERITY`` in ``diff.py``.
_APPROVAL_SEVERITY: dict[str, int] = {
    "auto": 0,
    "approve": 1,
    "block": 2,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReplayEvent:
    """A single recorded agent action to replay.

    Attributes:
        action: The action that was performed.
        agent_id: Identifier of the agent that performed the action.
        timestamp: When the action originally occurred.
        original_decision: The approval decision at the time (e.g. "auto").
        metadata: Arbitrary extra context carried from the recording.
    """

    action: Action
    agent_id: str
    timestamp: datetime
    original_decision: str
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ReplayResult:
    """Outcome of replaying a single event against a new policy.

    Attributes:
        event: The original replay event.
        new_decision: What the new policy would decide.
        changed: Whether the decision differs from the original.
        change_type: Classification of the change direction.
    """

    event: ReplayEvent
    new_decision: str
    changed: bool
    change_type: str  # "unchanged" | "promoted" | "restricted" | "newly_blocked" | "newly_allowed"


@dataclass(frozen=True)
class ReplayReport:
    """Aggregate report from replaying a batch of events.

    Attributes:
        total_events: Total number of events replayed.
        changed_count: How many events had different decisions.
        unchanged_count: How many events kept the same decision.
        promoted_count: How many became less restrictive.
        restricted_count: How many became more restrictive.
        newly_blocked: How many went from allowed to blocked.
        results: Per-event replay results.
        summary: Human-readable summary string.
    """

    total_events: int
    changed_count: int
    unchanged_count: int
    promoted_count: int
    restricted_count: int
    newly_blocked: int
    results: list[ReplayResult]
    summary: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_change(old_decision: str, new_decision: str) -> str:
    """Classify the direction of a decision change.

    Returns one of:
    - ``"unchanged"`` — same decision
    - ``"promoted"`` — became less restrictive
    - ``"restricted"`` — became more restrictive (but not blocked)
    - ``"newly_blocked"`` — was allowed (auto/approve), now blocked
    - ``"newly_allowed"`` — was blocked, now allowed (auto/approve)
    """
    if old_decision == new_decision:
        return "unchanged"

    old_sev = _APPROVAL_SEVERITY.get(old_decision, 0)
    new_sev = _APPROVAL_SEVERITY.get(new_decision, 0)

    # Specific transitions first
    if old_decision != "block" and new_decision == "block":
        return "newly_blocked"
    if old_decision == "block" and new_decision != "block":
        return "newly_allowed"

    # General direction
    if new_sev > old_sev:
        return "restricted"
    if new_sev < old_sev:
        return "promoted"

    return "unchanged"


def _build_summary(report_data: dict[str, int]) -> str:
    """Build a human-readable summary from report counters."""
    total = report_data["total_events"]
    changed = report_data["changed_count"]
    unchanged = report_data["unchanged_count"]
    promoted = report_data["promoted_count"]
    restricted = report_data["restricted_count"]
    blocked = report_data["newly_blocked"]

    if total == 0:
        return "No events to replay."

    if changed == 0:
        return f"Replayed {total} event(s): all decisions unchanged."

    parts: list[str] = [f"Replayed {total} event(s): {changed} changed, {unchanged} unchanged."]
    details: list[str] = []
    if promoted:
        details.append(f"{promoted} promoted")
    if restricted:
        details.append(f"{restricted} restricted")
    if blocked:
        details.append(f"{blocked} newly blocked")
    if details:
        parts.append("Changes: " + ", ".join(details) + ".")

    return " ".join(parts)


def _replay_single(event: ReplayEvent, policy: Policy) -> ReplayResult:
    """Replay one event against a policy and produce a result."""
    decision = policy.evaluate(event.action)
    new_decision = decision.approval.value
    change_type = _classify_change(event.original_decision, new_decision)
    changed = change_type != "unchanged"
    return ReplayResult(
        event=event,
        new_decision=new_decision,
        changed=changed,
        change_type=change_type,
    )


def _build_report(results: list[ReplayResult]) -> ReplayReport:
    """Build a :class:`ReplayReport` from a list of results."""
    total = len(results)
    changed = sum(1 for r in results if r.changed)
    unchanged = total - changed
    promoted = sum(1 for r in results if r.change_type == "promoted")
    restricted = sum(1 for r in results if r.change_type == "restricted")
    blocked = sum(1 for r in results if r.change_type == "newly_blocked")

    counters = {
        "total_events": total,
        "changed_count": changed,
        "unchanged_count": unchanged,
        "promoted_count": promoted,
        "restricted_count": restricted,
        "newly_blocked": blocked,
    }

    return ReplayReport(
        total_events=total,
        changed_count=changed,
        unchanged_count=unchanged,
        promoted_count=promoted,
        restricted_count=restricted,
        newly_blocked=blocked,
        results=results,
        summary=_build_summary(counters),
    )


# ---------------------------------------------------------------------------
# Event loaders
# ---------------------------------------------------------------------------


def load_events_from_jsonl(path: Path) -> list[ReplayEvent]:
    """Load replay events from a JSON Lines file.

    Each line must be a JSON object with at least::

        {
            "action_type": "...",
            "action_target": "...",
            "agent_id": "...",
            "timestamp": "...",       # ISO-8601
            "approval": "..."         # original decision
        }

    Optional keys: ``action_params``, ``action_desc``, ``metadata``,
    ``parent_agent_id``, ``chain_id``, ``chain_depth``.
    """
    events: list[ReplayEvent] = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)

            # Parse params — may be a JSON string or a dict already.
            raw_params = obj.get("action_params", {})
            if isinstance(raw_params, str):
                try:
                    raw_params = json.loads(raw_params)
                except (json.JSONDecodeError, TypeError):
                    raw_params = {}

            action = Action(
                type=obj["action_type"],
                target=obj["action_target"],
                params=raw_params if isinstance(raw_params, dict) else {},
                description=obj.get("action_desc", "") or "",
                agent_id=obj.get("agent_id", "") or "",
                parent_agent_id=obj.get("parent_agent_id", "") or "",
                chain_id=obj.get("chain_id", "") or "",
                chain_depth=int(obj.get("chain_depth", 0) or 0),
            )

            ts_raw = obj.get("timestamp", "")
            ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.min

            raw_meta = obj.get("metadata", {})
            metadata: dict[str, object] = raw_meta if isinstance(raw_meta, dict) else {}

            events.append(
                ReplayEvent(
                    action=action,
                    agent_id=obj.get("agent_id", "") or "",
                    timestamp=ts,
                    original_decision=obj.get("approval", "auto"),
                    metadata=metadata,
                )
            )
    return events


def load_events_from_audit_db(
    db_path: Path,
    session_id: str | None = None,
) -> list[ReplayEvent]:
    """Load replay events from a SQLite audit database.

    The schema is expected to match :class:`aegis.runtime.audit.AuditLogger`.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    query = "SELECT * FROM audit_log"
    params: list[object] = []
    if session_id is not None:
        query += " WHERE session_id = ?"
        params.append(session_id)
    query += " ORDER BY id"

    cursor = conn.execute(query, params)
    events: list[ReplayEvent] = []
    for row in cursor.fetchall():
        raw_params = row["action_params"]
        if isinstance(raw_params, str):
            try:
                parsed_params = json.loads(raw_params)
            except (json.JSONDecodeError, TypeError):
                parsed_params = {}
        else:
            parsed_params = raw_params or {}

        action = Action(
            type=row["action_type"],
            target=row["action_target"],
            params=parsed_params if isinstance(parsed_params, dict) else {},
            description=row["action_desc"] or "",
            agent_id=row["agent_id"] or "",
            parent_agent_id=row["parent_agent_id"] or "",
            chain_id=row["chain_id"] or "",
            chain_depth=int(row["chain_depth"] or 0),
        )

        ts_raw = row["timestamp"]
        ts = datetime.fromisoformat(ts_raw) if ts_raw else datetime.min

        metadata: dict[str, object] = {
            "session_id": row["session_id"],
            "risk_level": row["risk_level"],
            "matched_rule": row["matched_rule"],
        }

        events.append(
            ReplayEvent(
                action=action,
                agent_id=row["agent_id"] or "",
                timestamp=ts,
                original_decision=row["approval"],
                metadata=metadata,
            )
        )

    conn.close()
    return events


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ReplayEngine:
    """Replays recorded agent actions against policies.

    Instantiate with the current policy, then call one of the replay
    methods to evaluate how that policy (or a new one) would have
    decided each historical action.

    Example::

        engine = ReplayEngine(current_policy)
        report = engine.replay_events(events)
        print(report.summary)

        # What if we adopt a stricter policy?
        what_if_report = engine.what_if(events, stricter_policy)
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    def replay_events(self, events: list[ReplayEvent]) -> ReplayReport:
        """Replay a list of events against the engine's policy.

        Each event's ``original_decision`` is compared with the new
        evaluation result to classify the change.
        """
        results = [_replay_single(e, self._policy) for e in events]
        return _build_report(results)

    def replay_from_jsonl(self, path: Path) -> ReplayReport:
        """Load events from a JSONL file and replay them."""
        events = load_events_from_jsonl(path)
        return self.replay_events(events)

    def replay_from_audit_db(
        self,
        db_path: Path,
        session_id: str | None = None,
    ) -> ReplayReport:
        """Load events from a SQLite audit database and replay them."""
        events = load_events_from_audit_db(db_path, session_id=session_id)
        return self.replay_events(events)

    def what_if(
        self,
        events: list[ReplayEvent],
        new_policy: Policy,
    ) -> ReplayReport:
        """Replay events against a different policy.

        Temporarily swaps the engine's policy to ``new_policy`` for the
        replay, then restores the original.  Useful for what-if analysis.
        """
        results = [_replay_single(e, new_policy) for e in events]
        return _build_report(results)

    def compare_policies(
        self,
        events: list[ReplayEvent],
        policy_a: Policy,
        policy_b: Policy,
    ) -> tuple[ReplayReport, ReplayReport]:
        """Replay events against two policies and return both reports.

        Useful for side-by-side comparison of proposed policy changes.
        """
        results_a = [_replay_single(e, policy_a) for e in events]
        results_b = [_replay_single(e, policy_b) for e in events]
        return _build_report(results_a), _build_report(results_b)
