"""Audit Trails for Accountability in LLMs — lifecycle audit logging.

Provides a complete lifecycle audit trail for AI agent operations, from
creation through configuration, deployment, operation, updates,
suspension, termination, and audit events.  Each event is hash-chained
to its predecessor, forming a tamper-evident log.

Includes compliance checking against major regulatory frameworks:

- **EU AI Act Art. 12**: Logging requirements for high-risk AI systems.
- **SOC2**: Access control and audit trail requirements.
- **GDPR**: Data processing records and right-to-explanation.

No external dependencies.  Thread-safe.  Sub-millisecond per operation.

Reference:
    Audit Trails for Accountability in LLMs.
    arXiv:2601.20727 (2026).

Example::

    lc = AuditLifecycle()
    lc.record_event("agent-1", LifecyclePhase.CREATION, "initialized",
                     metadata={"version": "1.0"})
    lc.record_event("agent-1", LifecyclePhase.DEPLOYMENT, "deployed_to_prod")
    report = lc.get_timeline("agent-1")
    assert report.integrity_valid
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GENESIS_HASH = "0" * 64


def _sha256(data: str) -> str:
    """Compute SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _canonical_json(d: dict[str, Any]) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def _compute_event_hash(
    event_id: str, phase: str, action: str, timestamp: str, prev_hash: str
) -> str:
    """event hash = SHA-256(event_id + phase + action + timestamp + prev_hash)."""
    return _sha256(event_id + phase + action + timestamp + prev_hash)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LifecyclePhase(Enum):
    """Phase in an AI agent's lifecycle.

    Covers the complete lifecycle from creation to termination.
    """

    CREATION = "creation"
    CONFIGURATION = "configuration"
    DEPLOYMENT = "deployment"
    OPERATION = "operation"
    UPDATE = "update"
    SUSPENSION = "suspension"
    TERMINATION = "termination"
    AUDIT = "audit"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LifecycleEvent:
    """A single event in an agent's lifecycle audit trail.

    Attributes:
        event_id: Unique event identifier.
        phase: Lifecycle phase of this event.
        agent_id: Agent this event belongs to.
        action: Description of the action taken.
        timestamp: ISO 8601 timestamp.
        metadata: Arbitrary extra context.
        prev_hash: Hash of the previous event in the chain.
        event_hash: SHA-256(event_id + phase + action + timestamp + prev_hash).
    """

    event_id: str
    phase: LifecyclePhase
    agent_id: str
    action: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = _GENESIS_HASH
    event_hash: str = ""


@dataclass(frozen=True)
class LifecycleReport:
    """Timeline report for an agent's lifecycle.

    Attributes:
        agent_id: Agent this report covers.
        events: List of lifecycle events in chronological order.
        phase_counts: Count of events per phase.
        total_duration: Duration from first to last event (ISO string or empty).
        integrity_valid: Whether the hash chain is intact.
    """

    agent_id: str
    events: tuple[LifecycleEvent, ...]
    phase_counts: dict[str, int]
    total_duration: str
    integrity_valid: bool


@dataclass(frozen=True)
class ComplianceCheck:
    """Result of checking lifecycle trail against a compliance framework.

    Attributes:
        framework: Name of the compliance framework.
        requirements_met: List of requirements that are satisfied.
        requirements_failed: List of requirements that are not satisfied.
        coverage_pct: Percentage of requirements met (0.0-100.0).
    """

    framework: str
    requirements_met: tuple[str, ...]
    requirements_failed: tuple[str, ...]
    coverage_pct: float


# ---------------------------------------------------------------------------
# Compliance framework definitions
# ---------------------------------------------------------------------------

_EU_AI_ACT_REQUIREMENTS: dict[str, set[LifecyclePhase]] = {
    "Art.12.1: Automatic logging enabled": {LifecyclePhase.CREATION},
    "Art.12.2: Traceability of operation period": {
        LifecyclePhase.DEPLOYMENT,
        LifecyclePhase.OPERATION,
    },
    "Art.12.3: Monitoring capability": {LifecyclePhase.OPERATION},
    "Art.12.4: System modification logging": {LifecyclePhase.UPDATE},
}

_SOC2_REQUIREMENTS: dict[str, set[LifecyclePhase]] = {
    "CC6.1: Access control records": {LifecyclePhase.CONFIGURATION},
    "CC7.2: Audit trail integrity": {LifecyclePhase.AUDIT},
    "CC7.3: Change management records": {LifecyclePhase.UPDATE},
    "CC8.1: Deployment authorization": {LifecyclePhase.DEPLOYMENT},
}

_GDPR_REQUIREMENTS: dict[str, set[LifecyclePhase]] = {
    "Art.30: Records of processing activities": {LifecyclePhase.OPERATION},
    "Art.35: Impact assessment documented": {LifecyclePhase.CREATION},
    "Art.25: Data protection by design": {LifecyclePhase.CONFIGURATION},
    "Art.33: Breach notification readiness": {LifecyclePhase.SUSPENSION},
}

_FRAMEWORKS: dict[str, dict[str, set[LifecyclePhase]]] = {
    "eu_ai_act": _EU_AI_ACT_REQUIREMENTS,
    "soc2": _SOC2_REQUIREMENTS,
    "gdpr": _GDPR_REQUIREMENTS,
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class AuditLifecycle:
    """Thread-safe lifecycle audit trail for AI agents.

    Records hash-chained events across an agent's complete lifecycle,
    enabling compliance checking and integrity verification.
    """

    def __init__(self) -> None:
        self._events: dict[str, list[LifecycleEvent]] = {}
        self._lock = threading.Lock()

    # -- recording -----------------------------------------------------------

    def record_event(
        self,
        agent_id: str,
        phase: LifecyclePhase,
        action: str,
        metadata: dict[str, Any] | None = None,
    ) -> LifecycleEvent:
        """Record a lifecycle event for an agent.

        Events are hash-chained: each event's hash links to the previous.

        Parameters
        ----------
        agent_id:
            Agent this event belongs to.
        phase:
            Lifecycle phase.
        action:
            Description of the action taken.
        metadata:
            Optional extra context.

        Returns
        -------
        LifecycleEvent:
            The newly recorded event.

        Raises
        ------
        ValueError:
            If agent_id or action is empty.
        """
        if not agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if not action:
            raise ValueError("action must be a non-empty string")

        event_id = uuid.uuid4().hex
        timestamp = _now_iso()
        meta = dict(metadata) if metadata else {}

        with self._lock:
            chain = self._events.setdefault(agent_id, [])
            prev_hash = chain[-1].event_hash if chain else _GENESIS_HASH

            event_hash = _compute_event_hash(event_id, phase.value, action, timestamp, prev_hash)

            event = LifecycleEvent(
                event_id=event_id,
                phase=phase,
                agent_id=agent_id,
                action=action,
                timestamp=timestamp,
                metadata=meta,
                prev_hash=prev_hash,
                event_hash=event_hash,
            )
            chain.append(event)

        return event

    # -- timeline ------------------------------------------------------------

    def get_timeline(self, agent_id: str) -> LifecycleReport:
        """Get a chronological timeline report for an agent.

        Includes event listing, phase counts, duration, and integrity check.
        """
        with self._lock:
            chain = list(self._events.get(agent_id, []))

        phase_counts: dict[str, int] = {}
        for event in chain:
            key = event.phase.value
            phase_counts[key] = phase_counts.get(key, 0) + 1

        total_duration = ""
        if len(chain) >= 2:
            first = datetime.fromisoformat(chain[0].timestamp)
            last = datetime.fromisoformat(chain[-1].timestamp)
            delta = last - first
            total_duration = str(delta)

        integrity = self._verify_chain(chain)

        return LifecycleReport(
            agent_id=agent_id,
            events=tuple(chain),
            phase_counts=phase_counts,
            total_duration=total_duration,
            integrity_valid=integrity,
        )

    # -- integrity -----------------------------------------------------------

    def verify_integrity(self, agent_id: str) -> bool:
        """Verify the hash chain integrity for an agent's lifecycle trail.

        Returns ``True`` if the chain is intact.
        """
        with self._lock:
            chain = list(self._events.get(agent_id, []))

        return self._verify_chain(chain)

    @staticmethod
    def _verify_chain(chain: list[LifecycleEvent]) -> bool:
        """Verify hash chain integrity (no lock needed)."""
        if not chain:
            return True

        for i, event in enumerate(chain):
            expected_prev = chain[i - 1].event_hash if i > 0 else _GENESIS_HASH
            if event.prev_hash != expected_prev:
                return False

            expected_hash = _compute_event_hash(
                event.event_id,
                event.phase.value,
                event.action,
                event.timestamp,
                event.prev_hash,
            )
            if event.event_hash != expected_hash:
                return False

        return True

    # -- compliance ----------------------------------------------------------

    def check_compliance(self, agent_id: str, framework: str) -> ComplianceCheck:
        """Check an agent's lifecycle trail against a compliance framework.

        Supported frameworks: ``eu_ai_act``, ``soc2``, ``gdpr``.

        Raises
        ------
        ValueError:
            If the framework is not recognized.
        """
        requirements = _FRAMEWORKS.get(framework)
        if requirements is None:
            supported = sorted(_FRAMEWORKS.keys())
            raise ValueError(f"Unknown framework: {framework!r}. Supported: {supported}")

        with self._lock:
            chain = list(self._events.get(agent_id, []))

        observed_phases: set[LifecyclePhase] = {e.phase for e in chain}

        met: list[str] = []
        failed: list[str] = []

        for req_name, required_phases in requirements.items():
            if required_phases & observed_phases:
                met.append(req_name)
            else:
                failed.append(req_name)

        total = len(requirements)
        coverage = (len(met) / total * 100.0) if total > 0 else 0.0

        return ComplianceCheck(
            framework=framework,
            requirements_met=tuple(met),
            requirements_failed=tuple(failed),
            coverage_pct=round(coverage, 1),
        )

    # -- export --------------------------------------------------------------

    def export_trail(self, agent_id: str) -> str:
        """Export an agent's lifecycle trail as structured JSON.

        Returns a JSON string with events and metadata.
        """
        with self._lock:
            chain = list(self._events.get(agent_id, []))

        events_data: list[dict[str, Any]] = []
        for event in chain:
            events_data.append(
                {
                    "event_id": event.event_id,
                    "phase": event.phase.value,
                    "agent_id": event.agent_id,
                    "action": event.action,
                    "timestamp": event.timestamp,
                    "metadata": event.metadata,
                    "prev_hash": event.prev_hash,
                    "event_hash": event.event_hash,
                }
            )

        integrity = self._verify_chain(chain)
        export_data = {
            "agent_id": agent_id,
            "event_count": len(chain),
            "integrity_valid": integrity,
            "exported_at": _now_iso(),
            "events": events_data,
        }

        return json.dumps(export_data, indent=2, sort_keys=True)

    # -- queries -------------------------------------------------------------

    def get_events(
        self,
        agent_id: str,
        phase: LifecyclePhase | None = None,
    ) -> list[LifecycleEvent]:
        """Get events for an agent, optionally filtered by phase."""
        with self._lock:
            chain = list(self._events.get(agent_id, []))

        if phase is not None:
            chain = [e for e in chain if e.phase == phase]

        return chain

    def agent_ids(self) -> list[str]:
        """Return all agent IDs with recorded events."""
        with self._lock:
            return list(self._events.keys())
