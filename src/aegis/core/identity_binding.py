"""Binding Agent Identity (BAID) — configuration and code provenance binding.

Binds an agent's identity to its configuration, code, and model provenance
so that any unauthorized modification is detectable.  Each binding creates
a cryptographic hash of the agent's identity components, enabling tamper
detection and lineage tracking across agent versions.

Key capabilities:

- **Identity binding**: Tie agent ID to config, code, and model hashes.
- **Tamper detection**: Verify current state matches the recorded binding.
- **Provenance tracking**: Record and trace the lineage of agent changes.
- **Drift detection**: Compare historical bindings to detect unauthorized changes.

No external dependencies.  Thread-safe.  Sub-millisecond per operation.

Reference:
    BAID: Binding Agent Identity.
    arXiv:2512.17538 (2025).

Example::

    binder = IdentityBinder()
    binding = binder.bind("agent-1", config_hash="abc", code_hash="def",
                          model_hash="ghi")
    result = binder.verify_binding("agent-1", config_hash="abc",
                                   code_hash="def", model_hash="ghi")
    assert result.valid
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: str) -> str:
    """Compute SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _compute_binding_hash(agent_id: str, config_hash: str, code_hash: str, model_hash: str) -> str:
    """Compute binding_hash = SHA-256(agent_id + config_hash + code_hash + model_hash)."""
    return _sha256(agent_id + config_hash + code_hash + model_hash)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityBinding:
    """A cryptographic binding between an agent's identity and its components.

    Attributes:
        agent_id: Unique agent identifier.
        config_hash: SHA-256 hash of the agent's configuration.
        code_hash: SHA-256 hash of the agent's code.
        model_hash: SHA-256 hash of the model identifier/weights.
        binding_hash: SHA-256(agent_id + config_hash + code_hash + model_hash).
        created_at: Timestamp when the binding was created.
    """

    agent_id: str
    config_hash: str
    code_hash: str
    model_hash: str
    binding_hash: str
    created_at: str


@dataclass(frozen=True)
class BindingMismatch:
    """A single mismatch detected during binding verification.

    Attributes:
        field: Name of the mismatched field.
        expected_hash: Expected hash from the binding.
        actual_hash: Actual hash provided for verification.
        severity: Severity level (low, medium, high, critical).
    """

    field: str
    expected_hash: str
    actual_hash: str
    severity: str


@dataclass(frozen=True)
class BindingVerification:
    """Result of verifying an agent's identity binding.

    Attributes:
        valid: Whether the binding is intact.
        agent_id: The agent that was verified.
        mismatches: Tuple of detected mismatches.
        verified_at: Timestamp of verification.
    """

    valid: bool
    agent_id: str
    mismatches: tuple[BindingMismatch, ...]
    verified_at: str


@dataclass(frozen=True)
class ProvenanceRecord:
    """A provenance event recording a change in an agent's identity.

    Attributes:
        agent_id: Agent whose identity changed.
        version: Version number for this event.
        parent_id: Previous agent/version this was derived from.
        changes: Description of changes made.
        timestamp: Timestamp of the event.
        hash: SHA-256 hash of this provenance record.
    """

    agent_id: str
    version: int
    parent_id: str | None
    changes: dict[str, Any]
    timestamp: str
    hash: str


# ---------------------------------------------------------------------------
# Severity rules
# ---------------------------------------------------------------------------

_FIELD_SEVERITY: dict[str, str] = {
    "config_hash": "high",
    "code_hash": "critical",
    "model_hash": "critical",
    "binding_hash": "critical",
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class IdentityBinder:
    """Thread-safe identity-to-configuration binder.

    Creates and verifies cryptographic bindings between agent identities
    and their operational components (config, code, model).
    """

    def __init__(self) -> None:
        self._bindings: dict[str, IdentityBinding] = {}
        self._binding_history: dict[str, list[IdentityBinding]] = {}
        self._provenance: dict[str, list[ProvenanceRecord]] = {}
        self._lock = threading.Lock()

    # -- bind ----------------------------------------------------------------

    def bind(
        self,
        agent_id: str,
        config_hash: str,
        code_hash: str,
        model_hash: str,
    ) -> IdentityBinding:
        """Create a binding between an agent ID and its component hashes.

        Parameters
        ----------
        agent_id:
            Unique agent identifier.
        config_hash:
            Hash of the agent's configuration.
        code_hash:
            Hash of the agent's code.
        model_hash:
            Hash of the model identifier or weights.

        Returns
        -------
        IdentityBinding:
            The newly created binding.

        Raises
        ------
        ValueError:
            If agent_id is empty.
        """
        if not agent_id:
            raise ValueError("agent_id must be a non-empty string")

        binding_hash = _compute_binding_hash(agent_id, config_hash, code_hash, model_hash)
        created_at = _now_iso()

        binding = IdentityBinding(
            agent_id=agent_id,
            config_hash=config_hash,
            code_hash=code_hash,
            model_hash=model_hash,
            binding_hash=binding_hash,
            created_at=created_at,
        )

        with self._lock:
            # Archive previous binding if exists
            if agent_id in self._bindings:
                self._binding_history.setdefault(agent_id, []).append(self._bindings[agent_id])
            self._bindings[agent_id] = binding
            # Also add to history for complete trace
            self._binding_history.setdefault(agent_id, []).append(binding)

        return binding

    # -- verify --------------------------------------------------------------

    def verify_binding(
        self,
        agent_id: str,
        config_hash: str,
        code_hash: str,
        model_hash: str,
    ) -> BindingVerification:
        """Check if the current agent state matches its recorded binding.

        Compares each component hash and the overall binding hash.

        Returns
        -------
        BindingVerification:
            Result with any mismatches.
        """
        now = _now_iso()

        with self._lock:
            binding = self._bindings.get(agent_id)

        if binding is None:
            return BindingVerification(
                valid=False,
                agent_id=agent_id,
                mismatches=(
                    BindingMismatch(
                        field="agent_id",
                        expected_hash="(registered)",
                        actual_hash="(not found)",
                        severity="critical",
                    ),
                ),
                verified_at=now,
            )

        mismatches: list[BindingMismatch] = []

        if binding.config_hash != config_hash:
            mismatches.append(
                BindingMismatch(
                    field="config_hash",
                    expected_hash=binding.config_hash,
                    actual_hash=config_hash,
                    severity=_FIELD_SEVERITY["config_hash"],
                )
            )

        if binding.code_hash != code_hash:
            mismatches.append(
                BindingMismatch(
                    field="code_hash",
                    expected_hash=binding.code_hash,
                    actual_hash=code_hash,
                    severity=_FIELD_SEVERITY["code_hash"],
                )
            )

        if binding.model_hash != model_hash:
            mismatches.append(
                BindingMismatch(
                    field="model_hash",
                    expected_hash=binding.model_hash,
                    actual_hash=model_hash,
                    severity=_FIELD_SEVERITY["model_hash"],
                )
            )

        # Also verify binding_hash integrity
        expected_binding = _compute_binding_hash(agent_id, config_hash, code_hash, model_hash)
        if binding.binding_hash != expected_binding and not mismatches:
            mismatches.append(
                BindingMismatch(
                    field="binding_hash",
                    expected_hash=binding.binding_hash,
                    actual_hash=expected_binding,
                    severity=_FIELD_SEVERITY["binding_hash"],
                )
            )

        return BindingVerification(
            valid=len(mismatches) == 0,
            agent_id=agent_id,
            mismatches=tuple(mismatches),
            verified_at=now,
        )

    # -- provenance ----------------------------------------------------------

    def record_provenance(
        self,
        agent_id: str,
        changes: dict[str, Any],
        parent_id: str | None = None,
    ) -> ProvenanceRecord:
        """Record a provenance event for an agent.

        Parameters
        ----------
        agent_id:
            Agent whose identity changed.
        changes:
            Dictionary describing the changes.
        parent_id:
            Previous agent/version this derives from.

        Returns
        -------
        ProvenanceRecord:
            The recorded provenance event.
        """
        with self._lock:
            records = self._provenance.setdefault(agent_id, [])
            version = len(records) + 1
            timestamp = _now_iso()

            hash_payload = f"{agent_id}:{version}:{parent_id}:{timestamp}"
            record_hash = _sha256(hash_payload)

            record = ProvenanceRecord(
                agent_id=agent_id,
                version=version,
                parent_id=parent_id,
                changes=dict(changes),
                timestamp=timestamp,
                hash=record_hash,
            )
            records.append(record)

        return record

    def trace_lineage(self, agent_id: str) -> list[ProvenanceRecord]:
        """Trace an agent's provenance chain back to origin.

        Returns provenance records in chronological order (oldest first).
        """
        with self._lock:
            records = self._provenance.get(agent_id, [])
            return list(records)

    # -- drift detection -----------------------------------------------------

    def detect_drift(
        self,
        agent_id: str,
        config_hash: str,
        code_hash: str,
        model_hash: str,
    ) -> list[BindingMismatch]:
        """Compare current state to all historical bindings for drift.

        Returns a list of mismatches found against the latest binding.
        Also checks historical bindings for patterns of unauthorized change.
        """
        with self._lock:
            history = self._binding_history.get(agent_id, [])
            current = self._bindings.get(agent_id)

        if current is None:
            return [
                BindingMismatch(
                    field="agent_id",
                    expected_hash="(registered)",
                    actual_hash="(not found)",
                    severity="critical",
                )
            ]

        drifts: list[BindingMismatch] = []

        if current.config_hash != config_hash:
            drifts.append(
                BindingMismatch(
                    field="config_hash",
                    expected_hash=current.config_hash,
                    actual_hash=config_hash,
                    severity=_FIELD_SEVERITY["config_hash"],
                )
            )

        if current.code_hash != code_hash:
            drifts.append(
                BindingMismatch(
                    field="code_hash",
                    expected_hash=current.code_hash,
                    actual_hash=code_hash,
                    severity=_FIELD_SEVERITY["code_hash"],
                )
            )

        if current.model_hash != model_hash:
            drifts.append(
                BindingMismatch(
                    field="model_hash",
                    expected_hash=current.model_hash,
                    actual_hash=model_hash,
                    severity=_FIELD_SEVERITY["model_hash"],
                )
            )

        # Check for unauthorized changes not recorded in provenance
        with self._lock:
            provenance_records = self._provenance.get(agent_id, [])
        if history and len(history) > 1 and not provenance_records:
            drifts.append(
                BindingMismatch(
                    field="provenance",
                    expected_hash="(provenance records)",
                    actual_hash="(no provenance recorded)",
                    severity="high",
                )
            )

        return drifts

    # -- queries -------------------------------------------------------------

    def get_binding(self, agent_id: str) -> IdentityBinding | None:
        """Return the current binding for an agent, or ``None``."""
        with self._lock:
            return self._bindings.get(agent_id)

    def get_history(self, agent_id: str) -> list[IdentityBinding]:
        """Return the full binding history for an agent."""
        with self._lock:
            return list(self._binding_history.get(agent_id, []))
