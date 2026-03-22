"""Cryptographic audit chain for tamper-evident logging.

Provides hash-chained audit entries that satisfy:
- EU AI Act Article 12: tamper-resistant automatic logging for high-risk AI systems
- SOC2 Type II: cryptographically sealed, immutable audit trails

Each entry contains a SHA-256 (or SHA3-256) hash linking it to the previous
entry, forming a verifiable chain of custody for all agent actions.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditEntry:
    """A single immutable entry in the cryptographic audit chain.

    Args:
        sequence_id: Monotonically increasing identifier.
        timestamp: ISO 8601 timestamp of when the entry was created.
        agent_id: Identifier of the agent that performed the action.
        action_type: The kind of operation performed.
        action_target: The system or resource acted upon.
        decision: Governance decision — ``auto``, ``approve``, or ``block``.
        risk_level: Risk classification of the action.
        matched_rule: The policy rule that triggered the decision.
        metadata: Arbitrary extra context for the entry.
        previous_hash: Hash of the preceding entry (genesis uses ``"0" * 64``).
        entry_hash: SHA-256 hash of this entry's content chained to *previous_hash*.
    """

    sequence_id: int
    timestamp: str
    agent_id: str
    action_type: str
    action_target: str
    decision: str
    risk_level: str
    matched_rule: str
    metadata: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = "0" * 64
    entry_hash: str = ""


@dataclass(frozen=True)
class VerificationResult:
    """Result of verifying audit chain integrity.

    Args:
        valid: Whether the entire chain is intact.
        chain_length: Total number of entries in the chain.
        verified_entries: Number of entries successfully verified.
        first_broken_at: Sequence ID where the chain first breaks, if any.
        error_message: Human-readable error description (empty if valid).
        verification_hash: Hash of this result itself as a meta-proof.
    """

    valid: bool
    chain_length: int
    verified_entries: int
    first_broken_at: int | None
    error_message: str
    verification_hash: str = ""


@dataclass(frozen=True)
class EvidencePackage:
    """Compliance evidence bundle for SOC2 and EU AI Act auditors.

    Args:
        generated_at: ISO 8601 timestamp of when the package was created.
        chain_length: Total entries in the audit chain.
        first_entry_time: Timestamp of the earliest entry.
        last_entry_time: Timestamp of the most recent entry.
        chain_hash: Hash of the entire chain (last entry's entry_hash).
        algorithm: Hash algorithm used (e.g. ``sha256``).
        verification_result: Full chain verification at generation time.
        summary: Aggregate counts by action, decision, and agent.
        compliance_notes: Regulatory mapping notes for auditors.
    """

    generated_at: str
    chain_length: int
    first_entry_time: str
    last_entry_time: str
    chain_hash: str
    algorithm: str
    verification_result: VerificationResult
    summary: dict[str, Any] = field(default_factory=dict)
    compliance_notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_GENESIS_HASH = "0" * 64


def _canonical_json(data: dict[str, Any]) -> str:
    """Return deterministic JSON with sorted keys and no whitespace variation."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _compute_hash(payload: str, algorithm: str = "sha256") -> str:
    """Compute a hex digest of *payload* using the specified algorithm."""
    h = hashlib.new(algorithm)
    h.update(payload.encode("utf-8"))
    return h.hexdigest()


def _entry_content_dict(entry: AuditEntry) -> dict[str, Any]:
    """Extract the content fields used for hashing (excludes ``entry_hash``)."""
    return {
        "sequence_id": entry.sequence_id,
        "timestamp": entry.timestamp,
        "agent_id": entry.agent_id,
        "action_type": entry.action_type,
        "action_target": entry.action_target,
        "decision": entry.decision,
        "risk_level": entry.risk_level,
        "matched_rule": entry.matched_rule,
        "metadata": entry.metadata,
        "previous_hash": entry.previous_hash,
    }


def _hash_entry(entry: AuditEntry, algorithm: str = "sha256") -> str:
    """Compute the expected hash for *entry*."""
    canonical = _canonical_json(_entry_content_dict(entry))
    payload = canonical + entry.previous_hash
    return _compute_hash(payload, algorithm)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _make_verification_hash(
    valid: bool,
    chain_length: int,
    verified_entries: int,
    first_broken_at: int | None,
    error_message: str,
    algorithm: str = "sha256",
) -> str:
    data = _canonical_json(
        {
            "valid": valid,
            "chain_length": chain_length,
            "verified_entries": verified_entries,
            "first_broken_at": first_broken_at,
            "error_message": error_message,
        }
    )
    return _compute_hash(data, algorithm)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class CryptoAuditChain:
    """Thread-safe, hash-chained audit log.

    Parameters
    ----------
    algorithm:
        Hash algorithm — ``"sha256"`` (default) or ``"sha3_256"``.
    """

    _SUPPORTED_ALGORITHMS = {"sha256", "sha3_256"}

    def __init__(self, algorithm: str = "sha256") -> None:
        if algorithm not in self._SUPPORTED_ALGORITHMS:
            supported = self._SUPPORTED_ALGORITHMS
            msg = f"Unsupported algorithm: {algorithm!r}. Choose from {supported}."
            raise ValueError(msg)
        self._algorithm = algorithm
        self._chain: list[AuditEntry] = []
        self._lock = threading.Lock()

    # -- properties ----------------------------------------------------------

    @property
    def algorithm(self) -> str:
        return self._algorithm

    def __len__(self) -> int:
        with self._lock:
            return len(self._chain)

    # -- mutators ------------------------------------------------------------

    def append(
        self,
        agent_id: str,
        action_type: str,
        action_target: str,
        decision: str,
        risk_level: str,
        matched_rule: str,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Create a new entry linked to the current chain head and append it.

        Returns the newly created :class:`AuditEntry`.
        """
        with self._lock:
            seq = len(self._chain)
            prev_hash = self._chain[-1].entry_hash if self._chain else _GENESIS_HASH
            ts = _now_iso()
            meta = dict(metadata) if metadata is not None else {}

            # Build a temporary entry to compute hash
            tmp = AuditEntry(
                sequence_id=seq,
                timestamp=ts,
                agent_id=agent_id,
                action_type=action_type,
                action_target=action_target,
                decision=decision,
                risk_level=risk_level,
                matched_rule=matched_rule,
                metadata=meta,
                previous_hash=prev_hash,
                entry_hash="",  # placeholder
            )
            entry_hash = _hash_entry(tmp, self._algorithm)

            entry = AuditEntry(
                sequence_id=seq,
                timestamp=ts,
                agent_id=agent_id,
                action_type=action_type,
                action_target=action_target,
                decision=decision,
                risk_level=risk_level,
                matched_rule=matched_rule,
                metadata=meta,
                previous_hash=prev_hash,
                entry_hash=entry_hash,
            )
            self._chain.append(entry)
            return entry

    # -- queries -------------------------------------------------------------

    def get_entry(self, sequence_id: int) -> AuditEntry | None:
        """Return the entry with the given *sequence_id*, or ``None``."""
        with self._lock:
            if 0 <= sequence_id < len(self._chain):
                return self._chain[sequence_id]
            return None

    def get_entries(self, start: int = 0, end: int | None = None) -> list[AuditEntry]:
        """Return a slice of entries ``[start:end]``."""
        with self._lock:
            return list(self._chain[start:end])

    # -- verification --------------------------------------------------------

    def verify(self) -> VerificationResult:
        """Verify the entire chain's integrity.

        Checks that every entry's hash matches its content and that each
        ``previous_hash`` links to the preceding entry.
        """
        with self._lock:
            return self._verify_unlocked()

    def _verify_unlocked(self) -> VerificationResult:
        """Internal verification (caller must hold the lock)."""
        length = len(self._chain)
        if length == 0:
            return self._build_result(
                valid=True,
                chain_length=0,
                verified=0,
                broken_at=None,
                error="",
            )

        for i, entry in enumerate(self._chain):
            # Check previous_hash linkage
            expected_prev = self._chain[i - 1].entry_hash if i > 0 else _GENESIS_HASH
            if entry.previous_hash != expected_prev:
                return self._build_result(
                    valid=False,
                    chain_length=length,
                    verified=i,
                    broken_at=entry.sequence_id,
                    error=(
                        f"Entry {entry.sequence_id}: previous_hash mismatch. "
                        f"Expected {expected_prev!r}, got {entry.previous_hash!r}."
                    ),
                )

            # Check entry_hash integrity
            expected_hash = _hash_entry(entry, self._algorithm)
            if entry.entry_hash != expected_hash:
                return self._build_result(
                    valid=False,
                    chain_length=length,
                    verified=i,
                    broken_at=entry.sequence_id,
                    error=(
                        f"Entry {entry.sequence_id}: entry_hash mismatch. "
                        f"Expected {expected_hash!r}, got {entry.entry_hash!r}."
                    ),
                )

        return self._build_result(
            valid=True,
            chain_length=length,
            verified=length,
            broken_at=None,
            error="",
        )

    def _build_result(
        self,
        *,
        valid: bool,
        chain_length: int,
        verified: int,
        broken_at: int | None,
        error: str,
    ) -> VerificationResult:
        vh = _make_verification_hash(
            valid, chain_length, verified, broken_at, error, self._algorithm
        )
        return VerificationResult(
            valid=valid,
            chain_length=chain_length,
            verified_entries=verified,
            first_broken_at=broken_at,
            error_message=error,
            verification_hash=vh,
        )

    def verify_entry(self, sequence_id: int) -> bool:
        """Verify a single entry's hash and its link to the previous entry."""
        with self._lock:
            if sequence_id < 0 or sequence_id >= len(self._chain):
                return False
            entry = self._chain[sequence_id]

            # Check previous_hash linkage
            expected_prev = (
                self._chain[sequence_id - 1].entry_hash if sequence_id > 0 else _GENESIS_HASH
            )
            if entry.previous_hash != expected_prev:
                return False

            # Check entry_hash integrity
            return entry.entry_hash == _hash_entry(entry, self._algorithm)

    # -- serialization -------------------------------------------------------

    def export_jsonl(self, path: Path) -> int:
        """Export the chain to a JSONL file. Returns the number of entries written."""
        with self._lock:
            entries = list(self._chain)

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(json.dumps(asdict(entry), sort_keys=True) + "\n")
        return len(entries)

    def import_jsonl(self, path: Path) -> None:
        """Import a chain from a JSONL file, verifying integrity on load.

        Raises :class:`ValueError` if the file contains a broken chain.
        """
        entries: list[AuditEntry] = []
        with path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    msg = f"Invalid JSON on line {lineno}: {exc}"
                    raise ValueError(msg) from exc
                entries.append(AuditEntry(**data))

        # Verify the loaded chain before accepting it
        with self._lock:
            old_chain = self._chain
            self._chain = entries
            result = self._verify_unlocked()
            if not result.valid:
                self._chain = old_chain
                msg = f"Imported chain verification failed: {result.error_message}"
                raise ValueError(msg)

    # -- evidence generation -------------------------------------------------

    def generate_evidence_package(self, path: Path) -> EvidencePackage:
        """Generate a compliance evidence package and write it to *path*.

        The package includes chain verification, aggregate statistics,
        and regulatory compliance mapping notes.
        """
        with self._lock:
            result = self._verify_unlocked()
            entries = list(self._chain)
            algo = self._algorithm

        chain_hash = entries[-1].entry_hash if entries else _GENESIS_HASH
        first_time = entries[0].timestamp if entries else ""
        last_time = entries[-1].timestamp if entries else ""

        # Aggregate summary
        action_counts: dict[str, int] = {}
        decision_counts: dict[str, int] = {}
        agent_counts: dict[str, int] = {}
        risk_counts: dict[str, int] = {}

        for e in entries:
            action_counts[e.action_type] = action_counts.get(e.action_type, 0) + 1
            decision_counts[e.decision] = decision_counts.get(e.decision, 0) + 1
            agent_counts[e.agent_id] = agent_counts.get(e.agent_id, 0) + 1
            risk_counts[e.risk_level] = risk_counts.get(e.risk_level, 0) + 1

        summary: dict[str, Any] = {
            "action_counts": action_counts,
            "decision_counts": decision_counts,
            "agent_counts": agent_counts,
            "risk_counts": risk_counts,
        }

        compliance_notes = [
            "EU AI Act Article 12: Tamper-resistant automatic logging for high-risk AI systems. "
            "This audit chain provides cryptographic hash-chaining ensuring any modification "
            "to historical records is detectable.",
            "SOC2 Type II CC7.2: Cryptographically sealed, immutable audit trail. "
            "Each entry is linked to its predecessor via SHA-256 hash, forming an "
            "append-only verifiable log.",
            f"Hash algorithm: {algo}. Chain integrity verified at generation time.",
            f"Chain coverage: {first_time} to {last_time} ({len(entries)} entries).",
        ]

        package = EvidencePackage(
            generated_at=_now_iso(),
            chain_length=len(entries),
            first_entry_time=first_time,
            last_entry_time=last_time,
            chain_hash=chain_hash,
            algorithm=algo,
            verification_result=result,
            summary=summary,
            compliance_notes=compliance_notes,
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(asdict(package), fh, indent=2, sort_keys=True)

        return package
