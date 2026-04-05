"""Cryptographically verifiable execution traces for AI agents.

Implements a hash-chain model where each execution step links to the
previous step's hash, forming a tamper-evident log of agent actions.
The entire trace can be verified end-to-end by recomputing the chain
and comparing root hashes.

Each :class:`TraceEntry` contains:

* ``sequence_num`` -- position in the chain.
* ``action`` -- human-readable description of the step.
* ``input_hash`` / ``output_hash`` -- SHA-256 digests of step I/O.
* ``prev_hash`` -- hash of the preceding entry (empty string for the
  first entry).
* ``entry_hash`` -- SHA-256(sequence_num + action + input_hash +
  output_hash + prev_hash).

Verification walks the chain and confirms every link.  Traces can be
exported as JSON for external audit.

Pure Python, no external dependencies.  Thread-safe, sub-millisecond.

Reference:
    VET: Verifiable Execution Traces.
    arXiv:2512.15892 (2025).

Example::

    tracer = ExecutionTracer()
    trace_id = tracer.begin_trace("agent-1")
    tracer.record_step(trace_id, "read_file", "inputdata", "outputdata")
    trace = tracer.end_trace(trace_id)
    verification = tracer.verify_trace(trace)
    assert verification.valid
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Frozen data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TraceEntry:
    """Immutable entry in an execution trace.

    Attributes:
        entry_id: Unique identifier for this entry.
        sequence_num: Position in the trace chain (0-indexed).
        agent_id: Agent that performed this step.
        action: Description of the action taken.
        input_hash: SHA-256 hex digest of step input.
        output_hash: SHA-256 hex digest of step output.
        timestamp: When the step was recorded (monotonic clock).
        prev_hash: Hash of the preceding entry (empty for first).
        entry_hash: Computed hash of this entry.
    """

    entry_id: str
    sequence_num: int
    agent_id: str
    action: str
    input_hash: str
    output_hash: str
    timestamp: float
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True)
class ExecutionTrace:
    """Immutable finalized execution trace.

    Attributes:
        trace_id: Unique identifier for this trace.
        agent_id: Agent that produced this trace.
        entries: Ordered tuple of trace entries.
        root_hash: Hash computed over all entry hashes.
        created_at: Timestamp when trace was finalized.
    """

    trace_id: str
    agent_id: str
    entries: tuple[TraceEntry, ...]
    root_hash: str
    created_at: float


@dataclass(frozen=True)
class TraceVerification:
    """Immutable result of trace verification.

    Attributes:
        valid: Whether the entire trace is valid.
        verified_entries: Number of entries that passed verification.
        failed_at: Sequence number of first failure, or ``-1`` if valid.
        description: Human-readable verification summary.
    """

    valid: bool
    verified_entries: int
    failed_at: int
    description: str


@dataclass(frozen=True)
class TraceProof:
    """Immutable proof for a specific entry in a trace.

    Attributes:
        trace_id: The trace this proof belongs to.
        entry_id: The entry being proved.
        proof_chain: Hashes from the entry back to the root.
        root_hash: Root hash of the complete trace.
    """

    trace_id: str
    entry_id: str
    proof_chain: tuple[str, ...]
    root_hash: str


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


def _hash_data(data: str) -> str:
    """Compute SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def _compute_entry_hash(
    sequence_num: int,
    action: str,
    input_hash: str,
    output_hash: str,
    prev_hash: str,
) -> str:
    """Compute the hash of a trace entry.

    Hash = SHA-256(sequence_num + action + input_hash + output_hash +
    prev_hash).
    """
    content = f"{sequence_num}{action}{input_hash}{output_hash}{prev_hash}"
    return hashlib.sha256(content.encode()).hexdigest()


def _compute_root_hash(entries: list[TraceEntry] | tuple[TraceEntry, ...]) -> str:
    """Compute the root hash over all entry hashes."""
    h = hashlib.sha256()
    for entry in entries:
        h.update(entry.entry_hash.encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Mutable trace builder (internal)
# ---------------------------------------------------------------------------


class _TraceBuilder:
    """Mutable internal state for a trace being recorded."""

    __slots__ = ("trace_id", "agent_id", "entries", "started_at")

    def __init__(self, trace_id: str, agent_id: str) -> None:
        self.trace_id = trace_id
        self.agent_id = agent_id
        self.entries: list[TraceEntry] = []
        self.started_at = time.monotonic()


# ---------------------------------------------------------------------------
# ExecutionTracer
# ---------------------------------------------------------------------------


class ExecutionTracer:
    """Create and verify cryptographically chained execution traces.

    Thread-safe: all mutations are guarded by an internal lock.
    """

    def __init__(self) -> None:
        self._active: dict[str, _TraceBuilder] = {}
        self._completed: dict[str, ExecutionTrace] = {}
        self._lock = threading.Lock()

    def begin_trace(self, agent_id: str) -> str:
        """Start a new execution trace for an agent.

        Args:
            agent_id: The agent whose actions will be traced.

        Returns:
            The ``trace_id`` for this trace (use in subsequent calls).
        """
        trace_id = uuid.uuid4().hex[:16]
        with self._lock:
            self._active[trace_id] = _TraceBuilder(trace_id, agent_id)
        return trace_id

    def record_step(
        self,
        trace_id: str,
        action: str,
        input_data: str = "",
        output_data: str = "",
    ) -> TraceEntry:
        """Add a step to an active trace.

        The step's hash is chained to the previous entry's hash.

        Args:
            trace_id: Trace to append to.
            action: Description of the action taken.
            input_data: Raw input data (will be hashed).
            output_data: Raw output data (will be hashed).

        Returns:
            The created :class:`TraceEntry`.

        Raises:
            KeyError: If *trace_id* is not an active trace.
        """
        with self._lock:
            builder = self._active.get(trace_id)
            if builder is None:
                msg = f"No active trace with id '{trace_id}'"
                raise KeyError(msg)

            seq = len(builder.entries)
            prev_hash = builder.entries[-1].entry_hash if builder.entries else ""
            input_hash = _hash_data(input_data)
            output_hash = _hash_data(output_data)
            entry_hash = _compute_entry_hash(seq, action, input_hash, output_hash, prev_hash)

            entry = TraceEntry(
                entry_id=uuid.uuid4().hex[:16],
                sequence_num=seq,
                agent_id=builder.agent_id,
                action=action,
                input_hash=input_hash,
                output_hash=output_hash,
                timestamp=time.monotonic(),
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
            builder.entries.append(entry)
            return entry

    def end_trace(self, trace_id: str) -> ExecutionTrace:
        """Finalize a trace and compute its root hash.

        Args:
            trace_id: The trace to finalize.

        Returns:
            A frozen :class:`ExecutionTrace`.

        Raises:
            KeyError: If *trace_id* is not an active trace.
        """
        with self._lock:
            builder = self._active.pop(trace_id, None)
            if builder is None:
                msg = f"No active trace with id '{trace_id}'"
                raise KeyError(msg)

            root_hash = _compute_root_hash(builder.entries)
            trace = ExecutionTrace(
                trace_id=trace_id,
                agent_id=builder.agent_id,
                entries=tuple(builder.entries),
                root_hash=root_hash,
                created_at=time.monotonic(),
            )
            self._completed[trace_id] = trace
            return trace

    def verify_trace(self, trace: ExecutionTrace) -> TraceVerification:
        """Verify an entire trace's integrity.

        Recomputes every entry hash and the root hash, confirming the
        chain is intact.

        Args:
            trace: The trace to verify.

        Returns:
            A :class:`TraceVerification` result.
        """
        if not trace.entries:
            return TraceVerification(
                valid=True,
                verified_entries=0,
                failed_at=-1,
                description="Empty trace is trivially valid",
            )

        prev_hash = ""
        for entry in trace.entries:
            # Verify chain link
            if entry.prev_hash != prev_hash:
                return TraceVerification(
                    valid=False,
                    verified_entries=entry.sequence_num,
                    failed_at=entry.sequence_num,
                    description=(f"Chain break at entry {entry.sequence_num}: prev_hash mismatch"),
                )

            # Verify entry hash
            expected = _compute_entry_hash(
                entry.sequence_num,
                entry.action,
                entry.input_hash,
                entry.output_hash,
                entry.prev_hash,
            )
            if entry.entry_hash != expected:
                return TraceVerification(
                    valid=False,
                    verified_entries=entry.sequence_num,
                    failed_at=entry.sequence_num,
                    description=(
                        f"Hash mismatch at entry {entry.sequence_num}: "
                        f"expected {expected[:16]}..., "
                        f"got {entry.entry_hash[:16]}..."
                    ),
                )

            prev_hash = entry.entry_hash

        # Verify root hash
        expected_root = _compute_root_hash(trace.entries)
        if trace.root_hash != expected_root:
            return TraceVerification(
                valid=False,
                verified_entries=len(trace.entries),
                failed_at=-1,
                description="Root hash mismatch",
            )

        return TraceVerification(
            valid=True,
            verified_entries=len(trace.entries),
            failed_at=-1,
            description=f"All {len(trace.entries)} entries verified",
        )

    def verify_step(
        self,
        trace: ExecutionTrace,
        sequence_num: int,
    ) -> TraceVerification:
        """Verify a single step within a trace.

        Args:
            trace: The trace containing the step.
            sequence_num: The sequence number of the step to verify.

        Returns:
            A :class:`TraceVerification` for this single step.
        """
        if sequence_num < 0 or sequence_num >= len(trace.entries):
            return TraceVerification(
                valid=False,
                verified_entries=0,
                failed_at=sequence_num,
                description=f"Sequence number {sequence_num} out of range",
            )

        entry = trace.entries[sequence_num]
        prev_hash = trace.entries[sequence_num - 1].entry_hash if sequence_num > 0 else ""

        if entry.prev_hash != prev_hash:
            return TraceVerification(
                valid=False,
                verified_entries=0,
                failed_at=sequence_num,
                description=f"Chain break at entry {sequence_num}: prev_hash mismatch",
            )

        expected = _compute_entry_hash(
            entry.sequence_num,
            entry.action,
            entry.input_hash,
            entry.output_hash,
            entry.prev_hash,
        )
        if entry.entry_hash != expected:
            return TraceVerification(
                valid=False,
                verified_entries=0,
                failed_at=sequence_num,
                description=f"Hash mismatch at entry {sequence_num}",
            )

        return TraceVerification(
            valid=True,
            verified_entries=1,
            failed_at=-1,
            description=f"Entry {sequence_num} verified",
        )

    def get_proof(
        self,
        trace: ExecutionTrace,
        sequence_num: int,
    ) -> TraceProof:
        """Generate a proof chain for a specific entry.

        The proof chain consists of the entry's hash and all preceding
        hashes back to the root.

        Args:
            trace: The trace containing the entry.
            sequence_num: Entry to generate proof for.

        Returns:
            A :class:`TraceProof`.

        Raises:
            IndexError: If *sequence_num* is out of range.
        """
        if sequence_num < 0 or sequence_num >= len(trace.entries):
            msg = f"Sequence number {sequence_num} out of range"
            raise IndexError(msg)

        chain = []
        for i in range(sequence_num + 1):
            chain.append(trace.entries[i].entry_hash)

        entry = trace.entries[sequence_num]
        return TraceProof(
            trace_id=trace.trace_id,
            entry_id=entry.entry_id,
            proof_chain=tuple(chain),
            root_hash=trace.root_hash,
        )

    def export_trace(self, trace: ExecutionTrace) -> str:
        """Export a trace as a JSON string for external verification.

        Args:
            trace: The trace to export.

        Returns:
            JSON string representation of the trace.
        """
        data = {
            "trace_id": trace.trace_id,
            "agent_id": trace.agent_id,
            "root_hash": trace.root_hash,
            "created_at": trace.created_at,
            "entries": [
                {
                    "entry_id": e.entry_id,
                    "sequence_num": e.sequence_num,
                    "agent_id": e.agent_id,
                    "action": e.action,
                    "input_hash": e.input_hash,
                    "output_hash": e.output_hash,
                    "timestamp": e.timestamp,
                    "prev_hash": e.prev_hash,
                    "entry_hash": e.entry_hash,
                }
                for e in trace.entries
            ],
        }
        return json.dumps(data, indent=2)

    def get_trace(self, trace_id: str) -> ExecutionTrace | None:
        """Look up a completed trace by ID.

        Args:
            trace_id: The trace to retrieve.

        Returns:
            The :class:`ExecutionTrace` or ``None`` if not found.
        """
        with self._lock:
            return self._completed.get(trace_id)
