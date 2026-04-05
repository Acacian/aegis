"""Tests for aegis.core.exec_trace -- verifiable execution traces."""

from __future__ import annotations

import hashlib
import json
import threading

import pytest

from aegis.core.exec_trace import (
    ExecutionTrace,
    ExecutionTracer,
    TraceEntry,
    TraceProof,
    TraceVerification,
    _compute_entry_hash,
    _hash_data,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tracer() -> ExecutionTracer:
    return ExecutionTracer()


def _make_trace(tracer: ExecutionTracer, n: int = 3) -> ExecutionTrace:
    """Build a quick trace with *n* steps."""
    tid = tracer.begin_trace("agent-1")
    for i in range(n):
        tracer.record_step(tid, f"action_{i}", f"input_{i}", f"output_{i}")
    return tracer.end_trace(tid)


# ---------------------------------------------------------------------------
# Frozen dataclass invariants
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_trace_entry_frozen(self) -> None:
        e = TraceEntry("id", 0, "a", "act", "ih", "oh", 0.0, "", "eh")
        with pytest.raises(AttributeError):
            e.action = "x"  # type: ignore[misc]

    def test_execution_trace_frozen(self) -> None:
        t = ExecutionTrace("tid", "a", (), "rh", 0.0)
        with pytest.raises(AttributeError):
            t.root_hash = "x"  # type: ignore[misc]

    def test_trace_verification_frozen(self) -> None:
        v = TraceVerification(True, 0, -1, "ok")
        with pytest.raises(AttributeError):
            v.valid = False  # type: ignore[misc]

    def test_trace_proof_frozen(self) -> None:
        p = TraceProof("tid", "eid", ("h1",), "rh")
        with pytest.raises(AttributeError):
            p.root_hash = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


class TestHashing:
    def test_hash_data_deterministic(self) -> None:
        assert _hash_data("hello") == _hash_data("hello")

    def test_hash_data_sha256(self) -> None:
        expected = hashlib.sha256(b"hello").hexdigest()
        assert _hash_data("hello") == expected

    def test_entry_hash_deterministic(self) -> None:
        h1 = _compute_entry_hash(0, "act", "ih", "oh", "")
        h2 = _compute_entry_hash(0, "act", "ih", "oh", "")
        assert h1 == h2

    def test_entry_hash_changes_with_seq(self) -> None:
        h1 = _compute_entry_hash(0, "act", "ih", "oh", "")
        h2 = _compute_entry_hash(1, "act", "ih", "oh", "")
        assert h1 != h2


# ---------------------------------------------------------------------------
# Begin / record / end
# ---------------------------------------------------------------------------


class TestTraceLifecycle:
    def test_begin_returns_trace_id(self) -> None:
        t = _tracer()
        tid = t.begin_trace("agent-1")
        assert isinstance(tid, str)
        assert len(tid) > 0

    def test_record_step_returns_entry(self) -> None:
        t = _tracer()
        tid = t.begin_trace("agent-1")
        entry = t.record_step(tid, "read_file", "path", "content")
        assert entry.action == "read_file"
        assert entry.sequence_num == 0

    def test_sequential_sequence_numbers(self) -> None:
        t = _tracer()
        tid = t.begin_trace("agent-1")
        e0 = t.record_step(tid, "a0")
        e1 = t.record_step(tid, "a1")
        e2 = t.record_step(tid, "a2")
        assert e0.sequence_num == 0
        assert e1.sequence_num == 1
        assert e2.sequence_num == 2

    def test_chain_linking(self) -> None:
        t = _tracer()
        tid = t.begin_trace("agent-1")
        e0 = t.record_step(tid, "a0")
        e1 = t.record_step(tid, "a1")
        assert e0.prev_hash == ""
        assert e1.prev_hash == e0.entry_hash

    def test_end_trace_produces_root_hash(self) -> None:
        t = _tracer()
        trace = _make_trace(t)
        assert isinstance(trace.root_hash, str)
        assert len(trace.root_hash) == 64

    def test_end_trace_entries_tuple(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=2)
        assert isinstance(trace.entries, tuple)
        assert len(trace.entries) == 2

    def test_record_on_ended_trace_raises(self) -> None:
        t = _tracer()
        tid = t.begin_trace("agent-1")
        t.end_trace(tid)
        with pytest.raises(KeyError):
            t.record_step(tid, "late_step")

    def test_end_nonexistent_trace_raises(self) -> None:
        t = _tracer()
        with pytest.raises(KeyError):
            t.end_trace("nonexistent")

    def test_record_nonexistent_trace_raises(self) -> None:
        t = _tracer()
        with pytest.raises(KeyError):
            t.record_step("nonexistent", "step")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerification:
    def test_valid_trace(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=5)
        v = t.verify_trace(trace)
        assert v.valid
        assert v.verified_entries == 5
        assert v.failed_at == -1

    def test_empty_trace_valid(self) -> None:
        t = _tracer()
        tid = t.begin_trace("agent-1")
        trace = t.end_trace(tid)
        v = t.verify_trace(trace)
        assert v.valid
        assert v.verified_entries == 0

    def test_tampered_entry_hash(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=3)
        # Tamper with entry 1's hash
        entries = list(trace.entries)
        bad = TraceEntry(
            entry_id=entries[1].entry_id,
            sequence_num=entries[1].sequence_num,
            agent_id=entries[1].agent_id,
            action=entries[1].action,
            input_hash=entries[1].input_hash,
            output_hash=entries[1].output_hash,
            timestamp=entries[1].timestamp,
            prev_hash=entries[1].prev_hash,
            entry_hash="0000000000000000000000000000000000000000000000000000000000000000",
        )
        entries[1] = bad
        tampered = ExecutionTrace(
            trace.trace_id, trace.agent_id, tuple(entries), trace.root_hash, trace.created_at
        )
        v = t.verify_trace(tampered)
        assert not v.valid
        assert v.failed_at == 1

    def test_tampered_chain_link(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=3)
        entries = list(trace.entries)
        bad = TraceEntry(
            entry_id=entries[2].entry_id,
            sequence_num=entries[2].sequence_num,
            agent_id=entries[2].agent_id,
            action=entries[2].action,
            input_hash=entries[2].input_hash,
            output_hash=entries[2].output_hash,
            timestamp=entries[2].timestamp,
            prev_hash="bad_prev_hash",
            entry_hash=entries[2].entry_hash,
        )
        entries[2] = bad
        tampered = ExecutionTrace(
            trace.trace_id, trace.agent_id, tuple(entries), trace.root_hash, trace.created_at
        )
        v = t.verify_trace(tampered)
        assert not v.valid
        assert v.failed_at == 2

    def test_tampered_root_hash(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=2)
        tampered = ExecutionTrace(
            trace.trace_id, trace.agent_id, trace.entries, "bad_root", trace.created_at
        )
        v = t.verify_trace(tampered)
        assert not v.valid

    def test_verify_single_step(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=3)
        v = t.verify_step(trace, 1)
        assert v.valid

    def test_verify_step_out_of_range(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=2)
        v = t.verify_step(trace, 5)
        assert not v.valid

    def test_verify_step_negative_index(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=2)
        v = t.verify_step(trace, -1)
        assert not v.valid


# ---------------------------------------------------------------------------
# Proof
# ---------------------------------------------------------------------------


class TestProof:
    def test_proof_chain_length(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=5)
        proof = t.get_proof(trace, 3)
        # Chain includes entries 0..3 = 4 entries
        assert len(proof.proof_chain) == 4
        assert proof.root_hash == trace.root_hash

    def test_proof_first_entry(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=3)
        proof = t.get_proof(trace, 0)
        assert len(proof.proof_chain) == 1
        assert proof.proof_chain[0] == trace.entries[0].entry_hash

    def test_proof_out_of_range(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=2)
        with pytest.raises(IndexError):
            t.get_proof(trace, 10)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


class TestExport:
    def test_export_valid_json(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=2)
        exported = t.export_trace(trace)
        data = json.loads(exported)
        assert data["trace_id"] == trace.trace_id
        assert len(data["entries"]) == 2

    def test_export_contains_all_fields(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=1)
        data = json.loads(t.export_trace(trace))
        entry = data["entries"][0]
        required_fields = {
            "entry_id",
            "sequence_num",
            "agent_id",
            "action",
            "input_hash",
            "output_hash",
            "timestamp",
            "prev_hash",
            "entry_hash",
        }
        assert required_fields.issubset(set(entry.keys()))

    def test_export_root_hash(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=3)
        data = json.loads(t.export_trace(trace))
        assert data["root_hash"] == trace.root_hash


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


class TestRetrieval:
    def test_get_completed_trace(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=1)
        retrieved = t.get_trace(trace.trace_id)
        assert retrieved is not None
        assert retrieved.trace_id == trace.trace_id

    def test_get_nonexistent_trace(self) -> None:
        t = _tracer()
        assert t.get_trace("nonexistent") is None


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_traces(self) -> None:
        t = _tracer()
        errors: list[Exception] = []
        traces: list[ExecutionTrace] = []
        lock = threading.Lock()

        def build_trace(agent_id: str) -> None:
            try:
                tid = t.begin_trace(agent_id)
                for i in range(10):
                    t.record_step(tid, f"action_{i}", f"in_{i}", f"out_{i}")
                trace = t.end_trace(tid)
                with lock:
                    traces.append(trace)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=build_trace, args=(f"agent-{i}",)) for i in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert not errors
        assert len(traces) == 10
        # Each trace should be independently valid
        for trace in traces:
            v = t.verify_trace(trace)
            assert v.valid

    def test_concurrent_verify(self) -> None:
        t = _tracer()
        trace = _make_trace(t, n=20)
        errors: list[Exception] = []

        def verify() -> None:
            try:
                v = t.verify_trace(trace)
                assert v.valid
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=verify) for _ in range(10)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert not errors
