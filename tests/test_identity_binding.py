"""Tests for BAID: Binding Agent Identity.

Covers:
- Identity binding creation and hash computation
- Binding verification (valid, tampered config/code/model)
- Provenance recording and lineage tracing
- Drift detection across historical bindings
- Rebinding (updating an existing binding)
- Thread safety under concurrent operations
- Edge cases (empty IDs, unregistered agents)
- Frozen dataclass immutability

Reference: arXiv:2512.17538
"""

from __future__ import annotations

import hashlib
import threading
from datetime import datetime

import pytest

from aegis.core.identity_binding import (
    BindingMismatch,
    BindingVerification,
    IdentityBinder,
    IdentityBinding,
    _compute_binding_hash,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def binder() -> IdentityBinder:
    return IdentityBinder()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _bind_default(
    binder: IdentityBinder,
    agent_id: str = "agent-1",
    config_hash: str = "cfg_aaa",
    code_hash: str = "code_bbb",
    model_hash: str = "model_ccc",
) -> IdentityBinding:
    return binder.bind(agent_id, config_hash, code_hash, model_hash)


# ---------------------------------------------------------------------------
# Binding creation
# ---------------------------------------------------------------------------


class TestBindingCreation:
    def test_bind_creates_binding(self, binder: IdentityBinder) -> None:
        binding = _bind_default(binder)
        assert binding.agent_id == "agent-1"
        assert binding.config_hash == "cfg_aaa"
        assert binding.code_hash == "code_bbb"
        assert binding.model_hash == "model_ccc"

    def test_binding_hash_is_sha256(self, binder: IdentityBinder) -> None:
        binding = _bind_default(binder)
        expected = _compute_binding_hash("agent-1", "cfg_aaa", "code_bbb", "model_ccc")
        assert binding.binding_hash == expected
        assert len(binding.binding_hash) == 64

    def test_binding_hash_formula(self) -> None:
        """binding_hash = SHA-256(agent_id + config_hash + code_hash + model_hash)."""
        result = _compute_binding_hash("a", "b", "c", "d")
        expected = _sha256("abcd")
        assert result == expected

    def test_bind_sets_timestamp(self, binder: IdentityBinder) -> None:
        binding = _bind_default(binder)
        assert binding.created_at != ""
        datetime.fromisoformat(binding.created_at)

    def test_bind_empty_id_raises(self, binder: IdentityBinder) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            binder.bind("", "cfg", "code", "model")

    def test_bind_stores_in_registry(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        assert binder.get_binding("agent-1") is not None

    def test_rebind_updates_current(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        new_binding = binder.bind("agent-1", "new_cfg", "new_code", "new_model")
        current = binder.get_binding("agent-1")
        assert current is not None
        assert current.config_hash == "new_cfg"
        assert current.binding_hash == new_binding.binding_hash


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerification:
    def test_verify_valid_binding(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "cfg_aaa", "code_bbb", "model_ccc")
        assert result.valid is True
        assert len(result.mismatches) == 0

    def test_verify_config_tampered(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "tampered", "code_bbb", "model_ccc")
        assert result.valid is False
        fields = {m.field for m in result.mismatches}
        assert "config_hash" in fields

    def test_verify_code_tampered(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "cfg_aaa", "tampered", "model_ccc")
        assert result.valid is False
        fields = {m.field for m in result.mismatches}
        assert "code_hash" in fields

    def test_verify_model_tampered(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "cfg_aaa", "code_bbb", "tampered")
        assert result.valid is False
        fields = {m.field for m in result.mismatches}
        assert "model_hash" in fields

    def test_verify_all_tampered(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "x", "y", "z")
        assert result.valid is False
        assert len(result.mismatches) == 3

    def test_verify_unregistered_agent(self, binder: IdentityBinder) -> None:
        result = binder.verify_binding("unknown", "a", "b", "c")
        assert result.valid is False
        assert result.mismatches[0].field == "agent_id"

    def test_verify_sets_timestamp(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "cfg_aaa", "code_bbb", "model_ccc")
        assert result.verified_at != ""
        datetime.fromisoformat(result.verified_at)

    def test_mismatch_severity_levels(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "x", "y", "z")
        severities = {m.field: m.severity for m in result.mismatches}
        assert severities["config_hash"] == "high"
        assert severities["code_hash"] == "critical"
        assert severities["model_hash"] == "critical"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_record_provenance(self, binder: IdentityBinder) -> None:
        record = binder.record_provenance("agent-1", changes={"config": "updated"}, parent_id=None)
        assert record.agent_id == "agent-1"
        assert record.version == 1
        assert record.parent_id is None
        assert record.changes == {"config": "updated"}

    def test_provenance_versioning(self, binder: IdentityBinder) -> None:
        r1 = binder.record_provenance("agent-1", changes={"v": "1"})
        r2 = binder.record_provenance("agent-1", changes={"v": "2"})
        assert r1.version == 1
        assert r2.version == 2

    def test_provenance_hash(self, binder: IdentityBinder) -> None:
        record = binder.record_provenance("agent-1", changes={"x": "1"})
        assert len(record.hash) == 64

    def test_trace_lineage(self, binder: IdentityBinder) -> None:
        binder.record_provenance("agent-1", changes={"v": "1"})
        binder.record_provenance("agent-1", changes={"v": "2"}, parent_id="agent-0")
        binder.record_provenance("agent-1", changes={"v": "3"}, parent_id="agent-0")
        lineage = binder.trace_lineage("agent-1")
        assert len(lineage) == 3
        assert lineage[0].version == 1
        assert lineage[2].version == 3

    def test_trace_lineage_empty(self, binder: IdentityBinder) -> None:
        lineage = binder.trace_lineage("unknown")
        assert lineage == []

    def test_provenance_with_parent(self, binder: IdentityBinder) -> None:
        record = binder.record_provenance(
            "agent-2", changes={"delegated": "true"}, parent_id="agent-1"
        )
        assert record.parent_id == "agent-1"


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


class TestDriftDetection:
    def test_no_drift(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        drifts = binder.detect_drift("agent-1", "cfg_aaa", "code_bbb", "model_ccc")
        # Filter out provenance-related drifts for this check
        field_drifts = [d for d in drifts if d.field != "provenance"]
        assert len(field_drifts) == 0

    def test_config_drift(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        drifts = binder.detect_drift("agent-1", "changed_cfg", "code_bbb", "model_ccc")
        fields = {d.field for d in drifts}
        assert "config_hash" in fields

    def test_code_drift(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        drifts = binder.detect_drift("agent-1", "cfg_aaa", "changed_code", "model_ccc")
        fields = {d.field for d in drifts}
        assert "code_hash" in fields

    def test_drift_unregistered(self, binder: IdentityBinder) -> None:
        drifts = binder.detect_drift("unknown", "a", "b", "c")
        assert len(drifts) == 1
        assert drifts[0].field == "agent_id"

    def test_drift_after_rebind_without_provenance(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        binder.bind("agent-1", "new_cfg", "new_code", "new_model")
        # No provenance recorded — should flag
        drifts = binder.detect_drift("agent-1", "new_cfg", "new_code", "new_model")
        fields = {d.field for d in drifts}
        assert "provenance" in fields

    def test_drift_after_rebind_with_provenance(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        binder.record_provenance("agent-1", changes={"config": "updated"})
        binder.bind("agent-1", "new_cfg", "new_code", "new_model")
        drifts = binder.detect_drift("agent-1", "new_cfg", "new_code", "new_model")
        # With provenance, should not flag provenance drift
        field_drifts = [d for d in drifts if d.field == "provenance"]
        assert len(field_drifts) == 0


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


class TestHistory:
    def test_binding_history(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        binder.bind("agent-1", "v2_cfg", "v2_code", "v2_model")
        history = binder.get_history("agent-1")
        assert len(history) >= 2

    def test_empty_history(self, binder: IdentityBinder) -> None:
        history = binder.get_history("unknown")
        assert history == []


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_binds(self) -> None:
        binder = IdentityBinder()
        errors: list[str] = []

        def bind_agent(i: int) -> None:
            try:
                binder.bind(f"agent-{i}", f"cfg-{i}", f"code-{i}", f"model-{i}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=bind_agent, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        for i in range(50):
            assert binder.get_binding(f"agent-{i}") is not None

    def test_concurrent_verify(self) -> None:
        binder = IdentityBinder()
        for i in range(20):
            binder.bind(f"agent-{i}", f"cfg-{i}", f"code-{i}", f"model-{i}")

        results: list[BindingVerification] = []
        lock = threading.Lock()

        def verify(i: int) -> None:
            r = binder.verify_binding(f"agent-{i}", f"cfg-{i}", f"code-{i}", f"model-{i}")
            with lock:
                results.append(r)

        threads = [threading.Thread(target=verify, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r.valid for r in results)


# ---------------------------------------------------------------------------
# Frozen dataclass immutability
# ---------------------------------------------------------------------------


class TestImmutability:
    def test_binding_is_frozen(self, binder: IdentityBinder) -> None:
        binding = _bind_default(binder)
        with pytest.raises(AttributeError):
            binding.agent_id = "tampered"  # type: ignore[misc]

    def test_mismatch_is_frozen(self) -> None:
        m = BindingMismatch(field="x", expected_hash="a", actual_hash="b", severity="high")
        with pytest.raises(AttributeError):
            m.field = "y"  # type: ignore[misc]

    def test_verification_is_frozen(self, binder: IdentityBinder) -> None:
        _bind_default(binder)
        result = binder.verify_binding("agent-1", "cfg_aaa", "code_bbb", "model_ccc")
        with pytest.raises(AttributeError):
            result.valid = False  # type: ignore[misc]

    def test_provenance_is_frozen(self, binder: IdentityBinder) -> None:
        record = binder.record_provenance("agent-1", changes={"x": "1"})
        with pytest.raises(AttributeError):
            record.version = 999  # type: ignore[misc]
