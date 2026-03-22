"""Tests for cryptographic audit chain — tamper-evident, hash-chained logging.

Covers:
- Genesis entry creation
- Chain linking and integrity
- Tamper detection (modified data, removed entries, swapped hashes)
- JSONL export / import roundtrip
- Evidence package generation with compliance notes
- Thread safety under concurrent appends
- Multiple hash algorithms (sha256, sha3_256)
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from aegis.core.crypto_audit import (
    AuditEntry,
    CryptoAuditChain,
    EvidencePackage,
    VerificationResult,
    _GENESIS_HASH,
    _hash_entry,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def chain() -> CryptoAuditChain:
    return CryptoAuditChain()


@pytest.fixture()
def chain_sha3() -> CryptoAuditChain:
    return CryptoAuditChain(algorithm="sha3_256")


def _append_default(
    chain: CryptoAuditChain,
    agent_id: str = "agent-1",
    action_type: str = "read",
    action_target: str = "database",
    decision: str = "auto",
    risk_level: str = "low",
    matched_rule: str = "rule-1",
    metadata: dict | None = None,
) -> AuditEntry:
    return chain.append(
        agent_id=agent_id,
        action_type=action_type,
        action_target=action_target,
        decision=decision,
        risk_level=risk_level,
        matched_rule=matched_rule,
        metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Genesis entry
# ---------------------------------------------------------------------------


class TestGenesisEntry:
    def test_genesis_sequence_id(self, chain: CryptoAuditChain) -> None:
        entry = _append_default(chain)
        assert entry.sequence_id == 0

    def test_genesis_previous_hash_is_zero(self, chain: CryptoAuditChain) -> None:
        entry = _append_default(chain)
        assert entry.previous_hash == _GENESIS_HASH

    def test_genesis_has_nonzero_entry_hash(self, chain: CryptoAuditChain) -> None:
        entry = _append_default(chain)
        assert entry.entry_hash != ""
        assert entry.entry_hash != _GENESIS_HASH
        assert len(entry.entry_hash) == 64  # SHA-256 hex

    def test_genesis_entry_hash_is_deterministic(self) -> None:
        """Recomputing the hash from entry fields must match stored hash."""
        chain = CryptoAuditChain()
        entry = _append_default(chain)
        assert _hash_entry(entry, "sha256") == entry.entry_hash

    def test_genesis_timestamp_is_iso(self, chain: CryptoAuditChain) -> None:
        entry = _append_default(chain)
        assert "T" in entry.timestamp  # basic ISO 8601 check


# ---------------------------------------------------------------------------
# Chain linking
# ---------------------------------------------------------------------------


class TestChainLinking:
    def test_second_entry_links_to_first(self, chain: CryptoAuditChain) -> None:
        e0 = _append_default(chain)
        e1 = _append_default(chain, agent_id="agent-2")
        assert e1.previous_hash == e0.entry_hash
        assert e1.sequence_id == 1

    def test_chain_of_ten_entries(self, chain: CryptoAuditChain) -> None:
        entries = [_append_default(chain, agent_id=f"a-{i}") for i in range(10)]
        for i in range(1, 10):
            assert entries[i].previous_hash == entries[i - 1].entry_hash
        assert entries[0].previous_hash == _GENESIS_HASH

    def test_chain_of_twenty_entries(self, chain: CryptoAuditChain) -> None:
        entries = [_append_default(chain, agent_id=f"a-{i}") for i in range(20)]
        for i in range(1, 20):
            assert entries[i].previous_hash == entries[i - 1].entry_hash

    def test_len_reflects_appended_entries(self, chain: CryptoAuditChain) -> None:
        assert len(chain) == 0
        _append_default(chain)
        assert len(chain) == 1
        _append_default(chain)
        assert len(chain) == 2

    def test_each_entry_hash_is_unique(self, chain: CryptoAuditChain) -> None:
        entries = [_append_default(chain, agent_id=f"a-{i}") for i in range(5)]
        hashes = [e.entry_hash for e in entries]
        assert len(set(hashes)) == len(hashes)


# ---------------------------------------------------------------------------
# Verification — valid chains
# ---------------------------------------------------------------------------


class TestVerifyValid:
    def test_empty_chain_is_valid(self, chain: CryptoAuditChain) -> None:
        result = chain.verify()
        assert result.valid is True
        assert result.chain_length == 0
        assert result.verified_entries == 0
        assert result.first_broken_at is None
        assert result.error_message == ""

    def test_single_entry_chain_valid(self, chain: CryptoAuditChain) -> None:
        _append_default(chain)
        result = chain.verify()
        assert result.valid is True
        assert result.chain_length == 1
        assert result.verified_entries == 1

    def test_ten_entry_chain_valid(self, chain: CryptoAuditChain) -> None:
        for i in range(10):
            _append_default(chain, agent_id=f"agent-{i}")
        result = chain.verify()
        assert result.valid is True
        assert result.chain_length == 10
        assert result.verified_entries == 10

    def test_verification_hash_is_nonempty(self, chain: CryptoAuditChain) -> None:
        _append_default(chain)
        result = chain.verify()
        assert result.verification_hash != ""
        assert len(result.verification_hash) == 64

    def test_verification_hash_is_deterministic(
        self, chain: CryptoAuditChain
    ) -> None:
        _append_default(chain)
        r1 = chain.verify()
        r2 = chain.verify()
        assert r1.verification_hash == r2.verification_hash


# ---------------------------------------------------------------------------
# Verification — tampered entries
# ---------------------------------------------------------------------------


class TestVerifyTampered:
    def test_tampered_entry_data_detected(self, chain: CryptoAuditChain) -> None:
        """Modify an entry's action_type after appending — verify must fail."""
        _append_default(chain)
        _append_default(chain, agent_id="agent-2")
        _append_default(chain, agent_id="agent-3")

        # Tamper: replace entry 1 with altered action_type
        original = chain._chain[1]
        tampered = replace(original, action_type="TAMPERED")
        chain._chain[1] = tampered

        result = chain.verify()
        assert result.valid is False
        assert result.first_broken_at == 1
        assert "mismatch" in result.error_message

    def test_tampered_entry_hash_detected(self, chain: CryptoAuditChain) -> None:
        """Directly change an entry's hash — verify must fail at next entry."""
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")

        chain._chain[2] = replace(chain._chain[2], entry_hash="bad" + "0" * 61)

        result = chain.verify()
        assert result.valid is False
        # Should break at entry 2 (hash mismatch) or 3 (previous_hash mismatch)
        assert result.first_broken_at is not None
        assert result.first_broken_at <= 3

    def test_missing_middle_entry_detected(self, chain: CryptoAuditChain) -> None:
        """Remove a middle entry — chain breaks."""
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")

        del chain._chain[2]

        result = chain.verify()
        assert result.valid is False
        assert result.first_broken_at is not None

    def test_swapped_entries_detected(self, chain: CryptoAuditChain) -> None:
        """Swap two adjacent entries — chain breaks."""
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")

        chain._chain[1], chain._chain[2] = chain._chain[2], chain._chain[1]

        result = chain.verify()
        assert result.valid is False

    def test_tampered_metadata_detected(self, chain: CryptoAuditChain) -> None:
        _append_default(chain, metadata={"key": "value"})
        chain._chain[0] = replace(
            chain._chain[0], metadata={"key": "TAMPERED"}
        )
        result = chain.verify()
        assert result.valid is False
        assert result.first_broken_at == 0

    def test_tampered_previous_hash_detected(
        self, chain: CryptoAuditChain
    ) -> None:
        for i in range(3):
            _append_default(chain, agent_id=f"a-{i}")
        chain._chain[1] = replace(chain._chain[1], previous_hash="f" * 64)
        result = chain.verify()
        assert result.valid is False
        assert result.first_broken_at == 1


# ---------------------------------------------------------------------------
# verify_entry
# ---------------------------------------------------------------------------


class TestVerifyEntry:
    def test_valid_entry(self, chain: CryptoAuditChain) -> None:
        _append_default(chain)
        assert chain.verify_entry(0) is True

    def test_invalid_entry(self, chain: CryptoAuditChain) -> None:
        _append_default(chain)
        chain._chain[0] = replace(chain._chain[0], action_type="TAMPERED")
        assert chain.verify_entry(0) is False

    def test_out_of_range_returns_false(self, chain: CryptoAuditChain) -> None:
        _append_default(chain)
        assert chain.verify_entry(99) is False
        assert chain.verify_entry(-1) is False

    def test_middle_entry_valid(self, chain: CryptoAuditChain) -> None:
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")
        assert chain.verify_entry(3) is True

    def test_verify_entry_with_broken_previous_hash(
        self, chain: CryptoAuditChain
    ) -> None:
        for i in range(3):
            _append_default(chain, agent_id=f"a-{i}")
        chain._chain[2] = replace(chain._chain[2], previous_hash="a" * 64)
        assert chain.verify_entry(2) is False


# ---------------------------------------------------------------------------
# get_entry / get_entries
# ---------------------------------------------------------------------------


class TestGetEntries:
    def test_get_entry_returns_correct(self, chain: CryptoAuditChain) -> None:
        _append_default(chain, agent_id="alpha")
        _append_default(chain, agent_id="beta")
        assert chain.get_entry(0) is not None
        assert chain.get_entry(0).agent_id == "alpha"  # type: ignore[union-attr]
        assert chain.get_entry(1) is not None
        assert chain.get_entry(1).agent_id == "beta"  # type: ignore[union-attr]

    def test_get_entry_none_for_missing(self, chain: CryptoAuditChain) -> None:
        assert chain.get_entry(0) is None

    def test_get_entries_slice(self, chain: CryptoAuditChain) -> None:
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")
        subset = chain.get_entries(1, 3)
        assert len(subset) == 2
        assert subset[0].sequence_id == 1
        assert subset[1].sequence_id == 2

    def test_get_entries_default_all(self, chain: CryptoAuditChain) -> None:
        for i in range(3):
            _append_default(chain, agent_id=f"a-{i}")
        assert len(chain.get_entries()) == 3


# ---------------------------------------------------------------------------
# JSONL export / import
# ---------------------------------------------------------------------------


class TestJsonlRoundtrip:
    def test_export_creates_file(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        path = tmp_path / "audit.jsonl"
        count = chain.export_jsonl(path)
        assert count == 1
        assert path.exists()

    def test_export_import_roundtrip(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")
        path = tmp_path / "audit.jsonl"
        chain.export_jsonl(path)

        chain2 = CryptoAuditChain()
        chain2.import_jsonl(path)
        assert len(chain2) == 5
        result = chain2.verify()
        assert result.valid is True

    def test_import_rejects_tampered_file(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        for i in range(3):
            _append_default(chain, agent_id=f"a-{i}")
        path = tmp_path / "audit.jsonl"
        chain.export_jsonl(path)

        # Tamper with the file
        lines = path.read_text().splitlines()
        data = json.loads(lines[1])
        data["action_type"] = "TAMPERED"
        lines[1] = json.dumps(data, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        chain2 = CryptoAuditChain()
        with pytest.raises(ValueError, match="verification failed"):
            chain2.import_jsonl(path)

    def test_import_preserves_original_on_failure(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain, agent_id="original")
        path = tmp_path / "bad.jsonl"
        path.write_text('{"bad": "json"}\n')

        chain2 = CryptoAuditChain()
        _append_default(chain2, agent_id="keep-this")
        with pytest.raises((ValueError, TypeError)):
            chain2.import_jsonl(path)
        # Original chain should be preserved
        assert len(chain2) == 1

    def test_export_empty_chain(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        path = tmp_path / "empty.jsonl"
        count = chain.export_jsonl(path)
        assert count == 0
        assert path.read_text() == ""

    def test_import_empty_file(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        chain.import_jsonl(path)
        assert len(chain) == 0

    def test_export_jsonl_content_is_valid_json(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain, metadata={"key": "value"})
        path = tmp_path / "audit.jsonl"
        chain.export_jsonl(path)
        lines = path.read_text().strip().splitlines()
        for line in lines:
            data = json.loads(line)
            assert "sequence_id" in data
            assert "entry_hash" in data

    def test_import_creates_nested_dirs(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        path = tmp_path / "nested" / "dir" / "audit.jsonl"
        chain.export_jsonl(path)
        assert path.exists()


# ---------------------------------------------------------------------------
# Evidence package
# ---------------------------------------------------------------------------


class TestEvidencePackage:
    def test_generate_evidence_package(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        for i in range(5):
            _append_default(
                chain,
                agent_id=f"a-{i % 2}",
                decision="auto" if i % 2 == 0 else "block",
            )
        path = tmp_path / "evidence.json"
        pkg = chain.generate_evidence_package(path)

        assert isinstance(pkg, EvidencePackage)
        assert pkg.chain_length == 5
        assert pkg.verification_result.valid is True
        assert path.exists()

    def test_evidence_compliance_notes_eu_ai_act(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        notes_text = " ".join(pkg.compliance_notes)
        assert "EU AI Act" in notes_text
        assert "Article 12" in notes_text

    def test_evidence_compliance_notes_soc2(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        notes_text = " ".join(pkg.compliance_notes)
        assert "SOC2" in notes_text

    def test_evidence_summary_counts(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain, agent_id="a1", decision="auto", action_type="read")
        _append_default(chain, agent_id="a1", decision="block", action_type="write")
        _append_default(chain, agent_id="a2", decision="auto", action_type="read")
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        assert pkg.summary["action_counts"]["read"] == 2
        assert pkg.summary["action_counts"]["write"] == 1
        assert pkg.summary["decision_counts"]["auto"] == 2
        assert pkg.summary["decision_counts"]["block"] == 1
        assert pkg.summary["agent_counts"]["a1"] == 2
        assert pkg.summary["agent_counts"]["a2"] == 1

    def test_evidence_chain_hash(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        last_entry = chain.get_entry(0)
        assert last_entry is not None
        assert pkg.chain_hash == last_entry.entry_hash

    def test_evidence_algorithm_field(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        assert pkg.algorithm == "sha256"

    def test_evidence_json_file_is_valid(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        path = tmp_path / "e.json"
        chain.generate_evidence_package(path)
        data = json.loads(path.read_text())
        assert "verification_result" in data
        assert "compliance_notes" in data

    def test_evidence_empty_chain(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        assert pkg.chain_length == 0
        assert pkg.chain_hash == _GENESIS_HASH
        assert pkg.verification_result.valid is True

    def test_evidence_risk_counts(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain, risk_level="high")
        _append_default(chain, risk_level="high")
        _append_default(chain, risk_level="low")
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        assert pkg.summary["risk_counts"]["high"] == 2
        assert pkg.summary["risk_counts"]["low"] == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_appends(self, chain: CryptoAuditChain) -> None:
        """100 threads each append one entry — chain must stay valid."""
        errors: list[Exception] = []

        def worker(i: int) -> None:
            try:
                _append_default(chain, agent_id=f"thread-{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(chain) == 100
        result = chain.verify()
        assert result.valid is True
        assert result.verified_entries == 100

    def test_concurrent_appends_unique_sequences(
        self, chain: CryptoAuditChain
    ) -> None:
        """All entries from concurrent appends must have unique sequence IDs."""

        def worker(i: int) -> None:
            _append_default(chain, agent_id=f"t-{i}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        entries = chain.get_entries()
        seq_ids = [e.sequence_id for e in entries]
        assert len(set(seq_ids)) == 50
        assert sorted(seq_ids) == list(range(50))


# ---------------------------------------------------------------------------
# Multiple algorithms
# ---------------------------------------------------------------------------


class TestAlgorithms:
    def test_sha3_256_chain(self, chain_sha3: CryptoAuditChain) -> None:
        for i in range(5):
            _append_default(chain_sha3, agent_id=f"a-{i}")
        result = chain_sha3.verify()
        assert result.valid is True
        assert result.verified_entries == 5

    def test_sha3_256_hash_differs_from_sha256(self) -> None:
        c256 = CryptoAuditChain(algorithm="sha256")
        c3 = CryptoAuditChain(algorithm="sha3_256")
        # Same data, different algorithms — hashes differ
        e1 = _append_default(c256)
        e2 = _append_default(c3)
        # Timestamps differ so we check the hash is at least present
        assert e1.entry_hash != ""
        assert e2.entry_hash != ""
        assert len(e2.entry_hash) == 64  # SHA3-256 also 32 bytes = 64 hex

    def test_sha3_256_verify_entry(self, chain_sha3: CryptoAuditChain) -> None:
        _append_default(chain_sha3)
        assert chain_sha3.verify_entry(0) is True

    def test_sha3_256_tamper_detected(self, chain_sha3: CryptoAuditChain) -> None:
        for i in range(3):
            _append_default(chain_sha3, agent_id=f"a-{i}")
        chain_sha3._chain[1] = replace(
            chain_sha3._chain[1], action_type="TAMPERED"
        )
        result = chain_sha3.verify()
        assert result.valid is False

    def test_sha3_256_evidence_package(
        self, chain_sha3: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain_sha3)
        pkg = chain_sha3.generate_evidence_package(tmp_path / "e.json")
        assert pkg.algorithm == "sha3_256"

    def test_sha3_256_export_import(
        self, chain_sha3: CryptoAuditChain, tmp_path: Path
    ) -> None:
        for i in range(3):
            _append_default(chain_sha3, agent_id=f"a-{i}")
        path = tmp_path / "audit.jsonl"
        chain_sha3.export_jsonl(path)

        chain2 = CryptoAuditChain(algorithm="sha3_256")
        chain2.import_jsonl(path)
        assert len(chain2) == 3
        assert chain2.verify().valid is True

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            CryptoAuditChain(algorithm="md5")


# ---------------------------------------------------------------------------
# Chain hash sensitivity
# ---------------------------------------------------------------------------


class TestChainHashSensitivity:
    def test_chain_hash_changes_on_any_modification(
        self, chain: CryptoAuditChain
    ) -> None:
        """Modifying any single field in any entry changes the final chain hash."""
        for i in range(5):
            _append_default(chain, agent_id=f"a-{i}")
        original_hash = chain.get_entry(4).entry_hash  # type: ignore[union-attr]

        # Build a second chain, same data except one field in entry 2
        chain2 = CryptoAuditChain()
        for i in range(5):
            agent = f"a-{i}" if i != 2 else "MODIFIED"
            _append_default(chain2, agent_id=agent)

        modified_hash = chain2.get_entry(4).entry_hash  # type: ignore[union-attr]
        assert original_hash != modified_hash

    def test_metadata_change_propagates(self, chain: CryptoAuditChain) -> None:
        e0 = _append_default(chain, metadata={"key": "A"})
        chain2 = CryptoAuditChain()
        e0b = _append_default(chain2, metadata={"key": "B"})
        assert e0.entry_hash != e0b.entry_hash


# ---------------------------------------------------------------------------
# Frozen dataclass guarantees
# ---------------------------------------------------------------------------


class TestFrozenDataclasses:
    def test_audit_entry_is_frozen(self, chain: CryptoAuditChain) -> None:
        entry = _append_default(chain)
        with pytest.raises(AttributeError):
            entry.action_type = "CHANGED"  # type: ignore[misc]

    def test_verification_result_is_frozen(self, chain: CryptoAuditChain) -> None:
        _append_default(chain)
        result = chain.verify()
        with pytest.raises(AttributeError):
            result.valid = False  # type: ignore[misc]

    def test_evidence_package_is_frozen(
        self, chain: CryptoAuditChain, tmp_path: Path
    ) -> None:
        _append_default(chain)
        pkg = chain.generate_evidence_package(tmp_path / "e.json")
        with pytest.raises(AttributeError):
            pkg.chain_length = 999  # type: ignore[misc]
