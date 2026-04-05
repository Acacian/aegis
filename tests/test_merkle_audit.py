"""Tests for aegis.core.merkle_audit — Merkle tree audit log."""

from __future__ import annotations

import pytest

from aegis.core.merkle_audit import (
    BatchProofResult,
    MerkleAuditTree,
    MerkleLeaf,
    MerkleProof,
)


class TestMerkleAuditTree:
    def test_empty_tree(self) -> None:
        tree = MerkleAuditTree()
        assert len(tree) == 0
        assert tree.root_hash == "0" * 64

    def test_single_leaf(self) -> None:
        tree = MerkleAuditTree()
        idx = tree.append("agent-1", "read", "db", "auto", "low")
        assert idx == 0
        assert len(tree) == 1
        assert tree.root_hash != "0" * 64

    def test_multiple_leaves(self) -> None:
        tree = MerkleAuditTree()
        for i in range(10):
            tree.append(f"agent-{i}", "action", "target", "auto", "low")
        assert len(tree) == 10

    def test_root_changes_on_append(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        root1 = tree.root_hash
        tree.append("a", "write", "db", "approve", "high")
        root2 = tree.root_hash
        assert root1 != root2

    def test_get_leaf(self) -> None:
        tree = MerkleAuditTree()
        tree.append("agent-1", "read", "db", "auto", "low", metadata={"key": "val"})
        leaf = tree.get_leaf(0)
        assert leaf is not None
        assert isinstance(leaf, MerkleLeaf)
        assert leaf.agent_id == "agent-1"
        assert leaf.action_type == "read"
        assert leaf.metadata == {"key": "val"}

    def test_get_leaf_out_of_range(self) -> None:
        tree = MerkleAuditTree()
        assert tree.get_leaf(0) is None
        assert tree.get_leaf(-1) is None

    def test_get_leaves(self) -> None:
        tree = MerkleAuditTree()
        for i in range(5):
            tree.append(f"agent-{i}", "read", "db", "auto", "low")
        leaves = tree.get_leaves(1, 3)
        assert len(leaves) == 2
        assert leaves[0].agent_id == "agent-1"

    # -- Proofs ---------------------------------------------------------------

    def test_prove_single_leaf(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        proof = tree.prove(0)
        assert isinstance(proof, MerkleProof)
        assert proof.leaf_index == 0
        assert proof.tree_size == 1
        assert MerkleAuditTree.verify_proof(proof, tree.root_hash)

    def test_prove_two_leaves(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        tree.append("b", "write", "file", "approve", "high")

        proof0 = tree.prove(0)
        assert MerkleAuditTree.verify_proof(proof0, tree.root_hash)

        proof1 = tree.prove(1)
        assert MerkleAuditTree.verify_proof(proof1, tree.root_hash)

    def test_prove_power_of_two(self) -> None:
        tree = MerkleAuditTree()
        for i in range(8):
            tree.append(f"agent-{i}", "action", "target", "auto", "low")

        for i in range(8):
            proof = tree.prove(i)
            assert MerkleAuditTree.verify_proof(proof, tree.root_hash)

    def test_prove_non_power_of_two(self) -> None:
        tree = MerkleAuditTree()
        for i in range(5):
            tree.append(f"agent-{i}", "action", "target", "auto", "low")

        for i in range(5):
            proof = tree.prove(i)
            assert MerkleAuditTree.verify_proof(proof, tree.root_hash), (
                f"Proof failed for leaf {i}"
            )

    def test_prove_large_tree(self) -> None:
        tree = MerkleAuditTree()
        for i in range(100):
            tree.append(f"agent-{i}", "action", "target", "auto", "low")

        # Verify a sample of proofs
        for i in [0, 1, 49, 50, 99]:
            proof = tree.prove(i)
            assert MerkleAuditTree.verify_proof(proof, tree.root_hash)

    def test_proof_invalid_index(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        with pytest.raises(IndexError):
            tree.prove(1)
        with pytest.raises(IndexError):
            tree.prove(-1)

    def test_proof_fails_with_wrong_root(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        proof = tree.prove(0)
        assert not MerkleAuditTree.verify_proof(proof, "0" * 64)
        assert not MerkleAuditTree.verify_proof(proof, "deadbeef" * 8)

    def test_proof_survives_append(self) -> None:
        """Proof generated before append should still verify against its original root."""
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        tree.append("b", "write", "file", "approve", "high")
        old_root = tree.root_hash
        proof = tree.prove(0)

        # Append more entries
        tree.append("c", "delete", "record", "block", "critical")

        # Old proof still valid against old root
        assert MerkleAuditTree.verify_proof(proof, old_root)
        # But not against new root
        assert not MerkleAuditTree.verify_proof(proof, tree.root_hash)

    # -- Batch verification ---------------------------------------------------

    def test_verify_batch(self) -> None:
        tree = MerkleAuditTree()
        for i in range(10):
            tree.append(f"agent-{i}", "action", "target", "auto", "low")

        proofs = [tree.prove(i) for i in range(10)]
        result = tree.verify_batch(proofs)
        assert isinstance(result, BatchProofResult)
        assert result.all_valid
        assert len(result.results) == 10

    def test_verify_batch_with_stale_proof(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        old_proof = tree.prove(0)
        tree.append("b", "write", "file", "approve", "high")
        new_proof = tree.prove(1)

        result = tree.verify_batch([old_proof, new_proof])
        assert not result.all_valid
        assert result.results[0] is False  # stale proof
        assert result.results[1] is True

    # -- Export ---------------------------------------------------------------

    def test_export_json(self) -> None:
        tree = MerkleAuditTree()
        tree.append("a", "read", "db", "auto", "low")
        data = tree.export_json()
        assert data["size"] == 1
        assert data["root_hash"] == tree.root_hash
        assert len(data["leaves"]) == 1

    def test_export_empty(self) -> None:
        tree = MerkleAuditTree()
        data = tree.export_json()
        assert data["size"] == 0
        assert data["root_hash"] == "0" * 64
