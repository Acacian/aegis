"""Tests for aegis.core.reversibility -- action reversibility scoring."""

from __future__ import annotations

import threading

import pytest

from aegis.core.reversibility import (
    ReversibilityCategory,
    ReversibilityScore,
    ReversibilityScorer,
    RollbackCostEstimate,
    RollbackPoint,
    RollbackResult,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scorer() -> ReversibilityScorer:
    return ReversibilityScorer()


# ---------------------------------------------------------------------------
# Frozen dataclass invariants
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_reversibility_score_frozen(self) -> None:
        s = ReversibilityScore("read", 1.0, ReversibilityCategory.FULLY_REVERSIBLE, "ok")
        with pytest.raises(AttributeError):
            s.score = 0.5  # type: ignore[misc]

    def test_rollback_point_frozen(self) -> None:
        p = RollbackPoint("id1", "agent1", 0.0, "abc", ("read",))
        with pytest.raises(AttributeError):
            p.point_id = "id2"  # type: ignore[misc]

    def test_rollback_result_frozen(self) -> None:
        r = RollbackResult(True, ("read",), ())
        with pytest.raises(AttributeError):
            r.success = False  # type: ignore[misc]

    def test_rollback_cost_estimate_frozen(self) -> None:
        e = RollbackCostEstimate("id", 0, 0, 0, 0.0, True, "ok")
        with pytest.raises(AttributeError):
            e.feasible = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Scoring fully reversible actions
# ---------------------------------------------------------------------------


class TestFullyReversible:
    def test_read_file(self) -> None:
        s = _scorer().score_action("read_file")
        assert s.score == 1.0
        assert s.category == ReversibilityCategory.FULLY_REVERSIBLE

    def test_list_files(self) -> None:
        s = _scorer().score_action("list_files")
        assert s.score == 1.0

    def test_search(self) -> None:
        s = _scorer().score_action("search")
        assert s.score == 1.0

    def test_git_status(self) -> None:
        s = _scorer().score_action("git_status")
        assert s.score == 1.0
        assert s.category == ReversibilityCategory.FULLY_REVERSIBLE

    def test_preview(self) -> None:
        s = _scorer().score_action("preview")
        assert s.score == 1.0

    def test_validate(self) -> None:
        s = _scorer().score_action("validate")
        assert s.score == 1.0

    def test_case_insensitive(self) -> None:
        s = _scorer().score_action("READ_FILE")
        assert s.score == 1.0
        assert s.category == ReversibilityCategory.FULLY_REVERSIBLE


# ---------------------------------------------------------------------------
# Scoring partially reversible actions
# ---------------------------------------------------------------------------


class TestPartiallyReversible:
    def test_edit_file(self) -> None:
        s = _scorer().score_action("edit_file")
        assert 0.3 <= s.score <= 0.7
        assert s.category == ReversibilityCategory.PARTIALLY_REVERSIBLE

    def test_db_update(self) -> None:
        s = _scorer().score_action("db_update")
        assert s.category == ReversibilityCategory.PARTIALLY_REVERSIBLE

    def test_git_commit(self) -> None:
        s = _scorer().score_action("git_commit")
        assert s.category == ReversibilityCategory.PARTIALLY_REVERSIBLE

    def test_install_package(self) -> None:
        s = _scorer().score_action("install_package")
        assert s.category == ReversibilityCategory.PARTIALLY_REVERSIBLE


# ---------------------------------------------------------------------------
# Scoring irreversible actions
# ---------------------------------------------------------------------------


class TestIrreversible:
    def test_delete_no_backup(self) -> None:
        s = _scorer().score_action("delete_no_backup")
        assert s.score == 0.0
        assert s.category == ReversibilityCategory.IRREVERSIBLE

    def test_send_email(self) -> None:
        s = _scorer().score_action("send_email")
        assert s.score == 0.0
        assert s.category == ReversibilityCategory.IRREVERSIBLE

    def test_payment_transaction(self) -> None:
        s = _scorer().score_action("payment_transaction")
        assert s.score == 0.0

    def test_drop_table(self) -> None:
        s = _scorer().score_action("drop_table")
        assert s.score == 0.0

    def test_rm_rf(self) -> None:
        s = _scorer().score_action("rm_rf")
        assert s.score == 0.0
        assert s.category == ReversibilityCategory.IRREVERSIBLE


# ---------------------------------------------------------------------------
# Unknown actions and keyword fallback
# ---------------------------------------------------------------------------


class TestUnknownAndKeyword:
    def test_completely_unknown(self) -> None:
        s = _scorer().score_action("xyzzy_frobulate")
        assert s.category == ReversibilityCategory.UNKNOWN
        assert s.score == 0.5

    def test_keyword_read_fallback(self) -> None:
        s = _scorer().score_action("custom_read_operation")
        assert s.score == 1.0
        assert s.category == ReversibilityCategory.FULLY_REVERSIBLE

    def test_keyword_delete_fallback(self) -> None:
        s = _scorer().score_action("custom_delete_thing")
        assert s.category == ReversibilityCategory.IRREVERSIBLE

    def test_keyword_write_fallback(self) -> None:
        s = _scorer().score_action("custom_write_log")
        assert s.category == ReversibilityCategory.PARTIALLY_REVERSIBLE


# ---------------------------------------------------------------------------
# Custom action registration
# ---------------------------------------------------------------------------


class TestCustomActions:
    def test_register_custom_action(self) -> None:
        scorer = _scorer()
        scorer.register_action_reversibility(
            "deploy_staging", 0.8, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Can rollback"
        )
        s = scorer.score_action("deploy_staging")
        assert s.score == 0.8
        assert s.category == ReversibilityCategory.PARTIALLY_REVERSIBLE

    def test_custom_overrides_builtin(self) -> None:
        scorer = _scorer()
        # Override the built-in read_file with a custom score
        scorer.register_action_reversibility(
            "read_file", 0.9, ReversibilityCategory.PARTIALLY_REVERSIBLE, "Custom read"
        )
        s = scorer.score_action("read_file")
        assert s.score == 0.9

    def test_invalid_score_raises(self) -> None:
        scorer = _scorer()
        with pytest.raises(ValueError):
            scorer.register_action_reversibility("x", 1.5, ReversibilityCategory.UNKNOWN)

    def test_invalid_negative_score(self) -> None:
        scorer = _scorer()
        with pytest.raises(ValueError):
            scorer.register_action_reversibility("x", -0.1, ReversibilityCategory.UNKNOWN)

    def test_batch_scoring(self) -> None:
        scorer = _scorer()
        scores = scorer.score_actions(["read_file", "send_email", "edit_file"])
        assert len(scores) == 3
        assert scores[0].score == 1.0
        assert scores[1].score == 0.0
        assert 0.3 <= scores[2].score <= 0.7


# ---------------------------------------------------------------------------
# Checkpoint management
# ---------------------------------------------------------------------------


class TestCheckpoints:
    def test_create_checkpoint(self) -> None:
        scorer = _scorer()
        cp = scorer.create_checkpoint("agent-1", "hash123", ["read", "edit"])
        assert cp.agent_id == "agent-1"
        assert cp.state_hash == "hash123"
        assert cp.action_history == ("read", "edit")

    def test_can_rollback_no_checkpoints(self) -> None:
        scorer = _scorer()
        assert not scorer.can_rollback("agent-1")

    def test_can_rollback_with_checkpoint(self) -> None:
        scorer = _scorer()
        scorer.create_checkpoint("agent-1", "h1", ["read"])
        assert scorer.can_rollback("agent-1")

    def test_can_rollback_specific_point(self) -> None:
        scorer = _scorer()
        cp1 = scorer.create_checkpoint("agent-1", "h1", ["read"])
        scorer.create_checkpoint("agent-1", "h2", ["read", "edit_file"])
        assert scorer.can_rollback("agent-1", cp1.point_id)

    def test_cannot_rollback_past_irreversible(self) -> None:
        scorer = _scorer()
        cp1 = scorer.create_checkpoint("agent-1", "h1", ["read"])
        scorer.create_checkpoint("agent-1", "h2", ["read", "send_email"])
        assert not scorer.can_rollback("agent-1", cp1.point_id)

    def test_rollback_nonexistent_point(self) -> None:
        scorer = _scorer()
        scorer.create_checkpoint("agent-1", "h1", ["read"])
        assert not scorer.can_rollback("agent-1", "nonexistent-id")

    def test_get_checkpoints(self) -> None:
        scorer = _scorer()
        scorer.create_checkpoint("agent-1", "h1", ["a"])
        scorer.create_checkpoint("agent-1", "h2", ["a", "b"])
        cps = scorer.get_checkpoints("agent-1")
        assert len(cps) == 2
        assert cps[0].state_hash == "h1"

    def test_max_checkpoints_eviction(self) -> None:
        scorer = ReversibilityScorer(max_checkpoints=3)
        for i in range(5):
            scorer.create_checkpoint("agent-1", f"h{i}", [f"action_{i}"])
        cps = scorer.get_checkpoints("agent-1")
        assert len(cps) == 3
        # Oldest should have been evicted
        assert cps[0].state_hash == "h2"


# ---------------------------------------------------------------------------
# Rollback cost estimation
# ---------------------------------------------------------------------------


class TestRollbackCost:
    def test_no_actions_to_undo(self) -> None:
        scorer = _scorer()
        cp = scorer.create_checkpoint("agent-1", "h1", ["read"])
        est = scorer.estimate_rollback_cost("agent-1", cp.point_id)
        assert est.actions_to_undo == 0
        assert est.feasible

    def test_reversible_actions(self) -> None:
        scorer = _scorer()
        cp1 = scorer.create_checkpoint("agent-1", "h1", ["read"])
        scorer.create_checkpoint("agent-1", "h2", ["read", "edit_file", "create_file"])
        est = scorer.estimate_rollback_cost("agent-1", cp1.point_id)
        assert est.actions_to_undo == 2
        assert est.reversible_count == 2
        assert est.irreversible_count == 0
        assert est.feasible

    def test_irreversible_actions(self) -> None:
        scorer = _scorer()
        cp1 = scorer.create_checkpoint("agent-1", "h1", [])
        scorer.create_checkpoint("agent-1", "h2", ["send_email", "drop_table"])
        est = scorer.estimate_rollback_cost("agent-1", cp1.point_id)
        assert est.irreversible_count == 2
        assert not est.feasible

    def test_nonexistent_checkpoint(self) -> None:
        scorer = _scorer()
        est = scorer.estimate_rollback_cost("agent-1", "nope")
        assert not est.feasible
        assert est.estimated_risk == 1.0


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


class TestUtility:
    def test_compute_state_hash(self) -> None:
        h1 = ReversibilityScorer.compute_state_hash("a", "b")
        h2 = ReversibilityScorer.compute_state_hash("a", "b")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_different_inputs_different_hash(self) -> None:
        h1 = ReversibilityScorer.compute_state_hash("a")
        h2 = ReversibilityScorer.compute_state_hash("b")
        assert h1 != h2


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_scoring(self) -> None:
        scorer = _scorer()
        results: list[ReversibilityScore] = []
        lock = threading.Lock()

        def score_many() -> None:
            for action in ["read_file", "send_email", "edit_file"]:
                s = scorer.score_action(action)
                with lock:
                    results.append(s)

        threads = [threading.Thread(target=score_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 30

    def test_concurrent_checkpoint_creation(self) -> None:
        scorer = _scorer()
        errors: list[Exception] = []

        def create_many(agent_id: str) -> None:
            try:
                for i in range(20):
                    scorer.create_checkpoint(agent_id, f"h{i}", [f"a{i}"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=create_many, args=(f"agent-{i}",)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        for i in range(5):
            cps = scorer.get_checkpoints(f"agent-{i}")
            assert len(cps) == 20

    def test_concurrent_register_and_score(self) -> None:
        scorer = _scorer()
        errors: list[Exception] = []

        def register_and_score() -> None:
            try:
                scorer.register_action_reversibility(
                    "concurrent_test", 0.5, ReversibilityCategory.UNKNOWN
                )
                scorer.score_action("concurrent_test")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register_and_score) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
