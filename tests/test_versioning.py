"""Tests for the policy versioning and history system."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel
from aegis.core.versioning import (
    PolicyDelta,
    PolicyStore,
    PolicyVersion,
    _hash_dict,
    _policy_to_dict,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_policy(
    rules: list[PolicyRule] | None = None,
    default_risk: RiskLevel = RiskLevel.MEDIUM,
    default_approval: Approval = Approval.APPROVE,
) -> Policy:
    return Policy(
        rules=rules or [],
        default_risk_level=default_risk,
        default_approval=default_approval,
    )


def _read_rule(name: str = "read_ops") -> PolicyRule:
    return PolicyRule(
        name=name,
        match_type="read",
        match_target="*",
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
    )


def _write_rule(name: str = "write_ops") -> PolicyRule:
    return PolicyRule(
        name=name,
        match_type="write",
        match_target="*",
        risk_level=RiskLevel.HIGH,
        approval=Approval.APPROVE,
    )


def _delete_rule(name: str = "delete_ops") -> PolicyRule:
    return PolicyRule(
        name=name,
        match_type="delete",
        match_target="*",
        risk_level=RiskLevel.CRITICAL,
        approval=Approval.BLOCK,
    )


@pytest.fixture()
def store() -> PolicyStore:
    return PolicyStore()


@pytest.fixture()
def tmp_store(tmp_path: Path) -> PolicyStore:
    return PolicyStore(store_path=tmp_path / "policy_history.json")


# ---------------------------------------------------------------------------
# PolicyVersion dataclass
# ---------------------------------------------------------------------------


class TestPolicyVersion:
    def test_frozen(self) -> None:
        v = PolicyVersion(
            version_id="abc",
            version_number=1,
            created_at="2024-01-01T00:00:00+00:00",
            author="alice",
            message="init",
            policy_hash="deadbeef",
            parent_version=None,
            policy_dict={},
        )
        with pytest.raises(AttributeError):
            v.version_id = "xyz"  # type: ignore[misc]

    def test_fields_accessible(self) -> None:
        v = PolicyVersion(
            version_id="v1",
            version_number=1,
            created_at="2024-01-01T00:00:00+00:00",
            author="bob",
            message="first",
            policy_hash="aaa",
            parent_version=None,
            policy_dict={"version": "1"},
        )
        assert v.version_id == "v1"
        assert v.version_number == 1
        assert v.author == "bob"
        assert v.parent_version is None
        assert v.policy_dict == {"version": "1"}


# ---------------------------------------------------------------------------
# PolicyDelta dataclass
# ---------------------------------------------------------------------------


class TestPolicyDelta:
    def test_frozen(self) -> None:
        d = PolicyDelta(
            version_from="a",
            version_to="b",
            rules_added=[],
            rules_removed=[],
            rules_modified=[],
            defaults_changed={},
        )
        with pytest.raises(AttributeError):
            d.version_from = "x"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Empty store
# ---------------------------------------------------------------------------


class TestEmptyStore:
    def test_get_latest_empty(self, store: PolicyStore) -> None:
        assert store.get_latest() is None

    def test_get_history_empty(self, store: PolicyStore) -> None:
        assert store.get_history() == []

    def test_get_version_missing(self, store: PolicyStore) -> None:
        assert store.get_version("nonexistent") is None

    def test_get_by_tag_missing(self, store: PolicyStore) -> None:
        assert store.get_by_tag("production") is None


# ---------------------------------------------------------------------------
# Commit basics
# ---------------------------------------------------------------------------


class TestCommit:
    def test_commit_returns_version(self, store: PolicyStore) -> None:
        policy = _make_policy()
        v = store.commit(policy, "alice", "initial commit")
        assert isinstance(v, PolicyVersion)

    def test_commit_version_fields(self, store: PolicyStore) -> None:
        policy = _make_policy(rules=[_read_rule()])
        v = store.commit(policy, "alice", "add read rule")
        assert v.version_number == 1
        assert v.author == "alice"
        assert v.message == "add read rule"
        assert v.parent_version is None
        assert len(v.version_id) == 32  # uuid4 hex
        assert "T" in v.created_at  # ISO 8601

    def test_commit_auto_increments(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        v3 = store.commit(p, "a", "third")
        assert v1.version_number == 1
        assert v2.version_number == 2
        assert v3.version_number == 3

    def test_commit_parent_chain(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        v3 = store.commit(p, "a", "third")
        assert v1.parent_version is None
        assert v2.parent_version == v1.version_id
        assert v3.parent_version == v2.version_id

    def test_commit_policy_dict_contains_rules(self, store: PolicyStore) -> None:
        policy = _make_policy(rules=[_read_rule()])
        v = store.commit(policy, "alice", "with rule")
        assert "rules" in v.policy_dict
        rules = v.policy_dict["rules"]
        assert isinstance(rules, list)
        assert len(rules) == 1  # type: ignore[arg-type]
        assert rules[0]["name"] == "read_ops"  # type: ignore[index]

    def test_commit_policy_dict_defaults(self, store: PolicyStore) -> None:
        policy = _make_policy(default_risk=RiskLevel.HIGH, default_approval=Approval.BLOCK)
        v = store.commit(policy, "alice", "strict defaults")
        defaults = v.policy_dict["defaults"]
        assert defaults["risk_level"] == "high"  # type: ignore[index]
        assert defaults["approval"] == "block"  # type: ignore[index]

    def test_version_id_unique(self, store: PolicyStore) -> None:
        p = _make_policy()
        ids = {store.commit(p, "a", str(i)).version_id for i in range(20)}
        assert len(ids) == 20


# ---------------------------------------------------------------------------
# Get operations
# ---------------------------------------------------------------------------


class TestGetOperations:
    def test_get_version_by_id(self, store: PolicyStore) -> None:
        p = _make_policy()
        v = store.commit(p, "a", "first")
        assert store.get_version(v.version_id) == v

    def test_get_latest(self, store: PolicyStore) -> None:
        p = _make_policy()
        store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        assert store.get_latest() == v2

    def test_get_history_newest_first(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        v3 = store.commit(p, "a", "third")
        history = store.get_history()
        assert history == [v3, v2, v1]

    def test_get_history_limit(self, store: PolicyStore) -> None:
        p = _make_policy()
        for i in range(10):
            store.commit(p, "a", f"v{i}")
        history = store.get_history(limit=3)
        assert len(history) == 3
        assert history[0].version_number == 10

    def test_get_history_limit_exceeds_total(self, store: PolicyStore) -> None:
        p = _make_policy()
        store.commit(p, "a", "only one")
        history = store.get_history(limit=100)
        assert len(history) == 1


# ---------------------------------------------------------------------------
# Policy hash
# ---------------------------------------------------------------------------


class TestPolicyHash:
    def test_same_content_same_hash(self, store: PolicyStore) -> None:
        p = _make_policy(rules=[_read_rule()])
        v1 = store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        assert v1.policy_hash == v2.policy_hash

    def test_different_content_different_hash(self, store: PolicyStore) -> None:
        p1 = _make_policy(rules=[_read_rule()])
        p2 = _make_policy(rules=[_write_rule()])
        v1 = store.commit(p1, "a", "read policy")
        v2 = store.commit(p2, "a", "write policy")
        assert v1.policy_hash != v2.policy_hash

    def test_hash_is_sha256_hex(self, store: PolicyStore) -> None:
        v = store.commit(_make_policy(), "a", "test")
        assert len(v.policy_hash) == 64  # SHA-256 hex length
        int(v.policy_hash, 16)  # must be valid hex

    def test_hash_deterministic(self) -> None:
        d = {"key": "value", "nested": {"a": 1}}
        assert _hash_dict(d) == _hash_dict(d)  # type: ignore[arg-type]

    def test_hash_order_independent(self) -> None:
        d1: dict[str, object] = {"b": 2, "a": 1}
        d2: dict[str, object] = {"a": 1, "b": 2}
        assert _hash_dict(d1) == _hash_dict(d2)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


class TestDiff:
    def test_diff_no_changes(self, store: PolicyStore) -> None:
        p = _make_policy(rules=[_read_rule()])
        v1 = store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        delta = store.diff(v1.version_id, v2.version_id)
        assert delta.rules_added == []
        assert delta.rules_removed == []
        assert delta.rules_modified == []
        assert delta.defaults_changed == {}

    def test_diff_rule_added(self, store: PolicyStore) -> None:
        p1 = _make_policy(rules=[_read_rule()])
        p2 = _make_policy(rules=[_read_rule(), _write_rule()])
        v1 = store.commit(p1, "a", "base")
        v2 = store.commit(p2, "a", "add write")
        delta = store.diff(v1.version_id, v2.version_id)
        assert delta.rules_added == ["write_ops"]
        assert delta.rules_removed == []

    def test_diff_rule_removed(self, store: PolicyStore) -> None:
        p1 = _make_policy(rules=[_read_rule(), _write_rule()])
        p2 = _make_policy(rules=[_read_rule()])
        v1 = store.commit(p1, "a", "both")
        v2 = store.commit(p2, "a", "remove write")
        delta = store.diff(v1.version_id, v2.version_id)
        assert delta.rules_removed == ["write_ops"]
        assert delta.rules_added == []

    def test_diff_rule_modified(self, store: PolicyStore) -> None:
        rule_v1 = PolicyRule(
            name="ops",
            match_type="read",
            match_target="*",
            risk_level=RiskLevel.LOW,
            approval=Approval.AUTO,
        )
        rule_v2 = PolicyRule(
            name="ops",
            match_type="read",
            match_target="*",
            risk_level=RiskLevel.HIGH,
            approval=Approval.APPROVE,
        )
        v1 = store.commit(_make_policy(rules=[rule_v1]), "a", "v1")
        v2 = store.commit(_make_policy(rules=[rule_v2]), "a", "v2")
        delta = store.diff(v1.version_id, v2.version_id)
        assert delta.rules_modified == ["ops"]

    def test_diff_defaults_changed(self, store: PolicyStore) -> None:
        p1 = _make_policy(default_risk=RiskLevel.LOW, default_approval=Approval.AUTO)
        p2 = _make_policy(default_risk=RiskLevel.HIGH, default_approval=Approval.BLOCK)
        v1 = store.commit(p1, "a", "lax")
        v2 = store.commit(p2, "a", "strict")
        delta = store.diff(v1.version_id, v2.version_id)
        assert "risk_level" in delta.defaults_changed
        assert "approval" in delta.defaults_changed
        assert delta.defaults_changed["risk_level"] == ("low", "high")
        assert delta.defaults_changed["approval"] == ("auto", "block")

    def test_diff_unknown_version_raises(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "only")
        with pytest.raises(KeyError):
            store.diff(v1.version_id, "nonexistent")
        with pytest.raises(KeyError):
            store.diff("nonexistent", v1.version_id)

    def test_diff_returns_policy_delta(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "a")
        v2 = store.commit(p, "a", "b")
        delta = store.diff(v1.version_id, v2.version_id)
        assert isinstance(delta, PolicyDelta)
        assert delta.version_from == v1.version_id
        assert delta.version_to == v2.version_id

    def test_diff_multiple_changes(self, store: PolicyStore) -> None:
        p1 = _make_policy(rules=[_read_rule(), _write_rule()])
        p2 = _make_policy(rules=[_read_rule(), _delete_rule()])
        v1 = store.commit(p1, "a", "before")
        v2 = store.commit(p2, "a", "after")
        delta = store.diff(v1.version_id, v2.version_id)
        assert "delete_ops" in delta.rules_added
        assert "write_ops" in delta.rules_removed


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


class TestRollback:
    def test_rollback_creates_new_version(self, store: PolicyStore) -> None:
        p1 = _make_policy(rules=[_read_rule()])
        p2 = _make_policy(rules=[_write_rule()])
        v1 = store.commit(p1, "a", "first")
        store.commit(p2, "a", "second")
        v3 = store.rollback(v1.version_id)
        assert v3.version_number == 3
        assert v3.policy_hash == v1.policy_hash

    def test_rollback_preserves_content(self, store: PolicyStore) -> None:
        p1 = _make_policy(rules=[_read_rule()])
        p2 = _make_policy(rules=[_write_rule()])
        v1 = store.commit(p1, "a", "first")
        store.commit(p2, "a", "second")
        v3 = store.rollback(v1.version_id)
        assert v3.policy_dict == v1.policy_dict

    def test_rollback_parent_chain(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "first")
        v2 = store.commit(p, "a", "second")
        v3 = store.rollback(v1.version_id)
        assert v3.parent_version == v2.version_id

    def test_rollback_message(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "first")
        store.commit(p, "a", "second")
        v3 = store.rollback(v1.version_id)
        assert "Rollback" in v3.message
        assert v1.version_id in v3.message

    def test_rollback_unknown_raises(self, store: PolicyStore) -> None:
        with pytest.raises(KeyError):
            store.rollback("nonexistent")

    def test_rollback_is_in_history(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "first")
        store.commit(p, "a", "second")
        v3 = store.rollback(v1.version_id)
        history = store.get_history()
        assert history[0] == v3


# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------


class TestTagging:
    def test_tag_and_get(self, store: PolicyStore) -> None:
        p = _make_policy()
        v = store.commit(p, "a", "release")
        store.tag(v.version_id, "production")
        assert store.get_by_tag("production") == v

    def test_tag_overwrite(self, store: PolicyStore) -> None:
        p = _make_policy()
        v1 = store.commit(p, "a", "v1")
        v2 = store.commit(p, "a", "v2")
        store.tag(v1.version_id, "latest")
        store.tag(v2.version_id, "latest")
        assert store.get_by_tag("latest") == v2

    def test_multiple_tags(self, store: PolicyStore) -> None:
        p = _make_policy()
        v = store.commit(p, "a", "multi-tag")
        store.tag(v.version_id, "production")
        store.tag(v.version_id, "staging")
        assert store.get_by_tag("production") == v
        assert store.get_by_tag("staging") == v

    def test_tag_unknown_version_raises(self, store: PolicyStore) -> None:
        with pytest.raises(KeyError):
            store.tag("nonexistent", "bad")

    def test_get_by_tag_missing(self, store: PolicyStore) -> None:
        assert store.get_by_tag("nope") is None


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_save_load_roundtrip(self, tmp_store: PolicyStore, tmp_path: Path) -> None:
        p1 = _make_policy(rules=[_read_rule()])
        p2 = _make_policy(rules=[_read_rule(), _write_rule()])
        v1 = tmp_store.commit(p1, "alice", "initial")
        v2 = tmp_store.commit(p2, "alice", "add write")
        tmp_store.tag(v2.version_id, "production")
        tmp_store.save()

        loaded = PolicyStore(store_path=tmp_path / "policy_history.json")
        loaded.load()

        assert loaded.get_latest() is not None
        latest = loaded.get_latest()
        assert latest is not None
        assert latest.version_id == v2.version_id
        assert latest.version_number == 2

        assert loaded.get_version(v1.version_id) is not None
        assert loaded.get_by_tag("production") is not None
        assert loaded.get_by_tag("production") == loaded.get_version(v2.version_id)

    def test_save_creates_file(self, tmp_store: PolicyStore, tmp_path: Path) -> None:
        tmp_store.commit(_make_policy(), "a", "test")
        tmp_store.save()
        assert (tmp_path / "policy_history.json").exists()

    def test_save_valid_json(self, tmp_store: PolicyStore, tmp_path: Path) -> None:
        tmp_store.commit(_make_policy(), "a", "test")
        tmp_store.save()
        data = json.loads((tmp_path / "policy_history.json").read_text())
        assert "versions" in data
        assert "tags" in data

    def test_load_preserves_history_order(self, tmp_store: PolicyStore, tmp_path: Path) -> None:
        p = _make_policy()
        for i in range(5):
            tmp_store.commit(p, "a", f"commit {i}")
        tmp_store.save()

        loaded = PolicyStore(store_path=tmp_path / "policy_history.json")
        loaded.load()
        history = loaded.get_history()
        assert len(history) == 5
        assert history[0].version_number == 5
        assert history[-1].version_number == 1

    def test_save_without_path_raises(self) -> None:
        store = PolicyStore()
        with pytest.raises(RuntimeError):
            store.save()

    def test_load_without_path_raises(self) -> None:
        store = PolicyStore()
        with pytest.raises(RuntimeError):
            store.load()

    def test_load_missing_file_raises(self, tmp_path: Path) -> None:
        store = PolicyStore(store_path=tmp_path / "missing.json")
        with pytest.raises(FileNotFoundError):
            store.load()

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c" / "store.json"
        store = PolicyStore(store_path=deep)
        store.commit(_make_policy(), "a", "deep")
        store.save()
        assert deep.exists()

    def test_roundtrip_preserves_tags(self, tmp_path: Path) -> None:
        path = tmp_path / "tags_test.json"
        store = PolicyStore(store_path=path)
        p = _make_policy()
        v1 = store.commit(p, "a", "v1")
        v2 = store.commit(p, "a", "v2")
        store.tag(v1.version_id, "staging")
        store.tag(v2.version_id, "production")
        store.save()

        loaded = PolicyStore(store_path=path)
        loaded.load()
        assert loaded.get_by_tag("staging") is not None
        assert loaded.get_by_tag("staging") == loaded.get_version(v1.version_id)
        assert loaded.get_by_tag("production") is not None
        assert loaded.get_by_tag("production") == loaded.get_version(v2.version_id)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_commits(self, store: PolicyStore) -> None:
        """Multiple threads committing simultaneously must not corrupt state."""
        n_threads = 10
        n_commits_per_thread = 10
        errors: list[Exception] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(n_commits_per_thread):
                    p = _make_policy()
                    store.commit(p, f"thread-{thread_id}", f"commit-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent commits: {errors}"

        total = n_threads * n_commits_per_thread
        history = store.get_history(limit=total)
        assert len(history) == total

        # version_numbers must form a contiguous sequence 1..total
        numbers = sorted(v.version_number for v in history)
        assert numbers == list(range(1, total + 1))

    def test_concurrent_reads_during_writes(self, store: PolicyStore) -> None:
        """Reads must not fail while writes are happening."""
        stop = threading.Event()
        errors: list[Exception] = []

        def writer() -> None:
            for i in range(50):
                store.commit(_make_policy(), "writer", f"w-{i}")
            stop.set()

        def reader() -> None:
            try:
                while not stop.is_set():
                    store.get_latest()
                    store.get_history(limit=5)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        w = threading.Thread(target=writer)
        readers = [threading.Thread(target=reader) for _ in range(5)]
        for r in readers:
            r.start()
        w.start()
        w.join()
        for r in readers:
            r.join()

        assert errors == [], f"Errors during concurrent reads: {errors}"


# ---------------------------------------------------------------------------
# _policy_to_dict helper
# ---------------------------------------------------------------------------


class TestPolicyToDict:
    def test_basic_policy(self) -> None:
        p = _make_policy(rules=[_read_rule()])
        d = _policy_to_dict(p)
        assert d["version"] == "1"
        assert "defaults" in d
        assert "rules" in d

    def test_empty_rules_no_key(self) -> None:
        p = _make_policy()
        d = _policy_to_dict(p)
        assert "rules" not in d

    def test_scope_fields(self) -> None:
        p = Policy(scope="team", scope_id="eng-123")
        d = _policy_to_dict(p)
        assert d["scope"] == "team"
        assert d["scope_id"] == "eng-123"
