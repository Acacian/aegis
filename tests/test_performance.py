"""Tests for performance optimizations: compiled patterns, batch audit, policy cache."""

import fnmatch
from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.batch_audit import BatchAuditLogger

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_decision(
    action_type: str = "read",
    target: str = "salesforce",
    risk: RiskLevel = RiskLevel.LOW,
    approval: Approval = Approval.AUTO,
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(action_type, target),
        risk_level=risk,
        approval=approval,
        matched_rule="test_rule",
    )


# ===========================================================================
# 1. Compiled glob patterns produce same results as fnmatch
# ===========================================================================


def test_compiled_patterns_exact_match():
    """Compiled regex matches produce the same result as fnmatch for exact strings."""
    rule = PolicyRule(match_type="read", match_target="salesforce")
    action_match = Action("read", "salesforce")
    action_no_match = Action("write", "salesforce")

    assert rule.matches(action_match) is True
    assert fnmatch.fnmatch("read", "read") is True

    assert rule.matches(action_no_match) is False
    assert fnmatch.fnmatch("write", "read") is False


def test_compiled_patterns_glob_match():
    """Compiled regex matches produce the same result as fnmatch for glob patterns."""
    rule = PolicyRule(match_type="bulk_*", match_target="sales*")

    cases = [
        ("bulk_update", "salesforce", True),
        ("bulk_delete", "sales_db", True),
        ("update", "salesforce", False),
        ("bulk_update", "stripe", False),
    ]
    for action_type, target, expected in cases:
        assert rule.matches(Action(action_type, target)) is expected
        assert (
            fnmatch.fnmatch(action_type, "bulk_*") and fnmatch.fnmatch(target, "sales*")
        ) is expected


def test_compiled_patterns_wildcard():
    """Wildcard-only patterns match everything, same as fnmatch."""
    rule = PolicyRule(match_type="*", match_target="*")
    assert rule.matches(Action("anything", "anywhere"))
    assert rule.matches(Action("", ""))


def test_compiled_patterns_agent_match():
    """Agent pattern compilation produces correct results."""
    rule = PolicyRule(match_type="*", match_target="*", match_agent="bot_*")
    assert rule.matches(Action("read", "crm", agent_id="bot_alpha"))
    assert not rule.matches(Action("read", "crm", agent_id="user_alpha"))


def test_compiled_patterns_agent_wildcard():
    """Wildcard agent skips compilation (optimization) and matches all."""
    rule = PolicyRule(match_type="*", match_target="*", match_agent="*")
    assert rule._re_agent is None
    assert rule.matches(Action("read", "crm"))
    assert rule.matches(Action("read", "crm", agent_id="any_agent"))


# ===========================================================================
# 2-4. BatchAuditLogger
# ===========================================================================


def test_batch_audit_buffers_writes(tmp_path: Path):
    """Entries are buffered, not written immediately."""
    db = tmp_path / "batch.db"
    logger = BatchAuditLogger(db_path=db, batch_size=10, flush_interval=999)

    decision = _make_decision()
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)

    row_id = logger.log("s1", decision, result=result)
    assert row_id == 0  # placeholder ID

    # Should be buffered, not in DB yet
    assert logger.pending == 1
    entries = logger.get_log()
    assert len(entries) == 0

    logger.close()


def test_batch_audit_flush_writes_all(tmp_path: Path):
    """flush() writes all buffered entries in one transaction."""
    db = tmp_path / "batch.db"
    logger = BatchAuditLogger(db_path=db, batch_size=100, flush_interval=999)

    decision = _make_decision()
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)

    for i in range(5):
        logger.log(f"s{i}", decision, result=result)

    assert logger.pending == 5

    count = logger.flush()
    assert count == 5
    assert logger.pending == 0

    entries = logger.get_log()
    assert len(entries) == 5
    logger.close()


def test_batch_audit_auto_flushes_at_batch_size(tmp_path: Path):
    """Auto-flushes when buffer reaches batch_size."""
    db = tmp_path / "batch.db"
    logger = BatchAuditLogger(db_path=db, batch_size=3, flush_interval=999)

    decision = _make_decision()
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)

    # First two entries stay buffered
    logger.log("s1", decision, result=result)
    logger.log("s2", decision, result=result)
    assert logger.pending == 2

    # Third triggers flush
    logger.log("s3", decision, result=result)
    assert logger.pending == 0

    entries = logger.get_log()
    assert len(entries) == 3
    logger.close()


def test_batch_audit_close_flushes_remaining(tmp_path: Path):
    """close() flushes any remaining buffered entries."""
    db = tmp_path / "batch.db"
    logger = BatchAuditLogger(db_path=db, batch_size=100, flush_interval=999)

    decision = _make_decision()
    result = Result(action=decision.action, status=ResultStatus.SUCCESS)

    logger.log("s1", decision, result=result)
    logger.log("s2", decision, result=result)
    assert logger.pending == 2

    logger.close()

    # Re-open to verify data was persisted
    from aegis.runtime.audit import AuditLogger

    reader = AuditLogger(db_path=db)
    entries = reader.get_log()
    assert len(entries) == 2
    reader.close()


def test_batch_audit_flush_empty_is_noop(tmp_path: Path):
    """flush() on empty buffer returns 0 and does not error."""
    db = tmp_path / "batch.db"
    logger = BatchAuditLogger(db_path=db)

    count = logger.flush()
    assert count == 0
    logger.close()


# ===========================================================================
# 5-8. Policy evaluation cache
# ===========================================================================


def test_policy_with_cache_returns_self():
    """with_cache() returns the same Policy instance for chaining."""
    policy = Policy(rules=[PolicyRule(match_type="read", approval=Approval.AUTO, name="r")])
    result = policy.with_cache(128)
    assert result is policy
    assert policy._cache_maxsize == 128


def test_policy_cache_hits():
    """Cached evaluate returns the same decision for repeated calls."""
    policy = Policy(
        rules=[
            PolicyRule(
                match_type="read",
                match_target="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
        ]
    ).with_cache(256)

    action1 = Action("read", "salesforce")
    action2 = Action("read", "salesforce")

    d1 = policy.evaluate(action1)
    d2 = policy.evaluate(action2)

    assert d1.risk_level == d2.risk_level
    assert d1.approval == d2.approval
    assert d1.matched_rule == d2.matched_rule
    # Cache should have one entry
    assert len(policy._cache) == 1


def test_policy_cache_different_keys():
    """Different action keys produce separate cache entries."""
    policy = Policy(
        rules=[PolicyRule(match_type="*", approval=Approval.AUTO, name="all")]
    ).with_cache(256)

    policy.evaluate(Action("read", "crm"))
    policy.evaluate(Action("write", "crm"))
    policy.evaluate(Action("read", "stripe"))

    assert len(policy._cache) == 3


def test_policy_cache_respects_maxsize():
    """Cache evicts oldest entry when maxsize is reached."""
    policy = Policy(
        rules=[PolicyRule(match_type="*", approval=Approval.AUTO, name="all")]
    ).with_cache(maxsize=2)

    policy.evaluate(Action("a", "t1"))
    policy.evaluate(Action("b", "t1"))
    assert len(policy._cache) == 2

    # Third entry should evict the first
    policy.evaluate(Action("c", "t1"))
    assert len(policy._cache) == 2
    assert ("a", "t1", "") not in policy._cache
    assert ("b", "t1", "") in policy._cache
    assert ("c", "t1", "") in policy._cache


def test_policy_cache_skips_conditional_rules():
    """Rules with conditions are NOT cached."""
    policy = Policy(
        rules=[
            PolicyRule(
                match_type="write",
                approval=Approval.APPROVE,
                name="conditional_write",
                conditions={"param_gt": {"count": 100}},
            ),
        ]
    ).with_cache(256)

    policy.evaluate(Action("write", "crm", params={"count": 200}))

    # Should NOT be cached because the rule has conditions
    assert len(policy._cache) == 0


def test_policy_cache_caches_default_rule():
    """Default rule (no conditions) is cached."""
    policy = Policy(
        rules=[
            PolicyRule(match_type="read", approval=Approval.AUTO, name="read_only"),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    ).with_cache(256)

    # "write" does not match any rule -> falls back to default
    policy.evaluate(Action("write", "crm"))
    assert len(policy._cache) == 1
    assert ("write", "crm", "") in policy._cache


def test_policy_clear_cache():
    """clear_cache() empties the cache."""
    policy = Policy(
        rules=[PolicyRule(match_type="*", approval=Approval.AUTO, name="all")]
    ).with_cache(256)

    policy.evaluate(Action("read", "crm"))
    assert len(policy._cache) == 1

    policy.clear_cache()
    assert len(policy._cache) == 0


def test_policy_without_cache_works_normally():
    """Policy without cache (default) works exactly as before."""
    policy = Policy(
        rules=[
            PolicyRule(
                match_type="read",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
        ]
    )

    decision = policy.evaluate(Action("read", "salesforce"))
    assert decision.risk_level == RiskLevel.LOW
    assert decision.approval == Approval.AUTO
    assert decision.matched_rule == "read_auto"

    # No cache active
    assert policy._cache_maxsize == 0
    assert len(policy._cache) == 0


def test_policy_cache_returns_fresh_action():
    """Cached decision uses the new action object, not the original."""
    policy = Policy(
        rules=[PolicyRule(match_type="read", approval=Approval.AUTO, name="r")]
    ).with_cache(256)

    a1 = Action("read", "crm", description="first")
    a2 = Action("read", "crm", description="second")

    d1 = policy.evaluate(a1)
    d2 = policy.evaluate(a2)

    assert d1.action.description == "first"
    assert d2.action.description == "second"
    assert d1.matched_rule == d2.matched_rule
