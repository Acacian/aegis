"""Tests for multi-agent governance features.

Covers agent context on Actions, agent matching in PolicyRule,
scope metadata on Policy, PolicyHierarchy with conflict detection,
agent columns in AuditLogger, and Runtime agent context propagation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.adapters.base import BaseExecutor
from aegis.core.action import Action
from aegis.core.hierarchy import PolicyConflict, PolicyHierarchy
from aegis.core.policy import Approval, Policy, PolicyDecision, PolicyRule
from aegis.core.result import Result, ResultStatus
from aegis.core.risk import RiskLevel
from aegis.runtime.approval import AutoApprovalHandler
from aegis.runtime.audit import AuditLogger
from aegis.runtime.engine import Runtime

# -- Fake executor for runtime tests ------------------------------------


class FakeExecutor(BaseExecutor):
    """Executor that records calls and returns success."""

    def __init__(self) -> None:
        self.executed: list[Action] = []
        self.setup_called = False
        self.teardown_called = False

    async def execute(self, action: Action) -> Result:
        self.executed.append(action)
        return Result(
            action=action,
            status=ResultStatus.SUCCESS,
            data={"fake": True},
            completed_at=datetime.now(UTC),
        )

    async def setup(self) -> None:
        self.setup_called = True

    async def teardown(self) -> None:
        self.teardown_called = True


# ======================================================================
# 1. Action agent context
# ======================================================================


class TestActionAgentContext:
    """Action model carries agent identity and delegation chain info."""

    def test_action_with_agent_fields(self):
        action = Action(
            type="read",
            target="salesforce",
            agent_id="bot-1",
            parent_agent_id="orchestrator",
            chain_id="chain-abc",
            chain_depth=2,
        )
        assert action.agent_id == "bot-1"
        assert action.parent_agent_id == "orchestrator"
        assert action.chain_id == "chain-abc"
        assert action.chain_depth == 2

    def test_action_agent_defaults(self):
        action = Action(type="read", target="test")
        assert action.agent_id == ""
        assert action.parent_agent_id == ""
        assert action.chain_id == ""
        assert action.chain_depth == 0

    def test_str_includes_agent_id_when_present(self):
        action = Action(type="write", target="stripe", agent_id="bot-1")
        result = str(action)
        assert "[agent=bot-1]" in result
        assert "write" in result
        assert "stripe" in result

    def test_str_unchanged_when_agent_id_empty(self):
        action = Action(type="write", target="stripe")
        result = str(action)
        assert "[agent=" not in result
        assert "write" in result
        assert "stripe" in result

    def test_str_with_description_and_agent(self):
        action = Action(
            type="write",
            target="stripe",
            description="Update customer",
            agent_id="bot-2",
        )
        result = str(action)
        assert "Update customer" in result
        assert "[agent=bot-2]" in result


# ======================================================================
# 2. PolicyRule agent matching
# ======================================================================


class TestPolicyRuleAgentMatching:
    """PolicyRule.matches() respects match_agent glob patterns."""

    def test_match_agent_glob_matches(self):
        rule = PolicyRule(match_agent="bot-*")
        assert rule.matches(Action("read", "salesforce", agent_id="bot-1"))

    def test_match_agent_glob_rejects(self):
        rule = PolicyRule(match_agent="bot-*")
        assert not rule.matches(Action("read", "salesforce", agent_id="worker-1"))

    def test_default_match_agent_matches_any(self):
        rule = PolicyRule()  # match_agent defaults to "*"
        assert rule.matches(Action("read", "salesforce", agent_id="bot-1"))
        assert rule.matches(Action("read", "salesforce", agent_id="worker-1"))
        assert rule.matches(Action("read", "salesforce"))  # empty agent_id

    def test_match_agent_combined_with_type_and_target(self):
        rule = PolicyRule(
            match_type="write",
            match_target="salesforce",
            match_agent="bot-*",
        )
        # All three match
        assert rule.matches(Action("write", "salesforce", agent_id="bot-1"))
        # Agent matches, but type doesn't
        assert not rule.matches(Action("read", "salesforce", agent_id="bot-1"))
        # Type and target match, but agent doesn't
        assert not rule.matches(Action("write", "salesforce", agent_id="worker-1"))

    def test_match_agent_exact_string(self):
        rule = PolicyRule(match_agent="bot-alpha")
        assert rule.matches(Action("read", "test", agent_id="bot-alpha"))
        assert not rule.matches(Action("read", "test", agent_id="bot-beta"))

    def test_match_agent_question_mark_pattern(self):
        rule = PolicyRule(match_agent="bot-?")
        assert rule.matches(Action("read", "test", agent_id="bot-1"))
        assert not rule.matches(Action("read", "test", agent_id="bot-10"))


# ======================================================================
# 3. Policy scope metadata
# ======================================================================


class TestPolicyScopeMetadata:
    """Policy carries scope, scope_id, and version metadata."""

    def test_policy_scope_fields(self):
        policy = Policy(scope="team", scope_id="eng-platform", version=3)
        assert policy.scope == "team"
        assert policy.scope_id == "eng-platform"
        assert policy.version == 3

    def test_policy_scope_defaults(self):
        policy = Policy()
        assert policy.scope == "global"
        assert policy.scope_id == ""
        assert policy.version == 1

    def test_merge_preserves_base_scope(self):
        base = Policy(scope="org", scope_id="acme", version=2)
        override = Policy(scope="team", scope_id="eng", version=5)
        combined = base.merge(override)
        assert combined.scope == "org"
        assert combined.scope_id == "acme"
        assert combined.version == 2

    def test_from_dict_parses_scope_fields(self):
        data = {
            "scope": "agent",
            "scope_id": "bot-alpha",
            "version": 4,
            "defaults": {"risk_level": "low", "approval": "auto"},
        }
        policy = Policy.from_dict(data)
        assert policy.scope == "agent"
        assert policy.scope_id == "bot-alpha"
        assert policy.version == 4

    def test_from_dict_scope_defaults(self):
        data = {"defaults": {"risk_level": "low", "approval": "auto"}}
        policy = Policy.from_dict(data)
        assert policy.scope == "global"
        assert policy.scope_id == ""
        assert policy.version == 1


# ======================================================================
# 4. Policy from YAML/dict with agent matching
# ======================================================================


class TestPolicyFromDictAgentMatching:
    """from_dict() parses match.agent and evaluate() respects it."""

    def test_from_dict_parses_match_agent(self):
        data = {
            "rules": [
                {
                    "name": "bot_write_block",
                    "match": {"type": "write", "agent": "bot-*"},
                    "risk_level": "critical",
                    "approval": "block",
                },
            ],
        }
        policy = Policy.from_dict(data)
        assert len(policy.rules) == 1
        assert policy.rules[0].match_agent == "bot-*"

    def test_evaluate_respects_match_agent(self):
        data = {
            "defaults": {"risk_level": "low", "approval": "auto"},
            "rules": [
                {
                    "name": "bot_write_block",
                    "match": {"type": "write", "agent": "bot-*"},
                    "risk_level": "critical",
                    "approval": "block",
                },
            ],
        }
        policy = Policy.from_dict(data)

        # bot-1 writing -> blocked
        decision = policy.evaluate(Action("write", "salesforce", agent_id="bot-1"))
        assert decision.approval == Approval.BLOCK
        assert decision.risk_level == RiskLevel.CRITICAL
        assert decision.matched_rule == "bot_write_block"

        # worker-1 writing -> falls through to default (auto)
        decision = policy.evaluate(Action("write", "salesforce", agent_id="worker-1"))
        assert decision.approval == Approval.AUTO
        assert decision.risk_level == RiskLevel.LOW

    def test_from_dict_default_match_agent_is_wildcard(self):
        data = {
            "rules": [
                {
                    "name": "read_safe",
                    "match": {"type": "read"},
                    "risk_level": "low",
                    "approval": "auto",
                },
            ],
        }
        policy = Policy.from_dict(data)
        assert policy.rules[0].match_agent == "*"


# ======================================================================
# 5. PolicyHierarchy
# ======================================================================


def _org_policy(**kwargs: object) -> Policy:
    """Build a simple org-level policy with a single catch-all rule."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="*",
                match_target="*",
                risk_level=kwargs.get("risk", RiskLevel.MEDIUM),  # type: ignore[arg-type]
                approval=kwargs.get("approval", Approval.APPROVE),  # type: ignore[arg-type]
                name=kwargs.get("name", "org-rule"),  # type: ignore[arg-type]
            )
        ],
        scope="org",
    )


def _team_policy(**kwargs: object) -> Policy:
    """Build a simple team-level policy with a single catch-all rule."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="*",
                match_target="*",
                risk_level=kwargs.get("risk", RiskLevel.LOW),  # type: ignore[arg-type]
                approval=kwargs.get("approval", Approval.AUTO),  # type: ignore[arg-type]
                name=kwargs.get("name", "team-rule"),  # type: ignore[arg-type]
            )
        ],
        scope="team",
    )


def _agent_policy(**kwargs: object) -> Policy:
    """Build a simple agent-level policy with a single catch-all rule."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="*",
                match_target="*",
                risk_level=kwargs.get("risk", RiskLevel.LOW),  # type: ignore[arg-type]
                approval=kwargs.get("approval", Approval.AUTO),  # type: ignore[arg-type]
                name=kwargs.get("name", "agent-rule"),  # type: ignore[arg-type]
            )
        ],
        scope="agent",
    )


class TestPolicyHierarchy:
    """PolicyHierarchy evaluates layered policies, most restrictive wins."""

    def test_evaluate_org_only(self):
        hierarchy = PolicyHierarchy(org=_org_policy(approval=Approval.APPROVE))
        action = Action("write", "salesforce")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.APPROVE
        assert conflicts == []

    def test_evaluate_all_layers_same_decision(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.AUTO),
            team=_team_policy(approval=Approval.AUTO),
            agent=_agent_policy(approval=Approval.AUTO),
        )
        action = Action("read", "salesforce")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.AUTO
        assert conflicts == []

    def test_org_blocks_overrides_agent_allow(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.BLOCK, risk=RiskLevel.CRITICAL),
            agent=_agent_policy(approval=Approval.AUTO, risk=RiskLevel.LOW),
        )
        action = Action("delete", "production-db")
        decision, conflicts = hierarchy.evaluate(action)
        # Most restrictive wins: block
        assert decision.approval == Approval.BLOCK
        assert decision.risk_level == RiskLevel.CRITICAL

    def test_org_allows_but_team_requires_approval(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.AUTO, risk=RiskLevel.LOW),
            team=_team_policy(approval=Approval.APPROVE, risk=RiskLevel.MEDIUM),
        )
        action = Action("write", "salesforce")
        decision, conflicts = hierarchy.evaluate(action)
        # Most restrictive: approve > auto
        assert decision.approval == Approval.APPROVE
        assert decision.risk_level == RiskLevel.MEDIUM

    def test_conflict_detected_when_layers_disagree(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.BLOCK),
            team=_team_policy(approval=Approval.AUTO),
        )
        action = Action("write", "salesforce")
        decision, conflicts = hierarchy.evaluate(action)
        assert len(conflicts) == 1
        conflict = conflicts[0]
        assert isinstance(conflict, PolicyConflict)
        assert conflict.resolution == "most_restrictive"
        assert "org" in conflict.layer_decisions
        assert "team" in conflict.layer_decisions
        assert conflict.resolved.approval == Approval.BLOCK

    def test_no_conflict_when_layers_agree(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.APPROVE),
            team=_team_policy(approval=Approval.APPROVE),
            agent=_agent_policy(approval=Approval.APPROVE),
        )
        action = Action("write", "salesforce")
        _, conflicts = hierarchy.evaluate(action)
        assert conflicts == []

    def test_flatten_merges_all_layers(self):
        org = Policy(
            rules=[PolicyRule(match_type="delete", approval=Approval.BLOCK, name="org-block")],
            scope="org",
        )
        team = Policy(
            rules=[PolicyRule(match_type="write", approval=Approval.APPROVE, name="team-approve")],
            scope="team",
        )
        agent = Policy(
            rules=[PolicyRule(match_type="read", approval=Approval.AUTO, name="agent-auto")],
            scope="agent",
        )
        hierarchy = PolicyHierarchy(org=org, team=team, agent=agent)
        flat = hierarchy.flatten()

        # Org rules come first, then team, then agent
        assert len(flat.rules) == 3
        assert flat.rules[0].name == "org-block"
        assert flat.rules[1].name == "team-approve"
        assert flat.rules[2].name == "agent-auto"

    def test_evaluate_no_policies_default_decision(self):
        hierarchy = PolicyHierarchy()
        action = Action("read", "salesforce")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.BLOCK
        assert decision.risk_level == RiskLevel.CRITICAL
        assert decision.matched_rule == "<no-policy-configured>"
        assert conflicts == []

    def test_empty_hierarchy_flatten(self):
        hierarchy = PolicyHierarchy()
        flat = hierarchy.flatten()
        assert flat.rules == []
        assert flat.default_risk_level == RiskLevel.MEDIUM
        assert flat.default_approval == Approval.BLOCK

    def test_three_layer_conflict_block_wins_over_auto_and_approve(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.AUTO),
            team=_team_policy(approval=Approval.APPROVE),
            agent=_agent_policy(approval=Approval.BLOCK),
        )
        action = Action("write", "salesforce")
        decision, conflicts = hierarchy.evaluate(action)
        assert decision.approval == Approval.BLOCK
        assert len(conflicts) == 1

    def test_risk_level_most_restrictive(self):
        hierarchy = PolicyHierarchy(
            org=_org_policy(approval=Approval.AUTO, risk=RiskLevel.LOW),
            team=_team_policy(approval=Approval.AUTO, risk=RiskLevel.CRITICAL),
        )
        action = Action("read", "salesforce")
        decision, _ = hierarchy.evaluate(action)
        assert decision.risk_level == RiskLevel.CRITICAL


# ======================================================================
# 6. AuditLogger agent context
# ======================================================================


def _make_agent_decision(
    agent_id: str = "",
    parent_agent_id: str = "",
    chain_id: str = "",
    chain_depth: int = 0,
    action_type: str = "read",
    target: str = "salesforce",
) -> PolicyDecision:
    return PolicyDecision(
        action=Action(
            type=action_type,
            target=target,
            agent_id=agent_id,
            parent_agent_id=parent_agent_id,
            chain_id=chain_id,
            chain_depth=chain_depth,
        ),
        risk_level=RiskLevel.LOW,
        approval=Approval.AUTO,
        matched_rule="test_rule",
    )


class TestAuditLoggerAgentContext:
    """AuditLogger persists and queries agent context columns."""

    def test_log_writes_agent_fields(self, tmp_path: Path):
        logger = AuditLogger(db_path=tmp_path / "test.db")
        decision = _make_agent_decision(
            agent_id="bot-1",
            parent_agent_id="orchestrator",
            chain_id="chain-xyz",
            chain_depth=3,
        )
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("session-1", decision, result=result)

        entries = logger.get_log()
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "bot-1"
        assert entries[0]["parent_agent_id"] == "orchestrator"
        assert entries[0]["chain_id"] == "chain-xyz"
        assert entries[0]["chain_depth"] == 3
        logger.close()

    def test_get_log_filters_by_agent_id(self, tmp_path: Path):
        logger = AuditLogger(db_path=tmp_path / "test.db")

        d1 = _make_agent_decision(agent_id="bot-1", action_type="read")
        d2 = _make_agent_decision(agent_id="bot-2", action_type="write")

        logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        logger.log("s1", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))

        bot1_entries = logger.get_log(agent_id="bot-1")
        assert len(bot1_entries) == 1
        assert bot1_entries[0]["action_type"] == "read"

        bot2_entries = logger.get_log(agent_id="bot-2")
        assert len(bot2_entries) == 1
        assert bot2_entries[0]["action_type"] == "write"
        logger.close()

    def test_get_log_filters_by_chain_id(self, tmp_path: Path):
        logger = AuditLogger(db_path=tmp_path / "test.db")

        d1 = _make_agent_decision(chain_id="chain-a", action_type="read")
        d2 = _make_agent_decision(chain_id="chain-b", action_type="write")
        d3 = _make_agent_decision(chain_id="chain-a", action_type="delete")

        logger.log("s1", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        logger.log("s1", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))
        logger.log("s1", d3, result=Result(action=d3.action, status=ResultStatus.SUCCESS))

        chain_a = logger.get_log(chain_id="chain-a")
        assert len(chain_a) == 2
        assert {e["action_type"] for e in chain_a} == {"read", "delete"}
        logger.close()

    def test_agent_columns_defaults_when_not_set(self, tmp_path: Path):
        logger = AuditLogger(db_path=tmp_path / "test.db")
        decision = _make_agent_decision()  # all agent fields empty/zero
        result = Result(action=decision.action, status=ResultStatus.SUCCESS)
        logger.log("s1", decision, result=result)

        entries = logger.get_log()
        assert len(entries) == 1
        # Empty strings are stored as None in SQLite
        assert entries[0]["agent_id"] is None
        assert entries[0]["parent_agent_id"] is None
        assert entries[0]["chain_id"] is None
        assert entries[0]["chain_depth"] == 0
        logger.close()

    def test_combined_filters_agent_and_session(self, tmp_path: Path):
        logger = AuditLogger(db_path=tmp_path / "test.db")

        d1 = _make_agent_decision(agent_id="bot-1")
        d2 = _make_agent_decision(agent_id="bot-1")
        d3 = _make_agent_decision(agent_id="bot-2")

        logger.log("s-a", d1, result=Result(action=d1.action, status=ResultStatus.SUCCESS))
        logger.log("s-b", d2, result=Result(action=d2.action, status=ResultStatus.SUCCESS))
        logger.log("s-a", d3, result=Result(action=d3.action, status=ResultStatus.SUCCESS))

        # Filter by both session and agent
        entries = logger.get_log(session_id="s-a", agent_id="bot-1")
        assert len(entries) == 1
        logger.close()


# ======================================================================
# 7. Runtime agent context
# ======================================================================


class TestRuntimeAgentContext:
    """Runtime auto-populates agent_id into planned Actions."""

    @pytest.mark.asyncio
    async def test_runtime_agent_id_populates_actions(self, tmp_path: Path):
        executor = FakeExecutor()
        runtime = Runtime(
            executor=executor,
            policy=Policy(
                rules=[PolicyRule(match_type="*", approval=Approval.AUTO)],
            ),
            approval_handler=AutoApprovalHandler(),
            audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
            session_id="test-session",
            agent_id="runtime-bot",
        )

        action = Action("read", "salesforce")
        assert action.agent_id == ""  # no agent_id initially

        plan = runtime.plan([action])
        # After planning, the action in the decision should have agent_id
        assert plan.decisions[0].action.agent_id == "runtime-bot"

    @pytest.mark.asyncio
    async def test_runtime_without_agent_id_leaves_actions_unchanged(self, tmp_path: Path):
        executor = FakeExecutor()
        runtime = Runtime(
            executor=executor,
            policy=Policy(
                rules=[PolicyRule(match_type="*", approval=Approval.AUTO)],
            ),
            approval_handler=AutoApprovalHandler(),
            audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
            session_id="test-session",
        )

        action = Action("read", "salesforce")
        plan = runtime.plan([action])
        assert plan.decisions[0].action.agent_id == ""

    @pytest.mark.asyncio
    async def test_runtime_does_not_overwrite_existing_agent_id(self, tmp_path: Path):
        executor = FakeExecutor()
        runtime = Runtime(
            executor=executor,
            policy=Policy(
                rules=[PolicyRule(match_type="*", approval=Approval.AUTO)],
            ),
            approval_handler=AutoApprovalHandler(),
            audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
            session_id="test-session",
            agent_id="runtime-bot",
        )

        action = Action("read", "salesforce", agent_id="original-bot")
        plan = runtime.plan([action])
        # Action already had agent_id, should not be overwritten
        assert plan.decisions[0].action.agent_id == "original-bot"

    def test_parent_session_id_stored(self, tmp_path: Path):
        runtime = Runtime(
            executor=FakeExecutor(),
            policy=Policy(),
            approval_handler=AutoApprovalHandler(),
            audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
            parent_session_id="parent-session-123",
        )
        assert runtime.parent_session_id == "parent-session-123"

    def test_parent_session_id_defaults_empty(self, tmp_path: Path):
        runtime = Runtime(
            executor=FakeExecutor(),
            policy=Policy(),
            approval_handler=AutoApprovalHandler(),
            audit_logger=AuditLogger(db_path=tmp_path / "test.db"),
        )
        assert runtime.parent_session_id == ""

    @pytest.mark.asyncio
    async def test_runtime_agent_id_flows_to_audit(self, tmp_path: Path):
        executor = FakeExecutor()
        audit = AuditLogger(db_path=tmp_path / "test.db")
        runtime = Runtime(
            executor=executor,
            policy=Policy(
                rules=[PolicyRule(match_type="*", approval=Approval.AUTO)],
            ),
            approval_handler=AutoApprovalHandler(),
            audit_logger=audit,
            session_id="test-session",
            agent_id="runtime-bot",
        )

        plan = runtime.plan([Action("read", "salesforce")])
        await runtime.execute(plan)

        entries = audit.get_log(session_id="test-session")
        assert len(entries) == 1
        assert entries[0]["agent_id"] == "runtime-bot"


# ======================================================================
# 8. Exports
# ======================================================================


class TestExports:
    """PolicyHierarchy and PolicyConflict are importable from the aegis package."""

    def test_policy_hierarchy_importable(self):
        from aegis import PolicyHierarchy as PH

        assert PH is PolicyHierarchy

    def test_policy_conflict_importable(self):
        from aegis import PolicyConflict as PC

        assert PC is PolicyConflict

    def test_hierarchy_in_all(self):
        import aegis

        assert "PolicyHierarchy" in aegis.__all__
        assert "PolicyConflict" in aegis.__all__
