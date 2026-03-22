"""Tests for the Policy-as-Code SDK builder."""

from __future__ import annotations

import pytest
import yaml

from aegis.core.action import Action
from aegis.core.builder import PolicyBuilder, RuleBuilder
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# ======================================================================
# 1. Basic builder usage
# ======================================================================


class TestBasicBuilder:
    """Basic PolicyBuilder construction."""

    def test_empty_builder_creates_default_policy(self) -> None:
        policy = PolicyBuilder().build()
        assert policy.default_risk_level == RiskLevel.MEDIUM
        assert policy.default_approval == Approval.APPROVE
        assert policy.rules == []

    def test_single_rule(self) -> None:
        policy = PolicyBuilder().rule("r1").match(type="read").risk("low").approve_auto().build()
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "r1"
        assert policy.rules[0].match_type == "read"
        assert policy.rules[0].risk_level == RiskLevel.LOW
        assert policy.rules[0].approval == Approval.AUTO

    def test_multiple_rules(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="read*")
            .risk("low")
            .approve_auto()
            .rule("r2")
            .match(type="write*")
            .risk("medium")
            .approve_human()
            .rule("r3")
            .match(type="delete*")
            .risk("critical")
            .block()
            .build()
        )
        assert len(policy.rules) == 3
        assert [r.name for r in policy.rules] == ["r1", "r2", "r3"]

    def test_rule_order_preserved(self) -> None:
        """Rules should be in insertion order (first-match-wins)."""
        builder = PolicyBuilder()
        current: PolicyBuilder | RuleBuilder = builder
        for i in range(10):
            current = builder.rule(f"r{i}").match(type=f"type{i}").approve_auto()
        policy = current.build()
        assert [r.name for r in policy.rules] == [f"r{i}" for i in range(10)]


# ======================================================================
# 2. Defaults
# ======================================================================


class TestDefaults:
    """Test default risk level and approval."""

    def test_custom_defaults(self) -> None:
        policy = PolicyBuilder().defaults(risk_level="high", approval="block").build()
        assert policy.default_risk_level == RiskLevel.HIGH
        assert policy.default_approval == Approval.BLOCK

    def test_defaults_risk_only(self) -> None:
        policy = PolicyBuilder().defaults(risk_level="low").build()
        assert policy.default_risk_level == RiskLevel.LOW
        assert policy.default_approval == Approval.APPROVE  # unchanged

    def test_defaults_approval_only(self) -> None:
        policy = PolicyBuilder().defaults(approval="auto").build()
        assert policy.default_risk_level == RiskLevel.MEDIUM  # unchanged
        assert policy.default_approval == Approval.AUTO

    def test_invalid_default_risk_level(self) -> None:
        with pytest.raises(ValueError, match="Invalid default risk level"):
            PolicyBuilder().defaults(risk_level="extreme")

    def test_invalid_default_approval(self) -> None:
        with pytest.raises(ValueError, match="Invalid default approval"):
            PolicyBuilder().defaults(approval="maybe")

    def test_defaults_case_insensitive(self) -> None:
        policy = PolicyBuilder().defaults(risk_level="HIGH", approval="Auto").build()
        assert policy.default_risk_level == RiskLevel.HIGH
        assert policy.default_approval == Approval.AUTO

    def test_defaults_applied_to_unmatched_actions(self) -> None:
        policy = (
            PolicyBuilder()
            .defaults(risk_level="critical", approval="block")
            .rule("read_only")
            .match(type="read")
            .risk("low")
            .approve_auto()
            .build()
        )
        decision = policy.evaluate(Action("write", "anything"))
        assert decision.risk_level == RiskLevel.CRITICAL
        assert decision.approval == Approval.BLOCK

    def test_rule_inherits_default_risk_when_not_set(self) -> None:
        """Rules without explicit risk inherit the builder default."""
        policy = (
            PolicyBuilder()
            .defaults(risk_level="high")
            .rule("r1")
            .match(type="read")
            .approve_auto()
            .build()
        )
        assert policy.rules[0].risk_level == RiskLevel.HIGH

    def test_rule_inherits_default_approval_when_not_set(self) -> None:
        """Rules without explicit approval inherit the builder default."""
        policy = (
            PolicyBuilder()
            .defaults(approval="block")
            .rule("r1")
            .match(type="read")
            .risk("low")
            .build()
        )
        assert policy.rules[0].approval == Approval.BLOCK


# ======================================================================
# 3. Chainable methods
# ======================================================================


class TestChainableMethods:
    """Every setter should return the builder for chaining."""

    def test_match_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1")
        result = rb.match(type="read")
        assert isinstance(result, RuleBuilder)

    def test_risk_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1").match(type="read")
        result = rb.risk("low")
        assert isinstance(result, RuleBuilder)

    def test_approve_auto_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1").match(type="read")
        result = rb.approve_auto()
        assert isinstance(result, RuleBuilder)

    def test_approve_human_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1").match(type="read")
        result = rb.approve_human()
        assert isinstance(result, RuleBuilder)

    def test_block_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1").match(type="read")
        result = rb.block()
        assert isinstance(result, RuleBuilder)

    def test_when_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1").match(type="read")
        result = rb.when(semantic="destructive")
        assert isinstance(result, RuleBuilder)

    def test_description_returns_rule_builder(self) -> None:
        rb = PolicyBuilder().rule("r1").match(type="read")
        result = rb.description("test desc")
        assert isinstance(result, RuleBuilder)

    def test_defaults_returns_policy_builder(self) -> None:
        result = PolicyBuilder().defaults(risk_level="low")
        assert isinstance(result, PolicyBuilder)

    def test_scope_returns_policy_builder(self) -> None:
        result = PolicyBuilder().scope("team", scope_id="eng")
        assert isinstance(result, PolicyBuilder)

    def test_version_returns_policy_builder(self) -> None:
        result = PolicyBuilder().version(2)
        assert isinstance(result, PolicyBuilder)


# ======================================================================
# 4. Match patterns
# ======================================================================


class TestMatchPatterns:
    """Test glob pattern matching via the builder."""

    def test_exact_type_match(self) -> None:
        policy = PolicyBuilder().rule("r1").match(type="read").risk("low").approve_auto().build()
        d = policy.evaluate(Action("read", "any"))
        assert d.matched_rule == "r1"

    def test_wildcard_type_match(self) -> None:
        policy = PolicyBuilder().rule("r1").match(type="read*").risk("low").approve_auto().build()
        d = policy.evaluate(Action("read_all", "any"))
        assert d.matched_rule == "r1"

    def test_target_match(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="*", target="crm")
            .risk("low")
            .approve_auto()
            .build()
        )
        assert policy.evaluate(Action("read", "crm")).matched_rule == "r1"
        assert policy.evaluate(Action("read", "other")).matched_rule == "<default>"

    def test_agent_match(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="*", agent="agent_a")
            .risk("low")
            .approve_auto()
            .build()
        )
        assert policy.rules[0].match_agent == "agent_a"

    def test_combined_type_and_target(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="write*", target="prod*")
            .risk("high")
            .approve_human()
            .build()
        )
        d1 = policy.evaluate(Action("write_record", "production"))
        assert d1.matched_rule == "r1"
        d2 = policy.evaluate(Action("write_record", "staging"))
        assert d2.matched_rule == "<default>"


# ======================================================================
# 5. from_existing
# ======================================================================


class TestFromExisting:
    """Test seeding a builder from an existing Policy."""

    def test_from_existing_preserves_rules(self) -> None:
        original = Policy(
            rules=[
                PolicyRule(
                    match_type="read",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                    name="read_auto",
                ),
            ],
            default_risk_level=RiskLevel.HIGH,
            default_approval=Approval.BLOCK,
        )
        rebuilt = PolicyBuilder().from_existing(original).build()
        assert len(rebuilt.rules) == 1
        assert rebuilt.rules[0].name == "read_auto"
        assert rebuilt.rules[0].match_type == "read"
        assert rebuilt.rules[0].risk_level == RiskLevel.LOW
        assert rebuilt.rules[0].approval == Approval.AUTO

    def test_from_existing_preserves_defaults(self) -> None:
        original = Policy(
            default_risk_level=RiskLevel.CRITICAL,
            default_approval=Approval.BLOCK,
        )
        rebuilt = PolicyBuilder().from_existing(original).build()
        assert rebuilt.default_risk_level == RiskLevel.CRITICAL
        assert rebuilt.default_approval == Approval.BLOCK

    def test_from_existing_preserves_scope(self) -> None:
        original = Policy(scope="team", scope_id="eng", version=3)
        rebuilt = PolicyBuilder().from_existing(original).build()
        assert rebuilt.scope == "team"
        assert rebuilt.scope_id == "eng"
        assert rebuilt.version == 3

    def test_from_existing_preserves_conditions(self) -> None:
        original = Policy(
            rules=[
                PolicyRule(
                    match_type="delete*",
                    name="del",
                    conditions={"semantic": "destructive"},
                ),
            ]
        )
        rebuilt = PolicyBuilder().from_existing(original).build()
        assert rebuilt.rules[0].conditions == {"semantic": "destructive"}

    def test_from_existing_then_add_rule(self) -> None:
        original = Policy(
            rules=[
                PolicyRule(match_type="read", name="r1", risk_level=RiskLevel.LOW),
            ]
        )
        policy = (
            PolicyBuilder()
            .from_existing(original)
            .rule("r2")
            .match(type="write*")
            .risk("high")
            .approve_human()
            .build()
        )
        assert len(policy.rules) == 2
        assert policy.rules[0].name == "r1"
        assert policy.rules[1].name == "r2"

    def test_from_existing_clears_previous_rules(self) -> None:
        builder = PolicyBuilder().rule("old").match(type="x").risk("low").approve_auto()
        original = Policy(
            rules=[PolicyRule(match_type="new", name="new_rule")],
        )
        policy = builder.from_existing(original).build()
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "new_rule"


# ======================================================================
# 6. Merge
# ======================================================================


class TestMerge:
    """Test merging two builders."""

    def test_merge_appends_rules(self) -> None:
        b1 = PolicyBuilder().rule("r1").match(type="read").risk("low").approve_auto()
        b2 = PolicyBuilder().rule("r2").match(type="write").risk("high").approve_human()
        policy = b1.merge(b2).build()
        assert len(policy.rules) == 2
        assert policy.rules[0].name == "r1"
        assert policy.rules[1].name == "r2"

    def test_merge_keeps_base_defaults(self) -> None:
        b1 = PolicyBuilder().defaults(risk_level="critical", approval="block")
        b2 = PolicyBuilder().defaults(risk_level="low", approval="auto")
        policy = b1.merge(b2).build()
        assert policy.default_risk_level == RiskLevel.CRITICAL
        assert policy.default_approval == Approval.BLOCK

    def test_merge_preserves_conditions(self) -> None:
        b1 = PolicyBuilder()
        b2 = (
            PolicyBuilder()
            .rule("r1")
            .match(type="del*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
        )
        policy = b1.merge(b2).build()
        assert policy.rules[0].conditions == {"semantic": "destructive"}

    def test_merge_multiple_builders(self) -> None:
        b1 = PolicyBuilder().rule("r1").match(type="a").risk("low").approve_auto()
        b2 = PolicyBuilder().rule("r2").match(type="b").risk("medium").approve_human()
        b3 = PolicyBuilder().rule("r3").match(type="c").risk("high").block()
        policy = b1.merge(b2).merge(b3).build()
        assert len(policy.rules) == 3

    def test_merge_via_rule_builder(self) -> None:
        """Merge can be called from a RuleBuilder (delegates to parent)."""
        b2 = PolicyBuilder().rule("r2").match(type="b").risk("low").approve_auto()
        policy = (
            PolicyBuilder().rule("r1").match(type="a").risk("low").approve_auto().merge(b2).build()
        )
        assert len(policy.rules) == 2


# ======================================================================
# 7. to_yaml / to_dict
# ======================================================================


class TestExport:
    """Test YAML and dict export."""

    def test_to_dict_basic(self) -> None:
        d = (
            PolicyBuilder()
            .defaults(risk_level="low", approval="auto")
            .rule("r1")
            .match(type="read")
            .risk("low")
            .approve_auto()
            .to_dict()
        )
        assert d["version"] == "1"
        assert d["defaults"]["risk_level"] == "low"
        assert d["defaults"]["approval"] == "auto"
        assert len(d["rules"]) == 1
        assert d["rules"][0]["name"] == "r1"
        assert d["rules"][0]["match"]["type"] == "read"

    def test_to_dict_omits_wildcard_match(self) -> None:
        """Wildcard-only matches should not appear in the dict."""
        d = PolicyBuilder().rule("r1").match(type="read").risk("low").approve_auto().to_dict()
        assert "target" not in d["rules"][0].get("match", {})

    def test_to_dict_includes_conditions(self) -> None:
        d = (
            PolicyBuilder()
            .rule("r1")
            .match(type="del*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
            .to_dict()
        )
        assert d["rules"][0]["conditions"] == {"semantic": "destructive"}

    def test_to_dict_includes_description(self) -> None:
        d = (
            PolicyBuilder()
            .rule("r1")
            .match(type="read")
            .risk("low")
            .approve_auto()
            .description("Read ops are safe")
            .to_dict()
        )
        assert d["rules"][0]["description"] == "Read ops are safe"

    def test_to_dict_includes_scope(self) -> None:
        d = PolicyBuilder().scope("team", scope_id="eng-team").to_dict()
        assert d["scope"] == "team"
        assert d["scope_id"] == "eng-team"

    def test_to_yaml_is_valid_yaml(self) -> None:
        y = (
            PolicyBuilder()
            .defaults(risk_level="low")
            .rule("r1")
            .match(type="read")
            .risk("low")
            .approve_auto()
            .to_yaml()
        )
        parsed = yaml.safe_load(y)
        assert parsed["defaults"]["risk_level"] == "low"
        assert len(parsed["rules"]) == 1

    def test_to_yaml_roundtrip_via_policy(self) -> None:
        """YAML from builder should be loadable by Policy.from_dict."""
        y = (
            PolicyBuilder()
            .defaults(risk_level="high", approval="block")
            .rule("r1")
            .match(type="write*", target="prod")
            .risk("critical")
            .block()
            .to_yaml()
        )
        policy = Policy.from_dict(yaml.safe_load(y))
        assert policy.default_risk_level == RiskLevel.HIGH
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "r1"
        assert policy.rules[0].risk_level == RiskLevel.CRITICAL


# ======================================================================
# 8. Validation errors
# ======================================================================


class TestValidation:
    """Test that build() raises on invalid configurations."""

    def test_duplicate_rule_names(self) -> None:
        with pytest.raises(ValueError, match="Duplicate rule name.*'r1'"):
            (
                PolicyBuilder()
                .rule("r1")
                .match(type="a")
                .risk("low")
                .approve_auto()
                .rule("r1")
                .match(type="b")
                .risk("low")
                .approve_auto()
                .build()
            )

    def test_invalid_risk_level_in_rule(self) -> None:
        with pytest.raises(ValueError, match="Invalid risk level"):
            (PolicyBuilder().rule("r1").match(type="a").risk("extreme"))

    def test_missing_match_pattern(self) -> None:
        with pytest.raises(ValueError, match="no match pattern"):
            (PolicyBuilder().rule("r1").risk("low").approve_auto().build())

    def test_validation_on_to_dict(self) -> None:
        """Validation also runs on to_dict()."""
        with pytest.raises(ValueError, match="Duplicate rule name"):
            (PolicyBuilder().rule("r1").match(type="a").rule("r1").match(type="b").to_dict())

    def test_validation_on_to_yaml(self) -> None:
        """Validation also runs on to_yaml()."""
        with pytest.raises(ValueError, match="Duplicate rule name"):
            (PolicyBuilder().rule("r1").match(type="a").rule("r1").match(type="b").to_yaml())


# ======================================================================
# 9. Semantic conditions
# ======================================================================


class TestSemanticConditions:
    """Test semantic condition support in the builder."""

    def test_semantic_condition_stored(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="delete*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
            .build()
        )
        assert policy.rules[0].conditions == {"semantic": "destructive"}

    def test_semantic_condition_matches_action(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
            .build()
        )
        # "delete" is in the "destructive" semantic category
        d = policy.evaluate(Action("delete_all", "users"))
        assert d.matched_rule == "r1"
        assert d.approval == Approval.BLOCK

    def test_semantic_condition_no_match(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
            .build()
        )
        # "read" is not in "destructive" category
        d = policy.evaluate(Action("read", "users"))
        assert d.matched_rule == "<default>"

    def test_multiple_conditions_combined(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
            .when(param_gt={"count": 10})
            .build()
        )
        # Both conditions must match
        d1 = policy.evaluate(Action("delete_records", "db", params={"count": 50}))
        assert d1.matched_rule == "r1"

        d2 = policy.evaluate(Action("delete_records", "db", params={"count": 5}))
        assert d2.matched_rule == "<default>"


# ======================================================================
# 10. Complex multi-rule policies
# ======================================================================


class TestComplexPolicies:
    """Test complex realistic policy scenarios."""

    def test_full_example_from_spec(self) -> None:
        policy = (
            PolicyBuilder()
            .defaults(risk_level="medium", approval="approve")
            .rule("read_auto")
            .match(type="read*")
            .risk("low")
            .approve_auto()
            .rule("write_approve")
            .match(type="write*", target="crm")
            .risk("medium")
            .approve_human()
            .rule("delete_block")
            .match(type="delete*")
            .risk("critical")
            .block()
            .when(semantic="destructive")
            .build()
        )
        assert len(policy.rules) == 3

        # read -> auto
        d = policy.evaluate(Action("read_records", "crm"))
        assert d.approval == Approval.AUTO
        assert d.risk_level == RiskLevel.LOW

        # write to crm -> approve
        d = policy.evaluate(Action("write_record", "crm"))
        assert d.approval == Approval.APPROVE
        assert d.risk_level == RiskLevel.MEDIUM

        # delete -> block (matches semantic)
        d = policy.evaluate(Action("delete_all", "crm"))
        assert d.approval == Approval.BLOCK
        assert d.risk_level == RiskLevel.CRITICAL

    def test_first_match_wins(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("specific")
            .match(type="read", target="secret")
            .risk("critical")
            .block()
            .rule("general")
            .match(type="read*")
            .risk("low")
            .approve_auto()
            .build()
        )
        # Specific rule wins for exact match
        d = policy.evaluate(Action("read", "secret"))
        assert d.matched_rule == "specific"
        assert d.approval == Approval.BLOCK

        # General rule wins for non-matching target
        d = policy.evaluate(Action("read_all", "public"))
        assert d.matched_rule == "general"
        assert d.approval == Approval.AUTO

    def test_agent_scoped_rules(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("trusted_agent")
            .match(type="*", agent="trusted_bot")
            .risk("low")
            .approve_auto()
            .rule("untrusted_default")
            .match(type="*")
            .risk("high")
            .approve_human()
            .build()
        )
        d1 = policy.evaluate(Action("write", "db", agent_id="trusted_bot"))
        assert d1.matched_rule == "trusted_agent"
        assert d1.approval == Approval.AUTO

        d2 = policy.evaluate(Action("write", "db", agent_id="random"))
        assert d2.matched_rule == "untrusted_default"
        assert d2.approval == Approval.APPROVE

    def test_scope_and_version(self) -> None:
        policy = (
            PolicyBuilder()
            .scope("team", scope_id="engineering")
            .version(5)
            .rule("r1")
            .match(type="deploy*")
            .risk("high")
            .approve_human()
            .build()
        )
        assert policy.scope == "team"
        assert policy.scope_id == "engineering"
        assert policy.version == 5


# ======================================================================
# 11. Engine integration — built policies work with evaluate()
# ======================================================================


class TestEngineIntegration:
    """Verify that builder-produced policies work correctly with the engine."""

    def test_evaluate_returns_policy_decision(self) -> None:
        policy = PolicyBuilder().rule("r1").match(type="read").risk("low").approve_auto().build()
        from aegis.core.policy import PolicyDecision

        d = policy.evaluate(Action("read", "anything"))
        assert isinstance(d, PolicyDecision)
        assert d.is_allowed is True

    def test_block_is_not_allowed(self) -> None:
        policy = PolicyBuilder().rule("r1").match(type="nuke*").risk("critical").block().build()
        d = policy.evaluate(Action("nuke_db", "prod"))
        assert d.is_allowed is False

    def test_built_policy_merge_with_existing(self) -> None:
        """Builder policy can be merged with other Policy objects."""
        built = PolicyBuilder().rule("r1").match(type="read").risk("low").approve_auto().build()
        other = Policy(
            rules=[
                PolicyRule(
                    match_type="write",
                    name="r2",
                    risk_level=RiskLevel.HIGH,
                    approval=Approval.APPROVE,
                ),
            ]
        )
        merged = built.merge(other)
        assert len(merged.rules) == 2

    def test_built_policy_with_cache(self) -> None:
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="read")
            .risk("low")
            .approve_auto()
            .build()
            .with_cache(128)
        )
        d1 = policy.evaluate(Action("read", "x"))
        d2 = policy.evaluate(Action("read", "x"))
        assert d1.approval == d2.approval
        assert d1.risk_level == d2.risk_level

    def test_fallback_to_defaults(self) -> None:
        policy = (
            PolicyBuilder()
            .defaults(risk_level="high", approval="block")
            .rule("r1")
            .match(type="read")
            .risk("low")
            .approve_auto()
            .build()
        )
        d = policy.evaluate(Action("unknown_action", "unknown_target"))
        assert d.risk_level == RiskLevel.HIGH
        assert d.approval == Approval.BLOCK
        assert d.matched_rule == "<default>"

    def test_builder_dict_roundtrip_via_from_dict(self) -> None:
        """to_dict -> Policy.from_dict produces equivalent behavior."""
        builder = (
            PolicyBuilder()
            .defaults(risk_level="low", approval="auto")
            .rule("r1")
            .match(type="read*")
            .risk("low")
            .approve_auto()
            .rule("r2")
            .match(type="write*")
            .risk("high")
            .approve_human()
        )
        policy_direct = builder.build()
        policy_roundtrip = Policy.from_dict(builder.to_dict())

        action_read = Action("read_file", "docs")
        action_write = Action("write_record", "db")

        d1 = policy_direct.evaluate(action_read)
        d2 = policy_roundtrip.evaluate(action_read)
        assert d1.approval == d2.approval
        assert d1.risk_level == d2.risk_level

        d3 = policy_direct.evaluate(action_write)
        d4 = policy_roundtrip.evaluate(action_write)
        assert d3.approval == d4.approval
        assert d3.risk_level == d4.risk_level


# ======================================================================
# 12. Edge cases
# ======================================================================


class TestEdgeCases:
    """Edge cases and regression-prevention tests."""

    def test_when_merges_conditions(self) -> None:
        """Multiple .when() calls should merge, not overwrite."""
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="*")
            .when(semantic="destructive")
            .when(param_gt={"count": 10})
            .risk("critical")
            .block()
            .build()
        )
        conds = policy.rules[0].conditions
        assert "semantic" in conds
        assert "param_gt" in conds

    def test_empty_builder_to_dict(self) -> None:
        d = PolicyBuilder().to_dict()
        assert d["version"] == "1"
        assert "rules" not in d  # no rules to export

    def test_empty_builder_to_yaml(self) -> None:
        y = PolicyBuilder().to_yaml()
        parsed = yaml.safe_load(y)
        assert "rules" not in parsed

    def test_risk_level_whitespace_stripped(self) -> None:
        policy = PolicyBuilder().rule("r1").match(type="x").risk("  high  ").approve_auto().build()
        assert policy.rules[0].risk_level == RiskLevel.HIGH

    def test_defaults_called_from_rule_builder(self) -> None:
        """Calling .defaults() from a RuleBuilder delegates to parent."""
        policy = (
            PolicyBuilder()
            .rule("r1")
            .match(type="a")
            .risk("low")
            .approve_auto()
            .defaults(risk_level="critical")
            .build()
        )
        assert policy.default_risk_level == RiskLevel.CRITICAL
