"""Tests for the natural language policy generator (autopolicy)."""

from __future__ import annotations

from typing import Any

import yaml

from aegis.core.autopolicy import (
    POLICY_GENERATION_PROMPT,
    KeywordPolicyGenerator,
    PolicyGenerator,
    generate_policy,
    generate_policy_yaml,
)
from aegis.core.policy import Approval, Policy

# ======================================================================
# 1. KeywordPolicyGenerator.generate() — action verb patterns
# ======================================================================


class TestBlockPatterns:
    """Test that block/deny keywords produce BLOCK rules."""

    def test_block_deletes(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        delete_rule = rules[0]
        assert delete_rule["match"]["type"] == "delete*"
        assert delete_rule["approval"] == "block"
        assert delete_rule["risk_level"] == "critical"

    def test_deny_drops(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("deny drops")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "block"

    def test_prevent_removals(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("prevent removals")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "block"

    def test_forbid_exports(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("forbid exports")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "block"

    def test_block_all(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block all actions")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        # Wildcard match type omits the "match" key when target is also "*"
        # but the rule still has approval=block and risk_level=critical
        assert rules[0]["approval"] == "block"
        assert rules[0]["risk_level"] == "critical"


class TestAllowPatterns:
    """Test that allow/auto keywords produce AUTO rules."""

    def test_allow_reads(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("allow reads")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        read_rule = rules[0]
        assert read_rule["match"]["type"] == "read*"
        assert read_rule["approval"] == "auto"
        assert read_rule["risk_level"] == "low"

    def test_permit_searches(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("permit searches")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "auto"

    def test_auto_approve_views(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("auto-approve views")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "auto"

    def test_allow_all(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("allow all actions")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        # Wildcard match type may omit "match" key in the dict
        assert rules[0]["approval"] == "auto"


class TestApprovePatterns:
    """Test that approve/review keywords produce APPROVE rules."""

    def test_review_writes(self) -> None:
        """'review' keyword triggers approval for writes."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("review writes")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        write_rule = rules[0]
        assert write_rule["match"]["type"] == "write*"
        assert write_rule["approval"] == "approve"
        assert write_rule["risk_level"] == "medium"

    def test_human_review_for_updates(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("human review for updates")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "approve"

    def test_confirm_sends(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("confirm sends")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["type"] == "send*"
        assert rules[0]["approval"] == "approve"

    def test_review_deploys(self) -> None:
        """'review' keyword triggers approval for deploys."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("review deploys")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["type"] == "deploy*"
        assert rules[0]["approval"] == "approve"
        assert rules[0]["risk_level"] == "high"


# ======================================================================
# 2. Compound descriptions
# ======================================================================


class TestCompoundDescriptions:
    """Test that comma/semicolon-separated descriptions produce multiple rules."""

    def test_block_deletes_allow_reads_review_writes(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes, allow reads, review writes")
        rules = result.get("rules", [])
        assert len(rules) >= 3

        types = {r["match"]["type"] for r in rules}
        assert "delete*" in types
        assert "read*" in types
        assert "write*" in types

        by_type = {r["match"]["type"]: r for r in rules}
        assert by_type["delete*"]["approval"] == "block"
        assert by_type["read*"]["approval"] == "auto"
        assert by_type["write*"]["approval"] == "approve"

    def test_semicolon_separated(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes; allow reads; review writes")
        rules = result.get("rules", [])
        assert len(rules) >= 3

    def test_and_separated(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes and allow reads and review writes")
        rules = result.get("rules", [])
        assert len(rules) >= 3

    def test_deduplication(self) -> None:
        """Same match type should not appear twice (seen_types dedup)."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes, deny deletions")
        rules = result.get("rules", [])
        match_types = [r["match"]["type"] for r in rules]
        assert match_types.count("delete*") == 1


# ======================================================================
# 3. Condition parsing
# ======================================================================


class TestConditionParsing:
    """Test extraction of param_gt, time_after, weekdays conditions."""

    def test_over_dollar_amount(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block transfers over $10000")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "param_gt" in conds
        assert conds["param_gt"] == {"amount": 10000}

    def test_more_than_amount(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes more than $5000")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "param_gt" in conds
        assert conds["param_gt"] == {"amount": 5000}

    def test_exceeding_amount_no_commas(self) -> None:
        """Amounts without commas are parsed correctly with 'exceeding'."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes exceeding 1000000")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "param_gt" in conds
        assert conds["param_gt"] == {"amount": 1000000}

    def test_greater_than_amount(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes greater than 5000")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "param_gt" in conds
        assert conds["param_gt"] == {"amount": 5000}

    def test_after_hours(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes after hours")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "time_after" in conds
        assert conds["time_after"] == "18:00"

    def test_after_specific_time(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes after 21:00")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "time_after" in conds
        assert conds["time_after"] == "21:00"

    def test_weekday_condition(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes on weekday")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "weekdays" in conds
        assert conds["weekdays"] == [1, 2, 3, 4, 5]

    def test_weekend_condition(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes on weekend")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        conds = rules[0].get("conditions", {})
        assert "weekdays" in conds
        assert conds["weekdays"] == [6, 7]


# ======================================================================
# 4. Target detection
# ======================================================================


class TestTargetDetection:
    """Test that target patterns like 'on production' set match target."""

    def test_on_production(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes on production")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["target"] == "prod*"

    def test_in_database(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes in database")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["target"] == "db*"

    def test_on_staging(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("confirm writes on staging")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["target"] == "staging*"

    def test_on_crm(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("allow reads from crm")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["target"] == "crm*"

    def test_on_filesystem(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("confirm writes to filesystem")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["match"]["target"] == "file*"

    def test_no_target_defaults_to_wildcard(self) -> None:
        """When no target is specified, the match dict omits 'target' (wildcard default)."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        # The builder omits the target key when target is "*"
        match = rules[0].get("match", {})
        assert match.get("target", "*") == "*"


# ======================================================================
# 5. generate_policy() — returns Policy object
# ======================================================================


class TestGeneratePolicy:
    """Test the generate_policy() convenience function."""

    def test_returns_policy_object(self) -> None:
        policy = generate_policy("block deletes, allow reads")
        assert isinstance(policy, Policy)

    def test_policy_has_rules(self) -> None:
        policy = generate_policy("block deletes, allow reads, confirm writes")
        assert len(policy.rules) >= 3

    def test_policy_evaluates_correctly(self) -> None:
        policy = generate_policy("block deletes, allow reads")
        from aegis.core.action import Action

        decision = policy.evaluate(Action("delete_record", "db"))
        assert decision.approval == Approval.BLOCK

        decision = policy.evaluate(Action("read_data", "crm"))
        assert decision.approval == Approval.AUTO


# ======================================================================
# 6. generate_policy_yaml() — returns valid YAML string
# ======================================================================


class TestGeneratePolicyYaml:
    """Test the generate_policy_yaml() convenience function."""

    def test_returns_string(self) -> None:
        result = generate_policy_yaml("block deletes")
        assert isinstance(result, str)

    def test_valid_yaml(self) -> None:
        result = generate_policy_yaml("block deletes, allow reads")
        parsed = yaml.safe_load(result)
        assert isinstance(parsed, dict)
        assert "version" in parsed or "defaults" in parsed or "rules" in parsed

    def test_roundtrip_to_policy(self) -> None:
        yaml_str = generate_policy_yaml("block deletes, allow reads")
        parsed = yaml.safe_load(yaml_str)
        policy = Policy.from_dict(parsed)
        assert isinstance(policy, Policy)
        assert len(policy.rules) >= 2


# ======================================================================
# 7. PolicyGenerator protocol
# ======================================================================


class TestPolicyGeneratorProtocol:
    """Test that the PolicyGenerator protocol works with custom implementations."""

    def test_keyword_generator_is_policy_generator(self) -> None:
        gen = KeywordPolicyGenerator()
        assert isinstance(gen, PolicyGenerator)

    def test_custom_generator_via_protocol(self) -> None:
        class MockGenerator:
            def generate(self, description: str) -> dict[str, Any]:
                return {
                    "version": "1",
                    "defaults": {"risk_level": "high", "approval": "block"},
                    "rules": [
                        {
                            "name": "mock_rule",
                            "match": {"type": "mock*"},
                            "risk_level": "critical",
                            "approval": "block",
                        }
                    ],
                }

        gen = MockGenerator()
        assert isinstance(gen, PolicyGenerator)

    def test_generate_policy_with_custom_generator(self) -> None:
        class MockGenerator:
            def generate(self, description: str) -> dict[str, Any]:
                return {
                    "version": "1",
                    "defaults": {"risk_level": "high", "approval": "block"},
                    "rules": [
                        {
                            "name": "custom_rule",
                            "match": {"type": "*"},
                            "risk_level": "critical",
                            "approval": "block",
                        }
                    ],
                }

        policy = generate_policy("anything", generator=MockGenerator())
        assert isinstance(policy, Policy)
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "custom_rule"
        assert policy.rules[0].approval == Approval.BLOCK

    def test_generate_policy_yaml_with_custom_generator(self) -> None:
        class MockGenerator:
            def generate(self, description: str) -> dict[str, Any]:
                return {
                    "version": "1",
                    "rules": [
                        {
                            "name": "yaml_rule",
                            "match": {"type": "test*"},
                            "risk_level": "low",
                            "approval": "auto",
                        }
                    ],
                }

        yaml_str = generate_policy_yaml("irrelevant", generator=MockGenerator())
        parsed = yaml.safe_load(yaml_str)
        assert parsed["rules"][0]["name"] == "yaml_rule"


# ======================================================================
# 8. POLICY_GENERATION_PROMPT
# ======================================================================


class TestPromptTemplate:
    """Test that the LLM prompt template is well-formed."""

    def test_prompt_exists(self) -> None:
        assert isinstance(POLICY_GENERATION_PROMPT, str)
        assert len(POLICY_GENERATION_PROMPT) > 100

    def test_prompt_has_description_placeholder(self) -> None:
        assert "{description}" in POLICY_GENERATION_PROMPT

    def test_prompt_contains_yaml_schema(self) -> None:
        """Prompt includes YAML schema guidance for LLM generators."""
        assert "version" in POLICY_GENERATION_PROMPT
        assert "rules" in POLICY_GENERATION_PROMPT
        assert "risk_level" in POLICY_GENERATION_PROMPT
        assert "approval" in POLICY_GENERATION_PROMPT


# ======================================================================
# 9. Edge cases
# ======================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string_produces_no_rules(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("")
        rules = result.get("rules", [])
        assert len(rules) == 0

    def test_gibberish_input_produces_no_rules(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("xyzzy florp glurp bazzle")
        rules = result.get("rules", [])
        assert len(rules) == 0

    def test_generate_policy_empty_string(self) -> None:
        policy = generate_policy("")
        assert isinstance(policy, Policy)
        assert len(policy.rules) == 0

    def test_result_has_version(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes")
        assert result.get("version") == "1"

    def test_result_has_defaults(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes")
        defaults = result.get("defaults", {})
        assert defaults.get("risk_level") == "medium"
        assert defaults.get("approval") == "approve"

    def test_rule_name_generated_from_match_type(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("block deletes")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["name"] == "delete_block"

    def test_reverse_order_read_safe(self) -> None:
        """'read ... safe' (reversed) should be detected as auto-approve."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("read operations are safe")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "auto"
        assert rules[0]["match"]["type"] == "read*"

    def test_reverse_order_edit_review(self) -> None:
        """'edit ... review' (reversed) should be detected as approve."""
        gen = KeywordPolicyGenerator()
        result = gen.generate("edit actions need review")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "approve"

    def test_case_insensitive(self) -> None:
        gen = KeywordPolicyGenerator()
        result = gen.generate("BLOCK DELETES")
        rules = result.get("rules", [])
        assert len(rules) >= 1
        assert rules[0]["approval"] == "block"
