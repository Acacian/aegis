"""Tests for the semantic condition engine."""

from __future__ import annotations

import textwrap
from pathlib import Path

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel
from aegis.core.semantic import (
    SEMANTIC_CATEGORIES,
    KeywordSemanticEvaluator,
    SemanticEvaluator,
    evaluate_semantic_condition,
)

# ---------------------------------------------------------------------------
# Tier 1: Predefined category tests
# ---------------------------------------------------------------------------


class TestSemanticCategories:
    """Verify all predefined categories are defined and non-empty."""

    def test_destructive_category_exists(self) -> None:
        assert "destructive" in SEMANTIC_CATEGORIES
        assert len(SEMANTIC_CATEGORIES["destructive"]) > 0

    def test_data_exposure_category_exists(self) -> None:
        assert "data_exposure" in SEMANTIC_CATEGORIES
        assert len(SEMANTIC_CATEGORIES["data_exposure"]) > 0

    def test_privileged_category_exists(self) -> None:
        assert "privileged" in SEMANTIC_CATEGORIES
        assert len(SEMANTIC_CATEGORIES["privileged"]) > 0

    def test_financial_category_exists(self) -> None:
        assert "financial" in SEMANTIC_CATEGORIES
        assert len(SEMANTIC_CATEGORIES["financial"]) > 0

    def test_pii_category_exists(self) -> None:
        assert "pii" in SEMANTIC_CATEGORIES
        assert len(SEMANTIC_CATEGORIES["pii"]) > 0


class TestDestructiveCategory:
    """Match actions against the 'destructive' category."""

    def test_delete_action_matches(self) -> None:
        action = Action("delete", "database")
        assert evaluate_semantic_condition("destructive", action) is True

    def test_drop_in_description(self) -> None:
        action = Action("execute", "database", description="drop table users")
        assert evaluate_semantic_condition("destructive", action) is True

    def test_remove_in_params(self) -> None:
        action = Action("execute", "system", params={"operation": "remove"})
        assert evaluate_semantic_condition("destructive", action) is True

    def test_kill_in_type(self) -> None:
        action = Action("kill", "process")
        assert evaluate_semantic_condition("destructive", action) is True

    def test_terminate_in_target(self) -> None:
        action = Action("run", "terminate")
        assert evaluate_semantic_condition("destructive", action) is True

    def test_truncate_in_type(self) -> None:
        action = Action("truncate", "logs")
        assert evaluate_semantic_condition("destructive", action) is True

    def test_purge_in_params_key(self) -> None:
        action = Action("run", "system", params={"purge": True})
        assert evaluate_semantic_condition("destructive", action) is True

    def test_safe_action_no_match(self) -> None:
        action = Action("read", "database", description="select all users")
        assert evaluate_semantic_condition("destructive", action) is False


class TestDataExposureCategory:
    """Match actions against the 'data_exposure' category."""

    def test_export_action(self) -> None:
        action = Action("export", "crm")
        assert evaluate_semantic_condition("data_exposure", action) is True

    def test_download_in_type(self) -> None:
        action = Action("download", "files")
        assert evaluate_semantic_condition("data_exposure", action) is True

    def test_share_in_description(self) -> None:
        action = Action("run", "tool", description="share report with external user")
        assert evaluate_semantic_condition("data_exposure", action) is True

    def test_email_in_params(self) -> None:
        action = Action("send", "notification", params={"channel": "email"})
        assert evaluate_semantic_condition("data_exposure", action) is True

    def test_upload_in_type(self) -> None:
        action = Action("upload", "s3")
        assert evaluate_semantic_condition("data_exposure", action) is True

    def test_transfer_in_description(self) -> None:
        action = Action("run", "api", description="transfer data to partner")
        assert evaluate_semantic_condition("data_exposure", action) is True

    def test_no_match_for_read(self) -> None:
        action = Action("read", "database")
        assert evaluate_semantic_condition("data_exposure", action) is False


class TestPrivilegedCategory:
    """Match actions against the 'privileged' category."""

    def test_admin_in_type(self) -> None:
        action = Action("admin", "settings")
        assert evaluate_semantic_condition("privileged", action) is True

    def test_sudo_in_description(self) -> None:
        action = Action("run", "command", description="sudo apt install")
        assert evaluate_semantic_condition("privileged", action) is True

    def test_escalate_in_params(self) -> None:
        action = Action("update", "role", params={"action": "escalate"})
        assert evaluate_semantic_condition("privileged", action) is True

    def test_bypass_in_description(self) -> None:
        action = Action("run", "system", description="bypass auth check")
        assert evaluate_semantic_condition("privileged", action) is True

    def test_no_match_for_normal(self) -> None:
        action = Action("read", "report")
        assert evaluate_semantic_condition("privileged", action) is False


class TestFinancialCategory:
    """Match actions against the 'financial' category."""

    def test_payment_in_type(self) -> None:
        action = Action("payment", "stripe")
        assert evaluate_semantic_condition("financial", action) is True

    def test_refund_in_description(self) -> None:
        action = Action("create", "transaction", description="issue refund")
        assert evaluate_semantic_condition("financial", action) is True

    def test_charge_in_params(self) -> None:
        action = Action("execute", "billing", params={"type": "charge"})
        assert evaluate_semantic_condition("financial", action) is True

    def test_withdraw_in_type(self) -> None:
        action = Action("withdraw", "bank_account")
        assert evaluate_semantic_condition("financial", action) is True

    def test_no_match_for_read(self) -> None:
        action = Action("read", "report")
        assert evaluate_semantic_condition("financial", action) is False


class TestPiiCategory:
    """Match actions against the 'pii' category."""

    def test_email_in_params_key(self) -> None:
        action = Action("read", "users", params={"email": "alice@example.com"})
        assert evaluate_semantic_condition("pii", action) is True

    def test_ssn_in_params_key(self) -> None:
        action = Action("read", "hr", params={"ssn": "123-45-6789"})
        assert evaluate_semantic_condition("pii", action) is True

    def test_phone_in_description(self) -> None:
        action = Action("export", "contacts", description="export phone numbers")
        assert evaluate_semantic_condition("pii", action) is True

    def test_credit_card_in_params_key(self) -> None:
        action = Action("read", "payments", params={"credit_card": "4111..."})
        assert evaluate_semantic_condition("pii", action) is True

    def test_passport_in_description(self) -> None:
        action = Action("read", "identity", description="retrieve passport data")
        assert evaluate_semantic_condition("pii", action) is True

    def test_no_match_for_generic(self) -> None:
        action = Action("read", "logs", params={"level": "info"})
        assert evaluate_semantic_condition("pii", action) is False


# ---------------------------------------------------------------------------
# Tier 1: Custom keyword matching
# ---------------------------------------------------------------------------


class TestCustomKeywords:
    """Free-form semantic condition strings (not predefined categories)."""

    def test_single_keyword_match_in_type(self) -> None:
        action = Action("deploy", "production")
        assert evaluate_semantic_condition("deploy", action) is True

    def test_single_keyword_match_in_target(self) -> None:
        action = Action("run", "production")
        assert evaluate_semantic_condition("production", action) is True

    def test_multiple_keywords_any_match(self) -> None:
        action = Action("delete", "users")
        # "data exposure or PII leak" -> keywords: {data, exposure, leak} + pii category
        assert evaluate_semantic_condition("data exposure or PII leak", action) is False
        # "leak" is a keyword from the condition
        action2 = Action("run", "tool", description="potential data leak detected")
        assert evaluate_semantic_condition("data exposure or PII leak", action2) is True

    def test_stop_words_filtered(self) -> None:
        """Words like 'or', 'and', 'the' should be stripped."""
        action = Action("export", "data")
        # "data exposure or PII leak" -> keywords: {data, exposure, pii, leak}
        assert evaluate_semantic_condition("data exposure or PII leak", action) is True

    def test_case_insensitive_matching(self) -> None:
        action = Action("DELETE", "DATABASE")
        assert evaluate_semantic_condition("delete", action) is True

    def test_condition_case_insensitive(self) -> None:
        action = Action("delete", "database")
        assert evaluate_semantic_condition("DELETE", action) is True

    def test_category_case_insensitive(self) -> None:
        action = Action("delete", "database")
        assert evaluate_semantic_condition("DESTRUCTIVE", action) is True

    def test_mixed_category_and_keywords(self) -> None:
        """When a token matches a category name, its keywords are expanded."""
        # "pii" is a category, "export" is not (but matches data_exposure partially)
        action = Action("run", "tool", params={"email": "test@example.com"})
        assert evaluate_semantic_condition("pii or export", action) is True

    def test_keyword_in_param_value(self) -> None:
        action = Action("run", "tool", params={"command": "deploy to production"})
        assert evaluate_semantic_condition("production", action) is True

    def test_keyword_in_param_key(self) -> None:
        action = Action("run", "tool", params={"deploy_target": "us-east"})
        assert evaluate_semantic_condition("deploy", action) is True

    def test_empty_condition_returns_false(self) -> None:
        action = Action("read", "database")
        assert evaluate_semantic_condition("", action) is False

    def test_whitespace_only_condition_returns_false(self) -> None:
        action = Action("read", "database")
        assert evaluate_semantic_condition("   ", action) is False

    def test_no_match_returns_false(self) -> None:
        action = Action("read", "database", description="select query")
        assert evaluate_semantic_condition("deploy production", action) is False

    def test_underscore_in_keywords(self) -> None:
        """Underscored terms like 'credit_card' should be tokenized properly."""
        action = Action("read", "payments", params={"credit_card": "4111"})
        assert evaluate_semantic_condition("credit_card", action) is True


# ---------------------------------------------------------------------------
# KeywordSemanticEvaluator unit tests
# ---------------------------------------------------------------------------


class TestKeywordSemanticEvaluator:
    """Direct tests on the evaluator class."""

    def test_implements_protocol(self) -> None:
        evaluator = KeywordSemanticEvaluator()
        assert isinstance(evaluator, SemanticEvaluator)

    def test_resolve_known_category(self) -> None:
        keywords = KeywordSemanticEvaluator._resolve_keywords("destructive")
        assert "delete" in keywords
        assert "destroy" in keywords

    def test_resolve_custom_string(self) -> None:
        keywords = KeywordSemanticEvaluator._resolve_keywords("deploy production")
        assert "deploy" in keywords
        assert "production" in keywords

    def test_resolve_mixed_category_and_custom(self) -> None:
        keywords = KeywordSemanticEvaluator._resolve_keywords("destructive or deploy")
        # "destructive" expands to category keywords, "deploy" is kept
        assert "delete" in keywords
        assert "deploy" in keywords
        # "or" is a stop word, should not be in keywords
        assert "or" not in keywords


# ---------------------------------------------------------------------------
# Tier 2: Pluggable evaluator interface
# ---------------------------------------------------------------------------


class _AlwaysTrueEvaluator:
    """Test evaluator that always returns True."""

    def evaluate(self, condition: str, action: Action) -> bool:
        return True


class _AlwaysFalseEvaluator:
    """Test evaluator that always returns False."""

    def evaluate(self, condition: str, action: Action) -> bool:
        return False


class _RecordingEvaluator:
    """Test evaluator that records calls and returns a fixed result."""

    def __init__(self, result: bool = True) -> None:
        self.calls: list[tuple[str, Action]] = []
        self.result = result

    def evaluate(self, condition: str, action: Action) -> bool:
        self.calls.append((condition, action))
        return self.result


class TestPluggableEvaluator:
    """Tests for the Tier 2 pluggable evaluator interface."""

    def test_custom_evaluator_replaces_default(self) -> None:
        evaluator = _AlwaysTrueEvaluator()
        action = Action("read", "database")
        # "zzz_nonexistent" would never match keyword matcher
        assert evaluate_semantic_condition("zzz_nonexistent", action, evaluator=evaluator) is True

    def test_custom_false_evaluator(self) -> None:
        evaluator = _AlwaysFalseEvaluator()
        action = Action("delete", "database")
        # "destructive" would match keyword matcher, but custom says False
        assert evaluate_semantic_condition("destructive", action, evaluator=evaluator) is False

    def test_recording_evaluator_receives_correct_args(self) -> None:
        evaluator = _RecordingEvaluator(result=True)
        action = Action("delete", "database")
        evaluate_semantic_condition("test condition", action, evaluator=evaluator)
        assert len(evaluator.calls) == 1
        assert evaluator.calls[0] == ("test condition", action)

    def test_protocol_isinstance_check(self) -> None:
        """Custom evaluators should satisfy the Protocol check."""
        assert isinstance(_AlwaysTrueEvaluator(), SemanticEvaluator)
        assert isinstance(_AlwaysFalseEvaluator(), SemanticEvaluator)
        assert isinstance(_RecordingEvaluator(), SemanticEvaluator)


# ---------------------------------------------------------------------------
# Integration: PolicyRule with semantic conditions
# ---------------------------------------------------------------------------


class TestPolicyRuleSemanticCondition:
    """Test semantic conditions wired into PolicyRule.matches()."""

    def test_rule_with_semantic_destructive(self) -> None:
        rule = PolicyRule(
            match_type="*",
            match_target="*",
            approval=Approval.BLOCK,
            name="block_destructive",
            conditions={"semantic": "destructive"},
        )
        assert rule.matches(Action("delete", "database"))
        assert rule.matches(Action("destroy", "system"))
        assert not rule.matches(Action("read", "database"))

    def test_rule_with_semantic_data_exposure(self) -> None:
        rule = PolicyRule(
            match_type="*",
            match_target="*",
            approval=Approval.BLOCK,
            name="block_data_exposure",
            conditions={"semantic": "data_exposure"},
        )
        assert rule.matches(Action("export", "crm"))
        assert not rule.matches(Action("read", "crm"))

    def test_rule_with_semantic_and_other_conditions(self) -> None:
        """Semantic + param conditions should both need to pass (AND logic)."""
        rule = PolicyRule(
            match_type="*",
            match_target="*",
            approval=Approval.BLOCK,
            name="bulk_destructive",
            conditions={
                "semantic": "destructive",
                "param_gt": {"count": 100},
            },
        )
        # Both match
        assert rule.matches(Action("delete", "db", params={"count": 200}))
        # Semantic matches, param fails
        assert not rule.matches(Action("delete", "db", params={"count": 10}))
        # Param matches, semantic fails
        assert not rule.matches(Action("read", "db", params={"count": 200}))
        # Neither matches
        assert not rule.matches(Action("read", "db", params={"count": 10}))

    def test_rule_with_glob_and_semantic(self) -> None:
        """Glob pattern + semantic condition."""
        rule = PolicyRule(
            match_type="bulk_*",
            match_target="*",
            approval=Approval.BLOCK,
            name="block_bulk_destructive",
            conditions={"semantic": "destructive"},
        )
        # Glob matches, semantic matches (destroy in description)
        assert rule.matches(Action("bulk_operation", "db", description="destroy all records"))
        # Glob matches, semantic does not
        assert not rule.matches(Action("bulk_read", "db", description="read data"))
        # Glob does not match
        assert not rule.matches(Action("delete", "db"))

    def test_rule_with_custom_evaluator(self) -> None:
        """Semantic condition with pluggable evaluator via PolicyRule."""
        rule = PolicyRule(
            match_type="*",
            match_target="*",
            conditions={"semantic": "anything"},
        )
        always_true = _AlwaysTrueEvaluator()
        always_false = _AlwaysFalseEvaluator()

        assert rule.matches(Action("read", "db"), semantic_evaluator=always_true)
        assert not rule.matches(Action("read", "db"), semantic_evaluator=always_false)

    def test_rule_without_semantic_unchanged(self) -> None:
        """Rules without semantic conditions should behave exactly as before."""
        rule = PolicyRule(
            match_type="read",
            match_target="*",
            approval=Approval.AUTO,
            conditions={"param_eq": {"status": "active"}},
        )
        assert rule.matches(Action("read", "db", params={"status": "active"}))
        assert not rule.matches(Action("read", "db", params={"status": "inactive"}))
        assert not rule.matches(Action("write", "db", params={"status": "active"}))


# ---------------------------------------------------------------------------
# Integration: Full Policy with semantic conditions
# ---------------------------------------------------------------------------


class TestPolicySemanticIntegration:
    """End-to-end tests with Policy.evaluate() and semantic conditions."""

    def test_policy_from_dict_with_semantic(self) -> None:
        policy = Policy.from_dict(
            {
                "version": "1",
                "defaults": {"risk_level": "low", "approval": "auto"},
                "rules": [
                    {
                        "name": "block_destructive",
                        "match": {"type": "*"},
                        "conditions": {"semantic": "destructive"},
                        "risk_level": "critical",
                        "approval": "block",
                    },
                ],
            }
        )
        d1 = policy.evaluate(Action("delete", "database"))
        assert d1.approval == Approval.BLOCK
        assert d1.risk_level == RiskLevel.CRITICAL
        assert d1.matched_rule == "block_destructive"

        d2 = policy.evaluate(Action("read", "database"))
        assert d2.approval == Approval.AUTO
        assert d2.matched_rule == "<default>"

    def test_policy_from_dict_semantic_with_custom_keywords(self) -> None:
        policy = Policy.from_dict(
            {
                "version": "1",
                "defaults": {"risk_level": "low", "approval": "auto"},
                "rules": [
                    {
                        "name": "no_data_exposure",
                        "match": {"type": "*"},
                        "conditions": {"semantic": "data exposure or PII leak"},
                        "risk_level": "critical",
                        "approval": "block",
                    },
                ],
            }
        )
        # "exposure" is a keyword; action description contains "exposure"
        d1 = policy.evaluate(Action("run", "crm", description="potential data exposure via email"))
        assert d1.approval == Approval.BLOCK
        assert d1.matched_rule == "no_data_exposure"

        d2 = policy.evaluate(Action("read", "logs"))
        assert d2.approval == Approval.AUTO

    def test_policy_from_yaml_with_semantic(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            version: "1"
            defaults:
              risk_level: low
              approval: auto
            rules:
              - name: block_destructive
                match: { type: "*" }
                conditions:
                  semantic: "destructive"
                risk_level: critical
                approval: block
              - name: block_data_exposure
                match: { type: "*" }
                conditions:
                  semantic: "data_exposure"
                risk_level: high
                approval: approve
        """)
        policy_file = tmp_path / "semantic.yaml"
        policy_file.write_text(yaml_content)

        policy = Policy.from_yaml(policy_file)

        d1 = policy.evaluate(Action("delete", "database"))
        assert d1.approval == Approval.BLOCK
        assert d1.matched_rule == "block_destructive"

        d2 = policy.evaluate(Action("export", "crm"))
        assert d2.approval == Approval.APPROVE
        assert d2.matched_rule == "block_data_exposure"

        d3 = policy.evaluate(Action("read", "database"))
        assert d3.approval == Approval.AUTO

    def test_policy_with_custom_evaluator(self) -> None:
        """Policy.from_dict with a pluggable evaluator."""
        recorder = _RecordingEvaluator(result=True)
        policy = Policy.from_dict(
            {
                "version": "1",
                "defaults": {"risk_level": "low", "approval": "auto"},
                "rules": [
                    {
                        "name": "semantic_rule",
                        "match": {"type": "*"},
                        "conditions": {"semantic": "custom condition"},
                        "risk_level": "high",
                        "approval": "block",
                    },
                ],
            },
            semantic_evaluator=recorder,
        )

        action = Action("read", "database")
        d = policy.evaluate(action)
        assert d.approval == Approval.BLOCK
        assert len(recorder.calls) == 1
        assert recorder.calls[0] == ("custom condition", action)

    def test_policy_from_yaml_with_custom_evaluator(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            version: "1"
            rules:
              - name: llm_check
                match: { type: "*" }
                conditions:
                  semantic: "involves sensitive financial operation"
                risk_level: critical
                approval: block
        """)
        f = tmp_path / "llm_policy.yaml"
        f.write_text(yaml_content)

        recorder = _RecordingEvaluator(result=False)
        policy = Policy.from_yaml(f, semantic_evaluator=recorder)

        d = policy.evaluate(Action("transfer", "bank"))
        # Custom evaluator returns False, so semantic condition fails -> default
        assert d.matched_rule == "<default>"
        assert len(recorder.calls) == 1

    def test_semantic_rules_do_not_break_caching(self) -> None:
        """Rules with semantic conditions should not be cached."""
        policy = Policy.from_dict(
            {
                "version": "1",
                "defaults": {"risk_level": "low", "approval": "auto"},
                "rules": [
                    {
                        "name": "semantic_rule",
                        "match": {"type": "*"},
                        "conditions": {"semantic": "destructive"},
                        "risk_level": "critical",
                        "approval": "block",
                    },
                ],
            }
        ).with_cache(maxsize=64)

        d1 = policy.evaluate(Action("delete", "db"))
        assert d1.approval == Approval.BLOCK
        # Should not be cached because it has conditions
        assert len(policy._cache) == 0

    def test_semantic_condition_with_first_match_wins(self) -> None:
        """First matching semantic rule should win."""
        policy = Policy.from_dict(
            {
                "version": "1",
                "rules": [
                    {
                        "name": "block_destructive",
                        "match": {"type": "*"},
                        "conditions": {"semantic": "destructive"},
                        "approval": "block",
                    },
                    {
                        "name": "allow_all",
                        "match": {"type": "*"},
                        "approval": "auto",
                    },
                ],
            }
        )
        d1 = policy.evaluate(Action("delete", "db"))
        assert d1.matched_rule == "block_destructive"

        d2 = policy.evaluate(Action("read", "db"))
        assert d2.matched_rule == "allow_all"

    def test_merge_preserves_semantic_evaluator(self) -> None:
        """Policy.merge should preserve the semantic evaluator."""
        recorder = _RecordingEvaluator(result=True)
        base = Policy(
            rules=[],
            semantic_evaluator=recorder,
        )
        override = Policy(
            rules=[
                PolicyRule(
                    match_type="*",
                    conditions={"semantic": "test"},
                    name="sem_rule",
                ),
            ],
        )
        merged = base.merge(override)
        assert merged.semantic_evaluator is recorder

        d = merged.evaluate(Action("read", "db"))
        assert d.matched_rule == "sem_rule"
        assert len(recorder.calls) == 1

    def test_merge_picks_override_evaluator_when_base_none(self) -> None:
        recorder = _RecordingEvaluator(result=True)
        base = Policy(rules=[])
        override = Policy(
            rules=[
                PolicyRule(
                    match_type="*",
                    conditions={"semantic": "test"},
                    name="sem_rule",
                ),
            ],
            semantic_evaluator=recorder,
        )
        merged = base.merge(override)
        assert merged.semantic_evaluator is recorder


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestSemanticEdgeCases:
    """Edge cases and boundary conditions."""

    def test_non_string_param_values_ignored(self) -> None:
        """Non-string param values should not crash the matcher."""
        action = Action("run", "tool", params={"count": 42, "flag": True, "data": None})
        # Should not raise, just not match
        assert evaluate_semantic_condition("destructive", action) is False

    def test_nested_dict_params_not_recursed(self) -> None:
        """Nested dicts in params are not recursed (only top-level keys/values)."""
        action = Action("run", "tool", params={"config": {"action": "delete"}})
        # "delete" is inside a nested dict, not a string value at top level
        assert evaluate_semantic_condition("destructive", action) is False

    def test_list_param_values_not_matched(self) -> None:
        """List param values are not strings, should be skipped."""
        action = Action("run", "tool", params={"tags": ["delete", "admin"]})
        assert evaluate_semantic_condition("destructive", action) is False

    def test_empty_action_fields(self) -> None:
        """Action with empty type/target/description should not crash."""
        action = Action("", "", description="", params={})
        assert evaluate_semantic_condition("destructive", action) is False

    def test_only_stop_words_returns_false(self) -> None:
        """Condition with only stop words results in no keywords."""
        action = Action("delete", "database")
        assert evaluate_semantic_condition("or and the", action) is False

    def test_special_characters_in_condition(self) -> None:
        """Special characters should be handled gracefully."""
        action = Action("read", "database")
        # Regex-special characters should not crash
        assert evaluate_semantic_condition("foo.bar*baz()", action) is False

    def test_very_long_condition_string(self) -> None:
        """Long condition strings should not crash."""
        condition = " ".join(f"keyword_{i}" for i in range(100))
        action = Action("keyword_50", "target")
        assert evaluate_semantic_condition(condition, action) is True

    def test_semantic_condition_with_numeric_tokens(self) -> None:
        """Numeric tokens should be preserved."""
        action = Action("level3", "system")
        assert evaluate_semantic_condition("level3 access", action) is True
