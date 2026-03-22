"""Tests for the Policy Testing Framework."""

from __future__ import annotations

import textwrap
import threading
from pathlib import Path

import pytest

from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.policy_test_suite import (
    CaseResult,
    PolicyTestCase,
    PolicyTestResult,
    PolicyTestSuite,
    RegressionChange,
)
from aegis.core.risk import RiskLevel

# -- Helpers ---------------------------------------------------------


def _simple_policy() -> Policy:
    """Policy with read=auto, write=approve, delete=block."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="read",
                match_target="*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="read_auto",
            ),
            PolicyRule(
                match_type="write",
                match_target="*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name="write_approve",
            ),
            PolicyRule(
                match_type="delete",
                match_target="*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ],
        default_risk_level=RiskLevel.HIGH,
        default_approval=Approval.APPROVE,
    )


def _strict_policy() -> Policy:
    """Stricter variant: write->block, delete->block."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="read",
                match_target="*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name="read_approve",
            ),
            PolicyRule(
                match_type="write",
                match_target="*",
                risk_level=RiskLevel.HIGH,
                approval=Approval.BLOCK,
                name="write_block",
            ),
            PolicyRule(
                match_type="delete",
                match_target="*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="delete_block",
            ),
        ],
        default_risk_level=RiskLevel.CRITICAL,
        default_approval=Approval.BLOCK,
    )


# ================================================================
# PolicyTestCase
# ================================================================


class TestPolicyTestCaseCreation:
    """Tests for PolicyTestCase construction and validation."""

    def test_valid_auto_decision(self) -> None:
        case = PolicyTestCase(
            action={"type": "read", "target": "crm"},
            expected_decision="auto",
        )
        assert case.expected_decision == "auto"

    def test_valid_approve_decision(self) -> None:
        case = PolicyTestCase(
            action={"type": "write", "target": "crm"},
            expected_decision="approve",
        )
        assert case.expected_decision == "approve"

    def test_valid_block_decision(self) -> None:
        case = PolicyTestCase(
            action={"type": "delete", "target": "crm"},
            expected_decision="block",
        )
        assert case.expected_decision == "block"

    def test_invalid_decision_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            PolicyTestCase(
                action={"type": "x", "target": "y"},
                expected_decision="deny",
            )

    def test_valid_risk_levels(self) -> None:
        for level in ("low", "medium", "high", "critical"):
            case = PolicyTestCase(
                action={"type": "r", "target": "t"},
                expected_decision="auto",
                expected_risk_level=level,
            )
            assert case.expected_risk_level == level

    def test_invalid_risk_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid"):
            PolicyTestCase(
                action={"type": "x", "target": "y"},
                expected_decision="auto",
                expected_risk_level="extreme",
            )

    def test_empty_risk_level_allowed(self) -> None:
        case = PolicyTestCase(
            action={"type": "r", "target": "t"},
            expected_decision="auto",
            expected_risk_level="",
        )
        assert case.expected_risk_level == ""

    def test_description_preserved(self) -> None:
        case = PolicyTestCase(
            action={"type": "r", "target": "t"},
            expected_decision="auto",
            description="my test",
        )
        assert case.description == "my test"


# ================================================================
# PolicyTestSuite — add_test
# ================================================================


class TestAddTest:
    """Tests for PolicyTestSuite.add_test."""

    def test_add_single(self) -> None:
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "crm"},
                expected_decision="auto",
            )
        )
        assert len(suite) == 1

    def test_add_multiple(self) -> None:
        suite = PolicyTestSuite()
        for i in range(5):
            suite.add_test(
                PolicyTestCase(
                    action={"type": f"t{i}", "target": "x"},
                    expected_decision="auto",
                )
            )
        assert len(suite) == 5

    def test_add_wrong_type_raises(self) -> None:
        suite = PolicyTestSuite()
        with pytest.raises(TypeError, match="PolicyTestCase"):
            suite.add_test({"action": {}})  # type: ignore[arg-type]

    def test_cases_snapshot(self) -> None:
        suite = PolicyTestSuite()
        case = PolicyTestCase(
            action={"type": "r", "target": "t"},
            expected_decision="auto",
        )
        suite.add_test(case)
        snap = suite.cases
        assert snap == [case]
        # Mutating the snapshot does not affect the suite.
        snap.clear()
        assert len(suite) == 1


# ================================================================
# PolicyTestSuite — add_test_from_dict
# ================================================================


class TestAddTestFromDict:
    """Tests for PolicyTestSuite.add_test_from_dict."""

    def test_minimal_dict(self) -> None:
        suite = PolicyTestSuite()
        suite.add_test_from_dict(
            {
                "action": {"type": "read", "target": "crm"},
                "expected_decision": "auto",
            }
        )
        assert len(suite) == 1
        assert suite.cases[0].expected_decision == "auto"

    def test_full_dict(self) -> None:
        suite = PolicyTestSuite()
        suite.add_test_from_dict(
            {
                "action": {"type": "write", "target": "db"},
                "expected_decision": "approve",
                "expected_risk_level": "medium",
                "description": "Write to DB",
            }
        )
        c = suite.cases[0]
        assert c.expected_risk_level == "medium"
        assert c.description == "Write to DB"

    def test_non_dict_raises(self) -> None:
        suite = PolicyTestSuite()
        with pytest.raises(TypeError, match="dict"):
            suite.add_test_from_dict("bad")  # type: ignore[arg-type]

    def test_non_dict_action_raises(self) -> None:
        suite = PolicyTestSuite()
        with pytest.raises(TypeError, match="action"):
            suite.add_test_from_dict(
                {
                    "action": "not_a_dict",
                    "expected_decision": "auto",
                }
            )

    def test_defaults_when_keys_missing(self) -> None:
        suite = PolicyTestSuite()
        suite.add_test_from_dict({"action": {"type": "x", "target": "y"}})
        c = suite.cases[0]
        assert c.expected_decision == "approve"
        assert c.expected_risk_level == ""
        assert c.description == ""


# ================================================================
# PolicyTestSuite — run
# ================================================================


class TestRun:
    """Tests for PolicyTestSuite.run."""

    def test_all_pass(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "crm"},
                expected_decision="auto",
                expected_risk_level="low",
            )
        )
        suite.add_test(
            PolicyTestCase(
                action={"type": "write", "target": "db"},
                expected_decision="approve",
                expected_risk_level="medium",
            )
        )
        result = suite.run(policy)
        assert result.total == 2
        assert result.passed == 2
        assert result.failed == 0
        assert result.all_passed

    def test_decision_mismatch_fails(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "crm"},
                expected_decision="block",
            )
        )
        result = suite.run(policy)
        assert result.failed == 1
        assert not result.all_passed
        assert "decision" in result.results[0].message

    def test_risk_mismatch_fails(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "crm"},
                expected_decision="auto",
                expected_risk_level="critical",
            )
        )
        result = suite.run(policy)
        assert result.failed == 1
        assert "risk_level" in result.results[0].message

    def test_both_mismatch_shows_both(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "crm"},
                expected_decision="block",
                expected_risk_level="critical",
            )
        )
        result = suite.run(policy)
        assert result.failed == 1
        msg = result.results[0].message
        assert "decision" in msg
        assert "risk_level" in msg

    def test_empty_suite(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        result = suite.run(policy)
        assert result.total == 0
        assert result.passed == 0
        assert result.failed == 0
        assert result.all_passed

    def test_mixed_pass_and_fail(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="block",
            )
        )
        result = suite.run(policy)
        assert result.total == 2
        assert result.passed == 1
        assert result.failed == 1

    def test_default_behaviour(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={
                    "type": "unknown",
                    "target": "unknown",
                },
                expected_decision="approve",
                expected_risk_level="high",
            )
        )
        result = suite.run(policy)
        assert result.all_passed

    def test_pass_rate_full(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        result = suite.run(policy)
        assert result.pass_rate == 1.0

    def test_pass_rate_partial(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="block",
            )
        )
        result = suite.run(policy)
        assert result.pass_rate == 0.5

    def test_pass_rate_empty(self) -> None:
        result = PolicyTestSuite().run(_simple_policy())
        assert result.pass_rate == 1.0

    def test_result_has_executed_at(self) -> None:
        result = PolicyTestSuite().run(_simple_policy())
        assert result.executed_at  # non-empty ISO string

    def test_case_result_actual_values(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "delete", "target": "x"},
                expected_decision="block",
                expected_risk_level="critical",
            )
        )
        result = suite.run(policy)
        cr = result.results[0]
        assert cr.actual_decision == "block"
        assert cr.actual_risk_level == "critical"
        assert cr.passed

    def test_action_params_forwarded(self) -> None:
        """Params in the action dict are forwarded to Action."""
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="query",
                    match_target="*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                    name="query",
                ),
            ],
        )
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={
                    "type": "query",
                    "target": "db",
                    "params": {"limit": 10},
                },
                expected_decision="auto",
            )
        )
        result = suite.run(policy)
        assert result.all_passed

    def test_agent_id_forwarded(self) -> None:
        """agent_id in the action dict reaches the policy."""
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="read",
                    match_target="*",
                    match_agent="bot-*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                    name="bot_read",
                ),
            ],
            default_approval=Approval.BLOCK,
        )
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={
                    "type": "read",
                    "target": "x",
                    "agent_id": "bot-1",
                },
                expected_decision="auto",
            )
        )
        result = suite.run(policy)
        assert result.all_passed


# ================================================================
# PolicyTestSuite — run_regression
# ================================================================


class TestRunRegression:
    """Tests for PolicyTestSuite.run_regression."""

    def test_no_regressions(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        result = suite.run_regression(policy, policy)
        assert len(result.regression_changes) == 0

    def test_detects_decision_change(self) -> None:
        old = _simple_policy()
        new = _strict_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "write", "target": "x"},
                expected_decision="approve",
            )
        )
        result = suite.run_regression(old, new)
        assert len(result.regression_changes) == 1
        rc = result.regression_changes[0]
        assert rc.old_decision == "approve"
        assert rc.new_decision == "block"

    def test_detects_risk_level_change(self) -> None:
        old = _simple_policy()
        new = _strict_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        result = suite.run_regression(old, new)
        assert len(result.regression_changes) == 1
        rc = result.regression_changes[0]
        assert rc.old_risk_level == "low"
        assert rc.new_risk_level == "medium"

    def test_pass_fail_reflects_new_policy(self) -> None:
        old = _simple_policy()
        new = _strict_policy()
        suite = PolicyTestSuite()
        # Expectation matches OLD policy, not new.
        suite.add_test(
            PolicyTestCase(
                action={"type": "write", "target": "x"},
                expected_decision="approve",
            )
        )
        result = suite.run_regression(old, new)
        # New policy returns "block", expectation is "approve"
        assert result.failed == 1

    def test_multiple_regressions(self) -> None:
        old = _simple_policy()
        new = _strict_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        suite.add_test(
            PolicyTestCase(
                action={"type": "write", "target": "x"},
                expected_decision="approve",
            )
        )
        result = suite.run_regression(old, new)
        assert len(result.regression_changes) == 2

    def test_unchanged_excluded(self) -> None:
        """Cases identical under both policies are not regressions."""
        old = _simple_policy()
        new = _strict_policy()
        suite = PolicyTestSuite()
        # delete is BLOCK in both policies.
        suite.add_test(
            PolicyTestCase(
                action={"type": "delete", "target": "x"},
                expected_decision="block",
                expected_risk_level="critical",
            )
        )
        result = suite.run_regression(old, new)
        assert len(result.regression_changes) == 0

    def test_empty_suite_regression(self) -> None:
        result = PolicyTestSuite().run_regression(_simple_policy(), _strict_policy())
        assert result.total == 0
        assert len(result.regression_changes) == 0


# ================================================================
# PolicyTestSuite — load_from_yaml
# ================================================================


class TestLoadFromYaml:
    """Tests for PolicyTestSuite.load_from_yaml."""

    def test_load_basic(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            name: basic suite
            tests:
              - action: {type: read, target: crm}
                expected_decision: auto
                expected_risk_level: low
                description: Read CRM
              - action: {type: delete, target: db}
                expected_decision: block
        """)
        f = tmp_path / "suite.yaml"
        f.write_text(yaml_content)

        suite = PolicyTestSuite.load_from_yaml(f)
        assert suite.name == "basic suite"
        assert len(suite) == 2
        assert suite.cases[0].description == "Read CRM"

    def test_load_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            PolicyTestSuite.load_from_yaml("/no/such/file.yaml")

    def test_load_empty_tests(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.yaml"
        f.write_text("name: empty\ntests: []\n")
        suite = PolicyTestSuite.load_from_yaml(f)
        assert len(suite) == 0

    def test_load_no_name(self, tmp_path: Path) -> None:
        f = tmp_path / "noname.yaml"
        f.write_text(
            textwrap.dedent("""\
            tests:
              - action: {type: x, target: y}
                expected_decision: auto
        """)
        )
        suite = PolicyTestSuite.load_from_yaml(f)
        assert suite.name == ""
        assert len(suite) == 1

    def test_load_non_mapping_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "scalar.yaml"
        f.write_text("just a string\n")
        with pytest.raises(TypeError, match="mapping"):
            PolicyTestSuite.load_from_yaml(f)

    def test_load_and_run(self, tmp_path: Path) -> None:
        yaml_content = textwrap.dedent("""\
            name: integration
            tests:
              - action: {type: read, target: crm}
                expected_decision: auto
                expected_risk_level: low
              - action: {type: delete, target: db}
                expected_decision: block
                expected_risk_level: critical
        """)
        f = tmp_path / "suite.yaml"
        f.write_text(yaml_content)

        suite = PolicyTestSuite.load_from_yaml(f)
        result = suite.run(_simple_policy())
        assert result.all_passed


# ================================================================
# PolicyTestSuite — generate_from_policy
# ================================================================


class TestGenerateFromPolicy:
    """Tests for PolicyTestSuite.generate_from_policy."""

    def test_generates_cases_for_each_rule(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite.generate_from_policy(policy)
        # 3 rules + 1 default = 4 cases
        assert len(suite) == 4

    def test_generated_cases_pass(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite.generate_from_policy(policy)
        result = suite.run(policy)
        assert result.all_passed

    def test_default_case_included(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite.generate_from_policy(policy)
        descriptions = [c.description for c in suite.cases]
        assert "default behaviour" in descriptions

    def test_rule_names_in_descriptions(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite.generate_from_policy(policy)
        descs = [c.description for c in suite.cases]
        assert "rule: read_auto" in descs
        assert "rule: write_approve" in descs
        assert "rule: delete_block" in descs

    def test_custom_name(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite.generate_from_policy(policy, name="custom")
        assert suite.name == "custom"

    def test_default_name(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite.generate_from_policy(policy)
        assert suite.name == "auto-generated"

    def test_agent_match_in_generated_action(self) -> None:
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="read",
                    match_target="*",
                    match_agent="bot-*",
                    risk_level=RiskLevel.LOW,
                    approval=Approval.AUTO,
                    name="bot_read",
                ),
            ],
        )
        suite = PolicyTestSuite.generate_from_policy(policy)
        actions = [c.action for c in suite.cases]
        bot_action = actions[0]
        assert bot_action.get("agent_id") == "bot-*"

    def test_empty_policy(self) -> None:
        policy = Policy()
        suite = PolicyTestSuite.generate_from_policy(policy)
        # Only the default case.
        assert len(suite) == 1
        result = suite.run(policy)
        assert result.all_passed

    def test_unnamed_rule_description(self) -> None:
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="deploy",
                    match_target="prod",
                    approval=Approval.APPROVE,
                ),
            ],
        )
        suite = PolicyTestSuite.generate_from_policy(policy)
        descs = [c.description for c in suite.cases]
        assert any("deploy@prod" in d for d in descs)


# ================================================================
# Thread safety
# ================================================================


class TestThreadSafety:
    """Verify concurrent add_test and run are safe."""

    def test_concurrent_add(self) -> None:
        suite = PolicyTestSuite()
        n_threads = 8
        per_thread = 50
        barrier = threading.Barrier(n_threads)

        def worker() -> None:
            barrier.wait()
            for i in range(per_thread):
                suite.add_test(
                    PolicyTestCase(
                        action={
                            "type": f"t{i}",
                            "target": "x",
                        },
                        expected_decision="auto",
                    )
                )

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(suite) == n_threads * per_thread

    def test_concurrent_run(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        results: list[PolicyTestResult] = []
        lock = threading.Lock()
        barrier = threading.Barrier(4)

        def worker() -> None:
            barrier.wait()
            r = suite.run(policy)
            with lock:
                results.append(r)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 4
        assert all(r.all_passed for r in results)

    def test_concurrent_add_and_run(self) -> None:
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
            )
        )
        errors: list[str] = []
        barrier = threading.Barrier(4)

        def adder() -> None:
            barrier.wait()
            for i in range(20):
                suite.add_test(
                    PolicyTestCase(
                        action={
                            "type": f"t{i}",
                            "target": "x",
                        },
                        expected_decision="approve",
                    )
                )

        def runner() -> None:
            barrier.wait()
            try:
                for _ in range(20):
                    suite.run(policy)
            except Exception as exc:
                errors.append(str(exc))

        threads = [
            threading.Thread(target=adder),
            threading.Thread(target=adder),
            threading.Thread(target=runner),
            threading.Thread(target=runner),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []


# ================================================================
# Edge cases & misc
# ================================================================


class TestEdgeCases:
    """Additional edge-case and integration tests."""

    def test_suite_name(self) -> None:
        suite = PolicyTestSuite(name="my suite")
        assert suite.name == "my suite"

    def test_suite_default_name(self) -> None:
        suite = PolicyTestSuite()
        assert suite.name == ""

    def test_case_result_dataclass(self) -> None:
        cr = CaseResult(
            test_case=PolicyTestCase(
                action={"type": "r", "target": "t"},
                expected_decision="auto",
            ),
            passed=True,
            actual_decision="auto",
            actual_risk_level="low",
        )
        assert cr.passed
        assert cr.message == ""

    def test_regression_change_dataclass(self) -> None:
        rc = RegressionChange(
            test_case=PolicyTestCase(
                action={"type": "r", "target": "t"},
                expected_decision="auto",
            ),
            old_decision="auto",
            new_decision="block",
            old_risk_level="low",
            new_risk_level="critical",
        )
        assert rc.old_decision == "auto"
        assert rc.new_decision == "block"

    def test_policy_test_result_defaults(self) -> None:
        r = PolicyTestResult(total=0, passed=0, failed=0, results=[])
        assert r.regression_changes == []
        assert r.all_passed

    def test_wildcard_action_type(self) -> None:
        """Wildcard match_type in policy rule."""
        policy = Policy(
            rules=[
                PolicyRule(
                    match_type="*",
                    match_target="*",
                    approval=Approval.AUTO,
                    risk_level=RiskLevel.LOW,
                    name="allow_all",
                ),
            ],
        )
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={
                    "type": "anything",
                    "target": "anywhere",
                },
                expected_decision="auto",
                expected_risk_level="low",
            )
        )
        assert suite.run(policy).all_passed

    def test_risk_only_mismatch(self) -> None:
        """Decision matches but risk doesn't."""
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
                expected_risk_level="high",
            )
        )
        result = suite.run(policy)
        assert result.failed == 1
        assert "risk_level" in result.results[0].message
        assert "decision" not in result.results[0].message

    def test_no_risk_check_when_empty(self) -> None:
        """When expected_risk_level is empty, skip the check."""
        policy = _simple_policy()
        suite = PolicyTestSuite()
        suite.add_test(
            PolicyTestCase(
                action={"type": "read", "target": "x"},
                expected_decision="auto",
                expected_risk_level="",
            )
        )
        result = suite.run(policy)
        assert result.all_passed

    def test_generate_then_regression(self) -> None:
        """Generate from old, then regression against new."""
        old = _simple_policy()
        new = _strict_policy()
        suite = PolicyTestSuite.generate_from_policy(old)
        reg = suite.run_regression(old, new)
        # read and write changed; delete unchanged; default changed
        assert len(reg.regression_changes) >= 2
