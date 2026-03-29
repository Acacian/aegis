"""Tests for the enhanced Policy Test Runner (CI/CD-grade output)."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from xml.etree.ElementTree import fromstring

import pytest

from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.policy_test_runner import (
    CaseOutcome,
    CoverageReport,
    PolicyTestRunner,
    SuiteResults,
    SuiteTestCase,
    _format_action,
    _normalize_approval,
    _parse_suite_yaml,
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


def _payment_policy() -> Policy:
    """A more complex policy for coverage testing."""
    return Policy(
        rules=[
            PolicyRule(
                match_type="db_query",
                match_target="production",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="block_prod_queries",
            ),
            PolicyRule(
                match_type="read_file",
                match_target="docs",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
                name="allow_doc_reads",
            ),
            PolicyRule(
                match_type="api_call",
                match_target="external",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
                name="warn_external_api",
            ),
            PolicyRule(
                match_type="send_email",
                match_target="*",
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
                name="approve_emails",
            ),
            PolicyRule(
                match_type="deploy",
                match_target="production",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
                name="block_prod_deploy",
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _write_suite_yaml(tmp_path: Path, content: str) -> Path:
    """Write suite YAML to a temp file and return the path."""
    suite_file = tmp_path / "suite.yaml"
    suite_file.write_text(textwrap.dedent(content))
    return suite_file


# ================================================================
# Suite YAML parsing
# ================================================================


class TestSuiteYamlParsing:
    """Tests for parsing the enhanced YAML suite format."""

    def test_parse_enhanced_format(self) -> None:
        data = {
            "suite": "Payment Tests",
            "policy": "./policy.yaml",
            "tests": [
                {
                    "name": "blocks SQL injection",
                    "action": {"type": "db_query", "target": "production"},
                    "expect": {"approval": "block", "risk_level": "critical"},
                },
            ],
        }
        name, policy_path, cases = _parse_suite_yaml(data)
        assert name == "Payment Tests"
        assert policy_path == "./policy.yaml"
        assert len(cases) == 1
        assert cases[0].name == "blocks SQL injection"
        assert cases[0].expected_approval == "block"
        assert cases[0].expected_risk_level == "critical"

    def test_parse_legacy_format(self) -> None:
        data = {
            "name": "Legacy Suite",
            "tests": [
                {
                    "action": {"type": "read", "target": "crm"},
                    "expected_decision": "auto",
                    "expected_risk_level": "low",
                    "description": "Read CRM",
                },
            ],
        }
        name, _, cases = _parse_suite_yaml(data)
        assert name == "Legacy Suite"
        assert len(cases) == 1
        assert cases[0].expected_approval == "auto"

    def test_parse_empty_suite(self) -> None:
        data: dict = {"suite": "Empty", "tests": []}
        _, _, cases = _parse_suite_yaml(data)
        assert cases == []

    def test_parse_no_tests_key(self) -> None:
        data: dict = {"suite": "No tests"}
        _, _, cases = _parse_suite_yaml(data)
        assert cases == []

    def test_approval_normalization_allow(self) -> None:
        """'allow' in YAML maps to 'auto' internally."""
        data = {
            "tests": [
                {
                    "name": "allow test",
                    "action": {"type": "read", "target": "docs"},
                    "expect": {"approval": "allow"},
                },
            ],
        }
        _, _, cases = _parse_suite_yaml(data)
        assert cases[0].expected_approval == "auto"

    def test_approval_normalization_warn(self) -> None:
        """'warn' in YAML maps to 'approve' internally."""
        data = {
            "tests": [
                {
                    "name": "warn test",
                    "action": {"type": "api_call", "target": "ext"},
                    "expect": {"approval": "warn"},
                },
            ],
        }
        _, _, cases = _parse_suite_yaml(data)
        assert cases[0].expected_approval == "approve"

    def test_skip_flag_parsed(self) -> None:
        data = {
            "tests": [
                {
                    "name": "skipped test",
                    "action": {"type": "x", "target": "y"},
                    "expect": {"approval": "block"},
                    "skip": True,
                    "skip_reason": "not implemented yet",
                },
            ],
        }
        _, _, cases = _parse_suite_yaml(data)
        assert cases[0].skip is True
        assert cases[0].skip_reason == "not implemented yet"


# ================================================================
# PolicyTestRunner.run_suite
# ================================================================


class TestRunSuite:
    """Tests for running suites via PolicyTestRunner."""

    def test_all_pass(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Basic Tests"
            tests:
              - name: "read auto-approves"
                action: {type: read, target: crm}
                expect: {approval: auto, risk_level: low}
              - name: "write requires approval"
                action: {type: write, target: db}
                expect: {approval: approve, risk_level: medium}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())

        assert results.total == 2
        assert results.passed == 2
        assert results.failed == 0
        assert results.all_passed

    def test_failure_detected(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Fail Tests"
            tests:
              - name: "should fail"
                action: {type: read, target: crm}
                expect: {approval: block}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())

        assert results.failed == 1
        assert not results.all_passed
        assert "Expected: block" in results.results[0].message

    def test_risk_level_mismatch(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Risk Tests"
            tests:
              - name: "wrong risk"
                action: {type: read, target: crm}
                expect: {approval: auto, risk_level: critical}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())

        assert results.failed == 1
        assert "risk" in results.results[0].message.lower()

    def test_file_not_found(self) -> None:
        runner = PolicyTestRunner()
        with pytest.raises(FileNotFoundError):
            runner.run_suite("/nonexistent/suite.yaml", _simple_policy())

    def test_invalid_yaml_type(self, tmp_path: Path) -> None:
        suite_file = tmp_path / "bad.yaml"
        suite_file.write_text("just a string\n")
        runner = PolicyTestRunner()
        with pytest.raises(TypeError, match="mapping"):
            runner.run_suite(suite_file, _simple_policy())

    def test_empty_suite(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Empty"
            tests: []
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        assert results.total == 0
        assert results.all_passed

    def test_skipped_tests(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Skip Tests"
            tests:
              - name: "this is skipped"
                action: {type: read, target: crm}
                expect: {approval: auto}
                skip: true
                skip_reason: "not ready"
              - name: "this runs"
                action: {type: read, target: crm}
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())

        assert results.total == 2
        assert results.passed == 1
        assert results.skipped == 1
        assert results.failed == 0
        assert results.all_passed  # skipped don't count as failures

    def test_allow_maps_to_auto(self, tmp_path: Path) -> None:
        """User-friendly 'allow' maps to internal 'auto'."""
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Allow Test"
            tests:
              - name: "allow = auto"
                action: {type: read, target: crm}
                expect: {approval: allow}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        assert results.all_passed

    def test_action_params_forwarded(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Params Test"
            tests:
              - name: "with params"
                action:
                  type: read
                  target: crm
                  params:
                    limit: 10
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        assert results.all_passed

    def test_matched_rule_recorded(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Rule Match"
            tests:
              - name: "read matches read_auto"
                action: {type: read, target: crm}
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        assert results.results[0].matched_rule == "read_auto"

    def test_empty_yaml_file(self, tmp_path: Path) -> None:
        """Empty YAML files are treated as empty suites."""
        suite_file = tmp_path / "empty.yaml"
        suite_file.write_text("")
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        assert results.total == 0
        assert results.all_passed


# ================================================================
# Output formats
# ================================================================


class TestOutputFormats:
    """Tests for text, JSON, and JUnit XML output."""

    def _make_results(self, policy: Policy | None = None) -> SuiteResults:
        """Create sample test results for output tests."""
        if policy is None:
            policy = _simple_policy()

        suite_file_content = {
            "suite": "Output Tests",
            "tests": [
                {
                    "name": "read auto-approves",
                    "action": {"type": "read", "target": "crm"},
                    "expect": {"approval": "auto", "risk_level": "low"},
                },
                {
                    "name": "should fail",
                    "action": {"type": "read", "target": "crm"},
                    "expect": {"approval": "block"},
                },
            ],
        }
        runner = PolicyTestRunner()
        return runner.run_suite_from_dict(
            suite_file_content, policy, policy_path="test_policy.yaml"
        )

    def test_text_output_contains_summary(self) -> None:
        results = self._make_results()
        text = results.to_text()
        assert "1 passed" in text
        assert "1 failed" in text
        assert "PASS" in text
        assert "FAIL" in text
        assert "Output Tests" in text

    def test_text_output_shows_failure_details(self) -> None:
        results = self._make_results()
        text = results.to_text()
        assert "should fail" in text
        assert "Expected: block" in text

    def test_json_output_valid(self) -> None:
        results = self._make_results()
        data = json.loads(results.to_json())
        assert data["total"] == 2
        assert data["passed"] == 1
        assert data["failed"] == 1
        assert data["all_passed"] is False
        assert len(data["results"]) == 2

    def test_json_output_result_fields(self) -> None:
        results = self._make_results()
        data = json.loads(results.to_json())
        r = data["results"][0]
        assert "name" in r
        assert "passed" in r
        assert "expected_approval" in r
        assert "actual_approval" in r
        assert "action" in r

    def test_junit_xml_valid(self) -> None:
        results = self._make_results()
        xml_str = results.to_junit_xml()
        assert xml_str.startswith("<?xml")
        # Parse to verify well-formed XML
        root = fromstring(xml_str.split("\n", 1)[1])
        assert root.tag == "testsuites"

    def test_junit_xml_structure(self) -> None:
        results = self._make_results()
        xml_str = results.to_junit_xml()
        root = fromstring(xml_str.split("\n", 1)[1])
        testsuite = root.find("testsuite")
        assert testsuite is not None
        assert testsuite.get("name") == "Output Tests"
        assert testsuite.get("tests") == "2"
        assert testsuite.get("failures") == "1"

        testcases = testsuite.findall("testcase")
        assert len(testcases) == 2

    def test_junit_xml_failure_element(self) -> None:
        results = self._make_results()
        xml_str = results.to_junit_xml()
        root = fromstring(xml_str.split("\n", 1)[1])
        testsuite = root.find("testsuite")
        assert testsuite is not None
        failures = testsuite.findall(".//failure")
        assert len(failures) == 1
        assert "block" in (failures[0].text or "").lower()

    def test_junit_xml_skipped_element(self) -> None:
        suite_data = {
            "suite": "Skip XML",
            "tests": [
                {
                    "name": "skipped",
                    "action": {"type": "x", "target": "y"},
                    "expect": {"approval": "auto"},
                    "skip": True,
                },
            ],
        }
        runner = PolicyTestRunner()
        results = runner.run_suite_from_dict(suite_data, _simple_policy())
        xml_str = results.to_junit_xml()
        root = fromstring(xml_str.split("\n", 1)[1])
        testsuite = root.find("testsuite")
        assert testsuite is not None
        skipped_elems = testsuite.findall(".//skipped")
        assert len(skipped_elems) == 1

    def test_all_pass_output(self) -> None:
        suite_data = {
            "suite": "Pass",
            "tests": [
                {
                    "name": "ok",
                    "action": {"type": "read", "target": "x"},
                    "expect": {"approval": "auto"},
                },
            ],
        }
        runner = PolicyTestRunner()
        results = runner.run_suite_from_dict(suite_data, _simple_policy())
        text = results.to_text()
        assert "FAIL" not in text
        assert "1 passed" in text
        assert "0 failed" in text


# ================================================================
# Coverage report
# ================================================================


class TestCoverageReport:
    """Tests for policy rule coverage computation."""

    def test_full_coverage(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Full Coverage"
            tests:
              - name: "test read"
                action: {type: read, target: crm}
                expect: {approval: auto}
              - name: "test write"
                action: {type: write, target: db}
                expect: {approval: approve}
              - name: "test delete"
                action: {type: delete, target: x}
                expect: {approval: block}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)

        assert coverage.total_rules == 3
        assert coverage.tested_rules == 3
        assert coverage.percentage == 100.0
        assert coverage.untested_rules == []

    def test_partial_coverage(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Partial Coverage"
            tests:
              - name: "test read only"
                action: {type: read, target: crm}
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)

        assert coverage.total_rules == 3
        assert coverage.tested_rules == 1
        assert len(coverage.untested_rules) == 2
        assert "write_approve" in coverage.untested_rules
        assert "delete_block" in coverage.untested_rules
        assert abs(coverage.percentage - 33.3) < 0.1

    def test_zero_coverage(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Zero Coverage"
            tests:
              - name: "unmatched action"
                action: {type: unknown_type, target: unknown}
                expect: {approval: approve}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)

        assert coverage.tested_rules == 0
        assert coverage.percentage == 0.0

    def test_empty_policy_coverage(self) -> None:
        runner = PolicyTestRunner()
        empty_results = SuiteResults(
            suite_name="empty",
            policy_path="",
            total=0,
            passed=0,
            failed=0,
            skipped=0,
            results=[],
        )
        coverage = runner.coverage_report(Policy(), empty_results)
        assert coverage.total_rules == 0
        assert coverage.percentage == 100.0

    def test_coverage_text_output(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Text Test"
            tests:
              - name: "read"
                action: {type: read, target: x}
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)
        text = coverage.to_text()

        assert "1/3 rules tested" in text
        assert "33.3%" in text
        assert "Untested rules:" in text
        assert "write_approve" in text

    def test_coverage_json_output(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "JSON Test"
            tests:
              - name: "read"
                action: {type: read, target: x}
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)
        data = json.loads(coverage.to_json())

        assert data["total_rules"] == 3
        assert data["tested_rules"] == 1
        assert len(data["untested_rules"]) == 2
        assert "rule_hits" in data

    def test_rule_hits_counted(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Hits Test"
            tests:
              - name: "read1"
                action: {type: read, target: x}
                expect: {approval: auto}
              - name: "read2"
                action: {type: read, target: y}
                expect: {approval: auto}
              - name: "write1"
                action: {type: write, target: z}
                expect: {approval: approve}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)

        assert coverage.rule_hits["read_auto"] == 2
        assert coverage.rule_hits["write_approve"] == 1
        assert coverage.rule_hits["delete_block"] == 0

    def test_skipped_tests_not_counted_for_coverage(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Skip Coverage"
            tests:
              - name: "skipped read"
                action: {type: read, target: x}
                expect: {approval: auto}
                skip: true
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)

        assert coverage.tested_rules == 0
        assert coverage.percentage == 0.0


# ================================================================
# Fail-under threshold
# ================================================================


class TestFailUnder:
    """Tests for --fail-under threshold logic."""

    def test_above_threshold_passes(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Threshold"
            tests:
              - name: "read"
                action: {type: read, target: x}
                expect: {approval: auto}
              - name: "write"
                action: {type: write, target: x}
                expect: {approval: approve}
              - name: "delete"
                action: {type: delete, target: x}
                expect: {approval: block}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)
        assert coverage.percentage >= 80

    def test_below_threshold_detectable(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Low Coverage"
            tests:
              - name: "read only"
                action: {type: read, target: x}
                expect: {approval: auto}
            """,
        )
        runner = PolicyTestRunner()
        results = runner.run_suite(suite_file, _simple_policy())
        coverage = runner.coverage_report(_simple_policy(), results)
        # 1/3 = 33.3% which is below 80
        assert coverage.percentage < 80


# ================================================================
# Helper function tests
# ================================================================


class TestHelpers:
    """Tests for helper/utility functions."""

    def test_format_action_basic(self) -> None:
        result = _format_action({"type": "read", "target": "crm"})
        assert "read" in result
        assert "crm" in result

    def test_format_action_with_params(self) -> None:
        result = _format_action({"type": "send_email", "params": {"body": "hello"}})
        assert "send_email" in result
        assert "params=" in result

    def test_format_action_empty(self) -> None:
        result = _format_action({})
        assert "?" in result

    def test_normalize_approval_allow(self) -> None:
        assert _normalize_approval("allow") == "auto"

    def test_normalize_approval_warn(self) -> None:
        assert _normalize_approval("warn") == "approve"

    def test_normalize_approval_block(self) -> None:
        assert _normalize_approval("block") == "block"

    def test_normalize_approval_passthrough(self) -> None:
        assert _normalize_approval("auto") == "auto"
        assert _normalize_approval("approve") == "approve"

    def test_normalize_approval_case_insensitive(self) -> None:
        assert _normalize_approval("ALLOW") == "auto"
        assert _normalize_approval("Block") == "block"


# ================================================================
# Dataclass tests
# ================================================================


class TestDataclasses:
    """Tests for data model correctness."""

    def test_test_case_result_defaults(self) -> None:
        r = CaseOutcome(
            name="test",
            passed=True,
            skipped=False,
            expected_approval="auto",
            actual_approval="auto",
            expected_risk_level="low",
            actual_risk_level="low",
            action={"type": "read", "target": "x"},
        )
        assert r.message == ""
        assert r.matched_rule == ""
        assert r.duration_ms == 0.0

    def test_test_results_all_passed(self) -> None:
        r = SuiteResults(
            suite_name="test",
            policy_path="p.yaml",
            total=0,
            passed=0,
            failed=0,
            skipped=0,
            results=[],
        )
        assert r.all_passed

    def test_coverage_report_text_no_untested(self) -> None:
        c = CoverageReport(
            total_rules=3,
            tested_rules=3,
            untested_rules=[],
            percentage=100.0,
        )
        text = c.to_text()
        assert "100.0%" in text
        assert "Untested" not in text

    def test_suite_test_case_fields(self) -> None:
        tc = SuiteTestCase(
            name="test",
            action={"type": "read", "target": "x"},
            expected_approval="auto",
            skip=True,
            skip_reason="wip",
        )
        assert tc.skip is True
        assert tc.skip_reason == "wip"


# ================================================================
# run_suite_from_dict
# ================================================================


class TestRunSuiteFromDict:
    """Tests for run_suite_from_dict (no file I/O)."""

    def test_basic_from_dict(self) -> None:
        data = {
            "suite": "Dict Test",
            "tests": [
                {
                    "name": "ok",
                    "action": {"type": "read", "target": "x"},
                    "expect": {"approval": "auto"},
                },
            ],
        }
        runner = PolicyTestRunner()
        results = runner.run_suite_from_dict(data, _simple_policy())
        assert results.all_passed
        assert results.suite_name == "Dict Test"

    def test_policy_path_override(self) -> None:
        data = {
            "suite": "Path",
            "policy": "original.yaml",
            "tests": [],
        }
        runner = PolicyTestRunner()
        results = runner.run_suite_from_dict(data, _simple_policy(), policy_path="override.yaml")
        assert results.policy_path == "override.yaml"

    def test_policy_path_from_suite(self) -> None:
        data = {
            "suite": "Path",
            "policy": "from_suite.yaml",
            "tests": [],
        }
        runner = PolicyTestRunner()
        results = runner.run_suite_from_dict(data, _simple_policy())
        assert results.policy_path == "from_suite.yaml"

    def test_mixed_pass_fail(self) -> None:
        data = {
            "suite": "Mixed",
            "tests": [
                {
                    "name": "pass",
                    "action": {"type": "read", "target": "x"},
                    "expect": {"approval": "auto"},
                },
                {
                    "name": "fail",
                    "action": {"type": "read", "target": "x"},
                    "expect": {"approval": "block"},
                },
            ],
        }
        runner = PolicyTestRunner()
        results = runner.run_suite_from_dict(data, _simple_policy())
        assert results.passed == 1
        assert results.failed == 1
        assert not results.all_passed


# ================================================================
# Complex policy coverage
# ================================================================


class TestComplexPolicyCoverage:
    """Tests with a more complex policy to verify coverage accuracy."""

    def test_partial_coverage_5_rules(self, tmp_path: Path) -> None:
        suite_file = _write_suite_yaml(
            tmp_path,
            """\
            suite: "Payment Tests"
            tests:
              - name: "blocks SQL injection"
                action:
                  type: db_query
                  target: production
                expect:
                  approval: block
                  risk_level: critical
              - name: "allows doc reads"
                action:
                  type: read_file
                  target: docs
                expect:
                  approval: auto
                  risk_level: low
              - name: "warns on external API"
                action:
                  type: api_call
                  target: external
                expect:
                  approval: approve
                  risk_level: medium
            """,
        )
        runner = PolicyTestRunner()
        policy = _payment_policy()
        results = runner.run_suite(suite_file, policy)
        assert results.all_passed

        coverage = runner.coverage_report(policy, results)
        assert coverage.total_rules == 5
        assert coverage.tested_rules == 3
        assert coverage.percentage == 60.0
        assert "approve_emails" in coverage.untested_rules
        assert "block_prod_deploy" in coverage.untested_rules
