"""Policy Test Runner — CI/CD-grade test execution with coverage and output formats.

Runs policy test suites, computes rule coverage, and produces output
in text, JSON, or JUnit XML format for integration with CI/CD pipelines
(GitHub Actions, Jenkins, etc.).

Example::

    from aegis.core.policy_test_runner import PolicyTestRunner

    runner = PolicyTestRunner()
    results = runner.run_suite("tests/policy_tests.yaml", policy)
    print(results.to_text())

    coverage = runner.coverage_report(policy, results)
    print(coverage.to_text())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element, SubElement, tostring

from aegis.core.action import Action
from aegis.core.policy import Policy, PolicyDecision, PolicyRule
from aegis.core.policy_test_suite import _action_from_dict

# -------------------------------------------------------------------
# Data classes for the enhanced runner
# -------------------------------------------------------------------


@dataclass(frozen=True)
class SuiteTestCase:
    """A test case parsed from the YAML suite format.

    This wraps a :class:`PolicyTestCase` with additional metadata
    from the suite YAML ``expect`` block.
    """

    name: str
    action: dict[str, Any]
    expected_approval: str
    expected_risk_level: str = ""
    description: str = ""
    skip: bool = False
    skip_reason: str = ""


@dataclass(frozen=True)
class CaseOutcome:
    """Outcome of a single test case execution.

    Attributes:
        name: Test case name.
        passed: Whether all assertions held.
        skipped: Whether the test was skipped.
        expected_approval: Expected approval outcome.
        actual_approval: Actual approval outcome.
        expected_risk_level: Expected risk level.
        actual_risk_level: Actual risk level.
        action: Action dict from the test case.
        message: Explanation when a test fails.
        matched_rule: The policy rule that matched.
    """

    name: str
    passed: bool
    skipped: bool
    expected_approval: str
    actual_approval: str
    expected_risk_level: str
    actual_risk_level: str
    action: dict[str, Any]
    message: str = ""
    matched_rule: str = ""
    duration_ms: float = 0.0


@dataclass
class SuiteResults:
    """Aggregate results from running a test suite.

    Attributes:
        suite_name: Name of the test suite.
        policy_path: Path to the policy file (if known).
        total: Total test count.
        passed: Passing test count.
        failed: Failing test count.
        skipped: Skipped test count.
        results: Per-case outcomes.
    """

    suite_name: str
    policy_path: str
    total: int
    passed: int
    failed: int
    skipped: int
    results: list[CaseOutcome]

    @property
    def all_passed(self) -> bool:
        """True when every non-skipped test passed."""
        return self.failed == 0

    # -- Output formats -----------------------------------------------

    def to_text(self) -> str:
        """Render results as human-readable text."""
        lines: list[str] = []
        lines.append(f"Policy Test Results: {self.suite_name}")
        lines.append(f"Policy: {self.policy_path}")
        lines.append("")

        for r in self.results:
            if r.skipped:
                lines.append(f"  SKIP  {r.name}")
                if r.message:
                    lines.append(f"         {r.message}")
            elif r.passed:
                lines.append(f"  PASS  {r.name}")
            else:
                lines.append(f"  FAIL  {r.name}")
                lines.append(f"         {r.message}")
                action_desc = _format_action(r.action)
                lines.append(f"         Action: {action_desc}")

        lines.append("")
        lines.append(
            f"Policy Test Results: {self.passed} passed, "
            f"{self.failed} failed, {self.skipped} skipped"
        )

        if self.failed > 0:
            lines.append("")
            for r in self.results:
                if not r.passed and not r.skipped:
                    lines.append(f"FAILED: {r.name}")
                    lines.append(f"  {r.message}")
                    action_desc = _format_action(r.action)
                    lines.append(f"  Action: {action_desc}")
                    lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Render results as JSON."""
        data = {
            "suite_name": self.suite_name,
            "policy_path": self.policy_path,
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "all_passed": self.all_passed,
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "skipped": r.skipped,
                    "expected_approval": r.expected_approval,
                    "actual_approval": r.actual_approval,
                    "expected_risk_level": r.expected_risk_level,
                    "actual_risk_level": r.actual_risk_level,
                    "action": r.action,
                    "message": r.message,
                    "matched_rule": r.matched_rule,
                }
                for r in self.results
            ],
        }
        return json.dumps(data, indent=2)

    def to_junit_xml(self) -> str:
        """Render results as JUnit XML for CI/CD integration.

        Produces XML compatible with GitHub Actions, Jenkins, and
        other CI systems that consume JUnit test reports.
        """
        testsuites = Element("testsuites")
        testsuite = SubElement(
            testsuites,
            "testsuite",
            name=self.suite_name,
            tests=str(self.total),
            failures=str(self.failed),
            skipped=str(self.skipped),
            errors="0",
        )

        for r in self.results:
            testcase = SubElement(
                testsuite,
                "testcase",
                name=r.name,
                classname=self.suite_name,
                time=f"{r.duration_ms / 1000:.3f}",
            )

            if r.skipped:
                skipped_elem = SubElement(testcase, "skipped")
                if r.message:
                    skipped_elem.set("message", r.message)
            elif not r.passed:
                failure = SubElement(
                    testcase,
                    "failure",
                    message=r.message,
                    type="AssertionError",
                )
                action_desc = _format_action(r.action)
                failure.text = (
                    f"Expected: {r.expected_approval}, Got: {r.actual_approval}\n"
                    f"Action: {action_desc}"
                )
                if r.expected_risk_level and r.expected_risk_level != r.actual_risk_level:
                    failure.text += (
                        f"\nExpected risk: {r.expected_risk_level}, "
                        f"Got risk: {r.actual_risk_level}"
                    )

        xml_bytes = tostring(testsuites, encoding="unicode")
        return f'<?xml version="1.0" encoding="UTF-8"?>\n{xml_bytes}'


@dataclass
class CoverageReport:
    """Policy rule coverage report.

    Attributes:
        total_rules: Total number of policy rules.
        tested_rules: Number of rules exercised by test cases.
        untested_rules: List of untested rule names/descriptions.
        percentage: Coverage percentage (0.0-100.0).
        rule_hits: Map of rule name -> hit count.
    """

    total_rules: int
    tested_rules: int
    untested_rules: list[str]
    percentage: float
    rule_hits: dict[str, int] = field(default_factory=dict)

    def to_text(self) -> str:
        """Render coverage as human-readable text."""
        lines: list[str] = []
        lines.append(
            f"Policy Coverage: {self.tested_rules}/{self.total_rules} "
            f"rules tested ({self.percentage:.1f}%)"
        )

        if self.untested_rules:
            lines.append("")
            lines.append("Untested rules:")
            for i, rule_name in enumerate(self.untested_rules, 1):
                lines.append(f"  - Rule #{i}: {rule_name}")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Render coverage as JSON."""
        data = {
            "total_rules": self.total_rules,
            "tested_rules": self.tested_rules,
            "untested_rules": self.untested_rules,
            "percentage": round(self.percentage, 1),
            "rule_hits": self.rule_hits,
        }
        return json.dumps(data, indent=2)


# -------------------------------------------------------------------
# Helper functions
# -------------------------------------------------------------------


def _format_action(action: dict[str, Any]) -> str:
    """Format an action dict as a human-readable string."""
    atype = action.get("type", "?")
    target = action.get("target", "")
    params = action.get("params", {})
    parts = [atype]
    if target:
        parts[0] = f"{atype} target={target}"
    if params:
        parts.append(f"params={params}")
    return " ".join(parts)


def _normalize_approval(value: str) -> str:
    """Normalize approval values to the internal enum names.

    Supports both user-friendly names (``allow``, ``warn``) and
    internal enum names (``auto``, ``approve``).
    """
    mapping: dict[str, str] = {
        "allow": "auto",
        "warn": "approve",
        "block": "block",
        # Pass-through for internal names
        "auto": "auto",
        "approve": "approve",
    }
    return mapping.get(value.lower(), value.lower())


def _parse_suite_yaml(data: dict[str, Any]) -> tuple[str, str, list[SuiteTestCase]]:
    """Parse a suite YAML dict into (suite_name, policy_path, test_cases).

    Supports the enhanced YAML format with ``expect`` blocks::

        suite: "My Tests"
        policy: "./policy.yaml"
        tests:
          - name: "blocks SQL injection"
            action:
              type: db_query
              target: production
              params:
                query: "DROP TABLE"
            expect:
              approval: block
              risk_level: critical

    Also supports the existing simpler format for backward compatibility::

        name: "My Tests"
        tests:
          - action: {type: read, target: crm}
            expected_decision: auto
    """
    suite_name = data.get("suite", data.get("name", ""))
    policy_path = data.get("policy", "")
    tests: list[SuiteTestCase] = []

    for entry in data.get("tests", []):
        # Enhanced format with "expect" block
        if "expect" in entry:
            expect = entry["expect"]
            raw_approval = expect.get("approval", "approve")
            approval = _normalize_approval(raw_approval)
            risk_level = expect.get("risk_level", "")

            action = entry.get("action", {})
            name = entry.get("name", "")
            skip = entry.get("skip", False)
            skip_reason = entry.get("skip_reason", "")

            tests.append(
                SuiteTestCase(
                    name=name,
                    action=action,
                    expected_approval=approval,
                    expected_risk_level=risk_level,
                    description=entry.get("description", ""),
                    skip=skip,
                    skip_reason=skip_reason,
                )
            )
        else:
            # Legacy format
            action = entry.get("action", {})
            decision = entry.get("expected_decision", "approve")
            risk = entry.get("expected_risk_level", "")
            desc = entry.get("description", "")
            name = entry.get("name", desc or _format_action(action))

            tests.append(
                SuiteTestCase(
                    name=name,
                    action=action,
                    expected_approval=decision,
                    expected_risk_level=risk,
                    description=desc,
                )
            )

    return suite_name, policy_path, tests


def _match_rule_to_action(rule: PolicyRule, action: Action) -> bool:
    """Check if a rule's glob patterns match an action (ignoring conditions)."""
    return bool(rule._re_type.match(action.type) and rule._re_target.match(action.target))


# -------------------------------------------------------------------
# PolicyTestRunner
# -------------------------------------------------------------------


class PolicyTestRunner:
    """Runs policy test suites with CI/CD-grade output.

    Example::

        runner = PolicyTestRunner()
        results = runner.run_suite("tests.yaml", policy)
        if not results.all_passed:
            sys.exit(1)

        coverage = runner.coverage_report(policy, results)
        if coverage.percentage < 80:
            sys.exit(1)
    """

    def run_suite(
        self,
        suite_path: str | Path,
        policy: Policy,
    ) -> SuiteResults:
        """Run a test suite YAML against a policy.

        Args:
            suite_path: Path to the test suite YAML file.
            policy: The policy to test against.

        Returns:
            :class:`SuiteResults` with per-case outcomes and summary.

        Raises:
            FileNotFoundError: If the suite file does not exist.
            TypeError: If the YAML is not a mapping.
        """
        import yaml  # noqa: PLC0415

        filepath = Path(suite_path)
        if not filepath.exists():
            raise FileNotFoundError(f"Test suite file not found: {filepath}")

        with filepath.open() as f:
            data = yaml.safe_load(f)

        if data is None:
            data = {}

        if not isinstance(data, dict):
            raise TypeError(f"Expected mapping at top level, got {type(data).__name__}")

        return self.run_suite_from_dict(data, policy, policy_path=str(filepath))

    def run_suite_from_dict(
        self,
        data: dict[str, Any],
        policy: Policy,
        *,
        policy_path: str = "",
    ) -> SuiteResults:
        """Run a test suite from a parsed YAML dict.

        Args:
            data: Parsed YAML dict.
            policy: The policy to test against.
            policy_path: Display path for the policy.

        Returns:
            :class:`SuiteResults` with per-case outcomes and summary.
        """
        suite_name, suite_policy_path, test_cases = _parse_suite_yaml(data)
        display_policy = policy_path or suite_policy_path

        results: list[CaseOutcome] = []
        passed = 0
        failed = 0
        skipped = 0

        for tc in test_cases:
            if tc.skip:
                skipped += 1
                results.append(
                    CaseOutcome(
                        name=tc.name,
                        passed=False,
                        skipped=True,
                        expected_approval=tc.expected_approval,
                        actual_approval="",
                        expected_risk_level=tc.expected_risk_level,
                        actual_risk_level="",
                        action=tc.action,
                        message=tc.skip_reason or "skipped",
                    )
                )
                continue

            action = _action_from_dict(tc.action)
            decision: PolicyDecision = policy.evaluate(action)

            actual_approval = decision.approval.value
            actual_risk = decision.risk_level.name.lower()

            errors: list[str] = []
            expected_approval = tc.expected_approval.lower()
            if actual_approval != expected_approval:
                errors.append(f"Expected: {expected_approval}, Got: {actual_approval}")

            if tc.expected_risk_level:
                expected_risk = tc.expected_risk_level.lower()
                if actual_risk != expected_risk:
                    errors.append(f"Expected risk: {expected_risk}, Got risk: {actual_risk}")

            is_passed = len(errors) == 0
            message = "; ".join(errors)

            if is_passed:
                passed += 1
            else:
                failed += 1

            results.append(
                CaseOutcome(
                    name=tc.name,
                    passed=is_passed,
                    skipped=False,
                    expected_approval=expected_approval,
                    actual_approval=actual_approval,
                    expected_risk_level=tc.expected_risk_level,
                    actual_risk_level=actual_risk,
                    action=tc.action,
                    message=message,
                    matched_rule=decision.matched_rule,
                )
            )

        return SuiteResults(
            suite_name=suite_name,
            policy_path=display_policy,
            total=len(results),
            passed=passed,
            failed=failed,
            skipped=skipped,
            results=results,
        )

    def coverage_report(
        self,
        policy: Policy,
        test_results: SuiteResults,
    ) -> CoverageReport:
        """Compute which policy rules were exercised by the test suite.

        A rule is "covered" if any non-skipped test case's action
        matches the rule's type/target glob patterns.

        Args:
            policy: The policy whose rules to check.
            test_results: Results from a prior :meth:`run_suite` call.

        Returns:
            :class:`CoverageReport` with tested/untested rules.
        """
        if not policy.rules:
            return CoverageReport(
                total_rules=0,
                tested_rules=0,
                untested_rules=[],
                percentage=100.0,
                rule_hits={},
            )

        rule_hits: dict[str, int] = {}
        for rule in policy.rules:
            rule_name = rule.name or f"{rule.match_type}@{rule.match_target}"
            rule_hits[rule_name] = 0

        for r in test_results.results:
            if r.skipped:
                continue
            action = _action_from_dict(r.action)
            for rule in policy.rules:
                if _match_rule_to_action(rule, action):
                    rule_name = rule.name or f"{rule.match_type}@{rule.match_target}"
                    rule_hits[rule_name] += 1

        tested = sum(1 for count in rule_hits.values() if count > 0)
        total = len(policy.rules)
        untested = [name for name, count in rule_hits.items() if count == 0]
        percentage = (tested / total * 100.0) if total > 0 else 100.0

        return CoverageReport(
            total_rules=total,
            tested_rules=tested,
            untested_rules=untested,
            percentage=percentage,
            rule_hits=rule_hits,
        )
