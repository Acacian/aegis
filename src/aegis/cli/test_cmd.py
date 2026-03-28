"""CLI command for ``aegis test`` — policy regression testing for CI/CD.

Run policy test suites, generate test cases from policies, and detect
regressions when policies change. Designed for CI pipelines.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis.cli import colors
from aegis.core.policy import Policy
from aegis.core.policy_test_suite import (
    CaseResult,
    PolicyTestCase,
    PolicyTestResult,
    PolicyTestSuite,
)


def register(subparsers: argparse._SubParsersAction) -> None:  # type: ignore[type-arg]
    """Register the ``test`` subcommand."""
    test_parser = subparsers.add_parser(
        "test",
        help="Run policy regression tests (for CI/CD pipelines)",
    )
    test_parser.add_argument(
        "policy_file",
        help="Path to the policy YAML to test against",
    )
    test_parser.add_argument(
        "suite_file",
        nargs="?",
        help="Path to the test suite YAML (omit with --generate)",
    )
    test_parser.add_argument(
        "--generate",
        action="store_true",
        default=False,
        help="Auto-generate test suite from policy and print to stdout",
    )
    test_parser.add_argument(
        "--generate-output",
        metavar="PATH",
        help="Write generated test suite to file instead of stdout",
    )
    test_parser.add_argument(
        "--regression",
        metavar="OLD_POLICY",
        help="Compare test outcomes between OLD_POLICY and policy_file",
    )
    test_parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        dest="fmt",
        help="Output format (default: table)",
    )


def run(args: argparse.Namespace) -> None:
    """Execute the ``test`` command."""
    policy_path = Path(args.policy_file)
    if not policy_path.exists():
        print(colors.red(f"Policy file not found: {policy_path}"), file=sys.stderr)
        sys.exit(1)

    try:
        policy = Policy.from_yaml(policy_path)
    except Exception as e:
        print(colors.red(f"Failed to load policy: {e}"), file=sys.stderr)
        sys.exit(1)

    # --generate mode
    if args.generate:
        _generate_suite(policy, args)
        return

    # Need a suite file for test/regression
    if not args.suite_file:
        print(
            colors.red("Test suite file required. Use --generate to create one."),
            file=sys.stderr,
        )
        sys.exit(1)

    suite_path = Path(args.suite_file)
    if not suite_path.exists():
        print(colors.red(f"Test suite not found: {suite_path}"), file=sys.stderr)
        sys.exit(1)

    suite = PolicyTestSuite.load_from_yaml(suite_path)

    if len(suite) == 0:
        print(colors.yellow("Test suite is empty — no tests to run."))
        return

    # --regression mode
    if args.regression:
        old_path = Path(args.regression)
        if not old_path.exists():
            print(colors.red(f"Old policy not found: {old_path}"), file=sys.stderr)
            sys.exit(1)
        try:
            old_policy = Policy.from_yaml(old_path)
        except Exception as e:
            print(colors.red(f"Failed to load old policy: {e}"), file=sys.stderr)
            sys.exit(1)

        result = suite.run_regression(old_policy, policy)
        if args.fmt == "json":
            _print_regression_json(result)
        else:
            _print_regression_table(result, suite_path.name)
        if not result.all_passed or result.regression_changes:
            sys.exit(1)
        return

    # Normal test run
    result = suite.run(policy)
    if args.fmt == "json":
        _print_test_json(result)
    else:
        _print_test_table(result, suite_path.name, policy_path.name)

    if not result.all_passed:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Generate
# ---------------------------------------------------------------------------


def _generate_suite(policy: Policy, args: argparse.Namespace) -> None:
    """Generate a test suite YAML from a policy."""
    try:
        import yaml
    except ImportError:
        print(
            colors.red("PyYAML required for --generate. Install: pip install pyyaml"),
            file=sys.stderr,
        )
        sys.exit(1)

    suite = PolicyTestSuite.generate_from_policy(policy)
    data = {
        "name": f"auto-generated from {Path(args.policy_file).name}",
        "tests": [
            {
                "action": tc.action,
                "expected_decision": tc.expected_decision,
                "expected_risk_level": tc.expected_risk_level,
                "description": tc.description,
            }
            for tc in suite.cases
        ],
    }

    output = yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)

    if args.generate_output:
        out_path = Path(args.generate_output)
        out_path.write_text(output)
        print(f"Generated {len(suite)} test case(s) → {out_path}")
    else:
        print(output)


# ---------------------------------------------------------------------------
# Table output
# ---------------------------------------------------------------------------


def _case_desc(tc: PolicyTestCase) -> str:
    """Build a short description for a test case."""
    if tc.description:
        return tc.description
    t = tc.action.get("type", "?")
    tgt = tc.action.get("target", "?")
    return f"{t}@{tgt}"


def _print_test_table(
    result: PolicyTestResult,
    suite_name: str,
    policy_name: str,
) -> None:
    """Print test results in a human-readable table."""
    print()
    print(colors.bold(f"Aegis Policy Test: {suite_name} against {policy_name}"))
    print()

    for cr in result.results:
        desc = _case_desc(cr.test_case)
        if cr.passed:
            print(f"  {colors.green('PASS')}  {desc}")
        else:
            print(f"  {colors.red('FAIL')}  {desc}")
            print(f"         {colors.red(cr.message)}")

    print()
    _print_summary(result)


def _print_regression_table(result: PolicyTestResult, suite_name: str) -> None:
    """Print regression test results."""
    print()
    print(colors.bold(f"Aegis Policy Regression: {suite_name}"))
    print()

    if result.regression_changes:
        print(colors.bold("Regressions detected:"))
        print()
        for rc in result.regression_changes:
            desc = _case_desc(rc.test_case)
            decision_changed = rc.old_decision != rc.new_decision
            risk_changed = rc.old_risk_level != rc.new_risk_level

            parts: list[str] = []
            if decision_changed:
                parts.append(f"decision: {rc.old_decision} → {rc.new_decision}")
            if risk_changed:
                parts.append(f"risk: {rc.old_risk_level} → {rc.new_risk_level}")

            print(f"  {colors.yellow('REGR')}  {desc}")
            print(f"         {colors.yellow(', '.join(parts))}")
        print()

    # Also show pass/fail for the new policy
    for cr in result.results:
        desc = _case_desc(cr.test_case)
        if cr.passed:
            print(f"  {colors.green('PASS')}  {desc}")
        else:
            print(f"  {colors.red('FAIL')}  {desc}")
            print(f"         {colors.red(cr.message)}")

    print()
    _print_summary(result, regression=True)


def _print_summary(result: PolicyTestResult, *, regression: bool = False) -> None:
    """Print the final summary line."""
    if result.all_passed and not (regression and result.regression_changes):
        status = colors.green("ALL PASSED")
    else:
        status = colors.red("FAILED")

    parts = [f"{result.passed} passed", f"{result.failed} failed"]
    if regression and result.regression_changes:
        parts.append(f"{len(result.regression_changes)} regression(s)")

    print(f"Result: {status} ({', '.join(parts)} of {result.total} tests)")
    print()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def _case_result_dict(cr: CaseResult) -> dict[str, object]:
    return {
        "description": cr.test_case.description,
        "action": cr.test_case.action,
        "expected_decision": cr.test_case.expected_decision,
        "actual_decision": cr.actual_decision,
        "expected_risk_level": cr.test_case.expected_risk_level,
        "actual_risk_level": cr.actual_risk_level,
        "passed": cr.passed,
        "message": cr.message,
    }


def _print_test_json(result: PolicyTestResult) -> None:
    data = {
        "total": result.total,
        "passed": result.passed,
        "failed": result.failed,
        "all_passed": result.all_passed,
        "results": [_case_result_dict(cr) for cr in result.results],
    }
    print(json.dumps(data, indent=2))


def _print_regression_json(result: PolicyTestResult) -> None:
    data = {
        "total": result.total,
        "passed": result.passed,
        "failed": result.failed,
        "all_passed": result.all_passed,
        "regressions": [
            {
                "description": rc.test_case.description,
                "action": rc.test_case.action,
                "old_decision": rc.old_decision,
                "new_decision": rc.new_decision,
                "old_risk_level": rc.old_risk_level,
                "new_risk_level": rc.new_risk_level,
            }
            for rc in result.regression_changes
        ],
        "results": [_case_result_dict(cr) for cr in result.results],
    }
    print(json.dumps(data, indent=2))
