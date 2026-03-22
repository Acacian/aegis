"""Policy Testing Framework — automated test cases for governance policies.

Enables enterprises to write unit-test-style assertions for policy rules,
run regression checks when policies change, and auto-generate test suites
from existing rule definitions.

Example::

    from aegis.core.policy_test_suite import (
        PolicyTestCase,
        PolicyTestSuite,
    )

    suite = PolicyTestSuite()
    suite.add_test(PolicyTestCase(
        action={"type": "read", "target": "crm"},
        expected_decision="auto",
        expected_risk_level="low",
        description="Read ops should auto-approve",
    ))
    result = suite.run(policy)
    assert result.all_passed
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Policy, PolicyDecision

# -------------------------------------------------------------------
# Data classes
# -------------------------------------------------------------------

_VALID_DECISIONS = frozenset({"auto", "approve", "block"})
_VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True)
class PolicyTestCase:
    """A single test assertion for a policy rule.

    Attributes:
        action: Dict with ``type``, ``target``, and optional
            ``params``, ``agent_id`` keys describing the action.
        expected_decision: Expected approval outcome
            (``"auto"``, ``"approve"``, or ``"block"``).
        expected_risk_level: Expected risk level
            (``"low"``, ``"medium"``, ``"high"``, ``"critical"``).
            Pass ``""`` to skip risk-level assertion.
        description: Human-readable label for the test case.
    """

    action: dict[str, Any]
    expected_decision: str
    expected_risk_level: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        decision = self.expected_decision.lower()
        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid expected_decision {self.expected_decision!r}."
                f" Must be one of: {', '.join(sorted(_VALID_DECISIONS))}"
            )
        if self.expected_risk_level:
            risk = self.expected_risk_level.lower()
            if risk not in _VALID_RISK_LEVELS:
                raise ValueError(
                    f"Invalid expected_risk_level"
                    f" {self.expected_risk_level!r}."
                    f" Must be one of:"
                    f" {', '.join(sorted(_VALID_RISK_LEVELS))}"
                )


@dataclass(frozen=True)
class CaseResult:
    """Outcome of running a single :class:`PolicyTestCase`.

    Attributes:
        test_case: The original test case.
        passed: Whether all assertions held.
        actual_decision: The approval string returned by the policy.
        actual_risk_level: The risk-level string returned.
        message: Explanation when a test fails.
    """

    test_case: PolicyTestCase
    passed: bool
    actual_decision: str
    actual_risk_level: str
    message: str = ""


@dataclass(frozen=True)
class RegressionChange:
    """A test case whose outcome differs between two policies.

    Attributes:
        test_case: The test case that diverged.
        old_decision: Decision under the old policy.
        new_decision: Decision under the new policy.
        old_risk_level: Risk level under the old policy.
        new_risk_level: Risk level under the new policy.
    """

    test_case: PolicyTestCase
    old_decision: str
    new_decision: str
    old_risk_level: str
    new_risk_level: str


@dataclass
class PolicyTestResult:
    """Aggregate outcome of running a :class:`PolicyTestSuite`.

    Attributes:
        total: Number of test cases executed.
        passed: Number of passing cases.
        failed: Number of failing cases.
        results: Per-case outcomes.
        regression_changes: Populated only by
            :meth:`PolicyTestSuite.run_regression`.
        executed_at: Timestamp of the run.
    """

    total: int
    passed: int
    failed: int
    results: list[CaseResult]
    regression_changes: list[RegressionChange] = field(
        default_factory=list,
    )
    executed_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(),
    )

    @property
    def all_passed(self) -> bool:
        """True when every test case passed."""
        return self.failed == 0

    @property
    def pass_rate(self) -> float:
        """Fraction of tests that passed (0.0 – 1.0)."""
        if self.total == 0:
            return 1.0
        return self.passed / self.total


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------


def _action_from_dict(d: dict[str, Any]) -> Action:
    """Build an :class:`Action` from a plain dictionary."""
    return Action(
        type=d.get("type", ""),
        target=d.get("target", ""),
        params=d.get("params", {}),
        description=d.get("description", ""),
        agent_id=d.get("agent_id", ""),
    )


def _evaluate_case(
    policy: Policy,
    case: PolicyTestCase,
) -> CaseResult:
    """Evaluate a single test case against a policy."""
    action = _action_from_dict(case.action)
    decision: PolicyDecision = policy.evaluate(action)

    actual_decision = decision.approval.value
    actual_risk = decision.risk_level.name.lower()

    errors: list[str] = []
    expected_decision = case.expected_decision.lower()
    if actual_decision != expected_decision:
        errors.append(f"decision: expected {expected_decision!r}, got {actual_decision!r}")

    if case.expected_risk_level:
        expected_risk = case.expected_risk_level.lower()
        if actual_risk != expected_risk:
            errors.append(f"risk_level: expected {expected_risk!r}, got {actual_risk!r}")

    passed = len(errors) == 0
    message = "; ".join(errors) if errors else ""
    return CaseResult(
        test_case=case,
        passed=passed,
        actual_decision=actual_decision,
        actual_risk_level=actual_risk,
        message=message,
    )


# -------------------------------------------------------------------
# PolicyTestSuite
# -------------------------------------------------------------------


class PolicyTestSuite:
    """Collection of :class:`PolicyTestCase` instances with run methods.

    Thread-safe: all mutations to the internal test list are guarded
    by a :class:`threading.Lock`.

    Example::

        suite = PolicyTestSuite(name="CRM policy checks")
        suite.add_test(PolicyTestCase(
            action={"type": "read", "target": "crm"},
            expected_decision="auto",
        ))
        result = suite.run(policy)
        assert result.all_passed
    """

    def __init__(self, name: str = "") -> None:
        self.name = name
        self._cases: list[PolicyTestCase] = []
        self._lock = threading.Lock()

    # -- Mutation -------------------------------------------------

    def add_test(self, test_case: PolicyTestCase) -> None:
        """Append a test case to the suite.

        Raises:
            TypeError: If *test_case* is not a
                :class:`PolicyTestCase`.
        """
        if not isinstance(test_case, PolicyTestCase):
            raise TypeError(f"Expected PolicyTestCase, got {type(test_case).__name__}")
        with self._lock:
            self._cases.append(test_case)

    def add_test_from_dict(self, d: dict[str, Any]) -> None:
        """Create and add a :class:`PolicyTestCase` from a dict.

        Expected keys mirror the dataclass fields::

            {
                "action": {"type": "read", "target": "crm"},
                "expected_decision": "auto",
                "expected_risk_level": "low",  # optional
                "description": "Read CRM",     # optional
            }
        """
        if not isinstance(d, dict):
            raise TypeError(f"Expected dict, got {type(d).__name__}")
        action = d.get("action", {})
        if not isinstance(action, dict):
            raise TypeError("The 'action' key must be a dict")
        case = PolicyTestCase(
            action=action,
            expected_decision=d.get("expected_decision", "approve"),
            expected_risk_level=d.get("expected_risk_level", ""),
            description=d.get("description", ""),
        )
        self.add_test(case)

    @property
    def cases(self) -> list[PolicyTestCase]:
        """Return a snapshot of the current test cases."""
        with self._lock:
            return list(self._cases)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cases)

    # -- Execution ------------------------------------------------

    def run(self, policy: Policy) -> PolicyTestResult:
        """Run all test cases against *policy*.

        Returns a :class:`PolicyTestResult` summarising pass/fail.
        """
        with self._lock:
            snapshot = list(self._cases)

        results: list[CaseResult] = [_evaluate_case(policy, c) for c in snapshot]
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        return PolicyTestResult(
            total=len(results),
            passed=passed,
            failed=failed,
            results=results,
        )

    def run_regression(
        self,
        old_policy: Policy,
        new_policy: Policy,
    ) -> PolicyTestResult:
        """Compare outcomes between two policies.

        Runs each test case against both policies.  Cases where the
        *actual* decision or risk level differs are recorded as
        :class:`RegressionChange` entries.  The pass/fail counts
        reflect the **new** policy's results against expectations.
        """
        with self._lock:
            snapshot = list(self._cases)

        new_results: list[CaseResult] = []
        changes: list[RegressionChange] = []

        for case in snapshot:
            old_cr = _evaluate_case(old_policy, case)
            new_cr = _evaluate_case(new_policy, case)
            new_results.append(new_cr)

            if (
                old_cr.actual_decision != new_cr.actual_decision
                or old_cr.actual_risk_level != new_cr.actual_risk_level
            ):
                changes.append(
                    RegressionChange(
                        test_case=case,
                        old_decision=old_cr.actual_decision,
                        new_decision=new_cr.actual_decision,
                        old_risk_level=old_cr.actual_risk_level,
                        new_risk_level=new_cr.actual_risk_level,
                    )
                )

        passed = sum(1 for r in new_results if r.passed)
        failed = len(new_results) - passed
        return PolicyTestResult(
            total=len(new_results),
            passed=passed,
            failed=failed,
            results=new_results,
            regression_changes=changes,
        )

    # -- Loaders --------------------------------------------------

    @classmethod
    def load_from_yaml(cls, path: str | Path) -> PolicyTestSuite:
        """Load a test suite from a YAML file.

        Expected YAML structure::

            name: "My suite"
            tests:
              - action: {type: read, target: crm}
                expected_decision: auto
                expected_risk_level: low
                description: Read CRM auto-approves

        Returns an empty suite when ``yaml`` is unavailable.

        Raises:
            FileNotFoundError: If *path* does not exist.
        """
        try:
            import yaml  # noqa: PLC0415
        except ImportError:
            return cls()

        filepath = Path(path)
        if not filepath.exists():
            raise FileNotFoundError(f"Test suite file not found: {filepath}")

        with filepath.open() as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise TypeError(f"Expected mapping at top level, got {type(data).__name__}")

        suite = cls(name=data.get("name", ""))
        for entry in data.get("tests", []):
            suite.add_test_from_dict(entry)
        return suite

    # -- Generation -----------------------------------------------

    @classmethod
    def generate_from_policy(
        cls,
        policy: Policy,
        *,
        name: str = "",
    ) -> PolicyTestSuite:
        """Auto-generate test cases from a policy's rules.

        For each rule, a matching :class:`PolicyTestCase` is created
        whose ``expected_decision`` and ``expected_risk_level`` match
        the rule's configured values.  An additional case is added for
        the policy's default behaviour.

        This is useful as a starting point: generate, then customise.
        """
        suite = cls(
            name=name or "auto-generated",
        )

        for rule in policy.rules:
            action_dict: dict[str, Any] = {
                "type": rule.match_type,
                "target": rule.match_target,
            }
            if rule.match_agent != "*":
                action_dict["agent_id"] = rule.match_agent

            suite.add_test(
                PolicyTestCase(
                    action=action_dict,
                    expected_decision=rule.approval.value,
                    expected_risk_level=(rule.risk_level.name.lower()),
                    description=(
                        f"rule: {rule.name}"
                        if rule.name
                        else (f"rule: {rule.match_type}@{rule.match_target}")
                    ),
                )
            )

        # Default-behaviour case: use an unlikely action that
        # should fall through to the default.
        suite.add_test(
            PolicyTestCase(
                action={
                    "type": "__default_test__",
                    "target": "__default_test__",
                },
                expected_decision=(policy.default_approval.value),
                expected_risk_level=(policy.default_risk_level.name.lower()),
                description="default behaviour",
            )
        )

        return suite
