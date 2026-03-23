"""Adversarial policy probe — automated testing for governance gaps.

Generates adversarial test actions designed to find weaknesses in a policy:
boundary testing, glob bypass attempts, condition edge cases, and
escalation patterns.

Example::

    from aegis.core.probe import PolicyProbe

    probe = PolicyProbe()
    report = probe.run(policy)
    print(report.summary())
    # => 42 probes run, 3 potential gaps found

    for finding in report.findings:
        print(f"  {finding.severity}: {finding.description}")
"""

from __future__ import annotations

import dataclasses
import fnmatch
import itertools
import logging
from typing import Any

from aegis.core.action import Action
from aegis.core.policy import Approval, Policy, PolicyDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ProbeFinding:
    """A potential gap or weakness found during probing."""

    severity: str  # "low" | "medium" | "high" | "critical"
    category: str  # e.g. "glob_bypass", "missing_coverage", "escalation"
    description: str
    action: Action
    decision: PolicyDecision
    recommendation: str = ""


@dataclasses.dataclass
class ProbeReport:
    """Result of running a policy probe."""

    total_probes: int
    findings: list[ProbeFinding]
    probed_actions: list[tuple[Action, PolicyDecision]]

    @property
    def gap_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def score(self) -> int:
        """Policy robustness score (0-100). Higher = more robust."""
        if self.total_probes == 0:
            return 100
        penalty = sum(
            {"critical": 20, "high": 10, "medium": 5, "low": 2}.get(f.severity, 0)
            for f in self.findings
        )
        return max(0, 100 - penalty)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = [
            f"Probe Report: {self.total_probes} probes, {self.gap_count} findings",
            f"  Robustness score: {self.score}/100",
        ]
        if self.findings:
            by_severity: dict[str, list[ProbeFinding]] = {}
            for f in self.findings:
                by_severity.setdefault(f.severity, []).append(f)
            for sev in ["critical", "high", "medium", "low"]:
                items = by_severity.get(sev, [])
                if items:
                    lines.append(f"  {sev.upper()}: {len(items)}")
                    for item in items:
                        lines.append(f"    - {item.description}")
        else:
            lines.append("  No gaps found.")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Probe categories
# ---------------------------------------------------------------------------

# Common destructive action types that should be governed
_DESTRUCTIVE_TYPES = [
    "delete", "delete_all", "drop", "destroy", "remove", "purge",
    "truncate", "kill", "terminate", "format", "wipe",
]

# Common sensitive action types that should require approval
_SENSITIVE_TYPES = [
    "write", "update", "modify", "edit", "patch", "create",
    "send", "send_email", "post", "publish", "deploy",
    "transfer", "payment", "refund", "charge",
    "export", "download", "upload", "share",
]

# Common safe action types (should be auto-approved)
_SAFE_TYPES = [
    "read", "get", "list", "search", "query", "fetch", "view", "lookup",
]

# Common targets
_TARGETS = [
    "db", "database", "prod", "production", "staging", "crm",
    "filesystem", "api", "email", "users", "accounts",
]

# Glob bypass patterns — variants that might slip through naive globs
_BYPASS_SUFFIXES = ["", "_all", "_bulk", "_batch", "_force", "_admin", "_raw"]
_BYPASS_PREFIXES = ["", "bulk_", "batch_", "admin_", "force_", "unsafe_"]


class PolicyProbe:
    """Adversarial policy tester.

    Generates test actions that probe for common governance gaps:

    1. **Missing coverage**: Destructive actions not explicitly governed
    2. **Glob bypass**: Action variants that slip through glob patterns
    3. **Default fallthrough**: Actions hitting permissive defaults
    4. **Escalation**: Combining safe prefixes with destructive verbs
    5. **Target gaps**: Sensitive targets with permissive rules
    """

    def run(self, policy: Policy) -> ProbeReport:
        """Run all probe categories against the given policy.

        Args:
            policy: The policy to test.

        Returns:
            A :class:`ProbeReport` with findings and statistics.
        """
        probed: list[tuple[Action, PolicyDecision]] = []
        findings: list[ProbeFinding] = []

        # Run each probe category
        for probe_fn in [
            self._probe_destructive_coverage,
            self._probe_glob_bypass,
            self._probe_default_fallthrough,
            self._probe_escalation,
            self._probe_target_gaps,
            self._probe_wildcard_rules,
        ]:
            new_findings, new_probed = probe_fn(policy)
            findings.extend(new_findings)
            probed.extend(new_probed)

        return ProbeReport(
            total_probes=len(probed),
            findings=findings,
            probed_actions=probed,
        )

    def generate_probes(self, policy: Policy) -> list[Action]:
        """Generate adversarial actions without evaluating them.

        Useful for manual inspection or integration with other test tools.
        """
        actions: list[Action] = []
        actions.extend(self._gen_destructive_actions())
        actions.extend(self._gen_bypass_actions(policy))
        actions.extend(self._gen_escalation_actions())
        return actions

    # -- Probe: destructive coverage -----------------------------------------

    def _probe_destructive_coverage(
        self, policy: Policy
    ) -> tuple[list[ProbeFinding], list[tuple[Action, PolicyDecision]]]:
        """Check that all common destructive actions are blocked or governed."""
        findings: list[ProbeFinding] = []
        probed: list[tuple[Action, PolicyDecision]] = []

        for action_type in _DESTRUCTIVE_TYPES:
            for target in ["db", "production", "users"]:
                action = Action(type=action_type, target=target)
                decision = policy.evaluate(action)
                probed.append((action, decision))

                if decision.approval == Approval.AUTO:
                    findings.append(ProbeFinding(
                        severity="critical",
                        category="missing_coverage",
                        description=(
                            f"Destructive action '{action_type}' on '{target}' "
                            f"is auto-approved (no governance)"
                        ),
                        action=action,
                        decision=decision,
                        recommendation=(
                            f"Add a rule to block or require approval for "
                            f"'{action_type}' actions"
                        ),
                    ))
                elif decision.approval == Approval.APPROVE and not decision.matched_rule:
                    findings.append(ProbeFinding(
                        severity="high",
                        category="missing_coverage",
                        description=(
                            f"Destructive action '{action_type}' on '{target}' "
                            f"matched only the default rule"
                        ),
                        action=action,
                        decision=decision,
                        recommendation=(
                            f"Add an explicit rule for '{action_type}' actions"
                        ),
                    ))

        return findings, probed

    # -- Probe: glob bypass --------------------------------------------------

    def _probe_glob_bypass(
        self, policy: Policy
    ) -> tuple[list[ProbeFinding], list[tuple[Action, PolicyDecision]]]:
        """Try action variants that might bypass glob patterns."""
        findings: list[ProbeFinding] = []
        probed: list[tuple[Action, PolicyDecision]] = []

        # For each rule, try to find variants that bypass its glob
        governed_types: set[str] = set()
        for rule in policy.rules:
            governed_types.add(rule.match_type)

        for rule in policy.rules:
            if rule.approval != Approval.BLOCK:
                continue

            # This rule blocks something. Try bypass variants.
            base_type = rule.match_type.replace("*", "")
            for prefix in _BYPASS_PREFIXES:
                for suffix in _BYPASS_SUFFIXES:
                    if not prefix and not suffix:
                        continue
                    variant = f"{prefix}{base_type}{suffix}"
                    action = Action(type=variant, target="test")
                    decision = policy.evaluate(action)
                    probed.append((action, decision))

                    if decision.is_allowed and not any(
                        fnmatch.fnmatch(variant, gt) for gt in governed_types
                    ):
                        findings.append(ProbeFinding(
                            severity="high",
                            category="glob_bypass",
                            description=(
                                f"'{variant}' bypasses block rule '{rule.name}' "
                                f"(pattern: '{rule.match_type}') — "
                                f"got {decision.approval.value}"
                            ),
                            action=action,
                            decision=decision,
                            recommendation=(
                                f"Broaden the glob pattern or add a rule for "
                                f"'{variant}'"
                            ),
                        ))

        return findings, probed

    # -- Probe: default fallthrough ------------------------------------------

    def _probe_default_fallthrough(
        self, policy: Policy
    ) -> tuple[list[ProbeFinding], list[tuple[Action, PolicyDecision]]]:
        """Check if sensitive actions fall through to permissive defaults."""
        findings: list[ProbeFinding] = []
        probed: list[tuple[Action, PolicyDecision]] = []

        for action_type in _SENSITIVE_TYPES:
            action = Action(type=action_type, target="default_target")
            decision = policy.evaluate(action)
            probed.append((action, decision))

            if decision.approval == Approval.AUTO and not decision.matched_rule:
                findings.append(ProbeFinding(
                    severity="medium",
                    category="default_fallthrough",
                    description=(
                        f"Sensitive action '{action_type}' hits permissive "
                        f"default (auto-approved, no explicit rule)"
                    ),
                    action=action,
                    decision=decision,
                    recommendation=(
                        f"Add an explicit rule for '{action_type}' or tighten "
                        f"the default approval to 'approve'"
                    ),
                ))

        return findings, probed

    # -- Probe: escalation ---------------------------------------------------

    def _probe_escalation(
        self, policy: Policy
    ) -> tuple[list[ProbeFinding], list[tuple[Action, PolicyDecision]]]:
        """Try escalation patterns combining safe + destructive verbs."""
        findings: list[ProbeFinding] = []
        probed: list[tuple[Action, PolicyDecision]] = []

        escalation_types = [
            "read_then_delete", "search_and_destroy", "list_and_purge",
            "get_admin_access", "view_then_export", "query_and_transfer",
            "read_delete", "safe_destroy", "auto_purge", "quick_drop",
        ]

        for action_type in escalation_types:
            action = Action(type=action_type, target="production")
            decision = policy.evaluate(action)
            probed.append((action, decision))

            if decision.is_allowed:
                findings.append(ProbeFinding(
                    severity="medium",
                    category="escalation",
                    description=(
                        f"Escalation pattern '{action_type}' is allowed "
                        f"({decision.approval.value}) — may hide destructive intent"
                    ),
                    action=action,
                    decision=decision,
                    recommendation=(
                        "Consider adding semantic conditions to detect "
                        "compound destructive patterns"
                    ),
                ))

        return findings, probed

    # -- Probe: target gaps --------------------------------------------------

    def _probe_target_gaps(
        self, policy: Policy
    ) -> tuple[list[ProbeFinding], list[tuple[Action, PolicyDecision]]]:
        """Check if sensitive targets are adequately protected."""
        findings: list[ProbeFinding] = []
        probed: list[tuple[Action, PolicyDecision]] = []

        sensitive_targets = ["production", "prod_db", "users_pii", "financial", "credentials"]
        risky_types = ["write", "update", "delete", "export"]

        for target, action_type in itertools.product(sensitive_targets, risky_types):
            action = Action(type=action_type, target=target)
            decision = policy.evaluate(action)
            probed.append((action, decision))

            if decision.approval == Approval.AUTO:
                findings.append(ProbeFinding(
                    severity="high",
                    category="target_gap",
                    description=(
                        f"'{action_type}' on sensitive target '{target}' "
                        f"is auto-approved"
                    ),
                    action=action,
                    decision=decision,
                    recommendation=(
                        f"Add a target-specific rule for '{target}'"
                    ),
                ))

        return findings, probed

    # -- Probe: wildcard rules -----------------------------------------------

    def _probe_wildcard_rules(
        self, policy: Policy
    ) -> tuple[list[ProbeFinding], list[tuple[Action, PolicyDecision]]]:
        """Warn about overly permissive wildcard rules."""
        findings: list[ProbeFinding] = []
        probed: list[tuple[Action, PolicyDecision]] = []

        for rule in policy.rules:
            if rule.match_type == "*" and rule.approval == Approval.AUTO:
                action = Action(type="any_action", target="any_target")
                decision = policy.evaluate(action)
                probed.append((action, decision))
                findings.append(ProbeFinding(
                    severity="critical",
                    category="overly_permissive",
                    description=(
                        f"Rule '{rule.name}' auto-approves ALL actions "
                        f"(match type='*')"
                    ),
                    action=action,
                    decision=decision,
                    recommendation=(
                        "Replace wildcard auto-approve with specific rules, "
                        "or change default to 'approve'"
                    ),
                ))

        return findings, probed

    # -- Action generators (for generate_probes) ------------------------------

    @staticmethod
    def _gen_destructive_actions() -> list[Action]:
        actions = []
        for t in _DESTRUCTIVE_TYPES:
            for target in ["db", "production"]:
                actions.append(Action(type=t, target=target))
        return actions

    @staticmethod
    def _gen_bypass_actions(policy: Policy) -> list[Action]:
        actions = []
        for rule in policy.rules:
            if rule.approval != Approval.BLOCK:
                continue
            base = rule.match_type.replace("*", "")
            for prefix in _BYPASS_PREFIXES:
                for suffix in _BYPASS_SUFFIXES:
                    if not prefix and not suffix:
                        continue
                    actions.append(Action(
                        type=f"{prefix}{base}{suffix}", target="test"
                    ))
        return actions

    @staticmethod
    def _gen_escalation_actions() -> list[Action]:
        return [
            Action(type=t, target="production")
            for t in [
                "read_then_delete", "search_and_destroy",
                "list_and_purge", "get_admin_access",
                "view_then_export", "safe_destroy",
            ]
        ]
