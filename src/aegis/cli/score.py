"""Governance score calculator for Aegis policy files.

Analyzes a policy YAML and produces a 0–100 numeric score,
a letter grade, and a shields.io badge URL.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# Destructive action prefixes that a good policy should block.
_DESTRUCTIVE_PREFIXES = ("delete_", "drop_", "admin_", "delete*", "drop*", "admin*")

# Common action type prefixes a well-rounded policy should cover.
_COMMON_ACTIONS = ("read", "write", "update", "delete", "create", "list", "get")

# Time-related condition keys recognised by the conditions engine.
_TIME_CONDITION_KEYS = frozenset({"time_after", "time_before", "weekdays"})


@dataclass
class ScoreBreakdown:
    """Individual scoring criterion."""

    label: str
    points: int
    max_points: int
    passed: bool


@dataclass
class ScoreResult:
    """Aggregate governance score."""

    total: int
    grade: str
    breakdown: list[ScoreBreakdown]
    rule_count: int

    @property
    def badge_color(self) -> str:
        """Shields.io color token based on grade."""
        if self.grade in ("A+", "A"):
            return "brightgreen"
        if self.grade == "B":
            return "green"
        if self.grade == "C":
            return "yellow"
        if self.grade == "D":
            return "orange"
        return "red"

    @property
    def badge_url(self) -> str:
        """Shields.io badge image URL."""
        label = urllib.parse.quote("aegis governance", safe="")
        score_text = urllib.parse.quote(f"{self.grade} ({self.total}%)", safe="()")
        return f"https://img.shields.io/badge/{label}-{score_text}-{self.badge_color}"

    @property
    def badge_markdown(self) -> str:
        """Full Markdown badge with link to the Aegis repo."""
        return f"[![Aegis Governance]({self.badge_url})](https://github.com/Acacian/aegis)"


def _to_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


# -- criterion helpers -------------------------------------------------------


def _has_destructive_blocks(rules: list[dict[str, Any]]) -> bool:
    """Return True if any rule blocks destructive actions."""
    for rule in rules:
        match = rule.get("match", {})
        match_type: str = match.get("type", "*")
        approval: str = rule.get("approval", "")
        if approval == "block" and any(
            match_type.startswith(p.rstrip("*")) for p in _DESTRUCTIVE_PREFIXES
        ):
            return True
    return False


def _has_approval_gates(rules: list[dict[str, Any]]) -> bool:
    """Return True if high/critical risk rules require human approval."""
    for rule in rules:
        risk: str = rule.get("risk_level", "").lower()
        approval: str = rule.get("approval", "")
        if risk in ("high", "critical") and approval in ("approve", "block"):
            return True
    return False


def _has_time_conditions(rules: list[dict[str, Any]]) -> bool:
    """Return True if any rule uses time-based conditions."""
    for rule in rules:
        conditions: dict[str, Any] = rule.get("conditions", {}) or {}
        if _TIME_CONDITION_KEYS & set(conditions):
            return True
    return False


def _uses_multiple_risk_levels(
    rules: list[dict[str, Any]],
    defaults: dict[str, Any],
) -> bool:
    """Return True if at least two distinct risk levels are used."""
    levels: set[str] = set()
    default_level = (defaults.get("risk_level") or "medium").lower()
    levels.add(default_level)
    for rule in rules:
        levels.add((rule.get("risk_level") or "medium").lower())
    return len(levels) >= 2


def _action_coverage_score(rules: list[dict[str, Any]]) -> int:
    """Return coverage points: +15 if >=5 common actions covered, else +5."""
    covered = 0
    for action in _COMMON_ACTIONS:
        for rule in rules:
            match = rule.get("match", {})
            match_type: str = match.get("type", "*")
            # A rule covers an action if its pattern starts with the action prefix.
            if match_type.startswith(action):
                covered += 1
                break
    if covered >= 5:
        return 15
    if covered >= 1:
        return 5
    return 0


def _has_specific_patterns(rules: list[dict[str, Any]]) -> bool:
    """Return True if rules use specific patterns (not just '*')."""
    for rule in rules:
        match = rule.get("match", {})
        if match.get("type", "*") != "*" or match.get("target", "*") != "*":
            return True
    return False


def _has_restrictive_defaults(defaults: dict[str, Any]) -> bool:
    """Return True if defaults lean toward restriction."""
    approval = (defaults.get("approval") or "").lower()
    risk = (defaults.get("risk_level") or "").lower()
    return approval in ("approve", "block") or risk in ("high", "critical")


def _rule_count_bonus(count: int) -> int:
    """Bonus points for rule quantity: +5 for 5+, +10 for 10+."""
    if count >= 10:
        return 10
    if count >= 5:
        return 5
    return 0


# -- public API --------------------------------------------------------------


def calculate_score(policy_path: str | Path) -> ScoreResult:
    """Load a policy YAML and calculate its governance score."""
    path = Path(policy_path)
    with path.open() as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}

    rules: list[dict[str, Any]] = data.get("rules") or []
    defaults: dict[str, Any] = data.get("defaults") or {}
    rule_count = len(rules)

    breakdown: list[ScoreBreakdown] = []

    # 1. Destructive actions blocked (+20)
    destructive = _has_destructive_blocks(rules)
    breakdown.append(
        ScoreBreakdown("Destructive actions blocked", 20 if destructive else 0, 20, destructive)
    )

    # 2. Human approval gates (+15)
    approval_gates = _has_approval_gates(rules)
    breakdown.append(
        ScoreBreakdown("Human approval gates", 15 if approval_gates else 0, 15, approval_gates)
    )

    # 3. Time-based conditions (+10)
    time_conds = _has_time_conditions(rules)
    breakdown.append(
        ScoreBreakdown("Time-based conditions", 10 if time_conds else 0, 10, time_conds)
    )

    # 4. Multi-tier risk levels (+10)
    multi_risk = _uses_multiple_risk_levels(rules, defaults)
    breakdown.append(
        ScoreBreakdown("Multi-tier risk levels", 10 if multi_risk else 0, 10, multi_risk)
    )

    # 5. Action coverage (+5 or +15)
    cov = _action_coverage_score(rules)
    cov_label = "Broad action coverage" if cov >= 15 else "Limited action coverage"
    breakdown.append(ScoreBreakdown(cov_label, cov, 15, cov >= 15))

    # 6. Specific patterns (+10)
    specific = _has_specific_patterns(rules)
    breakdown.append(ScoreBreakdown("Specific patterns", 10 if specific else 0, 10, specific))

    # 7. Restrictive defaults (+10)
    restrictive = _has_restrictive_defaults(defaults)
    breakdown.append(
        ScoreBreakdown("Restrictive defaults", 10 if restrictive else 0, 10, restrictive)
    )

    # 8. Rule count bonus (+5 or +10)
    rc_bonus = _rule_count_bonus(rule_count)
    rc_label = f"{rule_count} rules"
    breakdown.append(ScoreBreakdown(rc_label, rc_bonus, 10, rc_bonus >= 5))

    total = min(sum(b.points for b in breakdown), 100)
    grade = _to_grade(total)

    return ScoreResult(
        total=total,
        grade=grade,
        breakdown=breakdown,
        rule_count=rule_count,
    )
