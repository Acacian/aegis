"""Policy-as-code Git integration.

Bridges Aegis policy versioning with Git workflows. Provides:

- **Diff formatting** — Renders :class:`PolicyDelta` as human-readable
  text or Markdown suitable for PR comments.
- **Impact analysis** — Given a policy change, reports which agents
  and action types are affected.
- **Drift detection** — Compares a policy YAML file on disk with the
  running policy to detect configuration drift.
- **Policy export** — Serialises a policy to YAML for version control.

Usage::

    from aegis.core.policy_git import PolicyDiffFormatter, PolicyDriftDetector

    # Format a diff for a PR comment
    formatter = PolicyDiffFormatter()
    markdown = formatter.to_markdown(delta)

    # Detect drift between YAML and running policy
    detector = PolicyDriftDetector()
    drift = detector.detect("policy.yaml", running_policy)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.core.versioning import PolicyDelta, PolicyStore, _policy_to_dict

# ---------------------------------------------------------------------------
# Diff formatter
# ---------------------------------------------------------------------------


class PolicyDiffFormatter:
    """Renders :class:`PolicyDelta` objects in multiple output formats.

    Supports plain text and Markdown (for PR comments / CI output).
    """

    def to_text(self, delta: PolicyDelta) -> str:
        """Render a policy delta as plain text."""
        lines: list[str] = []
        lines.append(f"Policy Diff: {delta.version_from[:8]} → {delta.version_to[:8]}")
        lines.append("-" * 50)

        if delta.rules_added:
            lines.append(f"\n+ Rules Added ({len(delta.rules_added)}):")
            for name in delta.rules_added:
                lines.append(f"  + {name}")

        if delta.rules_removed:
            lines.append(f"\n- Rules Removed ({len(delta.rules_removed)}):")
            for name in delta.rules_removed:
                lines.append(f"  - {name}")

        if delta.rules_modified:
            lines.append(f"\n~ Rules Modified ({len(delta.rules_modified)}):")
            for name in delta.rules_modified:
                lines.append(f"  ~ {name}")

        if delta.defaults_changed:
            lines.append("\n~ Defaults Changed:")
            for key, (old, new) in sorted(delta.defaults_changed.items()):
                lines.append(f"  {key}: {old} → {new}")

        if not (delta.rules_added or delta.rules_removed or delta.rules_modified
                or delta.defaults_changed):
            lines.append("\nNo changes detected.")

        return "\n".join(lines)

    def to_markdown(self, delta: PolicyDelta) -> str:
        """Render a policy delta as Markdown (suitable for PR comments)."""
        lines: list[str] = []
        lines.append(f"### Policy Diff: `{delta.version_from[:8]}` → `{delta.version_to[:8]}`")
        lines.append("")

        has_changes = bool(
            delta.rules_added or delta.rules_removed
            or delta.rules_modified or delta.defaults_changed
        )

        if not has_changes:
            lines.append("No policy changes detected.")
            return "\n".join(lines)

        # Summary counts
        summary_parts: list[str] = []
        if delta.rules_added:
            summary_parts.append(f"+{len(delta.rules_added)} added")
        if delta.rules_removed:
            summary_parts.append(f"-{len(delta.rules_removed)} removed")
        if delta.rules_modified:
            summary_parts.append(f"~{len(delta.rules_modified)} modified")
        lines.append(f"**Summary:** {', '.join(summary_parts)}")
        lines.append("")

        if delta.rules_added:
            lines.append("#### Added Rules")
            for name in delta.rules_added:
                lines.append(f"- `{name}`")
            lines.append("")

        if delta.rules_removed:
            lines.append("#### Removed Rules")
            for name in delta.rules_removed:
                lines.append(f"- ~~`{name}`~~")
            lines.append("")

        if delta.rules_modified:
            lines.append("#### Modified Rules")
            for name in delta.rules_modified:
                lines.append(f"- `{name}`")
            lines.append("")

        if delta.defaults_changed:
            lines.append("#### Default Changes")
            lines.append("| Setting | Before | After |")
            lines.append("|---------|--------|-------|")
            for key, (old, new) in sorted(delta.defaults_changed.items()):
                lines.append(f"| `{key}` | `{old}` | `{new}` |")
            lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Impact analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ImpactReport:
    """Result of analysing the impact of a policy change.

    Attributes:
        affected_action_types: Action types whose governance changes.
        newly_blocked: Action types that will be blocked after the change.
        newly_allowed: Action types that will be allowed after the change.
        risk_escalations: Rules where risk level increased.
        risk_deescalations: Rules where risk level decreased.
        approval_changes: Rules where approval requirement changed.
        severity: Overall change severity (info / warning / critical).
    """

    affected_action_types: list[str] = field(default_factory=list)
    newly_blocked: list[str] = field(default_factory=list)
    newly_allowed: list[str] = field(default_factory=list)
    risk_escalations: list[str] = field(default_factory=list)
    risk_deescalations: list[str] = field(default_factory=list)
    approval_changes: list[str] = field(default_factory=list)
    severity: str = "info"


class PolicyImpactAnalyzer:
    """Analyses the impact of a policy change using two policy dicts."""

    def analyze(
        self,
        old_policy: dict[str, Any],
        new_policy: dict[str, Any],
    ) -> ImpactReport:
        """Compare two policy dicts and produce an impact report.

        Args:
            old_policy: Previous policy as a dict (from ``_policy_to_dict``).
            new_policy: New policy as a dict.

        Returns:
            An :class:`ImpactReport` describing the impact.
        """
        old_rules = {
            str(r.get("name", "")): r
            for r in old_policy.get("rules", [])
        }
        new_rules = {
            str(r.get("name", "")): r
            for r in new_policy.get("rules", [])
        }

        affected: list[str] = []
        newly_blocked: list[str] = []
        newly_allowed: list[str] = []
        risk_escalations: list[str] = []
        risk_deescalations: list[str] = []
        approval_changes: list[str] = []

        # Added rules
        for name in sorted(set(new_rules) - set(old_rules)):
            affected.append(name)
            rule = new_rules[name]
            if _is_blocking(rule):
                newly_blocked.append(name)

        # Removed rules
        for name in sorted(set(old_rules) - set(new_rules)):
            affected.append(name)
            if _is_blocking(old_rules[name]):
                newly_allowed.append(name)

        # Modified rules
        _RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        for name in sorted(set(old_rules) & set(new_rules)):
            old_r = old_rules[name]
            new_r = new_rules[name]
            if old_r == new_r:
                continue
            affected.append(name)

            old_risk = str(old_r.get("risk_level", "medium")).lower()
            new_risk = str(new_r.get("risk_level", "medium")).lower()
            if _RISK_ORDER.get(new_risk, 1) > _RISK_ORDER.get(old_risk, 1):
                risk_escalations.append(name)
            elif _RISK_ORDER.get(new_risk, 1) < _RISK_ORDER.get(old_risk, 1):
                risk_deescalations.append(name)

            old_approval = str(old_r.get("approval", "auto"))
            new_approval = str(new_r.get("approval", "auto"))
            if old_approval != new_approval:
                approval_changes.append(name)

            if _is_blocking(new_r) and not _is_blocking(old_r):
                newly_blocked.append(name)
            elif _is_blocking(old_r) and not _is_blocking(new_r):
                newly_allowed.append(name)

        # Determine severity
        severity = "info"
        if newly_blocked or risk_escalations:
            severity = "warning"
        if len(newly_blocked) > 3 or len(risk_escalations) > 3:
            severity = "critical"

        return ImpactReport(
            affected_action_types=affected,
            newly_blocked=newly_blocked,
            newly_allowed=newly_allowed,
            risk_escalations=risk_escalations,
            risk_deescalations=risk_deescalations,
            approval_changes=approval_changes,
            severity=severity,
        )


def _is_blocking(rule: dict[str, Any]) -> bool:
    """Check if a rule blocks actions."""
    return str(rule.get("approval", "")).lower() == "block"


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftResult:
    """Result of comparing on-disk policy with running policy.

    Attributes:
        has_drift: ``True`` if the policies differ.
        file_hash: Hash of the on-disk policy.
        running_hash: Hash of the running policy.
        delta: Detailed delta if drift is detected.
    """

    has_drift: bool
    file_hash: str
    running_hash: str
    delta: PolicyDelta | None = None


class PolicyDriftDetector:
    """Detects configuration drift between on-disk YAML and running policy.

    Compares a policy YAML file on disk with a running policy object
    to identify undeployed changes or runtime modifications.
    """

    def detect(self, yaml_path: str | Path, running_policy: object) -> DriftResult:
        """Compare on-disk policy with the running policy.

        Args:
            yaml_path: Path to the policy YAML file.
            running_policy: The currently running Policy object.

        Returns:
            A :class:`DriftResult` indicating whether drift exists.
        """
        from aegis.core.policy import Policy

        yaml_path = Path(yaml_path)
        file_policy = Policy.from_yaml(str(yaml_path))

        file_dict = _policy_to_dict(file_policy)
        running_dict = _policy_to_dict(running_policy)

        from aegis.core.versioning import _hash_dict
        file_hash = _hash_dict(file_dict)
        running_hash = _hash_dict(running_dict)

        if file_hash == running_hash:
            return DriftResult(
                has_drift=False,
                file_hash=file_hash,
                running_hash=running_hash,
            )

        # Build a delta using PolicyStore
        store = PolicyStore()
        # Commit both as versions to get a diff
        v1 = store.commit(running_policy, "running", "Running policy")
        v2 = store.commit(file_policy, "file", "On-disk policy")
        delta = store.diff(v1.version_id, v2.version_id)

        return DriftResult(
            has_drift=True,
            file_hash=file_hash,
            running_hash=running_hash,
            delta=delta,
        )

    def detect_from_dicts(
        self,
        file_dict: dict[str, Any],
        running_dict: dict[str, Any],
    ) -> DriftResult:
        """Compare two policy dicts directly (no YAML parsing needed).

        Args:
            file_dict: Policy dict from the YAML file.
            running_dict: Policy dict from the running policy.

        Returns:
            A :class:`DriftResult`.
        """
        from aegis.core.versioning import _hash_dict

        file_hash = _hash_dict(file_dict)
        running_hash = _hash_dict(running_dict)

        if file_hash == running_hash:
            return DriftResult(
                has_drift=False,
                file_hash=file_hash,
                running_hash=running_hash,
            )

        # Build delta from dicts
        names_a = {str(r.get("name", "")) for r in running_dict.get("rules", [])}
        names_b = {str(r.get("name", "")) for r in file_dict.get("rules", [])}

        rules_a = {str(r.get("name", "")): r for r in running_dict.get("rules", [])}
        rules_b = {str(r.get("name", "")): r for r in file_dict.get("rules", [])}

        modified = [
            name for name in sorted(names_a & names_b)
            if rules_a[name] != rules_b[name]
        ]

        defaults_a = running_dict.get("defaults", {})
        defaults_b = file_dict.get("defaults", {})
        defaults_changed: dict[str, tuple[str, str]] = {}
        for key in set(defaults_a) | set(defaults_b):
            old_val = str(defaults_a.get(key, ""))
            new_val = str(defaults_b.get(key, ""))
            if old_val != new_val:
                defaults_changed[key] = (old_val, new_val)

        delta = PolicyDelta(
            version_from=running_hash[:8],
            version_to=file_hash[:8],
            rules_added=sorted(names_b - names_a),
            rules_removed=sorted(names_a - names_b),
            rules_modified=modified,
            defaults_changed=defaults_changed,
        )

        return DriftResult(
            has_drift=True,
            file_hash=file_hash,
            running_hash=running_hash,
            delta=delta,
        )


# ---------------------------------------------------------------------------
# Policy export
# ---------------------------------------------------------------------------


def export_policy_yaml(policy: object) -> str:
    """Serialise a Policy object to YAML string for version control.

    Uses the policy-to-dict conversion and formats as YAML.
    Does not require ``pyyaml`` — uses a simple built-in formatter.

    Args:
        policy: A Policy object.

    Returns:
        YAML-formatted string.
    """
    policy_dict = _policy_to_dict(policy)
    return _dict_to_yaml(policy_dict)


def _dict_to_yaml(d: dict[str, Any], indent: int = 0) -> str:
    """Minimal YAML formatter (no pyyaml dependency)."""
    lines: list[str] = []
    prefix = "  " * indent
    for key, value in d.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            lines.append(_dict_to_yaml(value, indent + 1))
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    lines.append(f"{prefix}  -")
                    for k, v in item.items():
                        if isinstance(v, dict):
                            lines.append(f"{prefix}    {k}:")
                            lines.append(_dict_to_yaml(v, indent + 3))
                        else:
                            lines.append(f"{prefix}    {k}: {v}")
                else:
                    lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{key}: {value}")
    return "\n".join(lines)
