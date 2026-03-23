"""Compliance report generator for audit logs.

Generates structured compliance reports (SOC2, GDPR, governance)
from Aegis audit log data. Designed for enterprise audit workflows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aegis.core.policy import Policy


def _html_escape(text: str) -> str:
    """Escape HTML special characters in *text*."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


@dataclass
class ComplianceFinding:
    """A single finding within a compliance report.

    Attributes:
        severity: One of ``"critical"``, ``"warning"``, or ``"info"``.
        category: Finding category (e.g. ``"access_control"``, ``"audit_trail"``).
        title: Short title for the finding.
        description: Detailed explanation.
        recommendation: Suggested remediation step.
    """

    severity: str  # "critical", "warning", "info"
    category: str  # "access_control", "audit_trail", "data_handling"
    title: str
    description: str
    recommendation: str


@dataclass
class ComplianceReport:
    """Structured compliance report generated from audit log data.

    Attributes:
        report_type: One of ``"soc2"``, ``"gdpr"``, ``"governance"``, ``"custom"``.
        generated_at: When the report was generated.
        period_start: Start of the audit period.
        period_end: End of the audit period.
        total_actions: Total number of audited actions.
        blocked_actions: Actions blocked by policy.
        approved_actions: Actions that required and received human approval.
        auto_approved: Actions auto-approved by policy.
        summary: Human-readable summary paragraph.
        findings: List of compliance findings.
        score: Numeric score from 0 to 100.
        grade: Letter grade from ``"A+"`` through ``"F"``.
    """

    report_type: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_actions: int
    blocked_actions: int
    approved_actions: int
    auto_approved: int
    summary: str
    findings: list[ComplianceFinding] = field(default_factory=list)
    score: int = 0
    grade: str = "F"


def _compute_grade(score: int) -> str:
    """Map a numeric score (0-100) to a letter grade."""
    if score >= 97:
        return "A+"
    if score >= 93:
        return "A"
    if score >= 90:
        return "A-"
    if score >= 87:
        return "B+"
    if score >= 83:
        return "B"
    if score >= 80:
        return "B-"
    if score >= 77:
        return "C+"
    if score >= 73:
        return "C"
    if score >= 70:
        return "C-"
    if score >= 67:
        return "D+"
    if score >= 63:
        return "D"
    if score >= 60:
        return "D-"
    return "F"


def _parse_timestamp(value: str | datetime | None) -> datetime | None:
    """Parse an ISO-format string to datetime, pass through datetime objects."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        # Handle both with and without timezone
        ts = value.replace("Z", "+00:00") if value.endswith("Z") else value
        return datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        return None


def _filter_by_period(
    entries: list[dict[str, Any]],
    period_start: datetime | None,
    period_end: datetime | None,
) -> list[dict[str, Any]]:
    """Filter audit entries to the requested time period."""
    if period_start is None and period_end is None:
        return entries
    filtered = []
    for entry in entries:
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is None:
            continue
        # Ensure naive datetimes are treated as UTC for comparison
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        start = period_start
        end = period_end
        if start and start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
        if end and end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
        if start and ts < start:
            continue
        if end and ts > end:
            continue
        filtered.append(entry)
    return filtered


def _count_by_approval(entries: list[dict[str, Any]]) -> dict[str, int]:
    """Count entries by approval field value."""
    counts: dict[str, int] = {"auto": 0, "approve": 0, "block": 0}
    for entry in entries:
        approval = str(entry.get("approval", "")).lower()
        if approval in counts:
            counts[approval] += 1
    return counts


def _count_by_risk(entries: list[dict[str, Any]]) -> dict[str, int]:
    """Count entries by risk_level field value."""
    counts: dict[str, int] = {}
    for entry in entries:
        level = str(entry.get("risk_level", "UNKNOWN")).upper()
        counts[level] = counts.get(level, 0) + 1
    return counts


def _count_by_agent(entries: list[dict[str, Any]]) -> dict[str, int]:
    """Count entries by agent_id."""
    counts: dict[str, int] = {}
    for entry in entries:
        agent = str(entry.get("agent_id") or "unknown")
        counts[agent] = counts.get(agent, 0) + 1
    return counts


def _count_by_action_type(entries: list[dict[str, Any]]) -> dict[str, int]:
    """Count entries by action_type."""
    counts: dict[str, int] = {}
    for entry in entries:
        atype = str(entry.get("action_type", "unknown"))
        counts[atype] = counts.get(atype, 0) + 1
    return counts


def _detect_audit_gaps(entries: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Detect gaps of >1 hour in the audit timeline.

    Returns list of (gap_start, gap_end) ISO timestamp pairs.
    """
    if len(entries) < 2:
        return []
    timestamps = []
    for entry in entries:
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is not None:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            timestamps.append(ts)
    timestamps.sort()
    gaps = []
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
        if delta > 3600:  # >1 hour gap
            gaps.append((timestamps[i - 1].isoformat(), timestamps[i].isoformat()))
    return gaps


def _infer_period(
    entries: list[dict[str, Any]],
    period_start: datetime | None,
    period_end: datetime | None,
) -> tuple[datetime, datetime]:
    """Infer period boundaries from entries when not explicitly given."""
    now = datetime.now(UTC)
    if period_start and period_end:
        return period_start, period_end

    timestamps = []
    for entry in entries:
        ts = _parse_timestamp(entry.get("timestamp"))
        if ts is not None:
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            timestamps.append(ts)

    if not timestamps:
        return period_start or now, period_end or now

    timestamps.sort()
    return period_start or timestamps[0], period_end or timestamps[-1]


# ---------------------------------------------------------------------------
# SOC2 report builder
# ---------------------------------------------------------------------------


def _generate_soc2(
    entries: list[dict[str, Any]],
    policy: Policy,
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a SOC2 Trust Services Criteria compliance report."""
    total = len(entries)
    approval_counts = _count_by_approval(entries)
    blocked = approval_counts["block"]
    approved = approval_counts["approve"]
    auto = approval_counts["auto"]

    findings: list[ComplianceFinding] = []
    score = 100

    # CC6.1 — Logical Access Security
    # Every action should have been evaluated against policy
    policy_evaluated = sum(1 for e in entries if e.get("matched_rule"))
    eval_pct = (policy_evaluated / total * 100) if total else 100.0
    if eval_pct >= 100.0:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="access_control",
                title="CC6.1 -- Logical Access Security: PASS",
                description=(
                    f"All {total:,} actions were evaluated against policy rules before execution."
                ),
                recommendation="Continue enforcing policy on all actions.",
            )
        )
    else:
        score -= 20
        findings.append(
            ComplianceFinding(
                severity="critical",
                category="access_control",
                title="CC6.1 -- Logical Access Security: FAIL",
                description=(
                    f"Only {eval_pct:.1f}% of actions ({policy_evaluated:,}/{total:,}) "
                    f"had policy evaluation. {total - policy_evaluated:,} actions "
                    f"bypassed policy."
                ),
                recommendation="Ensure all action paths go through the Aegis policy engine.",
            )
        )

    # CC6.8 — Unauthorized Access Prevention
    # Blocked actions should be >0 if there are high/critical risk actions
    bypass_count = sum(
        1
        for e in entries
        if str(e.get("risk_level", "")).upper() in ("HIGH", "CRITICAL")
        and str(e.get("approval", "")).lower() == "auto"
    )
    if bypass_count == 0:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="access_control",
                title="CC6.8 -- Unauthorized Access Prevention: PASS",
                description=(
                    f"{blocked:,} unauthorized access attempts were blocked. 0 bypasses detected."
                ),
                recommendation="Maintain current blocking policies.",
            )
        )
    else:
        score -= 25
        findings.append(
            ComplianceFinding(
                severity="critical",
                category="access_control",
                title="CC6.8 -- Unauthorized Access Prevention: FAIL",
                description=(
                    f"{bypass_count:,} high/critical-risk actions were auto-approved "
                    f"without human review."
                ),
                recommendation=(
                    "Review policy rules to require human approval for "
                    "high and critical risk actions."
                ),
            )
        )

    # CC7.2 — System Monitoring
    # Check for audit gaps (>1 hour without entries)
    gaps = _detect_audit_gaps(entries)
    if not gaps:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="audit_trail",
                title="CC7.2 -- System Monitoring: PASS",
                description="Continuous audit coverage with no gaps detected.",
                recommendation="Continue maintaining comprehensive audit logging.",
            )
        )
    else:
        penalty = min(15, len(gaps) * 5)
        score -= penalty
        findings.append(
            ComplianceFinding(
                severity="warning",
                category="audit_trail",
                title="CC7.2 -- System Monitoring: WARN",
                description=(
                    f"{len(gaps)} audit gap(s) detected (periods >1 hour with no logged activity)."
                ),
                recommendation=(
                    "Investigate monitoring gaps. Consider adding heartbeat "
                    "logging to detect system downtime."
                ),
            )
        )

    # CC8.1 — Change Management
    # Policy changes should be tracked (look for policy-related action types)
    policy_changes = [
        e
        for e in entries
        if "policy" in str(e.get("action_type", "")).lower()
        or "config" in str(e.get("action_type", "")).lower()
    ]
    if total > 0 and policy_changes:
        all_logged = all(e.get("matched_rule") for e in policy_changes)
        if all_logged:
            findings.append(
                ComplianceFinding(
                    severity="info",
                    category="audit_trail",
                    title="CC8.1 -- Change Management: PASS",
                    description=(
                        f"{len(policy_changes):,} policy/config changes detected, "
                        f"all logged with rule matches."
                    ),
                    recommendation="Continue tracking configuration changes.",
                )
            )
        else:
            score -= 10
            findings.append(
                ComplianceFinding(
                    severity="warning",
                    category="audit_trail",
                    title="CC8.1 -- Change Management: WARN",
                    description=(
                        f"{len(policy_changes):,} policy/config changes detected, "
                        f"but some lacked rule matches."
                    ),
                    recommendation="Add policy rules to cover configuration change actions.",
                )
            )
    else:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="audit_trail",
                title="CC8.1 -- Change Management: PASS",
                description="No policy/config change actions detected in the audit period.",
                recommendation="No action required.",
            )
        )

    score = max(0, min(100, score))
    pct_blocked = (blocked / total * 100) if total else 0.0
    pct_approved = (approved / total * 100) if total else 0.0
    enforcement_pct = eval_pct

    summary = (
        f"Total actions evaluated: {total:,}. "
        f"Policy enforcement rate: {enforcement_pct:.0f}%. "
        f"Blocked unauthorized actions: {blocked:,} ({pct_blocked:.1f}%). "
        f"Human-approved actions: {approved:,} ({pct_approved:.1f}%)."
    )

    return ComplianceReport(
        report_type="soc2",
        generated_at=datetime.now(UTC),
        period_start=period_start,
        period_end=period_end,
        total_actions=total,
        blocked_actions=blocked,
        approved_actions=approved,
        auto_approved=auto,
        summary=summary,
        findings=findings,
        score=score,
        grade=_compute_grade(score),
    )


# ---------------------------------------------------------------------------
# GDPR report builder
# ---------------------------------------------------------------------------


def _generate_gdpr(
    entries: list[dict[str, Any]],
    policy: Policy,
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a GDPR compliance report."""
    total = len(entries)
    approval_counts = _count_by_approval(entries)
    blocked = approval_counts["block"]
    approved = approval_counts["approve"]
    auto = approval_counts["auto"]

    findings: list[ComplianceFinding] = []
    score = 100

    # Data access logging — all read/write to personal data targets
    _personal_keywords = ("user", "customer", "personal", "pii", "profile", "account", "email")
    personal_data_actions = [
        e
        for e in entries
        if any(kw in str(e.get("action_target", "")).lower() for kw in _personal_keywords)
    ]
    pda_count = len(personal_data_actions)
    all_pda_logged = all(e.get("matched_rule") for e in personal_data_actions)
    if pda_count == 0:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="data_handling",
                title="Data Access Logging: PASS",
                description="No personal data access detected in the audit period.",
                recommendation="No action required.",
            )
        )
    elif all_pda_logged:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="data_handling",
                title="Data Access Logging: PASS",
                description=(
                    f"{pda_count:,} personal data accesses detected, all covered by policy rules."
                ),
                recommendation="Continue enforcing personal data access policies.",
            )
        )
    else:
        score -= 20
        unlogged = sum(1 for e in personal_data_actions if not e.get("matched_rule"))
        findings.append(
            ComplianceFinding(
                severity="critical",
                category="data_handling",
                title="Data Access Logging: FAIL",
                description=(
                    f"{unlogged:,} of {pda_count:,} personal data accesses "
                    f"lacked policy rule coverage."
                ),
                recommendation="Add policy rules for all personal data access patterns.",
            )
        )

    # Right to erasure — delete actions should be logged
    delete_actions = [e for e in entries if "delete" in str(e.get("action_type", "")).lower()]
    if delete_actions:
        all_logged = all(e.get("matched_rule") for e in delete_actions)
        if all_logged:
            findings.append(
                ComplianceFinding(
                    severity="info",
                    category="data_handling",
                    title="Right to Erasure Compliance: PASS",
                    description=(
                        f"{len(delete_actions):,} delete operations logged with full audit trail."
                    ),
                    recommendation="Continue logging all data deletion operations.",
                )
            )
        else:
            score -= 15
            findings.append(
                ComplianceFinding(
                    severity="warning",
                    category="data_handling",
                    title="Right to Erasure Compliance: WARN",
                    description=(
                        f"{len(delete_actions):,} delete operations found, "
                        f"but some lacked policy coverage."
                    ),
                    recommendation="Ensure all delete operations have explicit policy rules.",
                )
            )
    else:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="data_handling",
                title="Right to Erasure Compliance: PASS",
                description="No delete operations in the audit period.",
                recommendation="No action required.",
            )
        )

    # Data minimization — flag excessive data access patterns
    action_type_counts = _count_by_action_type(entries)
    read_types = {k: v for k, v in action_type_counts.items() if "read" in k.lower()}
    excessive_reads = {k: v for k, v in read_types.items() if v > total * 0.5 and total > 1}
    if excessive_reads:
        score -= 10
        patterns = ", ".join(f"{k} ({v}x)" for k, v in excessive_reads.items())
        findings.append(
            ComplianceFinding(
                severity="warning",
                category="data_handling",
                title="Data Minimization: WARN",
                description=(
                    f"Excessive data access patterns detected: {patterns}. "
                    f"These represent >50% of all actions."
                ),
                recommendation=(
                    "Review whether all data reads are necessary. "
                    "Consider implementing data minimization controls."
                ),
            )
        )
    else:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="data_handling",
                title="Data Minimization: PASS",
                description="No excessive data access patterns detected.",
                recommendation="Continue applying data minimization principles.",
            )
        )

    score = max(0, min(100, score))
    summary = (
        f"Total actions: {total:,}. "
        f"Personal data accesses: {pda_count:,}. "
        f"Delete operations: {len(delete_actions):,}. "
        f"Blocked actions: {blocked:,}."
    )

    return ComplianceReport(
        report_type="gdpr",
        generated_at=datetime.now(UTC),
        period_start=period_start,
        period_end=period_end,
        total_actions=total,
        blocked_actions=blocked,
        approved_actions=approved,
        auto_approved=auto,
        summary=summary,
        findings=findings,
        score=score,
        grade=_compute_grade(score),
    )


# ---------------------------------------------------------------------------
# Governance report builder
# ---------------------------------------------------------------------------


def _generate_governance(
    entries: list[dict[str, Any]],
    policy: Policy,
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a general governance compliance report."""
    total = len(entries)
    approval_counts = _count_by_approval(entries)
    blocked = approval_counts["block"]
    approved = approval_counts["approve"]
    auto = approval_counts["auto"]

    findings: list[ComplianceFinding] = []
    score = 100

    # Policy coverage — % of action types covered by rules
    action_type_counts = _count_by_action_type(entries)
    unique_types = set(action_type_counts.keys())
    covered = sum(1 for e in entries if e.get("matched_rule") and e["matched_rule"] != "<default>")
    coverage_pct = (covered / total * 100) if total else 100.0

    if coverage_pct >= 90.0:
        findings.append(
            ComplianceFinding(
                severity="info",
                category="access_control",
                title="Policy Coverage: PASS",
                description=(
                    f"{coverage_pct:.1f}% of actions matched explicit policy rules "
                    f"({covered:,}/{total:,}). "
                    f"{len(unique_types)} unique action types observed."
                ),
                recommendation="Maintain high policy coverage.",
            )
        )
    elif coverage_pct >= 70.0:
        score -= 10
        findings.append(
            ComplianceFinding(
                severity="warning",
                category="access_control",
                title="Policy Coverage: WARN",
                description=(
                    f"{coverage_pct:.1f}% of actions matched explicit rules. "
                    f"{total - covered:,} actions fell through to defaults."
                ),
                recommendation="Add rules for uncovered action types to improve governance.",
            )
        )
    else:
        score -= 25
        findings.append(
            ComplianceFinding(
                severity="critical",
                category="access_control",
                title="Policy Coverage: FAIL",
                description=(
                    f"Only {coverage_pct:.1f}% of actions matched explicit rules. "
                    f"Most actions are using default policy."
                ),
                recommendation=(
                    "Significantly expand policy rules. Low coverage means "
                    "most actions are not explicitly governed."
                ),
            )
        )

    # Approval gate usage — human review statistics
    if total > 0:
        approval_pct = approved / total * 100
        if approved > 0:
            findings.append(
                ComplianceFinding(
                    severity="info",
                    category="access_control",
                    title="Approval Gate Usage",
                    description=(
                        f"{approved:,} actions ({approval_pct:.1f}%) required "
                        f"human approval. {auto:,} were auto-approved."
                    ),
                    recommendation="Review approval thresholds periodically.",
                )
            )
        else:
            findings.append(
                ComplianceFinding(
                    severity="info",
                    category="access_control",
                    title="Approval Gate Usage",
                    description=(
                        f"No actions required human approval. "
                        f"All {auto:,} non-blocked actions were auto-approved."
                    ),
                    recommendation=(
                        "Consider whether some action types should require human review."
                    ),
                )
            )

    # Risk distribution
    risk_counts = _count_by_risk(entries)
    if risk_counts:
        risk_parts = [f"{k}: {v:,}" for k, v in sorted(risk_counts.items())]
        risk_desc = ", ".join(risk_parts)
        high_critical = risk_counts.get("HIGH", 0) + risk_counts.get("CRITICAL", 0)
        hc_pct = (high_critical / total * 100) if total else 0.0
        sev = "info"
        if hc_pct > 30:
            sev = "warning"
            score -= 10
        findings.append(
            ComplianceFinding(
                severity=sev,
                category="access_control",
                title="Risk Distribution",
                description=(
                    f"Actions by risk level: {risk_desc}. High/Critical: {hc_pct:.1f}% of total."
                ),
                recommendation=(
                    "Monitor high-risk action trends."
                    if hc_pct <= 30
                    else "High proportion of high/critical actions. Review policies."
                ),
            )
        )

    # Agent behavior — per-agent summaries
    agent_counts = _count_by_agent(entries)
    if agent_counts and not (len(agent_counts) == 1 and "unknown" in agent_counts):
        known_agents = {k: v for k, v in agent_counts.items() if k != "unknown"}
        if known_agents:
            agent_parts = [f"{k}: {v:,} actions" for k, v in sorted(known_agents.items())]
            findings.append(
                ComplianceFinding(
                    severity="info",
                    category="audit_trail",
                    title="Agent Behavior Summary",
                    description=f"Active agents: {', '.join(agent_parts)}.",
                    recommendation="Review per-agent activity for anomalies.",
                )
            )

    score = max(0, min(100, score))
    summary = (
        f"Total actions: {total:,}. "
        f"Policy coverage: {coverage_pct:.0f}%. "
        f"Blocked: {blocked:,}. "
        f"Human-approved: {approved:,}. "
        f"Auto-approved: {auto:,}."
    )

    return ComplianceReport(
        report_type="governance",
        generated_at=datetime.now(UTC),
        period_start=period_start,
        period_end=period_end,
        total_actions=total,
        blocked_actions=blocked,
        approved_actions=approved,
        auto_approved=auto,
        summary=summary,
        findings=findings,
        score=score,
        grade=_compute_grade(score),
    )


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Generates compliance reports from audit log entries.

    Usage::

        from aegis.core.policy import Policy
        from aegis.core.compliance import ReportGenerator

        policy = Policy.from_yaml("policy.yaml")
        gen = ReportGenerator(policy)
        report = gen.generate(audit_entries, report_type="soc2")
        print(gen.to_markdown(report))

    Args:
        policy: The :class:`Policy` used to provide context for the report.
    """

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    def generate(
        self,
        audit_entries: list[dict[str, Any]],
        report_type: str = "governance",
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> ComplianceReport:
        """Generate a compliance report from audit entries.

        Args:
            audit_entries: List of dicts matching the AuditLogger output schema.
            report_type: One of ``"soc2"``, ``"gdpr"``, ``"governance"``.
            period_start: Optional start of the audit period.
            period_end: Optional end of the audit period.

        Returns:
            A :class:`ComplianceReport` with findings and a grade.

        Raises:
            ValueError: If *report_type* is not recognized.
        """
        filtered = _filter_by_period(audit_entries, period_start, period_end)
        start, end = _infer_period(filtered, period_start, period_end)

        builders = {
            "soc2": _generate_soc2,
            "gdpr": _generate_gdpr,
            "governance": _generate_governance,
        }
        builder = builders.get(report_type)
        if builder is None:
            raise ValueError(
                f"Unknown report type: {report_type!r}. "
                f"Must be one of: {', '.join(sorted(builders))}"
            )
        return builder(filtered, self._policy, start, end)

    def to_markdown(self, report: ComplianceReport) -> str:
        """Render a compliance report as Markdown text."""
        lines: list[str] = []
        title_map = {
            "soc2": "SOC2 Compliance Report",
            "gdpr": "GDPR Compliance Report",
            "governance": "Governance Compliance Report",
        }
        default_title = f"{report.report_type.upper()} Compliance Report"
        title = title_map.get(report.report_type, default_title)
        lines.append(f"# {title}")
        lines.append("")
        lines.append(
            f"## Period: {report.period_start.strftime('%Y-%m-%d')} "
            f"to {report.period_end.strftime('%Y-%m-%d')}"
        )
        lines.append("")

        # Summary
        lines.append("### Summary")
        lines.append(f"- Total actions evaluated: {report.total_actions:,}")
        enforcement_pct = "100" if report.total_actions > 0 else "N/A"
        lines.append(f"- Policy enforcement rate: {enforcement_pct}%")
        if report.total_actions > 0:
            blocked_pct = report.blocked_actions / report.total_actions * 100
            approved_pct = report.approved_actions / report.total_actions * 100
        else:
            blocked_pct = 0.0
            approved_pct = 0.0
        lines.append(
            f"- Blocked unauthorized actions: {report.blocked_actions:,} ({blocked_pct:.1f}%)"
        )
        lines.append(
            f"- Human-approved actions: {report.approved_actions:,} ({approved_pct:.1f}%)"
        )
        lines.append("")

        # Findings
        section_title = {
            "soc2": "### Trust Services Criteria",
            "gdpr": "### GDPR Compliance Criteria",
            "governance": "### Governance Findings",
        }
        lines.append(section_title.get(report.report_type, "### Findings"))
        lines.append("")

        for finding in report.findings:
            status_icon = ""
            if ": PASS" in finding.title:
                status_icon = " [PASS]"
            elif ": FAIL" in finding.title:
                status_icon = " [FAIL]"
            elif ": WARN" in finding.title:
                status_icon = " [WARN]"
            lines.append(f"**{finding.title}{status_icon}**")
            lines.append(finding.description)
            if finding.severity != "info" or ": FAIL" in finding.title:
                lines.append(f"*Recommendation: {finding.recommendation}*")
            lines.append("")

        # Grade
        lines.append(f"### Grade: {report.grade} ({report.score}/100)")
        lines.append("")

        return "\n".join(lines)

    def to_html(self, report: ComplianceReport) -> str:
        """Render a compliance report as self-contained HTML.

        The output includes inline CSS styling, score visualization with
        color-coded letter grades, a findings table with severity highlighting,
        and a recommendations section. No external assets are required.
        """
        title_map = {
            "soc2": "SOC2 Compliance Report",
            "gdpr": "GDPR Compliance Report",
            "governance": "Governance Compliance Report",
        }
        default_title = f"{report.report_type.upper()} Compliance Report"
        title = title_map.get(report.report_type, default_title)

        # Score color
        if report.score >= 90:
            score_color = "#22c55e"  # green
            grade_bg = "#dcfce7"
        elif report.score >= 70:
            score_color = "#eab308"  # yellow
            grade_bg = "#fef9c3"
        elif report.score >= 50:
            score_color = "#f97316"  # orange
            grade_bg = "#ffedd5"
        else:
            score_color = "#ef4444"  # red
            grade_bg = "#fee2e2"

        # Severity colors for findings
        severity_styles = {
            "critical": "background:#fee2e2;color:#991b1b;",
            "warning": "background:#fef9c3;color:#854d0e;",
            "info": "background:#dbeafe;color:#1e40af;",
        }

        # Build percentages
        if report.total_actions > 0:
            blocked_pct = report.blocked_actions / report.total_actions * 100
            approved_pct = report.approved_actions / report.total_actions * 100
            auto_pct = report.auto_approved / report.total_actions * 100
        else:
            blocked_pct = 0.0
            approved_pct = 0.0
            auto_pct = 0.0

        # Build findings rows
        findings_rows = []
        for f in report.findings:
            sev_style = severity_styles.get(f.severity, "")
            findings_rows.append(
                f"<tr>"
                f'<td style="padding:8px 12px;{sev_style}font-weight:600;">'
                f"{_html_escape(f.severity.upper())}</td>"
                f'<td style="padding:8px 12px;">{_html_escape(f.category)}</td>'
                f'<td style="padding:8px 12px;">{_html_escape(f.title)}</td>'
                f'<td style="padding:8px 12px;">{_html_escape(f.description)}</td>'
                f'<td style="padding:8px 12px;">{_html_escape(f.recommendation)}</td>'
                f"</tr>"
            )
        findings_html = "\n".join(findings_rows)

        # Recommendations (only non-info findings)
        recs = [
            f for f in report.findings
            if f.severity != "info" or ": FAIL" in f.title
        ]
        recs_html = ""
        if recs:
            recs_items = "\n".join(
                f"<li><strong>{_html_escape(r.title)}</strong>: "
                f"{_html_escape(r.recommendation)}</li>"
                for r in recs
            )
            recs_html = f"""
    <div class="section">
      <h2>Recommendations</h2>
      <ul>{recs_items}</ul>
    </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_html_escape(title)}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         margin: 0; padding: 0; background: #f8fafc; color: #1e293b; }}
  .container {{ max-width: 960px; margin: 0 auto; padding: 24px; }}
  .header {{ background: #1e293b; color: #f8fafc; padding: 32px; border-radius: 8px 8px 0 0; }}
  .header h1 {{ margin: 0 0 8px 0; font-size: 28px; }}
  .header .meta {{ font-size: 14px; opacity: 0.8; }}
  .grade-box {{ display: inline-block; padding: 16px 24px; border-radius: 8px;
                background: {grade_bg}; text-align: center; margin: 16px 0; }}
  .grade-letter {{ font-size: 48px; font-weight: 700; color: {score_color}; }}
  .grade-score {{ font-size: 18px; color: {score_color}; }}
  .section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
              padding: 24px; margin: 16px 0; }}
  .section h2 {{ margin: 0 0 16px 0; font-size: 20px; color: #334155; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 12px; }}
  .summary-card {{ background: #f1f5f9; border-radius: 6px; padding: 16px; text-align: center; }}
  .summary-card .value {{ font-size: 28px; font-weight: 700; color: #0f172a; }}
  .summary-card .label {{ font-size: 13px; color: #64748b; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #f1f5f9; padding: 10px 12px; text-align: left;
       font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
  tr:hover {{ background: #f8fafc; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 8px; }}
  .footer {{ text-align: center; font-size: 12px; color: #94a3b8; padding: 16px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>{_html_escape(title)}</h1>
    <div class="meta">
      Period: {report.period_start.strftime('%Y-%m-%d')} to {report.period_end.strftime('%Y-%m-%d')}
      &middot; Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}
    </div>
  </div>

  <div class="section" style="text-align:center;">
    <div class="grade-box">
      <div class="grade-letter">{_html_escape(report.grade)}</div>
      <div class="grade-score">{report.score} / 100</div>
    </div>
  </div>

  <div class="section">
    <h2>Summary</h2>
    <div class="summary-grid">
      <div class="summary-card">
        <div class="value">{report.total_actions:,}</div>
        <div class="label">Total Actions</div>
      </div>
      <div class="summary-card">
        <div class="value">{report.blocked_actions:,}</div>
        <div class="label">Blocked ({blocked_pct:.1f}%)</div>
      </div>
      <div class="summary-card">
        <div class="value">{report.approved_actions:,}</div>
        <div class="label">Human Approved ({approved_pct:.1f}%)</div>
      </div>
      <div class="summary-card">
        <div class="value">{report.auto_approved:,}</div>
        <div class="label">Auto-Approved ({auto_pct:.1f}%)</div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Category</th>
          <th>Title</th>
          <th>Description</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>
{findings_html}
      </tbody>
    </table>
  </div>
{recs_html}
  <div class="footer">
    Generated by Aegis Compliance Engine
  </div>
</div>
</body>
</html>"""

    def to_dict(self, report: ComplianceReport) -> dict[str, Any]:
        """Serialize a compliance report to a plain dict."""
        return {
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "period_start": report.period_start.isoformat(),
            "period_end": report.period_end.isoformat(),
            "total_actions": report.total_actions,
            "blocked_actions": report.blocked_actions,
            "approved_actions": report.approved_actions,
            "auto_approved": report.auto_approved,
            "summary": report.summary,
            "score": report.score,
            "grade": report.grade,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                }
                for f in report.findings
            ],
        }
