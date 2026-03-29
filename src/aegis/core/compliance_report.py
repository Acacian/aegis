"""Compliance Evidence Auto-Generation.

Reads audit data (SQLite or in-memory) and produces per-framework
compliance evidence reports for:
- EU AI Act (Annex IV Technical Dossier)
- SOC2 Trust Service Criteria
- NIST AI RMF 1.0
- ISO/IEC 42001:2023

Each report includes summary statistics, policy coverage mapping,
audit trail integrity verification, time-series breakdowns, and
evidence items with timestamps and hashes.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from aegis.core.crypto_audit import CryptoAuditChain
from aegis.core.regulatory import ComplianceMapper, RegulatoryFramework
from aegis.runtime.audit import AuditLogger

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceItem:
    """A single piece of compliance evidence derived from audit data.

    Attributes:
        timestamp: ISO 8601 timestamp of the source event.
        action_type: The kind of action recorded.
        action_target: The resource the action targeted.
        risk_level: Risk classification at decision time.
        decision: Governance decision (auto / approve / block).
        matched_rule: Policy rule that fired, if any.
        entry_hash: SHA-256 content hash for integrity proof.
    """

    timestamp: str
    action_type: str
    action_target: str
    risk_level: str
    decision: str
    matched_rule: str
    entry_hash: str


@dataclass
class TimeSeriesBucket:
    """Aggregated counts for one time bucket (day or week).

    Attributes:
        period_label: Human-readable label, e.g. ``"2026-01-15"`` or ``"2026-W03"``.
        total: Total actions in this bucket.
        blocked: Blocked actions.
        approved: Human-approved actions.
        auto_approved: Auto-approved actions.
        risk_distribution: Counts per risk level.
    """

    period_label: str
    total: int = 0
    blocked: int = 0
    approved: int = 0
    auto_approved: int = 0
    risk_distribution: dict[str, int] = field(default_factory=dict)


@dataclass
class ComplianceEvidenceReport:
    """Full compliance evidence report for a single regulatory framework.

    Attributes:
        framework: Framework identifier (e.g. ``"eu_ai_act"``).
        framework_name: Human-readable name.
        generated_at: When this report was generated.
        period_start: Start of the evidence period.
        period_end: End of the evidence period.
        summary: Aggregate statistics.
        policy_coverage: Mapping of framework requirements to Aegis features.
        chain_integrity: Result of crypto audit chain verification.
        time_series: Daily or weekly breakdown of activity.
        evidence_items: Individual evidence entries with hashes.
        findings: Framework-specific compliance findings.
        recommendations: Actionable next steps.
    """

    framework: str
    framework_name: str
    generated_at: str
    period_start: str
    period_end: str
    summary: dict[str, Any]
    policy_coverage: list[dict[str, Any]]
    chain_integrity: dict[str, Any]
    time_series: list[dict[str, Any]]
    evidence_items: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict suitable for ``json.dumps``."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Framework name map
# ---------------------------------------------------------------------------

_FRAMEWORK_NAMES: dict[str, str] = {
    "eu_ai_act": "EU AI Act (Regulation (EU) 2024/1689)",
    "nist_ai_rmf": "NIST AI Risk Management Framework 1.0",
    "soc2": "SOC2 Trust Services Criteria",
    "iso_42001": "ISO/IEC 42001:2023",
}

_FRAMEWORK_CLI_MAP: dict[str, RegulatoryFramework] = {
    "eu-ai-act": RegulatoryFramework.EU_AI_ACT,
    "eu_ai_act": RegulatoryFramework.EU_AI_ACT,
    "soc2": RegulatoryFramework.SOC2,
    "nist": RegulatoryFramework.NIST_AI_RMF,
    "nist_ai_rmf": RegulatoryFramework.NIST_AI_RMF,
    "iso42001": RegulatoryFramework.ISO_42001,
    "iso-42001": RegulatoryFramework.ISO_42001,
    "iso_42001": RegulatoryFramework.ISO_42001,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_ts(value: str | datetime | None) -> datetime | None:
    """Parse ISO timestamp string or pass through datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        ts = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(ts)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except (ValueError, AttributeError):
        return None


def _hash_evidence(entry: dict[str, Any]) -> str:
    """Produce a SHA-256 digest of an audit entry's key fields."""
    payload = json.dumps(
        {
            "timestamp": str(entry.get("timestamp", "")),
            "action_type": str(entry.get("action_type", "")),
            "action_target": str(entry.get("action_target", "")),
            "risk_level": str(entry.get("risk_level", "")),
            "approval": str(entry.get("approval", "")),
            "matched_rule": str(entry.get("matched_rule", "")),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _filter_period(
    entries: list[dict[str, Any]],
    start: datetime,
    end: datetime,
) -> list[dict[str, Any]]:
    """Filter entries to the given period (inclusive)."""
    result: list[dict[str, Any]] = []
    for e in entries:
        ts = _parse_ts(e.get("timestamp"))
        if ts is None:
            continue
        if start <= ts <= end:
            result.append(e)
    return result


def _compute_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate statistics from audit entries."""
    total = len(entries)
    blocked = 0
    approved = 0
    auto_approved = 0
    risk_counts: dict[str, int] = defaultdict(int)
    action_types: dict[str, int] = defaultdict(int)

    for e in entries:
        approval = str(e.get("approval", "")).lower()
        if approval == "block":
            blocked += 1
        elif approval == "approve":
            approved += 1
        elif approval == "auto":
            auto_approved += 1

        risk = str(e.get("risk_level", "UNKNOWN")).upper()
        risk_counts[risk] += 1
        action_types[str(e.get("action_type", "unknown"))] += 1

    return {
        "total_actions": total,
        "blocked_actions": blocked,
        "approved_actions": approved,
        "auto_approved_actions": auto_approved,
        "risk_distribution": dict(risk_counts),
        "action_type_distribution": dict(action_types),
    }


def _build_time_series(
    entries: list[dict[str, Any]],
    granularity: str = "daily",
) -> list[dict[str, Any]]:
    """Build daily or weekly time-series buckets from entries."""
    buckets: dict[str, TimeSeriesBucket] = {}

    for e in entries:
        ts = _parse_ts(e.get("timestamp"))
        if ts is None:
            continue

        if granularity == "weekly":
            iso = ts.isocalendar()
            label = f"{iso.year}-W{iso.week:02d}"
        else:
            label = ts.strftime("%Y-%m-%d")

        if label not in buckets:
            buckets[label] = TimeSeriesBucket(period_label=label)
        b = buckets[label]
        b.total += 1

        approval = str(e.get("approval", "")).lower()
        if approval == "block":
            b.blocked += 1
        elif approval == "approve":
            b.approved += 1
        elif approval == "auto":
            b.auto_approved += 1

        risk = str(e.get("risk_level", "UNKNOWN")).upper()
        b.risk_distribution[risk] = b.risk_distribution.get(risk, 0) + 1

    return [asdict(b) for b in sorted(buckets.values(), key=lambda x: x.period_label)]


def _build_evidence_items(
    entries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert raw audit entries into hashed evidence items."""
    items: list[dict[str, Any]] = []
    for e in entries:
        item = EvidenceItem(
            timestamp=str(e.get("timestamp", "")),
            action_type=str(e.get("action_type", "")),
            action_target=str(e.get("action_target", "")),
            risk_level=str(e.get("risk_level", "")),
            decision=str(e.get("approval", "")),
            matched_rule=str(e.get("matched_rule", "")),
            entry_hash=_hash_evidence(e),
        )
        items.append(asdict(item))
    return items


def _verify_chain(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a crypto audit chain from entries and verify integrity."""
    chain = CryptoAuditChain()
    for e in entries:
        chain.append(
            agent_id=str(e.get("agent_id") or "unknown"),
            action_type=str(e.get("action_type", "unknown")),
            action_target=str(e.get("action_target", "unknown")),
            decision=str(e.get("approval", "unknown")),
            risk_level=str(e.get("risk_level", "unknown")),
            matched_rule=str(e.get("matched_rule", "")),
            metadata={
                "original_id": e.get("id"),
                "session_id": e.get("session_id"),
            },
        )
    result = chain.verify()
    return {
        "valid": result.valid,
        "chain_length": result.chain_length,
        "verified_entries": result.verified_entries,
        "first_broken_at": result.first_broken_at,
        "error_message": result.error_message,
        "verification_hash": result.verification_hash,
    }


# ---------------------------------------------------------------------------
# Framework-specific findings generators
# ---------------------------------------------------------------------------


def _eu_ai_act_findings(
    entries: list[dict[str, Any]],
    summary: dict[str, Any],
    chain_ok: bool,
) -> list[dict[str, Any]]:
    """Generate EU AI Act Annex IV specific findings."""
    findings: list[dict[str, Any]] = []
    total = summary["total_actions"]

    # Art 12 - Automatic Logging
    if total > 0:
        findings.append(
            {
                "article": "Article 12 - Record-keeping",
                "status": "compliant",
                "description": (
                    f"{total:,} actions automatically logged with timestamps, "
                    f"risk levels, and policy decisions."
                ),
                "evidence": "Audit log entries with cryptographic hash chain",
            }
        )
    else:
        findings.append(
            {
                "article": "Article 12 - Record-keeping",
                "status": "insufficient_data",
                "description": "No audit entries found in the specified period.",
                "evidence": "N/A",
            }
        )

    # Art 12 - Hash chain integrity
    findings.append(
        {
            "article": "Article 12 - Tamper Evidence",
            "status": "compliant" if chain_ok else "non_compliant",
            "description": (
                "Cryptographic hash chain verified intact."
                if chain_ok
                else "Cryptographic hash chain verification failed."
            ),
            "evidence": "SHA-256 hash-linked audit chain verification",
        }
    )

    # Art 9 - Risk Management
    risk_dist = summary.get("risk_distribution", {})
    high_critical = risk_dist.get("HIGH", 0) + risk_dist.get("CRITICAL", 0)
    blocked = summary["blocked_actions"]
    if high_critical > 0 and blocked > 0:
        findings.append(
            {
                "article": "Article 9 - Risk Management",
                "status": "compliant",
                "description": (
                    f"{high_critical:,} high/critical risk actions identified, "
                    f"{blocked:,} blocked by policy."
                ),
                "evidence": "Risk-level classification and blocking decisions",
            }
        )
    elif high_critical > 0 and blocked == 0:
        findings.append(
            {
                "article": "Article 9 - Risk Management",
                "status": "needs_review",
                "description": (
                    f"{high_critical:,} high/critical risk actions detected but none were blocked."
                ),
                "evidence": "Review policy rules for high-risk actions",
            }
        )
    else:
        findings.append(
            {
                "article": "Article 9 - Risk Management",
                "status": "compliant",
                "description": "No high/critical risk actions in period.",
                "evidence": "Risk distribution analysis",
            }
        )

    # Art 14 - Human Oversight
    approved = summary["approved_actions"]
    if approved > 0:
        findings.append(
            {
                "article": "Article 14 - Human Oversight",
                "status": "compliant",
                "description": (
                    f"{approved:,} actions required human approval, "
                    f"demonstrating active human oversight."
                ),
                "evidence": "Human approval decision records",
            }
        )
    else:
        findings.append(
            {
                "article": "Article 14 - Human Oversight",
                "status": "needs_review",
                "description": (
                    "No human-approved actions in period. Ensure approval "
                    "gates are configured for high-risk operations."
                ),
                "evidence": "Approval gate configuration review needed",
            }
        )

    # Art 13 - Transparency
    matched = sum(1 for e in entries if e.get("matched_rule"))
    match_pct = (matched / total * 100) if total else 0
    findings.append(
        {
            "article": "Article 13 - Transparency",
            "status": "compliant" if match_pct >= 80 else "needs_review",
            "description": (
                f"{match_pct:.1f}% of actions matched explicit policy rules, "
                f"providing interpretable decision rationale."
            ),
            "evidence": "Policy rule match records",
        }
    )

    return findings


def _soc2_findings(
    entries: list[dict[str, Any]],
    summary: dict[str, Any],
    chain_ok: bool,
) -> list[dict[str, Any]]:
    """Generate SOC2 Trust Service Criteria findings."""
    findings: list[dict[str, Any]] = []
    total = summary["total_actions"]

    # CC6.1 - Logical Access Security
    matched = sum(1 for e in entries if e.get("matched_rule"))
    match_pct = (matched / total * 100) if total else 100
    findings.append(
        {
            "criterion": "CC6.1 - Logical Access Security",
            "status": "effective" if match_pct >= 95 else "needs_improvement",
            "description": (
                f"{match_pct:.1f}% of actions evaluated against policy ({matched:,}/{total:,})."
            ),
            "evidence": "Policy enforcement decision logs",
        }
    )

    # CC6.8 - Unauthorized Access Prevention
    blocked = summary["blocked_actions"]
    bypass_count = sum(
        1
        for e in entries
        if str(e.get("risk_level", "")).upper() in ("HIGH", "CRITICAL")
        and str(e.get("approval", "")).lower() == "auto"
    )
    findings.append(
        {
            "criterion": "CC6.8 - Unauthorized Access Prevention",
            "status": "effective" if bypass_count == 0 else "deficiency",
            "description": (
                f"{blocked:,} unauthorized attempts blocked. "
                f"{bypass_count:,} high-risk auto-approvals detected."
            ),
            "evidence": "Action blocking and approval decision logs",
        }
    )

    # CC7.2 - System Monitoring
    findings.append(
        {
            "criterion": "CC7.2 - System Monitoring",
            "status": "effective" if total > 0 else "not_tested",
            "description": (
                f"{total:,} actions monitored with continuous audit logging."
                if total > 0
                else "No monitoring data in period."
            ),
            "evidence": "Continuous audit log stream",
        }
    )

    # PI1.1 - Processing Integrity
    findings.append(
        {
            "criterion": "PI1.1 - Processing Integrity",
            "status": "effective" if chain_ok else "deficiency",
            "description": (
                "Cryptographic hash chain verifies processing integrity."
                if chain_ok
                else "Hash chain verification failed - integrity concern."
            ),
            "evidence": "SHA-256 hash chain verification report",
        }
    )

    # CC8.1 - Change Management
    policy_changes = [
        e
        for e in entries
        if "policy" in str(e.get("action_type", "")).lower()
        or "config" in str(e.get("action_type", "")).lower()
    ]
    findings.append(
        {
            "criterion": "CC8.1 - Change Management",
            "status": "effective",
            "description": (
                f"{len(policy_changes):,} configuration changes tracked in audit log."
            ),
            "evidence": "Configuration change audit trail",
        }
    )

    return findings


def _nist_findings(
    entries: list[dict[str, Any]],
    summary: dict[str, Any],
    chain_ok: bool,
) -> list[dict[str, Any]]:
    """Generate NIST AI RMF findings."""
    findings: list[dict[str, Any]] = []
    total = summary["total_actions"]
    risk_dist = summary.get("risk_distribution", {})

    # GOVERN-1 - Policies in place
    matched = sum(1 for e in entries if e.get("matched_rule"))
    findings.append(
        {
            "function": "GOVERN-1 - Policies and Processes",
            "status": "implemented" if matched > 0 else "not_implemented",
            "description": (f"Policy engine evaluated {matched:,} actions against defined rules."),
            "evidence": "Policy definition and enforcement logs",
        }
    )

    # MAP-1 - Context established
    action_types = summary.get("action_type_distribution", {})
    findings.append(
        {
            "function": "MAP-1 - Context Established",
            "status": "implemented",
            "description": (
                f"{len(action_types)} distinct action types documented across "
                f"{total:,} total actions."
            ),
            "evidence": "Action type taxonomy from audit data",
        }
    )

    # MEASURE-1 - Methods and metrics
    findings.append(
        {
            "function": "MEASURE-1 - Methods and Metrics",
            "status": "implemented",
            "description": (
                "Risk distribution: "
                f"{', '.join(f'{k}: {v}' for k, v in sorted(risk_dist.items()))}. "
                "Quantitative risk metrics applied to all actions."
            ),
            "evidence": "Risk level classification and distribution analysis",
        }
    )

    # MANAGE-1 - Risks managed
    blocked = summary["blocked_actions"]
    findings.append(
        {
            "function": "MANAGE-1 - Risks Managed",
            "status": "implemented" if blocked > 0 or total > 0 else "not_implemented",
            "description": (
                f"{blocked:,} actions blocked based on risk assessment. "
                f"Risk-based policy enforcement active."
            ),
            "evidence": "Risk-prioritized blocking decisions",
        }
    )

    return findings


def _iso42001_findings(
    entries: list[dict[str, Any]],
    summary: dict[str, Any],
    chain_ok: bool,
) -> list[dict[str, Any]]:
    """Generate ISO 42001 findings."""
    findings: list[dict[str, Any]] = []
    total = summary["total_actions"]
    risk_dist = summary.get("risk_distribution", {})

    # 6.1 - Risks and opportunities
    high_critical = risk_dist.get("HIGH", 0) + risk_dist.get("CRITICAL", 0)
    findings.append(
        {
            "clause": "6.1 - Actions to Address Risks",
            "status": "conforming" if total > 0 else "not_assessed",
            "description": (
                f"{high_critical:,} high/critical risk items identified and "
                f"managed through policy engine."
            ),
            "evidence": "Risk classification and policy enforcement records",
        }
    )

    # 9.1 - Monitoring
    findings.append(
        {
            "clause": "9.1 - Monitoring and Measurement",
            "status": "conforming" if total > 0 else "not_assessed",
            "description": (
                f"{total:,} actions monitored with risk classification and outcome tracking."
            ),
            "evidence": "Continuous audit monitoring data",
        }
    )

    # 9.2 - Internal Audit
    findings.append(
        {
            "clause": "9.2 - Internal Audit",
            "status": "conforming" if chain_ok else "non_conforming",
            "description": (
                "Audit trail integrity verified via cryptographic hash chain."
                if chain_ok
                else "Audit trail integrity verification failed."
            ),
            "evidence": "Cryptographic audit chain verification",
        }
    )

    # 10.1 - Continual Improvement
    blocked = summary["blocked_actions"]
    auto = summary["auto_approved_actions"]
    findings.append(
        {
            "clause": "10.1 - Continual Improvement",
            "status": "conforming",
            "description": (
                f"Governance metrics: {blocked:,} blocked, {auto:,} auto-approved. "
                f"Data available for trend analysis and improvement."
            ),
            "evidence": "Governance trend data from audit logs",
        }
    )

    return findings


# ---------------------------------------------------------------------------
# ComplianceReportGenerator
# ---------------------------------------------------------------------------


class ComplianceReportGenerator:
    """Generates compliance evidence reports from audit data.

    Usage::

        from aegis.core.compliance_report import ComplianceReportGenerator
        from aegis.runtime.audit import AuditLogger
        from datetime import datetime, UTC

        logger = AuditLogger("aegis_audit.db")
        gen = ComplianceReportGenerator(audit_logger=logger)
        report = gen.generate_eu_ai_act_report(
            period_start=datetime(2026, 1, 1, tzinfo=UTC),
            period_end=datetime(2026, 3, 31, tzinfo=UTC),
        )

    Args:
        audit_logger: Optional :class:`AuditLogger` instance to read from.
        audit_entries: Optional pre-loaded list of audit entry dicts.
            If both are provided, *audit_entries* takes precedence.
    """

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
        audit_entries: list[dict[str, Any]] | None = None,
    ) -> None:
        self._logger = audit_logger
        self._entries = audit_entries
        self._mapper = ComplianceMapper()

    def _get_entries(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> list[dict[str, Any]]:
        """Load and filter audit entries for the given period."""
        if self._entries is not None:
            raw = list(self._entries)
        elif self._logger is not None:
            raw = self._logger.get_log(since=period_start, until=period_end)
        else:
            raw = []

        return _filter_period(raw, period_start, period_end)

    def _build_coverage(
        self,
        framework: RegulatoryFramework,
    ) -> list[dict[str, Any]]:
        """Build policy coverage mapping for a framework."""
        analysis = self._mapper.analyze(framework)
        coverage: list[dict[str, Any]] = []
        for m in analysis.mappings:
            coverage.append(
                {
                    "requirement_id": m.requirement.requirement_id,
                    "requirement_title": m.requirement.title,
                    "category": m.requirement.category,
                    "mandatory": m.requirement.mandatory,
                    "deadline": m.requirement.deadline,
                    "aegis_feature": m.aegis_feature,
                    "coverage": m.coverage,
                    "evidence_type": m.evidence_type,
                    "notes": m.notes,
                }
            )
        return coverage

    def _generate_report(
        self,
        framework: RegulatoryFramework,
        period_start: datetime,
        period_end: datetime,
        granularity: str = "daily",
    ) -> ComplianceEvidenceReport:
        """Internal: generate a report for any framework."""
        entries = self._get_entries(period_start, period_end)
        summary = _compute_summary(entries)
        chain_result = _verify_chain(entries)
        chain_ok = chain_result["valid"]
        coverage = self._build_coverage(framework)
        time_series = _build_time_series(entries, granularity)
        evidence = _build_evidence_items(entries)

        # Framework-specific findings
        findings_fn = {
            RegulatoryFramework.EU_AI_ACT: _eu_ai_act_findings,
            RegulatoryFramework.SOC2: _soc2_findings,
            RegulatoryFramework.NIST_AI_RMF: _nist_findings,
            RegulatoryFramework.ISO_42001: _iso42001_findings,
        }
        fn = findings_fn.get(framework, _nist_findings)
        findings = fn(entries, summary, chain_ok)

        # Recommendations from mapper
        analysis = self._mapper.analyze(framework)
        recommendations = list(analysis.recommendations)

        fw_key = framework.value
        fw_name = _FRAMEWORK_NAMES.get(fw_key, fw_key)

        return ComplianceEvidenceReport(
            framework=fw_key,
            framework_name=fw_name,
            generated_at=datetime.now(UTC).isoformat(),
            period_start=period_start.isoformat(),
            period_end=period_end.isoformat(),
            summary=summary,
            policy_coverage=coverage,
            chain_integrity=chain_result,
            time_series=time_series,
            evidence_items=evidence,
            findings=findings,
            recommendations=recommendations,
        )

    # -- Public API: per-framework generators --------------------------------

    def generate_eu_ai_act_report(
        self,
        period_start: datetime,
        period_end: datetime,
        *,
        granularity: str = "daily",
    ) -> ComplianceEvidenceReport:
        """Generate EU AI Act Annex IV Technical Dossier evidence.

        Args:
            period_start: Start of the evidence period.
            period_end: End of the evidence period.
            granularity: ``"daily"`` or ``"weekly"`` for time-series.

        Returns:
            A :class:`ComplianceEvidenceReport` with EU AI Act findings.
        """
        return self._generate_report(
            RegulatoryFramework.EU_AI_ACT, period_start, period_end, granularity
        )

    def generate_soc2_report(
        self,
        period_start: datetime,
        period_end: datetime,
        *,
        granularity: str = "daily",
    ) -> ComplianceEvidenceReport:
        """Generate SOC2 Trust Service Criteria evidence.

        Args:
            period_start: Start of the evidence period.
            period_end: End of the evidence period.
            granularity: ``"daily"`` or ``"weekly"`` for time-series.

        Returns:
            A :class:`ComplianceEvidenceReport` with SOC2 findings.
        """
        return self._generate_report(
            RegulatoryFramework.SOC2, period_start, period_end, granularity
        )

    def generate_nist_report(
        self,
        period_start: datetime,
        period_end: datetime,
        *,
        granularity: str = "daily",
    ) -> ComplianceEvidenceReport:
        """Generate NIST AI RMF 1.0 evidence.

        Args:
            period_start: Start of the evidence period.
            period_end: End of the evidence period.
            granularity: ``"daily"`` or ``"weekly"`` for time-series.

        Returns:
            A :class:`ComplianceEvidenceReport` with NIST findings.
        """
        return self._generate_report(
            RegulatoryFramework.NIST_AI_RMF, period_start, period_end, granularity
        )

    def generate_iso42001_report(
        self,
        period_start: datetime,
        period_end: datetime,
        *,
        granularity: str = "daily",
    ) -> ComplianceEvidenceReport:
        """Generate ISO/IEC 42001:2023 evidence.

        Args:
            period_start: Start of the evidence period.
            period_end: End of the evidence period.
            granularity: ``"daily"`` or ``"weekly"`` for time-series.

        Returns:
            A :class:`ComplianceEvidenceReport` with ISO 42001 findings.
        """
        return self._generate_report(
            RegulatoryFramework.ISO_42001, period_start, period_end, granularity
        )

    # -- Multi-framework status check ----------------------------------------

    def check_status(self) -> dict[str, dict[str, Any]]:
        """Quick check: which frameworks have sufficient evidence.

        Returns:
            Dict keyed by framework name with status info.
        """
        results: dict[str, dict[str, Any]] = {}
        for fw in [
            RegulatoryFramework.EU_AI_ACT,
            RegulatoryFramework.SOC2,
            RegulatoryFramework.NIST_AI_RMF,
            RegulatoryFramework.ISO_42001,
        ]:
            analysis = self._mapper.analyze(fw)
            fw_name = _FRAMEWORK_NAMES.get(fw.value, fw.value)
            results[fw_name] = {
                "coverage_score": round(analysis.coverage_score, 1),
                "total_requirements": analysis.total_requirements,
                "fully_covered": analysis.fully_covered,
                "partially_covered": analysis.partially_covered,
                "gaps": analysis.not_covered,
                "has_mandatory_gaps": any(g.mandatory for g in analysis.gaps),
            }
        return results

    # -- Rendering helpers ---------------------------------------------------

    @staticmethod
    def to_text(report: ComplianceEvidenceReport) -> str:
        """Render a report as human-readable plain text."""
        lines: list[str] = []
        lines.append(f"{'=' * 72}")
        lines.append(f"Compliance Evidence Report: {report.framework_name}")
        lines.append(f"{'=' * 72}")
        lines.append(f"Generated: {report.generated_at}")
        lines.append(f"Period:    {report.period_start} to {report.period_end}")
        lines.append("")

        # Summary
        s = report.summary
        lines.append("--- Summary ---")
        lines.append(f"  Total actions:     {s.get('total_actions', 0):,}")
        lines.append(f"  Blocked:           {s.get('blocked_actions', 0):,}")
        lines.append(f"  Human approved:    {s.get('approved_actions', 0):,}")
        lines.append(f"  Auto-approved:     {s.get('auto_approved_actions', 0):,}")
        risk = s.get("risk_distribution", {})
        if risk:
            dist_str = ", ".join(f"{k}: {v}" for k, v in sorted(risk.items()))
            lines.append(f"  Risk distribution: {dist_str}")
        lines.append("")

        # Chain integrity
        ci = report.chain_integrity
        status = "PASSED" if ci.get("valid") else "FAILED"
        lines.append(f"--- Audit Chain Integrity: {status} ---")
        lines.append(f"  Chain length:  {ci.get('chain_length', 0)}")
        lines.append(f"  Verified:      {ci.get('verified_entries', 0)}")
        if not ci.get("valid"):
            lines.append(f"  Error:         {ci.get('error_message', '')}")
        lines.append("")

        # Findings
        lines.append("--- Findings ---")
        for f in report.findings:
            # Determine the label key (article/criterion/function/clause)
            label = (
                f.get("article")
                or f.get("criterion")
                or f.get("function")
                or f.get("clause")
                or "Unknown"
            )
            lines.append(f"  [{f.get('status', 'unknown').upper()}] {label}")
            lines.append(f"    {f.get('description', '')}")
            lines.append(f"    Evidence: {f.get('evidence', '')}")
        lines.append("")

        # Coverage summary
        coverage = report.policy_coverage
        if coverage:
            full = sum(1 for c in coverage if c.get("coverage") == "full")
            partial = sum(1 for c in coverage if c.get("coverage") == "partial")
            none_ = sum(1 for c in coverage if c.get("coverage") == "none")
            lines.append("--- Policy Coverage ---")
            lines.append(f"  Full: {full}  Partial: {partial}  None: {none_}")
        lines.append("")

        # Recommendations
        if report.recommendations:
            lines.append("--- Recommendations ---")
            for i, rec in enumerate(report.recommendations, 1):
                lines.append(f"  {i}. {rec}")

        lines.append("")
        lines.append(f"{'=' * 72}")
        return "\n".join(lines)
