"""Tests for compliance evidence auto-generation.

Tests cover:
- ComplianceReportGenerator with mock audit data
- Each framework: eu-ai-act, soc2, nist, iso42001
- Period filtering
- Crypto hash chain validation in reports
- Summary statistics computation
- Time-series generation (daily and weekly)
- Evidence item hashing
- CLI command invocation
- Status check across frameworks
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from aegis.core.compliance_report import (
    ComplianceEvidenceReport,
    ComplianceReportGenerator,
    _build_evidence_items,
    _build_time_series,
    _compute_summary,
    _filter_period,
    _hash_evidence,
    _verify_chain,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(offset_hours: int = 0) -> str:
    """Generate an ISO timestamp offset from a base time."""
    base = datetime(2026, 1, 15, 10, 0, 0, tzinfo=UTC)
    return (base + timedelta(hours=offset_hours)).isoformat()


def _entry(
    action_type: str = "read",
    action_target: str = "crm",
    risk_level: str = "LOW",
    approval: str = "auto",
    matched_rule: str = "read_auto",
    timestamp: str | None = None,
    agent_id: str | None = None,
    result_status: str | None = "success",
    **kwargs: object,
) -> dict[str, Any]:
    """Build a mock audit entry matching AuditLogger output schema."""
    entry: dict[str, Any] = {
        "id": 1,
        "session_id": "sess-001",
        "timestamp": timestamp or _ts(0),
        "action_type": action_type,
        "action_target": action_target,
        "action_params": "{}",
        "action_desc": None,
        "risk_level": risk_level,
        "approval": approval,
        "matched_rule": matched_rule,
        "human_decision": None,
        "result_status": result_status,
        "result_data": None,
        "result_error": None,
        "agent_id": agent_id,
        "parent_agent_id": None,
        "chain_id": None,
        "chain_depth": 0,
    }
    entry.update(kwargs)
    return entry


def _sample_entries(count: int = 20) -> list[dict[str, Any]]:
    """Generate a diverse set of mock audit entries."""
    entries: list[dict[str, Any]] = []
    templates = [
        ("read", "crm", "LOW", "auto", "read_auto"),
        ("write", "db", "MEDIUM", "approve", "write_approve"),
        ("delete", "records", "CRITICAL", "block", "delete_block"),
        ("read", "analytics", "LOW", "auto", "read_auto"),
        ("bulk_update", "users", "HIGH", "approve", "bulk_high"),
    ]
    for i in range(count):
        t = templates[i % len(templates)]
        entries.append(
            _entry(
                action_type=t[0],
                action_target=t[1],
                risk_level=t[2],
                approval=t[3],
                matched_rule=t[4],
                timestamp=_ts(i),
                agent_id=f"agent-{i % 3}",
            )
        )
    return entries


# Period boundaries for Q1 2026
Q1_START = datetime(2026, 1, 1, tzinfo=UTC)
Q1_END = datetime(2026, 3, 31, 23, 59, 59, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Test: Summary computation
# ---------------------------------------------------------------------------


class TestComputeSummary:
    def test_empty_entries(self) -> None:
        summary = _compute_summary([])
        assert summary["total_actions"] == 0
        assert summary["blocked_actions"] == 0
        assert summary["approved_actions"] == 0
        assert summary["auto_approved_actions"] == 0

    def test_counts_by_approval(self) -> None:
        entries = [
            _entry(approval="auto"),
            _entry(approval="approve"),
            _entry(approval="block"),
            _entry(approval="auto"),
        ]
        summary = _compute_summary(entries)
        assert summary["total_actions"] == 4
        assert summary["blocked_actions"] == 1
        assert summary["approved_actions"] == 1
        assert summary["auto_approved_actions"] == 2

    def test_risk_distribution(self) -> None:
        entries = [
            _entry(risk_level="LOW"),
            _entry(risk_level="LOW"),
            _entry(risk_level="HIGH"),
            _entry(risk_level="CRITICAL"),
        ]
        summary = _compute_summary(entries)
        assert summary["risk_distribution"]["LOW"] == 2
        assert summary["risk_distribution"]["HIGH"] == 1
        assert summary["risk_distribution"]["CRITICAL"] == 1


# ---------------------------------------------------------------------------
# Test: Period filtering
# ---------------------------------------------------------------------------


class TestPeriodFiltering:
    def test_filters_by_period(self) -> None:
        entries = [
            _entry(timestamp="2026-01-15T10:00:00+00:00"),
            _entry(timestamp="2025-12-01T10:00:00+00:00"),  # before
            _entry(timestamp="2026-04-01T10:00:00+00:00"),  # after
        ]
        filtered = _filter_period(entries, Q1_START, Q1_END)
        assert len(filtered) == 1
        assert filtered[0]["timestamp"] == "2026-01-15T10:00:00+00:00"

    def test_inclusive_boundaries(self) -> None:
        entries = [
            _entry(timestamp="2026-01-01T00:00:00+00:00"),  # start boundary
            _entry(timestamp="2026-03-31T23:59:59+00:00"),  # end boundary
        ]
        filtered = _filter_period(entries, Q1_START, Q1_END)
        assert len(filtered) == 2

    def test_skips_unparseable_timestamps(self) -> None:
        entries = [
            _entry(timestamp="not-a-date"),
            _entry(timestamp="2026-01-15T10:00:00+00:00"),
        ]
        filtered = _filter_period(entries, Q1_START, Q1_END)
        assert len(filtered) == 1


# ---------------------------------------------------------------------------
# Test: Evidence item hashing
# ---------------------------------------------------------------------------


class TestEvidenceHashing:
    def test_hash_is_deterministic(self) -> None:
        e = _entry()
        h1 = _hash_evidence(e)
        h2 = _hash_evidence(e)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_different_entries_different_hashes(self) -> None:
        e1 = _entry(action_type="read")
        e2 = _entry(action_type="write")
        assert _hash_evidence(e1) != _hash_evidence(e2)

    def test_build_evidence_items(self) -> None:
        entries = _sample_entries(5)
        items = _build_evidence_items(entries)
        assert len(items) == 5
        for item in items:
            assert "entry_hash" in item
            assert len(item["entry_hash"]) == 64
            assert "timestamp" in item
            assert "action_type" in item
            assert "decision" in item


# ---------------------------------------------------------------------------
# Test: Time-series generation
# ---------------------------------------------------------------------------


class TestTimeSeries:
    def test_daily_buckets(self) -> None:
        entries = [
            _entry(timestamp="2026-01-15T10:00:00+00:00"),
            _entry(timestamp="2026-01-15T14:00:00+00:00"),
            _entry(timestamp="2026-01-16T10:00:00+00:00"),
        ]
        ts = _build_time_series(entries, granularity="daily")
        assert len(ts) == 2
        labels = [b["period_label"] for b in ts]
        assert "2026-01-15" in labels
        assert "2026-01-16" in labels
        # First day has 2 entries
        day1 = next(b for b in ts if b["period_label"] == "2026-01-15")
        assert day1["total"] == 2

    def test_weekly_buckets(self) -> None:
        entries = [
            _entry(timestamp="2026-01-12T10:00:00+00:00"),  # Monday W03
            _entry(timestamp="2026-01-13T10:00:00+00:00"),  # Tuesday W03
            _entry(timestamp="2026-01-19T10:00:00+00:00"),  # Monday W04
        ]
        ts = _build_time_series(entries, granularity="weekly")
        assert len(ts) == 2

    def test_empty_entries(self) -> None:
        ts = _build_time_series([], granularity="daily")
        assert ts == []


# ---------------------------------------------------------------------------
# Test: Crypto chain verification in reports
# ---------------------------------------------------------------------------


class TestChainVerification:
    def test_valid_chain(self) -> None:
        entries = _sample_entries(10)
        result = _verify_chain(entries)
        assert result["valid"] is True
        assert result["chain_length"] == 10
        assert result["verified_entries"] == 10
        assert result["first_broken_at"] is None

    def test_empty_chain(self) -> None:
        result = _verify_chain([])
        assert result["valid"] is True
        assert result["chain_length"] == 0


# ---------------------------------------------------------------------------
# Test: EU AI Act report generation
# ---------------------------------------------------------------------------


class TestEUAIActReport:
    def test_generates_report(self) -> None:
        entries = _sample_entries(20)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_eu_ai_act_report(Q1_START, Q1_END)

        assert isinstance(report, ComplianceEvidenceReport)
        assert report.framework == "eu_ai_act"
        assert "EU AI Act" in report.framework_name
        assert report.summary["total_actions"] == 20
        assert len(report.findings) > 0
        assert len(report.policy_coverage) > 0
        assert report.chain_integrity["valid"] is True

    def test_eu_ai_act_has_article_12_finding(self) -> None:
        entries = _sample_entries(5)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_eu_ai_act_report(Q1_START, Q1_END)

        articles = [f.get("article", "") for f in report.findings]
        assert any("Article 12" in a for a in articles)

    def test_eu_ai_act_human_oversight(self) -> None:
        entries = [
            _entry(approval="approve", timestamp=_ts(0)),
            _entry(approval="auto", timestamp=_ts(1)),
        ]
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_eu_ai_act_report(Q1_START, Q1_END)

        art14 = [f for f in report.findings if "Article 14" in f.get("article", "")]
        assert len(art14) == 1
        assert art14[0]["status"] == "compliant"


# ---------------------------------------------------------------------------
# Test: SOC2 report generation
# ---------------------------------------------------------------------------


class TestSOC2Report:
    def test_generates_report(self) -> None:
        entries = _sample_entries(15)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_soc2_report(Q1_START, Q1_END)

        assert report.framework == "soc2"
        assert "SOC2" in report.framework_name
        assert len(report.findings) > 0

    def test_soc2_logical_access(self) -> None:
        entries = _sample_entries(10)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_soc2_report(Q1_START, Q1_END)

        cc61 = [f for f in report.findings if "CC6.1" in f.get("criterion", "")]
        assert len(cc61) == 1

    def test_soc2_no_bypass_effective(self) -> None:
        entries = [
            _entry(risk_level="HIGH", approval="approve", timestamp=_ts(0)),
            _entry(risk_level="LOW", approval="auto", timestamp=_ts(1)),
        ]
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_soc2_report(Q1_START, Q1_END)

        cc68 = [f for f in report.findings if "CC6.8" in f.get("criterion", "")]
        assert len(cc68) == 1
        assert cc68[0]["status"] == "effective"


# ---------------------------------------------------------------------------
# Test: NIST report generation
# ---------------------------------------------------------------------------


class TestNISTReport:
    def test_generates_report(self) -> None:
        entries = _sample_entries(10)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_nist_report(Q1_START, Q1_END)

        assert report.framework == "nist_ai_rmf"
        assert "NIST" in report.framework_name
        assert len(report.findings) > 0
        assert report.summary["total_actions"] == 10

    def test_nist_governance_finding(self) -> None:
        entries = _sample_entries(5)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_nist_report(Q1_START, Q1_END)

        govern = [f for f in report.findings if "GOVERN" in f.get("function", "")]
        assert len(govern) >= 1


# ---------------------------------------------------------------------------
# Test: ISO 42001 report generation
# ---------------------------------------------------------------------------


class TestISO42001Report:
    def test_generates_report(self) -> None:
        entries = _sample_entries(10)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_iso42001_report(Q1_START, Q1_END)

        assert report.framework == "iso_42001"
        assert "42001" in report.framework_name
        assert len(report.findings) > 0

    def test_iso42001_monitoring_clause(self) -> None:
        entries = _sample_entries(5)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_iso42001_report(Q1_START, Q1_END)

        monitoring = [f for f in report.findings if "9.1" in f.get("clause", "")]
        assert len(monitoring) == 1
        assert monitoring[0]["status"] == "conforming"


# ---------------------------------------------------------------------------
# Test: Report serialization
# ---------------------------------------------------------------------------


class TestReportSerialization:
    def test_to_dict(self) -> None:
        entries = _sample_entries(5)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_eu_ai_act_report(Q1_START, Q1_END)

        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["framework"] == "eu_ai_act"
        assert "summary" in d
        assert "findings" in d
        assert "policy_coverage" in d
        assert "chain_integrity" in d
        assert "time_series" in d
        assert "evidence_items" in d

        # Must be JSON-serializable
        json_str = json.dumps(d, default=str)
        assert len(json_str) > 0

    def test_to_text(self) -> None:
        entries = _sample_entries(10)
        gen = ComplianceReportGenerator(audit_entries=entries)
        report = gen.generate_soc2_report(Q1_START, Q1_END)

        text = ComplianceReportGenerator.to_text(report)
        assert "SOC2" in text
        assert "Compliance Evidence Report" in text
        assert "Summary" in text
        assert "Findings" in text
        assert "Audit Chain Integrity" in text


# ---------------------------------------------------------------------------
# Test: Status check
# ---------------------------------------------------------------------------


class TestStatusCheck:
    def test_status_returns_all_frameworks(self) -> None:
        gen = ComplianceReportGenerator(audit_entries=[])
        status = gen.check_status()

        assert len(status) == 4
        for _fw_name, info in status.items():
            assert "coverage_score" in info
            assert "total_requirements" in info
            assert "fully_covered" in info
            assert "partially_covered" in info
            assert "gaps" in info
            assert "has_mandatory_gaps" in info

    def test_coverage_scores_are_reasonable(self) -> None:
        gen = ComplianceReportGenerator(audit_entries=[])
        status = gen.check_status()

        for _fw_name, info in status.items():
            assert 0 <= info["coverage_score"] <= 100
            assert info["total_requirements"] > 0


# ---------------------------------------------------------------------------
# Test: CLI invocation
# ---------------------------------------------------------------------------


class TestCLI:
    def test_compliance_report_help(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "aegis.cli.main", "compliance-report", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "compliance" in result.stdout.lower()

    def test_compliance_report_status_json(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aegis.cli.main",
                "compliance-report",
                "status",
                "--format",
                "json",
                "--db",
                "nonexistent.db",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert len(data) == 4

    def test_compliance_report_missing_period(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "aegis.cli.main",
                "compliance-report",
                "report",
                "--framework",
                "soc2",
                "--db",
                "nonexistent.db",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# Test: Empty audit data edge case
# ---------------------------------------------------------------------------


class TestEmptyData:
    def test_report_with_no_entries(self) -> None:
        gen = ComplianceReportGenerator(audit_entries=[])
        report = gen.generate_eu_ai_act_report(Q1_START, Q1_END)

        assert report.summary["total_actions"] == 0
        assert report.chain_integrity["valid"] is True
        assert len(report.findings) > 0  # still generates structural findings
        assert report.time_series == []
        assert report.evidence_items == []
