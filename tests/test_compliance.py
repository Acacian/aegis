"""Tests for the compliance report generator."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.compliance import (
    ComplianceFinding,
    ComplianceReport,
    ReportGenerator,
    _compute_grade,
)
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_policy() -> Policy:
    """Create a realistic policy for testing."""
    return Policy(
        rules=[
            PolicyRule(
                name="read_auto",
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
            PolicyRule(
                name="write_approve",
                match_type="write*",
                risk_level=RiskLevel.MEDIUM,
                approval=Approval.APPROVE,
            ),
            PolicyRule(
                name="delete_block",
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
            PolicyRule(
                name="bulk_high",
                match_type="bulk_*",
                risk_level=RiskLevel.HIGH,
                approval=Approval.APPROVE,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _ts(offset_hours: int = 0) -> str:
    """Generate an ISO timestamp offset from a base time."""
    base = datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)
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
) -> dict:
    """Build an audit log entry dict matching AuditLogger output."""
    entry = {
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


def _sample_entries(count: int = 20) -> list[dict]:
    """Generate a realistic set of audit entries."""
    entries = []
    for i in range(count):
        if i % 5 == 0:
            # Blocked delete
            entries.append(
                _entry(
                    action_type="delete",
                    action_target="database",
                    risk_level="CRITICAL",
                    approval="block",
                    matched_rule="delete_block",
                    timestamp=_ts(i),
                    result_status="blocked",
                    id=i + 1,
                )
            )
        elif i % 4 == 0:
            # Write requiring approval
            entries.append(
                _entry(
                    action_type="write",
                    action_target="crm",
                    risk_level="MEDIUM",
                    approval="approve",
                    matched_rule="write_approve",
                    timestamp=_ts(i),
                    id=i + 1,
                )
            )
        else:
            # Auto-approved reads
            entries.append(
                _entry(
                    action_type="read",
                    action_target="crm",
                    risk_level="LOW",
                    approval="auto",
                    matched_rule="read_auto",
                    timestamp=_ts(i),
                    id=i + 1,
                )
            )
    return entries


# ---------------------------------------------------------------------------
# Grade computation
# ---------------------------------------------------------------------------


class TestComputeGrade:
    def test_a_plus(self):
        assert _compute_grade(100) == "A+"
        assert _compute_grade(97) == "A+"

    def test_a(self):
        assert _compute_grade(95) == "A"
        assert _compute_grade(93) == "A"

    def test_a_minus(self):
        assert _compute_grade(90) == "A-"

    def test_b_range(self):
        assert _compute_grade(87) == "B+"
        assert _compute_grade(83) == "B"
        assert _compute_grade(80) == "B-"

    def test_c_range(self):
        assert _compute_grade(77) == "C+"
        assert _compute_grade(73) == "C"
        assert _compute_grade(70) == "C-"

    def test_d_range(self):
        assert _compute_grade(67) == "D+"
        assert _compute_grade(63) == "D"
        assert _compute_grade(60) == "D-"

    def test_f(self):
        assert _compute_grade(59) == "F"
        assert _compute_grade(0) == "F"


# ---------------------------------------------------------------------------
# ComplianceReport / ComplianceFinding dataclass basics
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_finding_creation(self):
        f = ComplianceFinding(
            severity="critical",
            category="access_control",
            title="Test",
            description="desc",
            recommendation="fix it",
        )
        assert f.severity == "critical"
        assert f.category == "access_control"

    def test_report_defaults(self):
        now = datetime.now(UTC)
        r = ComplianceReport(
            report_type="governance",
            generated_at=now,
            period_start=now,
            period_end=now,
            total_actions=0,
            blocked_actions=0,
            approved_actions=0,
            auto_approved=0,
            summary="empty",
        )
        assert r.score == 0
        assert r.grade == "F"
        assert r.findings == []


# ---------------------------------------------------------------------------
# SOC2 report tests
# ---------------------------------------------------------------------------


class TestSOC2Report:
    def test_clean_audit(self):
        """All actions properly governed -> high score."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(20)
        report = gen.generate(entries, report_type="soc2")

        assert report.report_type == "soc2"
        assert report.total_actions == 20
        assert report.score >= 85
        assert report.grade in ("A+", "A", "A-", "B+")
        assert any("CC6.1" in f.title for f in report.findings)
        assert any("CC6.8" in f.title for f in report.findings)
        assert any("CC7.2" in f.title for f in report.findings)
        assert any("CC8.1" in f.title for f in report.findings)

    def test_policy_bypass_detected(self):
        """High-risk auto-approved actions cause CC6.8 failure."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                action_type="write",
                risk_level="HIGH",
                approval="auto",
                matched_rule="some_rule",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(5)
        ]
        report = gen.generate(entries, report_type="soc2")

        cc68 = [f for f in report.findings if "CC6.8" in f.title]
        assert len(cc68) == 1
        assert "FAIL" in cc68[0].title
        assert report.score < 80

    def test_missing_matched_rules(self):
        """Actions without matched_rule cause CC6.1 failure."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [_entry(matched_rule="", timestamp=_ts(i), id=i + 1) for i in range(5)]
        report = gen.generate(entries, report_type="soc2")

        cc61 = [f for f in report.findings if "CC6.1" in f.title]
        assert len(cc61) == 1
        assert "FAIL" in cc61[0].title

    def test_audit_gaps_detected(self):
        """Large time gaps between entries trigger CC7.2 warning."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(timestamp=_ts(0), id=1),
            _entry(timestamp=_ts(2), id=2),  # 2 hours -> gap!
        ]
        report = gen.generate(entries, report_type="soc2")

        cc72 = [f for f in report.findings if "CC7.2" in f.title]
        assert len(cc72) == 1
        assert "WARN" in cc72[0].title or "gap" in cc72[0].description.lower()

    def test_policy_change_tracking(self):
        """Policy change actions are tracked by CC8.1."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                action_type="update_policy",
                matched_rule="policy_rule",
                timestamp=_ts(0),
                id=1,
            ),
            _entry(timestamp=_ts(1), id=2),
        ]
        report = gen.generate(entries, report_type="soc2")

        cc81 = [f for f in report.findings if "CC8.1" in f.title]
        assert len(cc81) == 1
        assert "PASS" in cc81[0].title

    def test_soc2_summary_format(self):
        """Summary string contains expected statistics."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)
        report = gen.generate(entries, report_type="soc2")

        assert "Total actions evaluated" in report.summary
        assert "Policy enforcement rate" in report.summary
        assert "Blocked unauthorized actions" in report.summary


# ---------------------------------------------------------------------------
# GDPR report tests
# ---------------------------------------------------------------------------


class TestGDPRReport:
    def test_clean_gdpr(self):
        """Standard entries with no personal data issues -> good score."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)
        report = gen.generate(entries, report_type="gdpr")

        assert report.report_type == "gdpr"
        assert report.score >= 80

    def test_personal_data_access_logged(self):
        """Personal data accesses detected and flagged."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                action_target="user_profiles",
                matched_rule="read_auto",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(5)
        ]
        report = gen.generate(entries, report_type="gdpr")

        data_access = [f for f in report.findings if "Data Access Logging" in f.title]
        assert len(data_access) == 1
        assert "PASS" in data_access[0].title
        assert "5" in data_access[0].description

    def test_personal_data_unlogged(self):
        """Personal data accesses without matched rules -> failure."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                action_target="customer_data",
                matched_rule="",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(3)
        ]
        report = gen.generate(entries, report_type="gdpr")

        data_access = [f for f in report.findings if "Data Access Logging" in f.title]
        assert len(data_access) == 1
        assert "FAIL" in data_access[0].title
        assert report.score < 90

    def test_delete_operations_logged(self):
        """Delete operations properly tracked for erasure compliance."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                action_type="delete_user",
                action_target="database",
                risk_level="CRITICAL",
                approval="block",
                matched_rule="delete_block",
                timestamp=_ts(i),
                result_status="blocked",
                id=i + 1,
            )
            for i in range(3)
        ]
        report = gen.generate(entries, report_type="gdpr")

        erasure = [f for f in report.findings if "Erasure" in f.title]
        assert len(erasure) == 1
        assert "PASS" in erasure[0].title

    def test_excessive_reads_flagged(self):
        """Data minimization warning when reads dominate."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        # All reads, same type
        entries = [
            _entry(
                action_type="read_data",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(10)
        ]
        report = gen.generate(entries, report_type="gdpr")

        minimization = [f for f in report.findings if "Minimization" in f.title]
        assert len(minimization) == 1
        assert "WARN" in minimization[0].title

    def test_gdpr_no_personal_data(self):
        """When no personal data targets are accessed."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(action_target="metrics_cache", timestamp=_ts(i), id=i + 1) for i in range(5)
        ]
        report = gen.generate(entries, report_type="gdpr")

        data_access = [f for f in report.findings if "Data Access Logging" in f.title]
        assert len(data_access) == 1
        assert "No personal data" in data_access[0].description


# ---------------------------------------------------------------------------
# Governance report tests
# ---------------------------------------------------------------------------


class TestGovernanceReport:
    def test_high_coverage(self):
        """Entries with explicit rules get good coverage score."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(20)
        report = gen.generate(entries, report_type="governance")

        assert report.report_type == "governance"
        assert report.total_actions == 20
        coverage = [f for f in report.findings if "Coverage" in f.title]
        assert len(coverage) == 1
        assert "PASS" in coverage[0].title

    def test_low_coverage(self):
        """Entries falling through to defaults -> low coverage."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                action_type="custom_action",
                matched_rule="<default>",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(10)
        ]
        report = gen.generate(entries, report_type="governance")

        coverage = [f for f in report.findings if "Coverage" in f.title]
        assert len(coverage) == 1
        assert "FAIL" in coverage[0].title
        assert report.score < 80

    def test_approval_gate_stats(self):
        """Approval gate usage finding is present."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(approval="approve", timestamp=_ts(0), id=1),
            _entry(approval="auto", timestamp=_ts(1), id=2),
            _entry(approval="auto", timestamp=_ts(2), id=3),
        ]
        report = gen.generate(entries, report_type="governance")

        gate = [f for f in report.findings if "Approval Gate" in f.title]
        assert len(gate) == 1
        assert "1" in gate[0].description  # 1 action required approval

    def test_risk_distribution(self):
        """Risk distribution finding summarizes risk levels."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(risk_level="LOW", timestamp=_ts(0), id=1),
            _entry(risk_level="MEDIUM", timestamp=_ts(1), id=2),
            _entry(risk_level="HIGH", timestamp=_ts(2), id=3),
        ]
        report = gen.generate(entries, report_type="governance")

        risk = [f for f in report.findings if "Risk Distribution" in f.title]
        assert len(risk) == 1
        assert "LOW" in risk[0].description
        assert "HIGH" in risk[0].description

    def test_high_risk_concentration_warning(self):
        """Lots of high/critical risk -> warning."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(
                risk_level="CRITICAL",
                approval="block",
                matched_rule="delete_block",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(10)
        ]
        report = gen.generate(entries, report_type="governance")

        risk = [f for f in report.findings if "Risk Distribution" in f.title]
        assert len(risk) == 1
        assert risk[0].severity == "warning"

    def test_agent_behavior_summary(self):
        """Per-agent summaries when agent IDs are present."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(agent_id="agent-a", timestamp=_ts(0), id=1),
            _entry(agent_id="agent-a", timestamp=_ts(1), id=2),
            _entry(agent_id="agent-b", timestamp=_ts(2), id=3),
        ]
        report = gen.generate(entries, report_type="governance")

        agent = [f for f in report.findings if "Agent Behavior" in f.title]
        assert len(agent) == 1
        assert "agent-a" in agent[0].description
        assert "agent-b" in agent[0].description

    def test_no_agent_ids(self):
        """No agent behavior finding when all agents are unknown."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [_entry(agent_id=None, timestamp=_ts(i), id=i + 1) for i in range(5)]
        report = gen.generate(entries, report_type="governance")

        agent = [f for f in report.findings if "Agent Behavior" in f.title]
        assert len(agent) == 0


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------


class TestMarkdown:
    def test_soc2_markdown(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(20)
        report = gen.generate(entries, report_type="soc2")
        md = gen.to_markdown(report)

        assert "# SOC2 Compliance Report" in md
        assert "## Period:" in md
        assert "### Summary" in md
        assert "### Trust Services Criteria" in md
        assert "### Grade:" in md
        assert "Total actions evaluated:" in md

    def test_gdpr_markdown(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)
        report = gen.generate(entries, report_type="gdpr")
        md = gen.to_markdown(report)

        assert "# GDPR Compliance Report" in md
        assert "### GDPR Compliance Criteria" in md

    def test_governance_markdown(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)
        report = gen.generate(entries, report_type="governance")
        md = gen.to_markdown(report)

        assert "# Governance Compliance Report" in md
        assert "### Governance Findings" in md

    def test_markdown_contains_findings(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)
        report = gen.generate(entries, report_type="soc2")
        md = gen.to_markdown(report)

        for finding in report.findings:
            assert finding.title in md

    def test_markdown_grade_line(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)
        report = gen.generate(entries, report_type="governance")
        md = gen.to_markdown(report)

        assert f"### Grade: {report.grade} ({report.score}/100)" in md


# ---------------------------------------------------------------------------
# Dict serialization
# ---------------------------------------------------------------------------


class TestToDict:
    def test_all_keys_present(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(5)
        report = gen.generate(entries, report_type="governance")
        d = gen.to_dict(report)

        expected_keys = {
            "report_type",
            "generated_at",
            "period_start",
            "period_end",
            "total_actions",
            "blocked_actions",
            "approved_actions",
            "auto_approved",
            "summary",
            "score",
            "grade",
            "findings",
        }
        assert set(d.keys()) == expected_keys

    def test_findings_serialized(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(5)
        report = gen.generate(entries, report_type="soc2")
        d = gen.to_dict(report)

        assert isinstance(d["findings"], list)
        assert len(d["findings"]) == len(report.findings)
        for finding_dict in d["findings"]:
            assert "severity" in finding_dict
            assert "category" in finding_dict
            assert "title" in finding_dict
            assert "description" in finding_dict
            assert "recommendation" in finding_dict

    def test_json_serializable(self):
        """to_dict output should be fully JSON-serializable."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(5)
        report = gen.generate(entries, report_type="governance")
        d = gen.to_dict(report)

        # Should not raise
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

    def test_roundtrip_score_grade(self):
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(20)
        report = gen.generate(entries, report_type="soc2")
        d = gen.to_dict(report)

        assert d["score"] == report.score
        assert d["grade"] == report.grade


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_entries(self):
        """Empty audit log still produces a valid report."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        report = gen.generate([], report_type="governance")

        assert report.total_actions == 0
        assert report.blocked_actions == 0
        assert report.approved_actions == 0
        assert report.auto_approved == 0
        assert report.score >= 0
        assert report.grade in (
            "A+",
            "A",
            "A-",
            "B+",
            "B",
            "B-",
            "C+",
            "C",
            "C-",
            "D+",
            "D",
            "D-",
            "F",
        )

    def test_single_entry(self):
        """Single audit entry produces a valid report."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        report = gen.generate([_entry()], report_type="soc2")

        assert report.total_actions == 1
        assert report.findings

    def test_unknown_report_type(self):
        """Unknown report type raises ValueError."""
        policy = _make_policy()
        gen = ReportGenerator(policy)

        with pytest.raises(ValueError, match="Unknown report type"):
            gen.generate([], report_type="hipaa")

    def test_period_filtering(self):
        """Period boundaries filter entries correctly."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            _entry(timestamp=_ts(0), id=1),
            _entry(timestamp=_ts(5), id=2),
            _entry(timestamp=_ts(10), id=3),
        ]
        # Only the middle entry falls in range
        start = datetime(2026, 3, 1, 14, 0, 0, tzinfo=UTC)
        end = datetime(2026, 3, 1, 16, 0, 0, tzinfo=UTC)
        report = gen.generate(
            entries,
            report_type="governance",
            period_start=start,
            period_end=end,
        )
        assert report.total_actions == 1

    def test_entries_without_timestamps(self):
        """Entries missing timestamps are excluded by period filter."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [
            {
                "action_type": "read",
                "action_target": "x",
                "approval": "auto",
                "risk_level": "LOW",
                "matched_rule": "r",
            },
        ]
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 12, 31, tzinfo=UTC)
        report = gen.generate(
            entries,
            report_type="governance",
            period_start=start,
            period_end=end,
        )
        # No timestamp -> filtered out
        assert report.total_actions == 0

    def test_entries_without_period_uses_all(self):
        """When no period is given, all entries are used."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = [_entry(timestamp=_ts(i), id=i + 1) for i in range(5)]
        report = gen.generate(entries, report_type="governance")
        assert report.total_actions == 5

    def test_all_report_types_accept_same_entries(self):
        """All three report types work with the same entry set."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(10)

        for rtype in ("soc2", "gdpr", "governance"):
            report = gen.generate(entries, report_type=rtype)
            assert report.report_type == rtype
            assert report.total_actions == 10

    def test_empty_policy(self):
        """Report generation works with an empty policy."""
        policy = Policy()
        gen = ReportGenerator(policy)
        entries = _sample_entries(5)
        report = gen.generate(entries, report_type="governance")

        assert report.total_actions == 5

    def test_score_clamped_0_100(self):
        """Score never goes below 0 or above 100."""
        policy = _make_policy()
        gen = ReportGenerator(policy)
        # Many failures stacked up
        entries = [
            _entry(
                action_type="write",
                risk_level="CRITICAL",
                approval="auto",
                matched_rule="",
                timestamp=_ts(i * 2),  # >1h gaps
                id=i + 1,
            )
            for i in range(20)
        ]
        report = gen.generate(entries, report_type="soc2")
        assert 0 <= report.score <= 100


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCLICompliance:
    def test_cli_compliance_markdown(self, tmp_path, capsys):
        """CLI compliance command produces markdown output."""
        from aegis.cli.main import main

        # Write a JSONL audit file
        audit_file = tmp_path / "audit.jsonl"
        entries = _sample_entries(10)
        with audit_file.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        main(["compliance", str(audit_file), "--type", "soc2", "--format", "markdown"])
        captured = capsys.readouterr()
        assert "SOC2 Compliance Report" in captured.out
        assert "Grade:" in captured.out

    def test_cli_compliance_json(self, tmp_path, capsys):
        """CLI compliance command produces JSON output."""
        from aegis.cli.main import main

        audit_file = tmp_path / "audit.jsonl"
        entries = _sample_entries(5)
        with audit_file.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        main(["compliance", str(audit_file), "--type", "governance", "--format", "json"])
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "report_type" in data
        assert data["report_type"] == "governance"
        assert "score" in data
        assert "findings" in data

    def test_cli_compliance_all_types(self, tmp_path, capsys):
        """CLI compliance command works with all report types."""
        from aegis.cli.main import main

        audit_file = tmp_path / "audit.jsonl"
        entries = _sample_entries(5)
        with audit_file.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        for rtype in ("soc2", "gdpr", "governance"):
            main(["compliance", str(audit_file), "--type", rtype, "--format", "json"])
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["report_type"] == rtype

    def test_cli_compliance_missing_file(self, tmp_path):
        """CLI exits with error for missing file."""
        from aegis.cli.main import main

        with pytest.raises(SystemExit):
            main(["compliance", str(tmp_path / "nonexistent.jsonl")])

    def test_cli_compliance_default_format(self, tmp_path, capsys):
        """Default format is markdown."""
        from aegis.cli.main import main

        audit_file = tmp_path / "audit.jsonl"
        entries = _sample_entries(5)
        with audit_file.open("w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

        main(["compliance", str(audit_file)])
        captured = capsys.readouterr()
        assert "Governance Compliance Report" in captured.out
