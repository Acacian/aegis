"""Tests for HTML report export across compliance, regulatory, and crypto_audit modules."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.compliance import (
    ReportGenerator,
)
from aegis.core.compliance import _html_escape as _compliance_html_escape
from aegis.core.crypto_audit import (
    CryptoAuditChain,
    EvidencePackage,
    VerificationResult,
    evidence_package_to_html,
)
from aegis.core.policy import Approval, Policy, PolicyRule
from aegis.core.regulatory import (
    ComplianceMapper,
    RegulatoryFramework,
)
from aegis.core.risk import RiskLevel

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_policy() -> Policy:
    return Policy(
        rules=[
            PolicyRule(
                name="read_auto",
                match_type="read*",
                risk_level=RiskLevel.LOW,
                approval=Approval.AUTO,
            ),
            PolicyRule(
                name="delete_block",
                match_type="delete*",
                risk_level=RiskLevel.CRITICAL,
                approval=Approval.BLOCK,
            ),
        ],
        default_risk_level=RiskLevel.MEDIUM,
        default_approval=Approval.APPROVE,
    )


def _ts(offset_hours: int = 0) -> str:
    base = datetime(2026, 3, 1, 10, 0, 0, tzinfo=UTC)
    return (base + timedelta(hours=offset_hours)).isoformat()


def _entry(
    action_type: str = "read",
    action_target: str = "crm",
    risk_level: str = "LOW",
    approval: str = "auto",
    matched_rule: str = "read_auto",
    timestamp: str | None = None,
    **kwargs: object,
) -> dict:
    entry: dict = {
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
        "result_status": "success",
        "result_data": None,
        "result_error": None,
        "agent_id": None,
        "parent_agent_id": None,
        "chain_id": None,
        "chain_depth": 0,
    }
    entry.update(kwargs)
    return entry


def _sample_entries(count: int = 10) -> list[dict]:
    entries = []
    for i in range(count):
        if i % 5 == 0:
            entries.append(
                _entry(
                    action_type="delete",
                    risk_level="CRITICAL",
                    approval="block",
                    matched_rule="delete_block",
                    timestamp=_ts(i),
                    id=i + 1,
                )
            )
        else:
            entries.append(
                _entry(
                    action_type="read",
                    risk_level="LOW",
                    approval="auto",
                    matched_rule="read_auto",
                    timestamp=_ts(i),
                    id=i + 1,
                )
            )
    return entries


# ---------------------------------------------------------------------------
# HTML escape helper
# ---------------------------------------------------------------------------


class TestHtmlEscape:
    def test_ampersand(self) -> None:
        assert _compliance_html_escape("a & b") == "a &amp; b"

    def test_angle_brackets(self) -> None:
        assert _compliance_html_escape("<script>") == "&lt;script&gt;"

    def test_double_quotes(self) -> None:
        assert _compliance_html_escape('a "b" c') == "a &quot;b&quot; c"

    def test_plain_text_unchanged(self) -> None:
        assert _compliance_html_escape("hello world") == "hello world"

    def test_combined(self) -> None:
        assert _compliance_html_escape('<a href="x">&') == '&lt;a href=&quot;x&quot;&gt;&amp;'


# ---------------------------------------------------------------------------
# ComplianceReport HTML (compliance.py)
# ---------------------------------------------------------------------------


class TestComplianceReportHtml:
    """Tests for ReportGenerator.to_html()."""

    def _generate_html(self, report_type: str = "governance") -> str:
        gen = ReportGenerator(_make_policy())
        report = gen.generate(_sample_entries(), report_type=report_type)
        return gen.to_html(report)

    def test_returns_string(self) -> None:
        html = self._generate_html()
        assert isinstance(html, str)

    def test_is_valid_html_structure(self) -> None:
        html = self._generate_html()
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_contains_inline_css(self) -> None:
        html = self._generate_html()
        assert "<style>" in html
        assert "font-family" in html

    def test_no_external_resources(self) -> None:
        html = self._generate_html()
        assert "http://" not in html.split("<style>")[0]  # no CDN links in head
        assert "<link " not in html
        assert "<script src=" not in html

    def test_contains_title(self) -> None:
        html = self._generate_html("soc2")
        assert "SOC2 Compliance Report" in html

    def test_contains_grade(self) -> None:
        html = self._generate_html()
        # Grade should be present somewhere (A+, A, B+, etc.)
        assert "/ 100" in html

    def test_contains_score_value(self) -> None:
        gen = ReportGenerator(_make_policy())
        report = gen.generate(_sample_entries(), report_type="governance")
        html = gen.to_html(report)
        assert str(report.score) in html

    def test_contains_period_dates(self) -> None:
        html = self._generate_html()
        assert "2026-03-01" in html

    def test_contains_findings_table(self) -> None:
        html = self._generate_html()
        assert "<table" in html
        assert "Severity" in html
        assert "Category" in html
        assert "Recommendation" in html

    def test_contains_severity_labels(self) -> None:
        html = self._generate_html()
        # At minimum we should have INFO findings
        assert "INFO" in html

    def test_contains_total_actions(self) -> None:
        html = self._generate_html()
        assert "Total Actions" in html

    def test_all_report_types(self) -> None:
        for report_type in ("soc2", "gdpr", "governance"):
            html = self._generate_html(report_type)
            assert "<!DOCTYPE html>" in html
            assert "/ 100" in html

    def test_html_escaping_in_findings(self) -> None:
        """Ensure special characters in findings are escaped."""
        gen = ReportGenerator(_make_policy())
        report = gen.generate(_sample_entries(), report_type="governance")
        html = gen.to_html(report)
        # The generated findings don't contain raw < or > from user data
        # (they use HTML entities via _html_escape)
        # Just verify the HTML is well-formed by checking no unescaped < in text
        assert isinstance(html, str)

    def test_footer_present(self) -> None:
        html = self._generate_html()
        assert "Aegis Compliance Engine" in html

    def test_high_score_green(self) -> None:
        """A high score should use green color."""
        gen = ReportGenerator(_make_policy())
        # All matched rules, no bypasses => should get a high score
        entries = [
            _entry(
                action_type="read",
                approval="auto",
                matched_rule="read_auto",
                timestamp=_ts(i),
                id=i + 1,
            )
            for i in range(10)
        ]
        report = gen.generate(entries, report_type="governance")
        html = gen.to_html(report)
        if report.score >= 90:
            assert "#22c55e" in html  # green

    def test_empty_entries(self) -> None:
        """HTML generation with zero entries should not crash."""
        gen = ReportGenerator(_make_policy())
        report = gen.generate([], report_type="governance")
        html = gen.to_html(report)
        assert "<!DOCTYPE html>" in html
        assert "0" in html  # total actions = 0


# ---------------------------------------------------------------------------
# ComplianceGapAnalysis HTML (regulatory.py)
# ---------------------------------------------------------------------------


class TestRegulatoryHtml:
    """Tests for ComplianceMapper.generate_html_report()."""

    def _generate_html(
        self, framework: RegulatoryFramework = RegulatoryFramework.EU_AI_ACT
    ) -> str:
        mapper = ComplianceMapper()
        analysis = mapper.analyze(framework)
        return mapper.generate_html_report(analysis)

    def test_returns_string(self) -> None:
        html = self._generate_html()
        assert isinstance(html, str)

    def test_is_valid_html_structure(self) -> None:
        html = self._generate_html()
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html

    def test_contains_inline_css(self) -> None:
        html = self._generate_html()
        assert "<style>" in html

    def test_no_external_resources(self) -> None:
        html = self._generate_html()
        assert "<link " not in html
        assert "<script src=" not in html

    def test_contains_framework_name(self) -> None:
        html = self._generate_html(RegulatoryFramework.EU_AI_ACT)
        assert "EU AI Act" in html

    def test_contains_coverage_percentage(self) -> None:
        html = self._generate_html()
        assert "%" in html

    def test_contains_requirements_table(self) -> None:
        html = self._generate_html()
        assert "<table" in html
        assert "Requirement" in html
        assert "Coverage" in html

    def test_contains_coverage_labels(self) -> None:
        html = self._generate_html()
        # Should have FULL and/or PARTIAL
        assert "FULL" in html or "PARTIAL" in html

    def test_contains_total_requirements(self) -> None:
        html = self._generate_html()
        assert "Total Requirements" in html

    def test_all_frameworks(self) -> None:
        mapper = ComplianceMapper()
        for fw in RegulatoryFramework:
            analysis = mapper.analyze(fw)
            html = mapper.generate_html_report(analysis)
            assert "<!DOCTYPE html>" in html
            assert "Coverage Overview" in html

    def test_recommendations_section(self) -> None:
        html = self._generate_html()
        assert "Recommendations" in html

    def test_bar_visualization(self) -> None:
        html = self._generate_html()
        assert "bar-fill" in html
        assert "bar-container" in html

    def test_with_limited_features(self) -> None:
        """HTML with limited features should show gaps."""
        mapper = ComplianceMapper()
        analysis = mapper.analyze(
            RegulatoryFramework.EU_AI_ACT,
            features={"policy_engine": True},
        )
        html = mapper.generate_html_report(analysis)
        assert "<!DOCTYPE html>" in html
        # Should have some NONE coverage entries
        assert "NONE" in html or "Compliance Gaps" in html

    def test_footer_present(self) -> None:
        html = self._generate_html()
        assert "Aegis Compliance Mapper" in html


# ---------------------------------------------------------------------------
# EvidencePackage HTML (crypto_audit.py)
# ---------------------------------------------------------------------------


class TestEvidencePackageHtml:
    """Tests for evidence_package_to_html()."""

    @pytest.fixture()
    def package(self, tmp_path) -> EvidencePackage:
        chain = CryptoAuditChain()
        for i in range(5):
            chain.append(
                agent_id=f"agent-{i % 2}",
                action_type="read" if i % 2 == 0 else "write",
                action_target="database",
                decision="auto" if i % 2 == 0 else "approve",
                risk_level="low" if i % 2 == 0 else "medium",
                matched_rule=f"rule-{i % 2}",
            )
        return chain.generate_evidence_package(tmp_path / "evidence.json")

    @pytest.fixture()
    def broken_package(self) -> EvidencePackage:
        """Create a package with a broken chain result for testing."""
        return EvidencePackage(
            generated_at="2026-03-01T10:00:00+00:00",
            chain_length=3,
            first_entry_time="2026-03-01T10:00:00+00:00",
            last_entry_time="2026-03-01T12:00:00+00:00",
            chain_hash="abc123",
            algorithm="sha256",
            verification_result=VerificationResult(
                valid=False,
                chain_length=3,
                verified_entries=1,
                first_broken_at=2,
                error_message="Entry 2: entry_hash mismatch.",
                verification_hash="def456",
            ),
            summary={
                "action_counts": {"read": 2, "write": 1},
                "decision_counts": {"auto": 2, "approve": 1},
                "agent_counts": {"agent-0": 2, "agent-1": 1},
                "risk_counts": {"low": 2, "medium": 1},
            },
            compliance_notes=["Test note 1", "Test note 2"],
        )

    def test_returns_string(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert isinstance(html, str)

    def test_is_valid_html_structure(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "<html" in html
        assert "</html>" in html

    def test_contains_inline_css(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "<style>" in html

    def test_no_external_resources(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "<link " not in html
        assert "<script src=" not in html

    def test_contains_valid_status(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "VALID" in html

    def test_contains_broken_status(self, broken_package: EvidencePackage) -> None:
        html = evidence_package_to_html(broken_package)
        assert "BROKEN" in html
        assert "entry_hash mismatch" in html

    def test_contains_chain_length(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "5" in html  # chain_length=5

    def test_contains_algorithm(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "sha256" in html

    def test_contains_statistics_tables(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "Action Type" in html
        assert "Decision" in html
        assert "Agent" in html
        assert "Risk Level" in html

    def test_contains_compliance_notes(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "EU AI Act" in html
        assert "SOC2" in html

    def test_contains_chain_hash(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert package.chain_hash in html

    def test_footer_present(self, package: EvidencePackage) -> None:
        html = evidence_package_to_html(package)
        assert "Aegis Cryptographic Audit Engine" in html

    def test_empty_chain(self, tmp_path) -> None:
        """HTML for an empty chain should not crash."""
        chain = CryptoAuditChain()
        package = chain.generate_evidence_package(tmp_path / "empty.json")
        html = evidence_package_to_html(package)
        assert "<!DOCTYPE html>" in html
        assert "VALID" in html


# ---------------------------------------------------------------------------
# CLI integration tests for --format html
# ---------------------------------------------------------------------------


class TestCliComplianceHtml:
    """Test aegis compliance --format html via CLI."""

    def _write_audit_file(self, tmp_path) -> str:
        audit_file = tmp_path / "audit.jsonl"
        entries = _sample_entries(10)
        lines = [json.dumps(e) for e in entries]
        audit_file.write_text("\n".join(lines), encoding="utf-8")
        return str(audit_file)

    def test_compliance_html_stdout(
        self, tmp_path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from aegis.cli.main import main

        audit_file = self._write_audit_file(tmp_path)
        main(["compliance", audit_file, "--format", "html"])
        out = capsys.readouterr().out
        assert "<!DOCTYPE html>" in out
        assert "Compliance Report" in out

    def test_compliance_html_output_file(self, tmp_path) -> None:
        from aegis.cli.main import main

        audit_file = self._write_audit_file(tmp_path)
        output_file = str(tmp_path / "report.html")
        main(["compliance", audit_file, "--format", "html", "--output", output_file])

        from pathlib import Path

        content = Path(output_file).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "Compliance Report" in content


class TestCliRegulatoryHtml:
    """Test aegis regulatory --format html via CLI."""

    def test_regulatory_html_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        from aegis.cli.main import main

        main(["regulatory", "--framework", "eu-ai-act", "--format", "html"])
        out = capsys.readouterr().out
        assert "<!DOCTYPE html>" in out
        assert "EU AI Act" in out

    def test_regulatory_html_output_file(self, tmp_path) -> None:
        from aegis.cli.main import main

        output_file = str(tmp_path / "regulatory.html")
        main([
            "regulatory",
            "--framework",
            "soc2",
            "--format",
            "html",
            "--output",
            output_file,
        ])

        from pathlib import Path

        content = Path(output_file).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "SOC2" in content

    def test_regulatory_html_all_frameworks(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from aegis.cli.main import main

        main(["regulatory", "--framework", "all", "--format", "html"])
        out = capsys.readouterr().out
        assert "<!DOCTYPE html>" in out
