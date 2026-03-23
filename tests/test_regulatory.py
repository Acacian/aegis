"""Tests for the EU AI Act & NIST AI RMF Compliance Mapper."""

from __future__ import annotations

import json

import pytest

from aegis.core.regulatory import (
    ComplianceGapAnalysis,
    ComplianceMapper,
    ComplianceRequirement,
    FeatureMapping,
    RegulatoryFramework,
)

# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestRegulatoryFramework:
    def test_eu_ai_act_value(self) -> None:
        assert RegulatoryFramework.EU_AI_ACT.value == "eu_ai_act"

    def test_nist_ai_rmf_value(self) -> None:
        assert RegulatoryFramework.NIST_AI_RMF.value == "nist_ai_rmf"

    def test_soc2_value(self) -> None:
        assert RegulatoryFramework.SOC2.value == "soc2"

    def test_iso_42001_value(self) -> None:
        assert RegulatoryFramework.ISO_42001.value == "iso_42001"

    def test_owasp_agentic_value(self) -> None:
        assert RegulatoryFramework.OWASP_AGENTIC.value == "owasp_agentic"

    def test_all_members_count(self) -> None:
        assert len(RegulatoryFramework) == 5


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


class TestComplianceRequirement:
    def test_frozen(self) -> None:
        req = ComplianceRequirement(
            framework=RegulatoryFramework.EU_AI_ACT,
            requirement_id="TEST-1",
            title="Test",
            description="desc",
            category="cat",
            mandatory=True,
        )
        with pytest.raises(AttributeError):
            req.title = "changed"  # type: ignore[misc]

    def test_optional_fields_default_none(self) -> None:
        req = ComplianceRequirement(
            framework=RegulatoryFramework.NIST_AI_RMF,
            requirement_id="TEST-2",
            title="Test",
            description="desc",
            category="cat",
            mandatory=False,
        )
        assert req.deadline is None
        assert req.penalty is None

    def test_fields_populated(self) -> None:
        req = ComplianceRequirement(
            framework=RegulatoryFramework.SOC2,
            requirement_id="SOC2-TEST",
            title="Test Title",
            description="Test Description",
            category="access_control",
            mandatory=True,
            deadline="2026-08-02",
            penalty="fine",
        )
        assert req.framework == RegulatoryFramework.SOC2
        assert req.requirement_id == "SOC2-TEST"
        assert req.deadline == "2026-08-02"
        assert req.penalty == "fine"


class TestFeatureMapping:
    def test_frozen(self) -> None:
        req = ComplianceRequirement(
            framework=RegulatoryFramework.EU_AI_ACT,
            requirement_id="T",
            title="T",
            description="d",
            category="c",
            mandatory=True,
        )
        fm = FeatureMapping(
            requirement=req,
            aegis_feature="policy_engine",
            coverage="full",
            evidence_type="logs",
            notes="note",
        )
        with pytest.raises(AttributeError):
            fm.coverage = "none"  # type: ignore[misc]

    def test_coverage_values(self) -> None:
        """Coverage should accept the three defined string values."""
        req = ComplianceRequirement(
            framework=RegulatoryFramework.EU_AI_ACT,
            requirement_id="T",
            title="T",
            description="d",
            category="c",
            mandatory=True,
        )
        for cov in ("full", "partial", "none"):
            fm = FeatureMapping(
                requirement=req,
                aegis_feature="test",
                coverage=cov,
                evidence_type="ev",
                notes="n",
            )
            assert fm.coverage == cov


class TestComplianceGapAnalysis:
    def test_frozen(self) -> None:
        analysis = ComplianceGapAnalysis(
            framework=RegulatoryFramework.EU_AI_ACT,
            total_requirements=0,
            fully_covered=0,
            partially_covered=0,
            not_covered=0,
            coverage_score=0.0,
            mappings=[],
            gaps=[],
            recommendations=[],
        )
        with pytest.raises(AttributeError):
            analysis.coverage_score = 50.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Built-in requirement database tests
# ---------------------------------------------------------------------------


class TestBuiltInRequirements:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_eu_ai_act_count(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        assert len(reqs) >= 10

    def test_nist_ai_rmf_count(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.NIST_AI_RMF)
        assert len(reqs) >= 8

    def test_soc2_count(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.SOC2)
        assert len(reqs) >= 6

    def test_iso_42001_count(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.ISO_42001)
        assert len(reqs) >= 5

    def test_eu_ai_act_art12_exists(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        ids = [r.requirement_id for r in reqs]
        assert "EU-AI-ACT-ART-12" in ids

    def test_nist_govern1_exists(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.NIST_AI_RMF)
        ids = [r.requirement_id for r in reqs]
        assert "NIST-GOVERN-1" in ids

    def test_soc2_cc61_exists(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.SOC2)
        ids = [r.requirement_id for r in reqs]
        assert "SOC2-CC6.1" in ids

    def test_eu_ai_act_requirements_are_mandatory(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        assert all(r.mandatory for r in reqs)

    def test_eu_ai_act_requirements_have_deadlines(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        assert all(r.deadline is not None for r in reqs)

    def test_nist_requirements_are_voluntary(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.NIST_AI_RMF)
        assert all(not r.mandatory for r in reqs)

    def test_get_requirements_returns_copy(self, mapper: ComplianceMapper) -> None:
        reqs1 = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        reqs2 = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        assert reqs1 is not reqs2
        assert reqs1 == reqs2


# ---------------------------------------------------------------------------
# EU AI Act analysis tests
# ---------------------------------------------------------------------------


class TestEUAIActAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_all_features_enabled(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        assert analysis.framework == RegulatoryFramework.EU_AI_ACT
        assert analysis.total_requirements >= 10
        assert analysis.coverage_score > 0
        assert analysis.not_covered == 0  # all requirements should have mappings

    def test_no_features_enabled(self, mapper: ComplianceMapper) -> None:
        features = {
            "policy_engine": False,
            "audit_logging": False,
            "crypto_audit": False,
            "anomaly_detection": False,
            "compliance_reports": False,
            "semantic_conditions": False,
            "agent_trust_chain": False,
            "rate_limiting": False,
            "human_oversight": False,
            "policy_diff": False,
        }
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        assert analysis.not_covered == analysis.total_requirements
        assert analysis.fully_covered == 0
        assert analysis.partially_covered == 0
        assert analysis.coverage_score == 0.0

    def test_some_features_disabled_creates_gaps(self, mapper: ComplianceMapper) -> None:
        features = {
            "policy_engine": True,
            "audit_logging": False,
            "crypto_audit": False,
            "anomaly_detection": False,
            "compliance_reports": False,
            "semantic_conditions": False,
            "agent_trust_chain": False,
            "rate_limiting": False,
            "human_oversight": False,
            "policy_diff": False,
        }
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        # With only policy_engine, Art 14 (human oversight) should be a gap
        gap_ids = [g.requirement_id for g in analysis.gaps]
        assert "EU-AI-ACT-ART-14" in gap_ids

    def test_coverage_score_calculation(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        expected = (
            (analysis.fully_covered + analysis.partially_covered)
            / analysis.total_requirements
            * 100.0
        )
        assert abs(analysis.coverage_score - expected) < 0.01

    def test_crypto_audit_maps_to_art12(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        art12_mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "EU-AI-ACT-ART-12"
            and m.aegis_feature == "crypto_audit"
        ]
        assert len(art12_mappings) == 1
        assert art12_mappings[0].coverage == "full"

    def test_human_oversight_maps_to_art14(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        art14_mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "EU-AI-ACT-ART-14"
            and m.aegis_feature == "human_oversight"
        ]
        assert len(art14_mappings) == 1
        assert art14_mappings[0].coverage == "full"

    def test_totals_add_up(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        assert (
            analysis.fully_covered + analysis.partially_covered + analysis.not_covered
            == analysis.total_requirements
        )


# ---------------------------------------------------------------------------
# NIST AI RMF analysis tests
# ---------------------------------------------------------------------------


class TestNISTAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_all_features_enabled(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.NIST_AI_RMF)
        assert analysis.framework == RegulatoryFramework.NIST_AI_RMF
        assert analysis.total_requirements >= 8
        assert analysis.coverage_score > 0

    def test_no_penalties_in_nist(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.NIST_AI_RMF)
        assert all(r.penalty is None for r in reqs)

    def test_no_deadlines_in_nist(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.NIST_AI_RMF)
        assert all(r.deadline is None for r in reqs)

    def test_policy_engine_maps_to_govern1(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.NIST_AI_RMF)
        gov1_mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "NIST-GOVERN-1"
            and m.aegis_feature == "policy_engine"
        ]
        assert len(gov1_mappings) == 1
        assert gov1_mappings[0].coverage == "full"


# ---------------------------------------------------------------------------
# SOC2 analysis tests
# ---------------------------------------------------------------------------


class TestSOC2Analysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_all_features_enabled(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.SOC2)
        assert analysis.framework == RegulatoryFramework.SOC2
        assert analysis.total_requirements >= 6
        assert analysis.coverage_score > 0

    def test_anomaly_detection_maps_to_monitoring(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.SOC2)
        cc72_mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "SOC2-CC7.2"
            and m.aegis_feature == "anomaly_detection"
        ]
        assert len(cc72_mappings) == 1
        assert cc72_mappings[0].coverage == "full"

    def test_all_soc2_mandatory(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.SOC2)
        assert all(r.mandatory for r in reqs)


# ---------------------------------------------------------------------------
# ISO 42001 analysis tests
# ---------------------------------------------------------------------------


class TestISO42001Analysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_all_features_enabled(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.ISO_42001)
        assert analysis.framework == RegulatoryFramework.ISO_42001
        assert analysis.total_requirements >= 5
        assert analysis.coverage_score > 0

    def test_no_full_coverage(self, mapper: ComplianceMapper) -> None:
        """ISO 42001 requirements all need organizational support, so no full coverage."""
        analysis = mapper.analyze(RegulatoryFramework.ISO_42001)
        # All ISO 42001 mappings are partial since they need organizational processes
        assert analysis.fully_covered == 0
        assert analysis.partially_covered > 0


# ---------------------------------------------------------------------------
# OWASP Agentic AI analysis tests
# ---------------------------------------------------------------------------


class TestOWASPAgenticAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_all_features_enabled(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        assert analysis.framework == RegulatoryFramework.OWASP_AGENTIC
        assert analysis.total_requirements == 10
        assert analysis.coverage_score > 0

    def test_has_all_10_requirements(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.OWASP_AGENTIC)
        assert len(reqs) == 10
        ids = [r.requirement_id for r in reqs]
        for i in range(1, 11):
            assert f"OWASP-AGENT-{i:02d}" in ids

    def test_requirement_titles(self, mapper: ComplianceMapper) -> None:
        """Each OWASP requirement has the official risk title."""
        reqs = mapper.get_requirements(RegulatoryFramework.OWASP_AGENTIC)
        titles = {r.requirement_id: r.title for r in reqs}
        assert titles["OWASP-AGENT-01"] == "Agent Goal Hijack"
        assert titles["OWASP-AGENT-02"] == "Tool Misuse"
        assert titles["OWASP-AGENT-03"] == "Identity and Privilege Abuse"
        assert titles["OWASP-AGENT-04"] == "Supply Chain Vulnerabilities"
        assert titles["OWASP-AGENT-05"] == "Unexpected Code Execution"
        assert titles["OWASP-AGENT-06"] == "Memory and Context Poisoning"
        assert titles["OWASP-AGENT-07"] == "Insecure Inter-Agent Communication"
        assert titles["OWASP-AGENT-08"] == "Cascading Failures"
        assert titles["OWASP-AGENT-09"] == "Human-Agent Trust Exploitation"
        assert titles["OWASP-AGENT-10"] == "Rogue Agents"

    def test_all_requirements_voluntary(self, mapper: ComplianceMapper) -> None:
        """OWASP is a best-practice framework, not legally mandatory."""
        reqs = mapper.get_requirements(RegulatoryFramework.OWASP_AGENTIC)
        assert all(not r.mandatory for r in reqs)

    def test_no_deadlines(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.OWASP_AGENTIC)
        assert all(r.deadline is None for r in reqs)

    def test_no_penalties(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.OWASP_AGENTIC)
        assert all(r.penalty is None for r in reqs)

    def test_all_requirements_covered(self, mapper: ComplianceMapper) -> None:
        """Every OWASP requirement has at least one Aegis feature mapping."""
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        assert analysis.not_covered == 0

    def test_no_full_coverage(self, mapper: ComplianceMapper) -> None:
        """All OWASP mappings are partial since agentic security needs defense-in-depth."""
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        assert analysis.fully_covered == 0
        assert analysis.partially_covered == 10

    def test_totals_add_up(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        assert (
            analysis.fully_covered + analysis.partially_covered + analysis.not_covered
            == analysis.total_requirements
        )

    def test_policy_engine_maps_to_goal_hijack(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "OWASP-AGENT-01"
            and m.aegis_feature == "policy_engine"
        ]
        assert len(mappings) == 1
        assert mappings[0].coverage == "partial"

    def test_agent_trust_chain_maps_to_privilege_abuse(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "OWASP-AGENT-03"
            and m.aegis_feature == "agent_trust_chain"
        ]
        assert len(mappings) == 1
        assert mappings[0].coverage == "partial"

    def test_human_oversight_maps_to_trust_exploitation(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == "OWASP-AGENT-09"
            and m.aegis_feature == "human_oversight"
        ]
        assert len(mappings) == 1
        assert mappings[0].coverage == "partial"

    def test_framework_specific_recommendation(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        owasp_recs = [r for r in analysis.recommendations if "OWASP" in r]
        assert len(owasp_recs) > 0

    def test_report_contains_framework_name(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        report = mapper.generate_report(analysis)
        assert "OWASP Top 10 for Agentic Applications" in report

    def test_evidence_map_framework_name(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        ev = mapper.generate_evidence_map(analysis)
        assert ev["framework"] == "OWASP Agentic AI"


# ---------------------------------------------------------------------------
# Gap identification tests
# ---------------------------------------------------------------------------


class TestGapIdentification:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_no_gaps_with_all_features(self, mapper: ComplianceMapper) -> None:
        for fw in RegulatoryFramework:
            analysis = mapper.analyze(fw)
            assert analysis.not_covered == len(analysis.gaps)

    def test_gaps_match_not_covered_count(self, mapper: ComplianceMapper) -> None:
        features = {"audit_logging": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        assert len(analysis.gaps) == analysis.not_covered

    def test_gaps_contain_requirement_objects(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        for gap in analysis.gaps:
            assert isinstance(gap, ComplianceRequirement)
            assert gap.framework == RegulatoryFramework.EU_AI_ACT

    def test_disabled_human_oversight_creates_art14_gap(self, mapper: ComplianceMapper) -> None:
        features = {
            "policy_engine": True,
            "audit_logging": True,
            "crypto_audit": True,
            "anomaly_detection": True,
            "compliance_reports": True,
            "semantic_conditions": True,
            "agent_trust_chain": True,
            "rate_limiting": True,
            "human_oversight": False,
            "policy_diff": True,
        }
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        gap_ids = [g.requirement_id for g in analysis.gaps]
        # Art 14 depends solely on human_oversight for full coverage
        # but Art 26 also maps human_oversight partially; it also maps audit_logging
        # So only Art 14 should be a gap
        assert "EU-AI-ACT-ART-14" in gap_ids


# ---------------------------------------------------------------------------
# Recommendations tests
# ---------------------------------------------------------------------------


class TestRecommendations:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_recommendations_not_empty(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        assert len(analysis.recommendations) > 0

    def test_recommendations_with_gaps_mention_urgent(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        urgent = [r for r in analysis.recommendations if "URGENT" in r]
        assert len(urgent) > 0  # EU AI Act gaps have deadlines

    def test_nist_no_urgent_deadlines(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True}
        analysis = mapper.analyze(RegulatoryFramework.NIST_AI_RMF, features)
        urgent = [r for r in analysis.recommendations if "URGENT" in r]
        assert len(urgent) == 0  # NIST has no deadlines

    def test_disabled_features_recommendation(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True, "audit_logging": False}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        enable_recs = [r for r in analysis.recommendations if "Enable disabled" in r]
        assert len(enable_recs) > 0

    def test_framework_specific_advice(self, mapper: ComplianceMapper) -> None:
        for fw in RegulatoryFramework:
            analysis = mapper.analyze(fw)
            # Each framework should produce at least some recommendations
            assert len(analysis.recommendations) > 0


# ---------------------------------------------------------------------------
# Report generation tests
# ---------------------------------------------------------------------------


class TestReportGeneration:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_report_is_markdown(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        report = mapper.generate_report(analysis)
        assert report.startswith("# Compliance Gap Analysis:")
        assert "## Executive Summary" in report

    def test_report_contains_framework_name(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        report = mapper.generate_report(analysis)
        assert "EU AI Act" in report

    def test_report_contains_coverage_score(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        report = mapper.generate_report(analysis)
        assert "Coverage Score" in report

    def test_report_with_gaps_has_gaps_section(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        report = mapper.generate_report(analysis)
        assert "## Compliance Gaps" in report

    def test_report_without_gaps_no_gaps_section(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        if analysis.not_covered == 0:
            report = mapper.generate_report(analysis)
            assert "## Compliance Gaps" not in report

    def test_report_has_recommendations(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        report = mapper.generate_report(analysis)
        assert "## Recommendations" in report

    def test_report_has_footer(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        report = mapper.generate_report(analysis)
        assert "Aegis Compliance Mapper" in report

    def test_nist_report_name(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.NIST_AI_RMF)
        report = mapper.generate_report(analysis)
        assert "NIST AI Risk Management Framework" in report

    def test_soc2_report_name(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.SOC2)
        report = mapper.generate_report(analysis)
        assert "SOC2 Trust Services Criteria" in report


# ---------------------------------------------------------------------------
# Evidence map tests
# ---------------------------------------------------------------------------


class TestEvidenceMap:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_evidence_map_is_json_serializable(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        ev = mapper.generate_evidence_map(analysis)
        # Should not raise
        result = json.dumps(ev)
        assert isinstance(result, str)

    def test_evidence_map_structure(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        ev = mapper.generate_evidence_map(analysis)
        assert "framework" in ev
        assert "summary" in ev
        assert "mappings" in ev
        assert "gaps" in ev
        assert "recommendations" in ev

    def test_evidence_map_summary_values(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        ev = mapper.generate_evidence_map(analysis)
        summary = ev["summary"]
        assert isinstance(summary, dict)
        assert summary["total_requirements"] == analysis.total_requirements  # type: ignore[index]
        assert summary["fully_covered"] == analysis.fully_covered  # type: ignore[index]

    def test_evidence_map_mappings_structure(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.SOC2)
        ev = mapper.generate_evidence_map(analysis)
        mappings = ev["mappings"]
        assert isinstance(mappings, list)
        assert len(mappings) > 0
        first = mappings[0]  # type: ignore[index]
        assert "requirement_id" in first
        assert "aegis_feature" in first
        assert "coverage" in first
        assert "evidence_type" in first

    def test_evidence_map_with_gaps(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        ev = mapper.generate_evidence_map(analysis)
        gaps = ev["gaps"]
        assert isinstance(gaps, list)
        assert len(gaps) > 0


# ---------------------------------------------------------------------------
# Deadlines tests
# ---------------------------------------------------------------------------


class TestDeadlines:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_get_deadlines_returns_list(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        assert isinstance(deadlines, list)
        assert len(deadlines) > 0

    def test_deadlines_are_sorted(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        dates = [d for d, _ in deadlines]
        assert dates == sorted(dates)

    def test_deadlines_contain_eu_ai_act(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        frameworks = {req.framework for _, req in deadlines}
        assert RegulatoryFramework.EU_AI_ACT in frameworks

    def test_nist_not_in_deadlines(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        frameworks = {req.framework for _, req in deadlines}
        assert RegulatoryFramework.NIST_AI_RMF not in frameworks

    def test_all_deadlines_are_strings(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        for date_str, _ in deadlines:
            assert isinstance(date_str, str)
            # Should be YYYY-MM-DD format
            parts = date_str.split("-")
            assert len(parts) == 3


# ---------------------------------------------------------------------------
# Edge case & integration tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_empty_features_dict(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, {})
        assert analysis.not_covered == analysis.total_requirements

    def test_unknown_features_ignored(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True, "nonexistent_feature": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        # Should not raise; nonexistent feature is just ignored
        assert analysis.total_requirements > 0

    def test_all_frameworks_analyzable(self, mapper: ComplianceMapper) -> None:
        for fw in RegulatoryFramework:
            analysis = mapper.analyze(fw)
            assert analysis.total_requirements > 0
            assert analysis.coverage_score >= 0
            assert analysis.coverage_score <= 100

    def test_multiple_analyses_independent(self, mapper: ComplianceMapper) -> None:
        a1 = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        a2 = mapper.analyze(
            RegulatoryFramework.EU_AI_ACT,
            {"policy_engine": True},
        )
        assert a1.coverage_score != a2.coverage_score

    def test_none_coverage_mapping_for_gaps(self, mapper: ComplianceMapper) -> None:
        features = {"policy_engine": True}
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT, features)
        none_mappings = [m for m in analysis.mappings if m.coverage == "none"]
        # Each gap should have exactly one "(none)" mapping
        assert len(none_mappings) == analysis.not_covered
        for m in none_mappings:
            assert m.aegis_feature == "(none)"
