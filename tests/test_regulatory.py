"""Tests for the EU AI Act & NIST AI RMF Compliance Mapper."""

from __future__ import annotations

import json

import pytest

from aegis.core.regulatory import (
    ComplianceMapper,
    ComplianceRequirement,
    FeatureMapping,
    RegulatoryFramework,
)

# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_compliance_requirement_frozen(self) -> None:
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

    def test_compliance_requirement_fields(self) -> None:
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

    def test_compliance_requirement_optional_defaults(self) -> None:
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

    def test_feature_mapping_coverage_values(self) -> None:
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


# ---------------------------------------------------------------------------
# Built-in requirement database tests
# ---------------------------------------------------------------------------


class TestBuiltInRequirements:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    @pytest.mark.parametrize(
        ("framework", "min_count"),
        [
            (RegulatoryFramework.EU_AI_ACT, 10),
            (RegulatoryFramework.NIST_AI_RMF, 8),
            (RegulatoryFramework.SOC2, 6),
            (RegulatoryFramework.ISO_42001, 5),
        ],
    )
    def test_framework_requirement_count(
        self,
        mapper: ComplianceMapper,
        framework: RegulatoryFramework,
        min_count: int,
    ) -> None:
        reqs = mapper.get_requirements(framework)
        assert len(reqs) >= min_count

    @pytest.mark.parametrize(
        ("framework", "expected_id"),
        [
            (RegulatoryFramework.EU_AI_ACT, "EU-AI-ACT-ART-12"),
            (RegulatoryFramework.NIST_AI_RMF, "NIST-GOVERN-1"),
            (RegulatoryFramework.SOC2, "SOC2-CC6.1"),
        ],
    )
    def test_known_requirement_exists(
        self,
        mapper: ComplianceMapper,
        framework: RegulatoryFramework,
        expected_id: str,
    ) -> None:
        ids = [r.requirement_id for r in mapper.get_requirements(framework)]
        assert expected_id in ids

    def test_eu_ai_act_requirements_are_mandatory_with_deadlines(
        self, mapper: ComplianceMapper
    ) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        assert all(r.mandatory for r in reqs)
        assert all(r.deadline is not None for r in reqs)

    @pytest.mark.parametrize(
        "framework",
        [RegulatoryFramework.NIST_AI_RMF, RegulatoryFramework.OWASP_AGENTIC],
    )
    def test_voluntary_frameworks_no_deadlines_no_penalties(
        self, mapper: ComplianceMapper, framework: RegulatoryFramework
    ) -> None:
        reqs = mapper.get_requirements(framework)
        assert all(not r.mandatory for r in reqs)
        assert all(r.deadline is None for r in reqs)
        assert all(r.penalty is None for r in reqs)

    def test_all_soc2_mandatory(self, mapper: ComplianceMapper) -> None:
        reqs = mapper.get_requirements(RegulatoryFramework.SOC2)
        assert all(r.mandatory for r in reqs)

    def test_get_requirements_returns_copy(self, mapper: ComplianceMapper) -> None:
        reqs1 = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        reqs2 = mapper.get_requirements(RegulatoryFramework.EU_AI_ACT)
        assert reqs1 is not reqs2
        assert reqs1 == reqs2


# ---------------------------------------------------------------------------
# Cross-framework analysis tests (replaces per-framework all_features_enabled)
# ---------------------------------------------------------------------------


class TestCrossFrameworkAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    @pytest.mark.parametrize(
        ("framework", "min_reqs"),
        [
            (RegulatoryFramework.EU_AI_ACT, 10),
            (RegulatoryFramework.NIST_AI_RMF, 8),
            (RegulatoryFramework.SOC2, 6),
            (RegulatoryFramework.ISO_42001, 5),
            (RegulatoryFramework.OWASP_AGENTIC, 10),
        ],
    )
    def test_all_features_enabled(
        self,
        mapper: ComplianceMapper,
        framework: RegulatoryFramework,
        min_reqs: int,
    ) -> None:
        analysis = mapper.analyze(framework)
        assert analysis.framework == framework
        assert analysis.total_requirements >= min_reqs
        assert analysis.coverage_score > 0

    def test_totals_add_up_all_frameworks(self, mapper: ComplianceMapper) -> None:
        for fw in RegulatoryFramework:
            analysis = mapper.analyze(fw)
            assert (
                analysis.fully_covered + analysis.partially_covered + analysis.not_covered
                == analysis.total_requirements
            )

    def test_all_frameworks_analyzable(self, mapper: ComplianceMapper) -> None:
        for fw in RegulatoryFramework:
            analysis = mapper.analyze(fw)
            assert analysis.total_requirements > 0
            assert 0 <= analysis.coverage_score <= 100


# ---------------------------------------------------------------------------
# EU AI Act analysis tests
# ---------------------------------------------------------------------------


class TestEUAIActAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

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

    def test_eu_ai_act_no_gaps_all_features(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        assert analysis.not_covered == 0


# ---------------------------------------------------------------------------
# NIST AI RMF analysis tests
# ---------------------------------------------------------------------------


class TestNISTAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

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


# ---------------------------------------------------------------------------
# ISO 42001 analysis tests
# ---------------------------------------------------------------------------


class TestISO42001Analysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_no_full_coverage(self, mapper: ComplianceMapper) -> None:
        """ISO 42001 requirements all need organizational support, so no full coverage."""
        analysis = mapper.analyze(RegulatoryFramework.ISO_42001)
        assert analysis.fully_covered == 0
        assert analysis.partially_covered > 0


# ---------------------------------------------------------------------------
# OWASP Agentic AI analysis tests
# ---------------------------------------------------------------------------


class TestOWASPAgenticAnalysis:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

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

    def test_all_requirements_covered_partial(self, mapper: ComplianceMapper) -> None:
        """Every OWASP requirement is covered, all partial (defense-in-depth)."""
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        assert analysis.not_covered == 0
        assert analysis.fully_covered == 0
        assert analysis.partially_covered == 10

    @pytest.mark.parametrize(
        ("req_id", "feature"),
        [
            ("OWASP-AGENT-01", "policy_engine"),
            ("OWASP-AGENT-03", "agent_trust_chain"),
            ("OWASP-AGENT-09", "human_oversight"),
        ],
    )
    def test_feature_maps_to_requirement(
        self,
        mapper: ComplianceMapper,
        req_id: str,
        feature: str,
    ) -> None:
        analysis = mapper.analyze(RegulatoryFramework.OWASP_AGENTIC)
        mappings = [
            m
            for m in analysis.mappings
            if m.requirement.requirement_id == req_id and m.aegis_feature == feature
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
            assert len(analysis.recommendations) > 0


# ---------------------------------------------------------------------------
# Report generation tests
# ---------------------------------------------------------------------------


class TestReportGeneration:
    @pytest.fixture()
    def mapper(self) -> ComplianceMapper:
        return ComplianceMapper()

    def test_report_structure(self, mapper: ComplianceMapper) -> None:
        analysis = mapper.analyze(RegulatoryFramework.EU_AI_ACT)
        report = mapper.generate_report(analysis)
        assert report.startswith("# Compliance Gap Analysis:")
        assert "## Executive Summary" in report
        assert "Coverage Score" in report
        assert "EU AI Act" in report
        assert "## Recommendations" in report
        assert "Aegis Compliance Mapper" in report

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

    @pytest.mark.parametrize(
        ("framework", "expected_name"),
        [
            (RegulatoryFramework.NIST_AI_RMF, "NIST AI Risk Management Framework"),
            (RegulatoryFramework.SOC2, "SOC2 Trust Services Criteria"),
        ],
    )
    def test_framework_report_name(
        self,
        mapper: ComplianceMapper,
        framework: RegulatoryFramework,
        expected_name: str,
    ) -> None:
        analysis = mapper.analyze(framework)
        report = mapper.generate_report(analysis)
        assert expected_name in report


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

    def test_get_deadlines_returns_sorted_list(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        assert isinstance(deadlines, list)
        assert len(deadlines) > 0
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

    def test_all_deadlines_are_date_strings(self, mapper: ComplianceMapper) -> None:
        deadlines = mapper.get_deadlines()
        for date_str, _ in deadlines:
            assert isinstance(date_str, str)
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
        assert analysis.total_requirements > 0

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
        assert len(none_mappings) == analysis.not_covered
        for m in none_mappings:
            assert m.aegis_feature == "(none)"
