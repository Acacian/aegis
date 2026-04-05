"""Tests for the Threat Taxonomy module."""

from __future__ import annotations

import threading

import pytest

from aegis.core.threat_taxonomy import (
    MitigationStatus,
    Threat,
    ThreatAssessment,
    ThreatCategory,
    ThreatMitigation,
    ThreatSeverity,
    ThreatTaxonomy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_taxonomy(**kwargs) -> ThreatTaxonomy:
    return ThreatTaxonomy(**kwargs)


def _custom_threat(
    id: str = "T100",
    name: str = "Custom Threat",
    category: ThreatCategory = ThreatCategory.TOOL_MISUSE,
) -> Threat:
    return Threat(
        id=id,
        name=name,
        category=category,
        severity=ThreatSeverity.HIGH,
        owasp_id="ASI04",
        mitre_id="AML.T0040",
        description="A custom test threat",
        mitigations=("M001",),
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestThreatCategoryEnum:
    def test_at_least_12_categories(self) -> None:
        cats = list(ThreatCategory)
        assert len(cats) >= 12

    def test_owasp_categories_present(self) -> None:
        assert ThreatCategory.EXCESSIVE_AGENCY.value == "excessive_agency"
        assert ThreatCategory.SUPPLY_CHAIN.value == "supply_chain"
        assert ThreatCategory.INSECURE_OUTPUT.value == "insecure_output"
        assert ThreatCategory.TOOL_MISUSE.value == "tool_misuse"
        assert ThreatCategory.MEMORY_POISONING.value == "memory_poisoning"
        assert ThreatCategory.PROMPT_INJECTION.value == "prompt_injection"
        assert ThreatCategory.MULTI_AGENT_MANIPULATION.value == "multi_agent_manipulation"
        assert ThreatCategory.CASCADING_FAILURES.value == "cascading_failures"
        assert ThreatCategory.TRUST_BOUNDARY.value == "trust_boundary"
        assert ThreatCategory.ROGUE_AGENT.value == "rogue_agent"

    def test_academic_categories_present(self) -> None:
        assert ThreatCategory.REWARD_HACKING.value == "reward_hacking"
        assert ThreatCategory.DATA_EXFILTRATION.value == "data_exfiltration"
        assert ThreatCategory.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert ThreatCategory.GOAL_MISALIGNMENT.value == "goal_misalignment"
        assert ThreatCategory.DECEPTIVE_ALIGNMENT.value == "deceptive_alignment"
        assert ThreatCategory.ADVERSARIAL_ROBUSTNESS.value == "adversarial_robustness"


class TestThreatSeverityEnum:
    def test_four_levels(self) -> None:
        assert len(list(ThreatSeverity)) == 4

    def test_values(self) -> None:
        assert ThreatSeverity.LOW == "low"
        assert ThreatSeverity.MEDIUM == "medium"
        assert ThreatSeverity.HIGH == "high"
        assert ThreatSeverity.CRITICAL == "critical"


class TestMitigationStatusEnum:
    def test_four_statuses(self) -> None:
        assert len(list(MitigationStatus)) == 4


# ---------------------------------------------------------------------------
# Frozen dataclass tests
# ---------------------------------------------------------------------------


class TestFrozenDataclasses:
    def test_threat_frozen(self) -> None:
        t = _custom_threat()
        with pytest.raises(AttributeError):
            t.name = "changed"  # type: ignore[misc]

    def test_mitigation_frozen(self) -> None:
        m = ThreatMitigation(
            id="M100",
            name="Test",
            threat_ids=("T001",),
            description="test",
        )
        with pytest.raises(AttributeError):
            m.name = "changed"  # type: ignore[misc]

    def test_assessment_frozen(self) -> None:
        a = ThreatAssessment(
            threats_found=(),
            risk_score=0.0,
            recommendations=(),
        )
        with pytest.raises(AttributeError):
            a.risk_score = 1.0  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Built-in database
# ---------------------------------------------------------------------------


class TestBuiltinDatabase:
    def test_at_least_20_threats(self) -> None:
        tax = _build_taxonomy()
        threats = tax.get_all_threats()
        assert len(threats) >= 20

    def test_all_owasp_asi_covered(self) -> None:
        """Verify all OWASP ASI01-ASI10 have at least one threat."""
        tax = _build_taxonomy()
        for i in range(1, 11):
            asi_id = f"ASI{i:02d}"
            threats = tax.get_threats_by_owasp(asi_id)
            assert len(threats) >= 1, f"No threats found for {asi_id}"

    def test_threats_have_required_fields(self) -> None:
        tax = _build_taxonomy()
        for t in tax.get_all_threats():
            assert t.id
            assert t.name
            assert t.category
            assert t.severity
            assert t.description

    def test_get_threat_by_id(self) -> None:
        tax = _build_taxonomy()
        t = tax.get_threat("T001")
        assert t is not None
        assert t.name == "Unrestricted Tool Access"

    def test_get_nonexistent_threat(self) -> None:
        tax = _build_taxonomy()
        assert tax.get_threat("T999") is None

    def test_empty_taxonomy(self) -> None:
        tax = _build_taxonomy(include_builtin=False)
        assert tax.get_all_threats() == []


# ---------------------------------------------------------------------------
# Threat queries
# ---------------------------------------------------------------------------


class TestThreatQueries:
    def test_get_by_category(self) -> None:
        tax = _build_taxonomy()
        threats = tax.get_threats_by_category(ThreatCategory.PROMPT_INJECTION)
        assert len(threats) >= 2
        for t in threats:
            assert t.category == ThreatCategory.PROMPT_INJECTION

    def test_get_by_owasp_asi06(self) -> None:
        tax = _build_taxonomy()
        threats = tax.get_threats_by_owasp("ASI06")
        assert len(threats) >= 1
        for t in threats:
            assert t.owasp_id == "ASI06"

    def test_academic_threats_no_owasp_id(self) -> None:
        tax = _build_taxonomy()
        threats = tax.get_threats_by_category(ThreatCategory.REWARD_HACKING)
        assert len(threats) >= 1
        for t in threats:
            assert t.owasp_id == ""  # academic threats have no OWASP ID


# ---------------------------------------------------------------------------
# Action assessment
# ---------------------------------------------------------------------------


class TestAssessAction:
    def test_execute_code_matches_threats(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("execute code on remote server")
        assert len(result.threats_found) > 0
        assert result.risk_score > 0.0

    def test_delete_file_matches_tool_misuse(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("delete important configuration file")
        categories = {t.category for t in result.threats_found}
        assert ThreatCategory.TOOL_MISUSE in categories

    def test_install_plugin_matches_supply_chain(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("install third-party plugin")
        categories = {t.category for t in result.threats_found}
        assert ThreatCategory.SUPPLY_CHAIN in categories

    def test_prompt_injection_detected(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("inject system prompt override")
        categories = {t.category for t in result.threats_found}
        assert ThreatCategory.PROMPT_INJECTION in categories

    def test_benign_action_low_risk(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("check system status")
        assert result.risk_score == 0.0

    def test_explicit_categories(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action(
            "any action",
            categories=[ThreatCategory.CASCADING_FAILURES],
        )
        for t in result.threats_found:
            assert t.category == ThreatCategory.CASCADING_FAILURES

    def test_assessment_has_recommendations(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("execute dangerous code")
        assert len(result.recommendations) > 0

    def test_risk_score_bounded(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("execute delete inject override sudo chain cascade")
        assert 0.0 <= result.risk_score <= 1.0

    def test_sensitive_data_matches_exfiltration(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("access sensitive credential data")
        categories = {t.category for t in result.threats_found}
        assert ThreatCategory.DATA_EXFILTRATION in categories

    def test_privilege_escalation_detected(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("escalate to admin privilege")
        categories = {t.category for t in result.threats_found}
        assert ThreatCategory.PRIVILEGE_ESCALATION in categories


# ---------------------------------------------------------------------------
# Mitigations
# ---------------------------------------------------------------------------


class TestMitigations:
    def test_get_mitigations_for_threat(self) -> None:
        tax = _build_taxonomy()
        mits = tax.get_mitigations(["T001"])
        assert len(mits) >= 1
        for m in mits:
            assert "T001" in m.threat_ids

    def test_get_mitigations_for_multiple_threats(self) -> None:
        tax = _build_taxonomy()
        mits = tax.get_mitigations(["T001", "T010"])
        ids = {m.id for m in mits}
        assert len(ids) >= 2

    def test_get_mitigations_for_nonexistent_threat(self) -> None:
        tax = _build_taxonomy()
        mits = tax.get_mitigations(["T999"])
        assert mits == []

    def test_get_mitigation_by_id(self) -> None:
        tax = _build_taxonomy()
        m = tax.get_mitigation("M001")
        assert m is not None
        assert m.name == "Least Privilege Enforcement"


# ---------------------------------------------------------------------------
# Mitigation status
# ---------------------------------------------------------------------------


class TestMitigationStatus:
    def test_set_status(self) -> None:
        tax = _build_taxonomy()
        assert tax.set_mitigation_status("M001", MitigationStatus.IMPLEMENTED) is True
        m = tax.get_mitigation("M001")
        assert m is not None
        assert m.implementation_status == MitigationStatus.IMPLEMENTED

    def test_set_status_nonexistent(self) -> None:
        tax = _build_taxonomy()
        assert tax.set_mitigation_status("M999", MitigationStatus.IMPLEMENTED) is False


# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------


class TestCoverageReport:
    def test_no_mitigations_implemented(self) -> None:
        tax = _build_taxonomy()
        report = tax.coverage_report()
        assert report.total_threats >= 20
        assert report.mitigated_threats == 0
        assert report.coverage_ratio == 0.0

    def test_partial_coverage(self) -> None:
        tax = _build_taxonomy()
        tax.set_mitigation_status("M001", MitigationStatus.IMPLEMENTED)
        report = tax.coverage_report()
        assert report.mitigated_threats > 0
        assert report.coverage_ratio > 0.0

    def test_coverage_with_partial_status(self) -> None:
        tax = _build_taxonomy()
        tax.set_mitigation_status("M001", MitigationStatus.PARTIAL)
        report = tax.coverage_report()
        assert report.mitigated_threats > 0

    def test_coverage_report_fields(self) -> None:
        tax = _build_taxonomy()
        report = tax.coverage_report()
        assert report.total_threats == report.mitigated_threats + report.unmitigated_threats
        assert isinstance(report.threat_coverage, dict)

    def test_empty_taxonomy_coverage(self) -> None:
        tax = _build_taxonomy(include_builtin=False)
        report = tax.coverage_report()
        assert report.total_threats == 0
        assert report.coverage_ratio == 0.0


# ---------------------------------------------------------------------------
# Custom threat/mitigation registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_register_custom_threat(self) -> None:
        tax = _build_taxonomy()
        custom = _custom_threat()
        tax.register_threat(custom)
        assert tax.get_threat("T100") is not None

    def test_register_custom_mitigation(self) -> None:
        tax = _build_taxonomy()
        m = ThreatMitigation(
            id="M100",
            name="Custom Mitigation",
            threat_ids=("T001",),
            description="test",
        )
        tax.register_mitigation(m)
        assert tax.get_mitigation("M100") is not None

    def test_custom_threat_in_assessment(self) -> None:
        tax = _build_taxonomy()
        custom = _custom_threat(category=ThreatCategory.TOOL_MISUSE)
        tax.register_threat(custom)
        result = tax.assess_action("execute dangerous tool")
        threat_ids = {t.id for t in result.threats_found}
        assert "T100" in threat_ids

    def test_override_existing_threat(self) -> None:
        tax = _build_taxonomy()
        replacement = Threat(
            id="T001",
            name="Replaced Threat",
            category=ThreatCategory.EXCESSIVE_AGENCY,
            severity=ThreatSeverity.LOW,
            owasp_id="ASI01",
            mitre_id="AML.T0048",
            description="Replaced",
        )
        tax.register_threat(replacement)
        t = tax.get_threat("T001")
        assert t is not None
        assert t.name == "Replaced Threat"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_assess(self) -> None:
        tax = _build_taxonomy()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                for _ in range(50):
                    tax.assess_action("execute code delete file")
                    tax.assess_action("install plugin download")
                    tax.assess_action("check status")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors

    def test_concurrent_register_and_assess(self) -> None:
        tax = _build_taxonomy()
        errors: list[Exception] = []

        def registerer() -> None:
            try:
                for i in range(50):
                    tax.register_threat(_custom_threat(id=f"TX{i}"))
            except Exception as e:
                errors.append(e)

        def assesser() -> None:
            try:
                for _ in range(50):
                    tax.assess_action("execute something dangerous")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=registerer) for _ in range(2)]
        threads += [threading.Thread(target=assesser) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_action_description(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("")
        assert result.risk_score == 0.0
        assert len(result.threats_found) == 0

    def test_case_insensitive_matching(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("EXECUTE CODE")
        assert len(result.threats_found) > 0

    def test_very_long_action_description(self) -> None:
        tax = _build_taxonomy()
        desc = "execute " * 1000
        result = tax.assess_action(desc)
        assert isinstance(result, ThreatAssessment)

    def test_recommendations_skip_implemented(self) -> None:
        tax = _build_taxonomy()
        tax.set_mitigation_status("M001", MitigationStatus.IMPLEMENTED)
        result = tax.assess_action("run unrestricted autonomous agent")
        # M001 should not appear in recommendations since it's implemented
        for rec in result.recommendations:
            assert "[implemented]" not in rec.lower()

    def test_multiple_keyword_hits(self) -> None:
        tax = _build_taxonomy()
        result = tax.assess_action("inject prompt override escalate privilege")
        categories = {t.category for t in result.threats_found}
        assert len(categories) >= 2
