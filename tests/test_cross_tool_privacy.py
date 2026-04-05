"""Tests for aegis.core.cross_tool_privacy — cross-tool privacy inference."""

from __future__ import annotations

from aegis.core.cross_tool_privacy import (
    CrossToolPrivacyDetector,
    PIICategory,
    PrivacyFinding,
    PrivacyReport,
)


class TestCrossToolPrivacyDetector:
    def setup_method(self) -> None:
        self.detector = CrossToolPrivacyDetector()

    # -- Basic observation ---------------------------------------------------

    def test_observe_returns_pii_categories(self) -> None:
        pii = self.detector.observe("get_email", {"user_id": "u1"}, "test@example.com")
        assert PIICategory.EMAIL in pii

    def test_observe_no_pii(self) -> None:
        pii = self.detector.observe("fetch_weather", {"query": "Seoul"}, "22°C sunny")
        assert len(pii) == 0

    # -- Clean analysis ------------------------------------------------------

    def test_clean_report(self) -> None:
        self.detector.observe("fetch_weather", {"city": "Seoul"}, "22°C")
        report = self.detector.analyze()
        assert report.clean

    def test_empty_report(self) -> None:
        report = self.detector.analyze()
        assert report.clean
        assert report.observations_analyzed == 0

    # -- PII accumulation ----------------------------------------------------

    def test_pii_accumulation(self) -> None:
        self.detector.observe("get_name", {"user_id": "u1"}, "John Doe")
        self.detector.observe("get_email", {"user_id": "u1"}, "john@example.com")
        self.detector.observe("get_location", {"user_id": "u1"}, "Seoul, Korea")
        report = self.detector.analyze()
        assert not report.clean
        accum_findings = [f for f in report.findings if f.category == "pii_accumulation"]
        assert len(accum_findings) > 0

    def test_pii_accumulation_below_threshold(self) -> None:
        self.detector.observe("get_name", {"user_id": "u1"}, "John Doe")
        self.detector.observe("get_email", {"user_id": "u1"}, "john@example.com")
        # Only 2 categories — below default threshold of 3
        report = self.detector.analyze()
        accum_findings = [f for f in report.findings if f.category == "pii_accumulation"]
        assert len(accum_findings) == 0

    def test_pii_accumulation_different_subjects(self) -> None:
        """PII from different subjects should NOT accumulate."""
        self.detector.observe("get_name", {"user_id": "u1"}, "John")
        self.detector.observe("get_email", {"user_id": "u2"}, "jane@example.com")
        self.detector.observe("get_location", {"user_id": "u3"}, "Seoul")
        report = self.detector.analyze()
        accum_findings = [f for f in report.findings if f.category == "pii_accumulation"]
        assert len(accum_findings) == 0

    # -- Quasi-identifier detection ------------------------------------------

    def test_quasi_identifier_detection(self) -> None:
        self.detector.observe("get_location", {"user_id": "u1"}, "Seoul")
        self.detector.observe("get_gender", {"user_id": "u1"}, "male")
        self.detector.observe("get_dob", {"user_id": "u1"}, "1990-01-15")
        report = self.detector.analyze()
        qi_findings = [f for f in report.findings if f.category == "quasi_identifier"]
        assert len(qi_findings) > 0

    def test_name_plus_location_quasi_id(self) -> None:
        self.detector.observe("get_name", {"user_id": "u1"}, "John Doe")
        self.detector.observe("get_location", {"user_id": "u1"}, "Seoul")
        report = self.detector.analyze()
        qi_findings = [f for f in report.findings if f.category == "quasi_identifier"]
        assert len(qi_findings) > 0

    # -- Temporal profiling --------------------------------------------------

    def test_temporal_profiling(self) -> None:
        detector = CrossToolPrivacyDetector(profiling_threshold=3)
        # Rapid-fire PII queries
        detector.observe("get_name", {"user_id": "u1"}, "John")
        detector.observe("get_email", {"user_id": "u1"}, "john@example.com")
        detector.observe("get_phone", {"user_id": "u1"}, "+82-10-1234-5678")
        detector.observe("get_address", {"user_id": "u1"}, "Seoul 123")
        detector.observe("get_dob", {"user_id": "u1"}, "1990-01-15")
        report = detector.analyze()
        profiling = [f for f in report.findings if f.category == "temporal_profiling"]
        assert len(profiling) > 0

    # -- Cross-reference detection -------------------------------------------

    def test_cross_reference(self) -> None:
        # Tool A provides name, Tool B provides location — complementary PII
        self.detector.observe("hr_system", {"user_id": "u1"}, "Employee: John, title: VP")
        self.detector.observe("location_service", {"user_id": "u1"}, "Seoul HQ, city: Seoul")
        report = self.detector.analyze()
        xref = [f for f in report.findings if f.category == "cross_reference"]
        assert len(xref) > 0

    # -- Report structure ----------------------------------------------------

    def test_report_structure(self) -> None:
        self.detector.observe("get_name", {"user_id": "u1"}, "John")
        self.detector.observe("get_email", {"user_id": "u1"}, "john@example.com")
        self.detector.observe("get_location", {"user_id": "u1"}, "Seoul")
        report = self.detector.analyze()
        assert isinstance(report, PrivacyReport)
        assert report.observations_analyzed == 3
        assert report.unique_subjects == 1
        assert len(report.pii_categories_seen) > 0
        assert report.generated_at > 0

    def test_finding_structure(self) -> None:
        self.detector.observe("get_name", {"user_id": "u1"}, "John")
        self.detector.observe("get_email", {"user_id": "u1"}, "john@example.com")
        self.detector.observe("get_location", {"user_id": "u1"}, "Seoul")
        report = self.detector.analyze()
        for finding in report.findings:
            assert isinstance(finding, PrivacyFinding)
            assert finding.category
            assert finding.severity
            assert finding.description

    # -- Reset ---------------------------------------------------------------

    def test_reset(self) -> None:
        self.detector.observe("get_name", {"user_id": "u1"}, "John")
        self.detector.reset()
        report = self.detector.analyze()
        assert report.observations_analyzed == 0
        assert report.clean

    # -- Custom thresholds ---------------------------------------------------

    def test_custom_min_pii(self) -> None:
        detector = CrossToolPrivacyDetector(min_pii_accumulation=5)
        detector.observe("get_name", {"user_id": "u1"}, "John")
        detector.observe("get_email", {"user_id": "u1"}, "john@example.com")
        detector.observe("get_location", {"user_id": "u1"}, "Seoul")
        report = detector.analyze()
        accum = [f for f in report.findings if f.category == "pii_accumulation"]
        assert len(accum) == 0  # Only 3 categories, threshold is 5

    def test_custom_quasi_id_sets(self) -> None:
        custom_qi = [frozenset({PIICategory.INCOME, PIICategory.LOCATION})]
        detector = CrossToolPrivacyDetector(quasi_id_sets=custom_qi)
        detector.observe("get_income", {"user_id": "u1"}, "salary: 100000")
        detector.observe("get_location", {"user_id": "u1"}, "Seoul")
        report = detector.analyze()
        qi = [f for f in report.findings if f.category == "quasi_identifier"]
        assert len(qi) > 0
