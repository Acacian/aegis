"""Tests for aegis.core.hazard_classifier -- safety hazard classification."""

from __future__ import annotations

import threading

import pytest

from aegis.core.hazard_classifier import (
    Hazard,
    HazardAssessment,
    HazardCategory,
    HazardClassifier,
    OverallRisk,
    Severity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classifier() -> HazardClassifier:
    return HazardClassifier()


# ---------------------------------------------------------------------------
# Frozen dataclass invariants
# ---------------------------------------------------------------------------


class TestDataModels:
    def test_hazard_frozen(self) -> None:
        h = Hazard("id", "name", HazardCategory.DATA_LOSS, Severity.HIGH, "desc", ())
        with pytest.raises(AttributeError):
            h.name = "x"  # type: ignore[misc]

    def test_hazard_assessment_frozen(self) -> None:
        a = HazardAssessment("task", (), OverallRisk.SAFE, True, ())
        with pytest.raises(AttributeError):
            a.safe_to_proceed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PHYSICAL_HARM
# ---------------------------------------------------------------------------


class TestPhysicalHarm:
    def test_robot_control(self) -> None:
        a = _classifier().classify_task("robot arm control the actuator")
        assert any(h.category == HazardCategory.PHYSICAL_HARM for h in a.hazards_found)
        assert not a.safe_to_proceed

    def test_iot_command(self) -> None:
        a = _classifier().classify_task("smart home set thermostat to 100")
        assert any(h.category == HazardCategory.PHYSICAL_HARM for h in a.hazards_found)

    def test_vehicle_operation(self) -> None:
        a = _classifier().classify_task("drone fly to coordinates")
        assert any(h.category == HazardCategory.PHYSICAL_HARM for h in a.hazards_found)

    def test_medical_device(self) -> None:
        a = _classifier().classify_task("infusion pump set dose rate")
        assert any(h.category == HazardCategory.PHYSICAL_HARM for h in a.hazards_found)
        assert not a.safe_to_proceed


# ---------------------------------------------------------------------------
# DATA_LOSS
# ---------------------------------------------------------------------------


class TestDataLoss:
    def test_delete_all_data(self) -> None:
        a = _classifier().classify_task("delete all data from the database")
        assert any(h.category == HazardCategory.DATA_LOSS for h in a.hazards_found)
        assert not a.safe_to_proceed

    def test_truncate_table(self) -> None:
        a = _classifier().classify_task("truncate table users")
        assert any(h.category == HazardCategory.DATA_LOSS for h in a.hazards_found)

    def test_drop_database(self) -> None:
        a = _classifier().classify_task("drop database production")
        assert any(h.category == HazardCategory.DATA_LOSS for h in a.hazards_found)

    def test_rm_rf(self) -> None:
        a = _classifier().classify_task("rm -rf /var/data")
        assert any(h.category == HazardCategory.DATA_LOSS for h in a.hazards_found)

    def test_format_disk(self) -> None:
        a = _classifier().classify_task("format the server disk")
        assert any(h.category == HazardCategory.DATA_LOSS for h in a.hazards_found)


# ---------------------------------------------------------------------------
# PRIVACY_BREACH
# ---------------------------------------------------------------------------


class TestPrivacyBreach:
    def test_extract_pii(self) -> None:
        a = _classifier().classify_task("extract personal information from users")
        assert any(h.category == HazardCategory.PRIVACY_BREACH for h in a.hazards_found)

    def test_surveillance(self) -> None:
        a = _classifier().classify_task("track user location history")
        assert any(h.category == HazardCategory.PRIVACY_BREACH for h in a.hazards_found)

    def test_log_credentials(self) -> None:
        a = _classifier().classify_task("log password to file for debugging")
        assert any(h.category == HazardCategory.PRIVACY_BREACH for h in a.hazards_found)

    def test_access_private_data(self) -> None:
        a = _classifier().classify_task("access private data in the restricted zone")
        assert any(h.category == HazardCategory.PRIVACY_BREACH for h in a.hazards_found)


# ---------------------------------------------------------------------------
# FINANCIAL_LOSS
# ---------------------------------------------------------------------------


class TestFinancialLoss:
    def test_payment_process(self) -> None:
        a = _classifier().classify_task("payment process for customer order")
        assert any(h.category == HazardCategory.FINANCIAL_LOSS for h in a.hazards_found)

    def test_transfer_funds(self) -> None:
        a = _classifier().classify_task("transfer funds to external account")
        assert any(h.category == HazardCategory.FINANCIAL_LOSS for h in a.hazards_found)

    def test_trading(self) -> None:
        a = _classifier().classify_task("buy stock AAPL at market price")
        assert any(h.category == HazardCategory.FINANCIAL_LOSS for h in a.hazards_found)


# ---------------------------------------------------------------------------
# SYSTEM_DAMAGE
# ---------------------------------------------------------------------------


class TestSystemDamage:
    def test_root_access(self) -> None:
        a = _classifier().classify_task("sudo access to modify kernel")
        assert any(h.category == HazardCategory.SYSTEM_DAMAGE for h in a.hazards_found)

    def test_kernel_module(self) -> None:
        a = _classifier().classify_task("insmod custom_driver.ko")
        assert any(h.category == HazardCategory.SYSTEM_DAMAGE for h in a.hazards_found)

    def test_install_driver(self) -> None:
        a = _classifier().classify_task("install driver for GPU")
        assert any(h.category == HazardCategory.SYSTEM_DAMAGE for h in a.hazards_found)

    def test_kill_process(self) -> None:
        a = _classifier().classify_task("kill -9 critical service")
        assert any(h.category == HazardCategory.SYSTEM_DAMAGE for h in a.hazards_found)


# ---------------------------------------------------------------------------
# SOCIAL_HARM
# ---------------------------------------------------------------------------


class TestSocialHarm:
    def test_impersonation(self) -> None:
        a = _classifier().classify_task("impersonate the CEO in emails")
        assert any(h.category == HazardCategory.SOCIAL_HARM for h in a.hazards_found)

    def test_harassment(self) -> None:
        a = _classifier().classify_task("harass the user with repeated messages")
        assert any(h.category == HazardCategory.SOCIAL_HARM for h in a.hazards_found)

    def test_deception(self) -> None:
        a = _classifier().classify_task("deceive the user into sharing credentials")
        assert any(h.category == HazardCategory.SOCIAL_HARM for h in a.hazards_found)

    def test_spam(self) -> None:
        a = _classifier().classify_task("mass email all contacts with promotion")
        assert any(h.category == HazardCategory.SOCIAL_HARM for h in a.hazards_found)


# ---------------------------------------------------------------------------
# LEGAL_RISK
# ---------------------------------------------------------------------------


class TestLegalRisk:
    def test_web_scraping(self) -> None:
        a = _classifier().classify_task("scrape website for pricing data")
        assert any(h.category == HazardCategory.LEGAL_RISK for h in a.hazards_found)

    def test_copyright(self) -> None:
        a = _classifier().classify_task("download copyrighted content from site")
        assert any(h.category == HazardCategory.LEGAL_RISK for h in a.hazards_found)

    def test_dmca(self) -> None:
        a = _classifier().classify_task("bypass DRM protection on the file")
        assert any(h.category == HazardCategory.LEGAL_RISK for h in a.hazards_found)


# ---------------------------------------------------------------------------
# ENVIRONMENTAL
# ---------------------------------------------------------------------------


class TestEnvironmental:
    def test_crypto_mining(self) -> None:
        a = _classifier().classify_task("bitcoin mining on GPU cluster")
        assert any(h.category == HazardCategory.ENVIRONMENTAL for h in a.hazards_found)

    def test_resource_exhaustion(self) -> None:
        a = _classifier().classify_task("fork bomb to test system limits")
        assert any(h.category == HazardCategory.ENVIRONMENTAL for h in a.hazards_found)


# ---------------------------------------------------------------------------
# Safe tasks
# ---------------------------------------------------------------------------


class TestSafeTasks:
    def test_empty_task(self) -> None:
        a = _classifier().classify_task("")
        assert a.safe_to_proceed
        assert a.overall_risk == OverallRisk.SAFE

    def test_benign_task(self) -> None:
        a = _classifier().classify_task("read the README and summarize it")
        assert a.safe_to_proceed

    def test_is_safe_shortcut(self) -> None:
        assert _classifier().is_safe("read a text file")
        assert not _classifier().is_safe("delete all data from production")


# ---------------------------------------------------------------------------
# Plan classification
# ---------------------------------------------------------------------------


class TestPlanClassification:
    def test_safe_plan(self) -> None:
        plan = ["read file", "analyze data", "write summary"]
        a = _classifier().classify_plan(plan)
        assert a.safe_to_proceed

    def test_unsafe_plan(self) -> None:
        plan = ["read file", "drop table users", "send report"]
        a = _classifier().classify_plan(plan)
        assert not a.safe_to_proceed
        assert any(h.category == HazardCategory.DATA_LOSS for h in a.hazards_found)

    def test_plan_deduplication(self) -> None:
        plan = ["drop table A", "drop table B"]
        a = _classifier().classify_plan(plan)
        # Both trigger "drop_table" but should be deduplicated
        names = [h.name for h in a.hazards_found]
        assert names.count("drop_table") == 1

    def test_multi_category_plan(self) -> None:
        plan = [
            "drop database production",
            "transfer funds to offshore",
            "impersonate admin",
        ]
        a = _classifier().classify_plan(plan)
        categories = {h.category for h in a.hazards_found}
        assert HazardCategory.DATA_LOSS in categories
        assert HazardCategory.FINANCIAL_LOSS in categories
        assert HazardCategory.SOCIAL_HARM in categories


# ---------------------------------------------------------------------------
# Custom patterns
# ---------------------------------------------------------------------------


class TestCustomPatterns:
    def test_add_custom_hazard(self) -> None:
        c = _classifier()
        c.add_hazard_pattern(
            "custom_danger",
            HazardCategory.SYSTEM_DAMAGE,
            Severity.HIGH,
            r"\bxyzzy_danger\b",
            "Custom dangerous pattern",
            ["Avoid using xyzzy_danger"],
        )
        a = c.classify_task("execute xyzzy_danger now")
        assert any(h.name == "custom_danger" for h in a.hazards_found)

    def test_custom_pattern_with_no_mitigations(self) -> None:
        c = _classifier()
        c.add_hazard_pattern(
            "bare_pattern",
            HazardCategory.DATA_LOSS,
            Severity.MEDIUM,
            r"\bbare_op\b",
        )
        a = c.classify_task("run bare_op command")
        assert any(h.name == "bare_pattern" for h in a.hazards_found)


# ---------------------------------------------------------------------------
# Overall risk and recommendations
# ---------------------------------------------------------------------------


class TestRiskAssessment:
    def test_critical_risk(self) -> None:
        a = _classifier().classify_task("drop database production_db")
        assert a.overall_risk == OverallRisk.CRITICAL

    def test_recommendations_present(self) -> None:
        a = _classifier().classify_task("delete all records from database")
        assert len(a.recommendations) > 0

    def test_human_review_recommendation(self) -> None:
        a = _classifier().classify_task("payment process the invoice")
        assert "Human review required before proceeding" in a.recommendations

    def test_safe_no_hazards(self) -> None:
        a = _classifier().classify_task("compute the average of a list")
        assert a.overall_risk == OverallRisk.SAFE
        assert len(a.hazards_found) == 0


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_classification(self) -> None:
        c = _classifier()
        errors: list[Exception] = []

        def classify_many() -> None:
            try:
                for task in [
                    "drop table users",
                    "read the docs",
                    "delete all data",
                    "summarize report",
                ]:
                    c.classify_task(task)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=classify_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_concurrent_add_pattern_and_classify(self) -> None:
        c = _classifier()
        errors: list[Exception] = []

        def add_patterns() -> None:
            try:
                for i in range(10):
                    c.add_hazard_pattern(
                        f"concurrent_{i}",
                        HazardCategory.DATA_LOSS,
                        Severity.MEDIUM,
                        rf"\bconcurrent{i}\b",
                    )
            except Exception as e:
                errors.append(e)

        def classify() -> None:
            try:
                for _ in range(20):
                    c.classify_task("drop table or something")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=add_patterns),
            threading.Thread(target=classify),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
