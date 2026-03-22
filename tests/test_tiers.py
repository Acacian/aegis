"""Tests for the Enterprise Feature Tier System."""

from __future__ import annotations

import pytest

from aegis.core.tiers import (
    TIER_FEATURES,
    Feature,
    FeatureGate,
    FeatureNotAvailableError,
    Tier,
    TierInfo,
)

# ---------------------------------------------------------------------------
# Tier enum
# ---------------------------------------------------------------------------


class TestTierEnum:
    def test_community_value(self) -> None:
        assert Tier.COMMUNITY.value == "community"

    def test_pro_value(self) -> None:
        assert Tier.PRO.value == "pro"

    def test_enterprise_value(self) -> None:
        assert Tier.ENTERPRISE.value == "enterprise"

    def test_tier_count(self) -> None:
        assert len(Tier) == 3


# ---------------------------------------------------------------------------
# Feature enum
# ---------------------------------------------------------------------------


class TestFeatureEnum:
    def test_feature_count(self) -> None:
        assert len(Feature) == 22

    @pytest.mark.parametrize(
        "member,value",
        [
            (Feature.POLICY_ENGINE, "policy_engine"),
            (Feature.YAML_POLICIES, "yaml_policies"),
            (Feature.BASIC_AUDIT, "basic_audit"),
            (Feature.CLI_TOOLS, "cli_tools"),
            (Feature.POLICY_BUILDER, "policy_builder"),
            (Feature.SIMULATE, "simulate"),
            (Feature.SCAN, "scan"),
            (Feature.SCORE, "score"),
            (Feature.ANOMALY_DETECTION, "anomaly_detection"),
            (Feature.POLICY_DIFF, "policy_diff"),
            (Feature.COMPLIANCE_REPORTS, "compliance_reports"),
            (Feature.MONITORING, "monitoring"),
            (Feature.SEMANTIC_CONDITIONS, "semantic_conditions"),
            (Feature.RATE_LIMITING, "rate_limiting"),
            (Feature.AGENT_TRUST_CHAIN, "agent_trust_chain"),
            (Feature.ACTION_REPLAY, "action_replay"),
            (Feature.CRYPTO_AUDIT, "crypto_audit"),
            (Feature.REGULATORY_COMPLIANCE, "regulatory_compliance"),
            (Feature.EVIDENCE_PACKAGES, "evidence_packages"),
            (Feature.WEBHOOKS, "webhooks"),
            (Feature.SSO_SAML, "sso_saml"),
            (Feature.PRIORITY_SUPPORT, "priority_support"),
        ],
    )
    def test_feature_value(self, member: Feature, value: str) -> None:
        assert member.value == value

    def test_all_features_assigned_to_at_least_one_tier(self) -> None:
        all_assigned = frozenset().union(*TIER_FEATURES.values())
        assert all_assigned == frozenset(Feature)


# ---------------------------------------------------------------------------
# TIER_FEATURES mapping
# ---------------------------------------------------------------------------

_EXPECTED_COMMUNITY = frozenset(
    {
        Feature.POLICY_ENGINE,
        Feature.YAML_POLICIES,
        Feature.BASIC_AUDIT,
        Feature.CLI_TOOLS,
        Feature.POLICY_BUILDER,
        Feature.SIMULATE,
        Feature.SCAN,
        Feature.SCORE,
    }
)

_EXPECTED_PRO_ONLY = frozenset(
    {
        Feature.ANOMALY_DETECTION,
        Feature.POLICY_DIFF,
        Feature.COMPLIANCE_REPORTS,
        Feature.MONITORING,
        Feature.SEMANTIC_CONDITIONS,
        Feature.RATE_LIMITING,
        Feature.AGENT_TRUST_CHAIN,
        Feature.ACTION_REPLAY,
    }
)

_EXPECTED_ENTERPRISE_ONLY = frozenset(
    {
        Feature.CRYPTO_AUDIT,
        Feature.REGULATORY_COMPLIANCE,
        Feature.EVIDENCE_PACKAGES,
        Feature.WEBHOOKS,
        Feature.SSO_SAML,
        Feature.PRIORITY_SUPPORT,
    }
)


class TestTierFeatures:
    def test_community_exact_features(self) -> None:
        assert TIER_FEATURES[Tier.COMMUNITY] == _EXPECTED_COMMUNITY

    def test_community_feature_count(self) -> None:
        assert len(TIER_FEATURES[Tier.COMMUNITY]) == 8

    def test_pro_includes_all_community(self) -> None:
        assert TIER_FEATURES[Tier.COMMUNITY] <= TIER_FEATURES[Tier.PRO]

    def test_pro_has_additional_features(self) -> None:
        pro_only = TIER_FEATURES[Tier.PRO] - TIER_FEATURES[Tier.COMMUNITY]
        assert pro_only == _EXPECTED_PRO_ONLY

    def test_pro_feature_count(self) -> None:
        assert len(TIER_FEATURES[Tier.PRO]) == 16

    def test_enterprise_includes_all_pro(self) -> None:
        assert TIER_FEATURES[Tier.PRO] <= TIER_FEATURES[Tier.ENTERPRISE]

    def test_enterprise_has_additional_features(self) -> None:
        ent_only = TIER_FEATURES[Tier.ENTERPRISE] - TIER_FEATURES[Tier.PRO]
        assert ent_only == _EXPECTED_ENTERPRISE_ONLY

    def test_enterprise_feature_count(self) -> None:
        assert len(TIER_FEATURES[Tier.ENTERPRISE]) == 22

    def test_enterprise_covers_all_features(self) -> None:
        assert TIER_FEATURES[Tier.ENTERPRISE] == frozenset(Feature)


# ---------------------------------------------------------------------------
# FeatureGate — availability
# ---------------------------------------------------------------------------


class TestFeatureGateAvailability:
    def test_default_tier_is_community(self) -> None:
        gate = FeatureGate()
        assert gate.current_tier is Tier.COMMUNITY

    def test_community_allows_policy_engine(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        assert gate.is_available(Feature.POLICY_ENGINE)

    def test_community_denies_anomaly_detection(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        assert not gate.is_available(Feature.ANOMALY_DETECTION)

    def test_community_denies_crypto_audit(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        assert not gate.is_available(Feature.CRYPTO_AUDIT)

    def test_pro_allows_anomaly_detection(self) -> None:
        gate = FeatureGate(Tier.PRO)
        assert gate.is_available(Feature.ANOMALY_DETECTION)

    def test_pro_allows_community_feature(self) -> None:
        gate = FeatureGate(Tier.PRO)
        assert gate.is_available(Feature.BASIC_AUDIT)

    def test_pro_denies_crypto_audit(self) -> None:
        gate = FeatureGate(Tier.PRO)
        assert not gate.is_available(Feature.CRYPTO_AUDIT)

    def test_enterprise_allows_everything(self) -> None:
        gate = FeatureGate(Tier.ENTERPRISE)
        for feature in Feature:
            assert gate.is_available(feature), f"{feature} should be available"


# ---------------------------------------------------------------------------
# FeatureGate — require
# ---------------------------------------------------------------------------


class TestFeatureGateRequire:
    def test_require_passes_for_available(self) -> None:
        gate = FeatureGate(Tier.PRO)
        gate.require(Feature.POLICY_ENGINE)  # no exception

    def test_require_raises_for_unavailable(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        with pytest.raises(FeatureNotAvailableError):
            gate.require(Feature.ANOMALY_DETECTION)

    def test_require_raises_with_correct_fields(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        with pytest.raises(FeatureNotAvailableError) as exc_info:
            gate.require(Feature.CRYPTO_AUDIT)
        err = exc_info.value
        assert err.feature is Feature.CRYPTO_AUDIT
        assert err.current_tier is Tier.COMMUNITY
        assert err.required_tier is Tier.ENTERPRISE


# ---------------------------------------------------------------------------
# FeatureNotAvailableError
# ---------------------------------------------------------------------------


class TestFeatureNotAvailableError:
    def test_message_format(self) -> None:
        err = FeatureNotAvailableError(
            feature=Feature.CRYPTO_AUDIT,
            current_tier=Tier.COMMUNITY,
            required_tier=Tier.ENTERPRISE,
        )
        msg = str(err)
        assert "crypto_audit" in msg
        assert "Enterprise" in msg
        assert "Community" in msg
        assert "https://aegis.dev/pricing" in msg

    def test_message_for_pro_feature(self) -> None:
        err = FeatureNotAvailableError(
            feature=Feature.ANOMALY_DETECTION,
            current_tier=Tier.COMMUNITY,
            required_tier=Tier.PRO,
        )
        msg = str(err)
        assert "anomaly_detection" in msg
        assert "Pro" in msg

    def test_is_exception(self) -> None:
        err = FeatureNotAvailableError(
            feature=Feature.WEBHOOKS,
            current_tier=Tier.PRO,
            required_tier=Tier.ENTERPRISE,
        )
        assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# FeatureGate — tier_for_feature
# ---------------------------------------------------------------------------


class TestTierForFeature:
    @pytest.mark.parametrize("feature", list(_EXPECTED_COMMUNITY))
    def test_community_features_resolve_to_community(self, feature: Feature) -> None:
        gate = FeatureGate()
        assert gate.tier_for_feature(feature) is Tier.COMMUNITY

    @pytest.mark.parametrize("feature", list(_EXPECTED_PRO_ONLY))
    def test_pro_only_features_resolve_to_pro(self, feature: Feature) -> None:
        gate = FeatureGate()
        assert gate.tier_for_feature(feature) is Tier.PRO

    @pytest.mark.parametrize("feature", list(_EXPECTED_ENTERPRISE_ONLY))
    def test_enterprise_only_features_resolve_to_enterprise(self, feature: Feature) -> None:
        gate = FeatureGate()
        assert gate.tier_for_feature(feature) is Tier.ENTERPRISE


# ---------------------------------------------------------------------------
# FeatureGate — upgrade_to
# ---------------------------------------------------------------------------


class TestUpgradeTo:
    def test_upgrade_changes_tier(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        gate.upgrade_to(Tier.PRO)
        assert gate.current_tier is Tier.PRO

    def test_upgrade_unlocks_features(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        assert not gate.is_available(Feature.ANOMALY_DETECTION)
        gate.upgrade_to(Tier.PRO)
        assert gate.is_available(Feature.ANOMALY_DETECTION)

    def test_downgrade_locks_features(self) -> None:
        gate = FeatureGate(Tier.ENTERPRISE)
        assert gate.is_available(Feature.CRYPTO_AUDIT)
        gate.upgrade_to(Tier.COMMUNITY)
        assert not gate.is_available(Feature.CRYPTO_AUDIT)


# ---------------------------------------------------------------------------
# FeatureGate — available / missing features
# ---------------------------------------------------------------------------


class TestAvailableAndMissing:
    def test_available_features_match_tier(self) -> None:
        gate = FeatureGate(Tier.PRO)
        assert gate.available_features() == TIER_FEATURES[Tier.PRO]

    def test_missing_features_community(self) -> None:
        gate = FeatureGate(Tier.COMMUNITY)
        missing = gate.missing_features()
        assert Feature.ANOMALY_DETECTION in missing
        assert Feature.CRYPTO_AUDIT in missing
        assert Feature.POLICY_ENGINE not in missing

    def test_missing_features_enterprise_is_empty(self) -> None:
        gate = FeatureGate(Tier.ENTERPRISE)
        assert gate.missing_features() == frozenset()

    def test_available_plus_missing_equals_all(self) -> None:
        gate = FeatureGate(Tier.PRO)
        assert gate.available_features() | gate.missing_features() == frozenset(Feature)


# ---------------------------------------------------------------------------
# FeatureGate — compare_tiers
# ---------------------------------------------------------------------------


class TestCompareTiers:
    def test_returns_three_entries(self) -> None:
        gate = FeatureGate()
        infos = gate.compare_tiers()
        assert len(infos) == 3

    def test_order_community_pro_enterprise(self) -> None:
        gate = FeatureGate()
        infos = gate.compare_tiers()
        assert infos[0].tier is Tier.COMMUNITY
        assert infos[1].tier is Tier.PRO
        assert infos[2].tier is Tier.ENTERPRISE

    def test_info_types(self) -> None:
        gate = FeatureGate()
        for info in gate.compare_tiers():
            assert isinstance(info, TierInfo)


# ---------------------------------------------------------------------------
# TierInfo
# ---------------------------------------------------------------------------


class TestTierInfo:
    def test_community_pricing(self) -> None:
        gate = FeatureGate()
        info = gate.compare_tiers()[0]
        assert info.price == "Free"

    def test_pro_pricing(self) -> None:
        gate = FeatureGate()
        info = gate.compare_tiers()[1]
        assert info.price == "$99/month"

    def test_enterprise_pricing(self) -> None:
        gate = FeatureGate()
        info = gate.compare_tiers()[2]
        assert info.price == "Custom"

    def test_community_name(self) -> None:
        gate = FeatureGate()
        info = gate.compare_tiers()[0]
        assert info.name == "Community"

    def test_highlights_are_populated(self) -> None:
        gate = FeatureGate()
        for info in gate.compare_tiers():
            assert len(info.highlights) > 0

    def test_features_match_tier_map(self) -> None:
        gate = FeatureGate()
        for info in gate.compare_tiers():
            assert info.features == TIER_FEATURES[info.tier]

    def test_frozen(self) -> None:
        gate = FeatureGate()
        info = gate.compare_tiers()[0]
        with pytest.raises(AttributeError):
            info.name = "Changed"  # type: ignore[misc]
