"""Enterprise feature tier system.

Defines pricing tiers (Community / Pro / Enterprise) and which features
are available in each.  Provides a :class:`FeatureGate` that can check
availability and raise :class:`FeatureNotAvailableError` when a caller
tries to use a feature above the current tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Tier(Enum):
    """Pricing tier."""

    COMMUNITY = "community"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class Feature(Enum):
    """Every feature flag known to Aegis."""

    # Community
    POLICY_ENGINE = "policy_engine"
    YAML_POLICIES = "yaml_policies"
    BASIC_AUDIT = "basic_audit"
    CLI_TOOLS = "cli_tools"
    POLICY_BUILDER = "policy_builder"
    SIMULATE = "simulate"
    SCAN = "scan"
    SCORE = "score"

    # Pro
    ANOMALY_DETECTION = "anomaly_detection"
    POLICY_DIFF = "policy_diff"
    COMPLIANCE_REPORTS = "compliance_reports"
    MONITORING = "monitoring"
    SEMANTIC_CONDITIONS = "semantic_conditions"
    RATE_LIMITING = "rate_limiting"
    AGENT_TRUST_CHAIN = "agent_trust_chain"
    ACTION_REPLAY = "action_replay"

    # Enterprise
    CRYPTO_AUDIT = "crypto_audit"
    REGULATORY_COMPLIANCE = "regulatory_compliance"
    EVIDENCE_PACKAGES = "evidence_packages"
    WEBHOOKS = "webhooks"
    SSO_SAML = "sso_saml"
    PRIORITY_SUPPORT = "priority_support"


# ---------------------------------------------------------------------------
# Tier → feature mapping
# ---------------------------------------------------------------------------

_COMMUNITY_FEATURES: frozenset[Feature] = frozenset(
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

_PRO_FEATURES: frozenset[Feature] = _COMMUNITY_FEATURES | frozenset(
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

_ENTERPRISE_FEATURES: frozenset[Feature] = _PRO_FEATURES | frozenset(
    {
        Feature.CRYPTO_AUDIT,
        Feature.REGULATORY_COMPLIANCE,
        Feature.EVIDENCE_PACKAGES,
        Feature.WEBHOOKS,
        Feature.SSO_SAML,
        Feature.PRIORITY_SUPPORT,
    }
)

TIER_FEATURES: dict[Tier, frozenset[Feature]] = {
    Tier.COMMUNITY: _COMMUNITY_FEATURES,
    Tier.PRO: _PRO_FEATURES,
    Tier.ENTERPRISE: _ENTERPRISE_FEATURES,
}


# ---------------------------------------------------------------------------
# TierInfo dataclass
# ---------------------------------------------------------------------------

# Tier ordering used by internal helpers (lowest → highest).
_TIER_ORDER: list[Tier] = [Tier.COMMUNITY, Tier.PRO, Tier.ENTERPRISE]


@dataclass(frozen=True)
class TierInfo:
    """Human-readable description of a pricing tier."""

    tier: Tier
    name: str
    description: str
    price: str
    features: frozenset[Feature]
    highlights: list[str] = field(default_factory=list)

    # Registry of all tier info objects, populated at module level.
    _registry: ClassVar[dict[Tier, TierInfo]] = {}


_TIER_INFOS: list[TierInfo] = [
    TierInfo(
        tier=Tier.COMMUNITY,
        name="Community",
        description="Core governance for open-source and personal projects.",
        price="Free",
        features=_COMMUNITY_FEATURES,
        highlights=[
            "YAML policy engine",
            "Basic audit logging",
            "CLI tools (simulate, scan, score)",
            "Policy builder API",
        ],
    ),
    TierInfo(
        tier=Tier.PRO,
        name="Pro",
        description="Advanced governance for teams and production workloads.",
        price="$99/month",
        features=_PRO_FEATURES,
        highlights=[
            "Everything in Community",
            "Anomaly detection",
            "Policy diff & compliance reports",
            "Semantic conditions & rate limiting",
            "Agent trust chain & action replay",
        ],
    ),
    TierInfo(
        tier=Tier.ENTERPRISE,
        name="Enterprise",
        description="Full regulatory compliance and enterprise integration.",
        price="Custom",
        features=_ENTERPRISE_FEATURES,
        highlights=[
            "Everything in Pro",
            "Cryptographic audit chain",
            "EU AI Act & NIST compliance mapping",
            "Evidence packages for auditors",
            "SSO/SAML, webhooks, priority support",
        ],
    ),
]

# Populate TierInfo class-level registry for quick lookup.
for _info in _TIER_INFOS:
    TierInfo._registry[_info.tier] = _info


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class FeatureNotAvailableError(Exception):
    """Raised when a feature is not available in the current tier."""

    def __init__(
        self,
        feature: Feature,
        current_tier: Tier,
        required_tier: Tier,
    ) -> None:
        self.feature = feature
        self.current_tier = current_tier
        self.required_tier = required_tier
        super().__init__(
            f"Feature '{feature.value}' requires {required_tier.value.title()} tier "
            f"(current: {current_tier.value.title()}). "
            f"Upgrade at https://aegis.dev/pricing"
        )


# ---------------------------------------------------------------------------
# FeatureGate
# ---------------------------------------------------------------------------


class FeatureGate:
    """Runtime gate that checks feature availability against the active tier."""

    def __init__(self, tier: Tier = Tier.COMMUNITY) -> None:
        self._tier = tier

    # -- queries -----------------------------------------------------------

    @property
    def current_tier(self) -> Tier:
        """Return the active tier."""
        return self._tier

    def is_available(self, feature: Feature) -> bool:
        """Return *True* if *feature* is included in the current tier."""
        return feature in TIER_FEATURES[self._tier]

    def require(self, feature: Feature) -> None:
        """Raise :class:`FeatureNotAvailableError` if *feature* is not available."""
        if not self.is_available(feature):
            raise FeatureNotAvailableError(
                feature=feature,
                current_tier=self._tier,
                required_tier=self.tier_for_feature(feature),
            )

    def available_features(self) -> frozenset[Feature]:
        """Return all features available in the current tier."""
        return TIER_FEATURES[self._tier]

    def missing_features(self) -> frozenset[Feature]:
        """Return features *not* included in the current tier."""
        return frozenset(Feature) - TIER_FEATURES[self._tier]

    # -- tier helpers ------------------------------------------------------

    def tier_for_feature(self, feature: Feature) -> Tier:
        """Return the minimum tier that includes *feature*."""
        for tier in _TIER_ORDER:
            if feature in TIER_FEATURES[tier]:
                return tier
        # Should never happen — every Feature must belong to at least one tier.
        raise ValueError(f"Feature {feature!r} is not mapped to any tier")  # pragma: no cover

    def compare_tiers(self) -> list[TierInfo]:
        """Return :class:`TierInfo` objects for all tiers (ascending order)."""
        return [TierInfo._registry[t] for t in _TIER_ORDER]

    # -- mutation ----------------------------------------------------------

    def upgrade_to(self, tier: Tier) -> None:
        """Change the active tier."""
        self._tier = tier
