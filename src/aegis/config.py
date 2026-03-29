"""Unified Aegis configuration system.

Loads all governance settings from a single YAML file (or dict) and
exposes them as typed dataclasses.  Each section is optional — omitting
a section simply disables that feature.

Example YAML::

    guardrails:
      pii:
        enabled: true
        action: mask
      injection:
        enabled: true
        action: block

    integrations:
      auto_patch:
        - openai
        - anthropic

    audit:
      enabled: true
      backend: sqlite
      path: ./aegis_audit.db
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.config")


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------


@dataclass
class PIIConfig:
    """PII guardrail settings."""

    enabled: bool = True
    action: str = "mask"  # mask, block, warn, log
    categories: list[str] | None = None  # None = all
    severity: str = "high"


@dataclass
class InjectionConfig:
    """Prompt injection guardrail settings."""

    enabled: bool = True
    action: str = "block"  # block, warn, log
    sensitivity: str = "medium"  # low, medium, high
    severity: str = "critical"


@dataclass
class GuardrailsConfig:
    """Top-level guardrails configuration."""

    pii: PIIConfig | None = None
    injection: InjectionConfig | None = None
    custom_packs: list[str] | None = None  # paths to additional YAML packs


@dataclass
class PolicyConfig:
    """Policy engine configuration."""

    rules_path: str | None = None  # path to policy YAML
    rules: list[dict[str, Any]] | None = None  # inline rules


@dataclass
class CostConfig:
    """Cost tracking / budget configuration.

    Supports multi-dimensional cost limits that integrate with the
    policy engine.  All limits are optional — omitted limits are not
    enforced.

    Attributes:
        budget_usd: Overall budget ceiling in dollars.
        per_call_limit_usd: Maximum cost for a single LLM call.
        per_session_limit_usd: Maximum cost for a single session.
        per_minute_tokens: Maximum tokens per rolling minute window.
        daily_budget_usd: Maximum daily spend in dollars.
        alert_threshold: Fraction (0-1) of budget that triggers alerts.
        on_exceed: Action when a limit is exceeded: ``block``, ``warn``,
            or ``log``.
    """

    budget_usd: float | None = None
    per_call_limit_usd: float | None = None
    per_session_limit_usd: float | None = None
    per_minute_tokens: int | None = None
    daily_budget_usd: float | None = None
    alert_threshold: float = 0.8  # alert at 80% budget
    on_exceed: str = "block"  # block, warn, log


@dataclass
class AuditConfig:
    """Audit logging configuration."""

    enabled: bool = True
    backend: str = "sqlite"  # sqlite, redis, postgres
    path: str = "./aegis_audit.db"  # for sqlite
    dsn: str | None = None  # for redis/postgres


@dataclass
class DriftConfig:
    """Behavioral drift detection configuration.

    Controls whether drift detection is active and defines per-metric
    baselines with thresholds and enforcement actions.

    Attributes:
        enabled: Whether drift detection is active.
        baselines: List of per-metric configurations.  Each entry is a dict
            with keys ``name``, ``window``, ``threshold``, ``action``.
    """

    enabled: bool = False
    baselines: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class IntegrationsConfig:
    """Integration auto-patching configuration."""

    auto_patch: list[str] = field(default_factory=list)  # ["openai", "anthropic"]
    on_block: str = "raise"  # raise, return_none, log


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------


@dataclass
class AegisConfig:
    """Complete Aegis configuration loaded from YAML or dict.

    Every section is optional.  Omitted sections disable that feature.
    """

    guardrails: GuardrailsConfig | None = None
    policy: PolicyConfig | None = None
    cost: CostConfig | None = None
    audit: AuditConfig | None = None
    integrations: IntegrationsConfig | None = None
    drift: DriftConfig | None = None

    @classmethod
    def sensible_defaults(cls) -> AegisConfig:
        """Return a config with basic protections enabled.

        Used by ``aegis.init()`` when no explicit config or YAML file is
        found.  Enables PII masking, injection blocking, audit logging,
        and auto-patching of OpenAI/Anthropic clients.
        """
        return cls(
            guardrails=GuardrailsConfig(
                pii=PIIConfig(enabled=True, action="mask"),
                injection=InjectionConfig(enabled=True, action="block"),
            ),
            audit=AuditConfig(enabled=True, backend="sqlite", path="./aegis_audit.db"),
            integrations=IntegrationsConfig(
                auto_patch=["openai", "anthropic"],
                on_block="raise",
            ),
        )

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: str | Path) -> AegisConfig:
        """Load configuration from a YAML file.

        Args:
            path: Path to the YAML file.

        Raises:
            FileNotFoundError: If the file does not exist.
            ImportError: If PyYAML is not installed.
        """
        resolved = Path(path)
        if not resolved.exists():
            raise FileNotFoundError(f"Config file not found: {resolved}")

        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "PyYAML is required to load YAML config files. Install it with: pip install pyyaml"
            ) from exc

        text = resolved.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            logger.warning("Config file %s did not contain a mapping; using defaults", resolved)
            return cls()
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AegisConfig:
        """Build configuration from a plain dictionary.

        Keys that do not match a known section are silently ignored.
        """
        return cls(
            guardrails=_parse_guardrails(data.get("guardrails")),
            policy=_parse_policy(data.get("policy")),
            cost=_parse_cost(data.get("cost")),
            audit=_parse_audit(data.get("audit")),
            integrations=_parse_integrations(data.get("integrations")),
            drift=_parse_drift(data.get("drift")),
        )


# ---------------------------------------------------------------------------
# Section parsers (defensive: tolerate missing keys, wrong types)
# ---------------------------------------------------------------------------


def _parse_guardrails(raw: Any) -> GuardrailsConfig | None:
    if raw is None or not isinstance(raw, dict):
        return None

    pii: PIIConfig | None = None
    pii_raw = raw.get("pii")
    if isinstance(pii_raw, dict):
        pii = PIIConfig(
            enabled=bool(pii_raw.get("enabled", True)),
            action=str(pii_raw.get("action", "mask")),
            categories=pii_raw.get("categories"),
            severity=str(pii_raw.get("severity", "high")),
        )

    injection: InjectionConfig | None = None
    inj_raw = raw.get("injection")
    if isinstance(inj_raw, dict):
        injection = InjectionConfig(
            enabled=bool(inj_raw.get("enabled", True)),
            action=str(inj_raw.get("action", "block")),
            sensitivity=str(inj_raw.get("sensitivity", "medium")),
            severity=str(inj_raw.get("severity", "critical")),
        )

    packs = raw.get("custom_packs")
    if packs is not None and not isinstance(packs, list):
        packs = None

    return GuardrailsConfig(pii=pii, injection=injection, custom_packs=packs)


def _parse_policy(raw: Any) -> PolicyConfig | None:
    if raw is None or not isinstance(raw, dict):
        return None
    return PolicyConfig(
        rules_path=raw.get("rules_path"),
        rules=raw.get("rules"),
    )


def _parse_cost(raw: Any) -> CostConfig | None:
    if raw is None or not isinstance(raw, dict):
        return None

    per_minute_tokens = raw.get("per_minute_tokens")
    if per_minute_tokens is not None:
        per_minute_tokens = int(per_minute_tokens)

    return CostConfig(
        budget_usd=raw.get("budget_usd"),
        per_call_limit_usd=raw.get("per_call_limit_usd"),
        per_session_limit_usd=raw.get("per_session_limit_usd"),
        per_minute_tokens=per_minute_tokens,
        daily_budget_usd=raw.get("daily_budget_usd"),
        alert_threshold=float(raw.get("alert_threshold", 0.8)),
        on_exceed=str(raw.get("on_exceed", "block")),
    )


def _parse_audit(raw: Any) -> AuditConfig | None:
    if raw is None or not isinstance(raw, dict):
        return None
    return AuditConfig(
        enabled=bool(raw.get("enabled", True)),
        backend=str(raw.get("backend", "sqlite")),
        path=str(raw.get("path", "./aegis_audit.db")),
        dsn=raw.get("dsn"),
    )


def _parse_integrations(raw: Any) -> IntegrationsConfig | None:
    if raw is None or not isinstance(raw, dict):
        return None
    auto_patch = raw.get("auto_patch")
    if not isinstance(auto_patch, list):
        auto_patch = []
    return IntegrationsConfig(
        auto_patch=[str(p) for p in auto_patch],
        on_block=str(raw.get("on_block", "raise")),
    )


def _parse_drift(raw: Any) -> DriftConfig | None:
    if raw is None or not isinstance(raw, dict):
        return None
    baselines = raw.get("baselines")
    if not isinstance(baselines, list):
        baselines = []
    return DriftConfig(
        enabled=bool(raw.get("enabled", False)),
        baselines=[dict(b) for b in baselines if isinstance(b, dict)],
    )
