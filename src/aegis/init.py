"""Aegis unified initialisation.

Provides :class:`Aegis` — the single entry-point that reads one config
and wires guardrails, integrations, audit logging, and cost tracking
together.

Usage::

    import aegis

    # Auto-discover aegis.yaml in CWD / parent dirs
    aegis.init()

    # Or specify a path
    aegis.init("path/to/aegis.yaml")

    # Programmatic config
    from aegis.config import AegisConfig, GuardrailsConfig, PIIConfig
    aegis.init(config=AegisConfig(
        guardrails=GuardrailsConfig(pii=PIIConfig(action="mask")),
    ))

After ``init()``, OpenAI / Anthropic calls are automatically governed.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, ClassVar

from aegis.config import AegisConfig
from aegis.guardrails.base import Guardrail, GuardrailResult

logger = logging.getLogger("aegis.init")

# Auto-discovery file names (checked in order).
_CONFIG_FILENAMES: list[str] = ["aegis.yaml", "aegis.yml"]
# How many parent directories to traverse during auto-discovery.
_MAX_PARENT_DEPTH: int = 5


class Aegis:
    """Global Aegis instance.  Wires everything together from config."""

    _instance: ClassVar[Aegis | None] = None

    def __init__(self, config: AegisConfig) -> None:
        self.config: AegisConfig = config

        # Components — populated during _activate()
        self.guardrail_engine: Any | None = None
        self.audit_logger: Any | None = None
        self.cost_tracker: Any | None = None

        self._patched_openai: bool = False
        self._patched_anthropic: bool = False

    # ------------------------------------------------------------------
    # Public class-level API
    # ------------------------------------------------------------------

    @classmethod
    def init(
        cls,
        config_path: str | Path | None = None,
        *,
        config: AegisConfig | None = None,
        auto_discover: bool = True,
    ) -> Aegis:
        """Initialise Aegis.  This is THE entry point.

        Args:
            config_path: Path to ``aegis.yaml``.  If *None* and
                *auto_discover* is ``True``, searches CWD and parent
                directories for a config file.
            config: Provide an :class:`AegisConfig` directly instead of
                loading from a file.
            auto_discover: When no explicit path or config is given,
                search for ``aegis.yaml`` / ``aegis.yml`` in the CWD
                and up to 5 parent directories.

        Returns:
            The global :class:`Aegis` singleton.

        Raises:
            RuntimeError: If called when already initialised.  Call
                :meth:`shutdown` first.
        """
        if cls._instance is not None:
            logger.debug("Aegis already initialised; returning existing instance")
            return cls._instance

        resolved_config = cls._resolve_config(
            config_path, config=config, auto_discover=auto_discover
        )
        instance = cls(resolved_config)
        instance._activate()
        cls._instance = instance

        logger.info("Aegis initialised")
        return instance

    @classmethod
    def get(cls) -> Aegis:
        """Return the current global instance.

        Raises:
            RuntimeError: If :meth:`init` has not been called yet.
        """
        if cls._instance is None:
            raise RuntimeError("Aegis has not been initialised. Call aegis.init() first.")
        return cls._instance

    @classmethod
    def shutdown(cls) -> None:
        """Tear down: unpatch integrations, close connections, reset singleton."""
        instance = cls._instance
        if instance is None:
            return

        instance._deactivate()
        cls._instance = None
        logger.info("Aegis shut down")

    # ------------------------------------------------------------------
    # Config resolution
    # ------------------------------------------------------------------

    @classmethod
    def _resolve_config(
        cls,
        config_path: str | Path | None,
        *,
        config: AegisConfig | None,
        auto_discover: bool,
    ) -> AegisConfig:
        """Determine which config to use."""
        # 1. Explicit config object takes priority.
        if config is not None:
            logger.debug("Using provided AegisConfig object")
            return config

        # 2. Explicit path.
        if config_path is not None:
            logger.debug("Loading config from explicit path: %s", config_path)
            return AegisConfig.from_yaml(config_path)

        # 3. Auto-discover.
        if auto_discover:
            discovered = cls._discover_config()
            if discovered is not None:
                logger.debug("Auto-discovered config at: %s", discovered)
                return AegisConfig.from_yaml(discovered)
            logger.info(
                "No config file discovered; using sensible defaults "
                "(PII masking + injection blocking + audit + auto-patch)"
            )

        return AegisConfig.sensible_defaults()

    @classmethod
    def _discover_config(cls) -> Path | None:
        """Search CWD and parent dirs for an aegis config file."""
        current = Path.cwd()
        for _ in range(_MAX_PARENT_DEPTH + 1):
            for name in _CONFIG_FILENAMES:
                candidate = current / name
                if candidate.is_file():
                    return candidate
            parent = current.parent
            if parent == current:
                break  # filesystem root reached
            current = parent
        return None

    # ------------------------------------------------------------------
    # Activation (wiring)
    # ------------------------------------------------------------------

    def _activate(self) -> None:
        """Build components and patch integrations based on config."""
        self._setup_audit()
        self._setup_guardrails()
        self._setup_cost_tracker()
        self._setup_integrations()

    def _deactivate(self) -> None:
        """Undo patching and release resources."""
        self._teardown_integrations()
        self._teardown_audit()

    # -- Audit ----------------------------------------------------------

    def _setup_audit(self) -> None:
        cfg = self.config.audit
        if cfg is None or not cfg.enabled:
            return

        if cfg.backend == "sqlite":
            try:
                from aegis.runtime.audit import AuditLogger

                self.audit_logger = AuditLogger(db_path=cfg.path)
                logger.debug("Audit logger initialised (sqlite: %s)", cfg.path)
            except Exception:
                logger.warning("Failed to initialise SQLite audit logger", exc_info=True)
        else:
            logger.warning(
                "Audit backend %r is not directly managed by init(); "
                "configure it via the appropriate adapter",
                cfg.backend,
            )

    def _teardown_audit(self) -> None:
        if self.audit_logger is not None:
            try:
                self.audit_logger.close()
            except Exception:
                logger.debug("Error closing audit logger", exc_info=True)
            self.audit_logger = None

    # -- Guardrails -----------------------------------------------------

    def _setup_guardrails(self) -> None:
        cfg = self.config.guardrails
        if cfg is None:
            return

        from aegis.guardrails.engine import GuardrailEngine

        engine = GuardrailEngine()

        # PII guardrail
        if cfg.pii is not None and cfg.pii.enabled:
            try:
                from aegis.guardrails.pii import PIIGuardrail

                pii_guard = PIIGuardrail(
                    categories=cfg.pii.categories,
                    action=cfg.pii.action,
                    severity=cfg.pii.severity,
                )
                # Wrap the raw PIIGuardrail in the Guardrail interface adapter
                pii_adapter = _PIIGuardrailAdapter(pii_guard, severity=cfg.pii.severity)
                engine.add(pii_adapter)
                logger.debug("PII guardrail added (action=%s)", cfg.pii.action)
            except Exception:
                logger.warning("Failed to set up PII guardrail", exc_info=True)

        # Injection guardrail
        if cfg.injection is not None and cfg.injection.enabled:
            try:
                from aegis.guardrails.injection import InjectionGuardrail

                inj_guard = InjectionGuardrail(
                    action=cfg.injection.action,
                    sensitivity=cfg.injection.sensitivity,
                    severity=cfg.injection.severity,
                )
                inj_adapter = _InjectionGuardrailAdapter(
                    inj_guard, severity=cfg.injection.severity
                )
                engine.add(inj_adapter)
                logger.debug(
                    "Injection guardrail added (action=%s, sensitivity=%s)",
                    cfg.injection.action,
                    cfg.injection.sensitivity,
                )
            except Exception:
                logger.warning("Failed to set up injection guardrail", exc_info=True)

        # Custom packs
        if cfg.custom_packs:
            for pack_path in cfg.custom_packs:
                try:
                    pack_engine = GuardrailEngine.from_pack(pack_path)
                    for g in pack_engine.guardrails:
                        engine.add(g)
                    logger.debug("Custom pack loaded: %s", pack_path)
                except Exception:
                    logger.warning("Failed to load custom pack: %s", pack_path, exc_info=True)

        if len(engine) > 0:
            self.guardrail_engine = engine
            logger.debug("GuardrailEngine ready with %d guardrail(s)", len(engine))

    # -- Cost tracker ---------------------------------------------------

    def _setup_cost_tracker(self) -> None:
        cfg = self.config.cost
        if cfg is None:
            return

        try:
            from aegis.core.budget import CostTracker

            self.cost_tracker = CostTracker(
                max_budget=cfg.budget_usd or 0.0,
                warn_threshold=cfg.alert_threshold,
            )
            logger.debug(
                "Cost tracker initialised (budget=$%s, alert=%s%%)",
                cfg.budget_usd or "unlimited",
                int(cfg.alert_threshold * 100),
            )
        except Exception:
            logger.warning("Failed to initialise cost tracker", exc_info=True)

    # -- Integrations ---------------------------------------------------

    def _setup_integrations(self) -> None:
        cfg = self.config.integrations
        if cfg is None or not cfg.auto_patch:
            return

        on_block = cfg.on_block

        for name in cfg.auto_patch:
            name_lower = name.lower().strip()
            if name_lower == "openai":
                self._patch_openai(on_block)
            elif name_lower == "anthropic":
                self._patch_anthropic(on_block)
            else:
                logger.warning("Unknown integration target: %r (skipped)", name)

    def _patch_openai(self, on_block: str) -> None:
        try:
            from aegis.integrations.patch_openai import patch_openai

            patch_openai(
                guardrails=self.guardrail_engine,
                on_block=on_block,
                audit=self.audit_logger is not None,
            )
            self._patched_openai = True
            logger.debug("OpenAI client patched")
        except ImportError:
            logger.info(
                "openai package not installed; skipping OpenAI auto-patch. "
                "Install with: pip install openai"
            )
        except Exception:
            logger.warning("Failed to patch OpenAI client", exc_info=True)

    def _patch_anthropic(self, on_block: str) -> None:
        try:
            from aegis.integrations.patch_anthropic import patch_anthropic

            patch_anthropic(
                guardrails=self.guardrail_engine,
                on_block=on_block,
                audit=self.audit_logger is not None,
            )
            self._patched_anthropic = True
            logger.debug("Anthropic client patched")
        except ImportError:
            logger.info(
                "anthropic package not installed; skipping Anthropic auto-patch. "
                "Install with: pip install anthropic"
            )
        except Exception:
            logger.warning("Failed to patch Anthropic client", exc_info=True)

    def _teardown_integrations(self) -> None:
        if self._patched_openai:
            try:
                from aegis.integrations.patch_openai import unpatch_openai

                unpatch_openai()
                self._patched_openai = False
            except Exception:
                logger.debug("Error unpatching OpenAI", exc_info=True)

        if self._patched_anthropic:
            try:
                from aegis.integrations.patch_anthropic import unpatch_anthropic

                unpatch_anthropic()
                self._patched_anthropic = False
            except Exception:
                logger.debug("Error unpatching Anthropic", exc_info=True)

    # ------------------------------------------------------------------
    # Repr
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        parts: list[str] = []
        if self.guardrail_engine is not None:
            parts.append(f"guardrails={len(self.guardrail_engine)}")
        if self.audit_logger is not None:
            parts.append("audit=on")
        if self.cost_tracker is not None:
            parts.append("cost=on")
        if self._patched_openai:
            parts.append("openai=patched")
        if self._patched_anthropic:
            parts.append("anthropic=patched")
        detail = ", ".join(parts) if parts else "defaults"
        return f"Aegis({detail})"


# ---------------------------------------------------------------------------
# Guardrail adapters
# ---------------------------------------------------------------------------
# PIIGuardrail and InjectionGuardrail have their own result types and are
# NOT subclasses of the base Guardrail ABC.  We need thin adapters so the
# GuardrailEngine (which expects the Guardrail interface) can run them.
# ---------------------------------------------------------------------------


class _PIIGuardrailAdapter(Guardrail):
    """Adapts :class:`PIIGuardrail` to the :class:`Guardrail` interface."""

    def __init__(self, inner: Any, *, severity: str = "high") -> None:
        super().__init__(name="pii", description="PII detection and masking", severity=severity)
        self._inner = inner

    def check(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> GuardrailResult:
        result = self._inner.check(content)
        if not result.detected:
            return GuardrailResult(
                passed=True,
                guardrail_name=self.name,
                action="allowed",
                severity=self.severity,
            )

        action = self._inner.action
        gr_action = {
            "mask": "masked",
            "block": "blocked",
            "warn": "warned",
            "log": "allowed",
        }.get(action, "allowed")

        return GuardrailResult(
            passed=gr_action not in ("blocked", "masked"),
            guardrail_name=self.name,
            action=gr_action,
            details=f"PII detected: {', '.join(sorted(result.categories_found))}",
            severity=result.severity,
        )

    def check_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[GuardrailResult, str]:
        transform = self._inner.check_and_transform(content)
        if not transform.detected:
            return (
                GuardrailResult(
                    passed=True,
                    guardrail_name=self.name,
                    action="allowed",
                    severity=self.severity,
                ),
                content,
            )

        action = transform.action_taken
        gr_action = {
            "mask": "masked",
            "block": "blocked",
            "warn": "warned",
            "log": "allowed",
            "none": "allowed",
        }.get(action, "allowed")

        return (
            GuardrailResult(
                passed=gr_action not in ("blocked",),
                guardrail_name=self.name,
                action=gr_action,
                details=(
                    f"PII {action}: {', '.join(sorted(m.category for m in transform.matches))}"
                ),
                masked_content=transform.content,
                original_content=transform.original_content,
                severity=self.severity,
            ),
            transform.content,
        )


class _InjectionGuardrailAdapter(Guardrail):
    """Adapts :class:`InjectionGuardrail` to the :class:`Guardrail` interface."""

    def __init__(self, inner: Any, *, severity: str = "critical") -> None:
        super().__init__(
            name="prompt_injection",
            description="Prompt injection detection",
            severity=severity,
        )
        self._inner = inner

    def check(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> GuardrailResult:
        result = self._inner.check(content)
        return GuardrailResult(
            passed=result.passed,
            guardrail_name=self.name,
            action=result.action,
            details=result.details,
            severity=result.severity,
        )

    def check_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[GuardrailResult, str]:
        result = self._inner.check(content)
        transformed = content
        if result.action == "blocked":
            transformed = "[BLOCKED: prompt injection detected]"

        return (
            GuardrailResult(
                passed=result.passed,
                guardrail_name=self.name,
                action=result.action,
                details=result.details,
                severity=result.severity,
            ),
            transformed,
        )
