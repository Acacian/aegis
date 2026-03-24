"""Global instrumentation state.

Tracks which frameworks have been patched and stores shared configuration
(guardrail engine, audit settings) used by all framework patches.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("aegis.instrument")


@dataclass
class FrameworkPatch:
    """Record of a single framework patch."""

    name: str
    patched: bool = False
    targets: list[str] = field(default_factory=list)
    error: str | None = None


class InstrumentationState:
    """Thread-safe global state for the instrumentation layer."""

    _instance: InstrumentationState | None = None
    _lock = threading.Lock()

    def __init__(self) -> None:
        self._patches: dict[str, FrameworkPatch] = {}
        self._guardrail_engine: Any = None
        self._on_block: str = "raise"
        self._audit: bool = True
        self._active = False

    @classmethod
    def get(cls) -> InstrumentationState:
        """Return the singleton instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset global state (for testing / unpatch-all)."""
        with cls._lock:
            cls._instance = None

    # -- Configuration ---------------------------------------------------

    def configure(
        self,
        *,
        guardrail_engine: Any = None,
        on_block: str = "raise",
        audit: bool = True,
    ) -> None:
        """Set shared configuration for all patches."""
        self._guardrail_engine = guardrail_engine
        self._on_block = on_block
        self._audit = audit
        self._active = True

    @property
    def guardrail_engine(self) -> Any:
        return self._guardrail_engine

    @property
    def on_block(self) -> str:
        return self._on_block

    @property
    def audit(self) -> bool:
        return self._audit

    @property
    def active(self) -> bool:
        return self._active

    # -- Patch tracking --------------------------------------------------

    def register_patch(self, patch: FrameworkPatch) -> None:
        """Register a framework patch result."""
        self._patches[patch.name] = patch

    def get_patch(self, name: str) -> FrameworkPatch | None:
        return self._patches.get(name)

    def is_patched(self, name: str) -> bool:
        p = self._patches.get(name)
        return p is not None and p.patched

    @property
    def patched_frameworks(self) -> list[str]:
        return [name for name, p in self._patches.items() if p.patched]

    @property
    def all_patches(self) -> dict[str, FrameworkPatch]:
        return dict(self._patches)

    def clear_patches(self) -> None:
        self._patches.clear()
        self._active = False
