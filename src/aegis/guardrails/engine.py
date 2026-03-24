"""Guardrail engine that orchestrates multiple guardrails.

The engine runs guardrails in registration order.  A single ``"blocked"``
result short-circuits the pipeline.  Masking transformations are applied
sequentially so that downstream guardrails see already-masked content.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from aegis.guardrails.base import Guardrail, GuardrailResult


class GuardrailEngine:
    """Run a pipeline of :class:`Guardrail` instances against content.

    Usage::

        engine = GuardrailEngine()
        engine.add(my_pii_guardrail)
        engine.add(my_injection_guardrail)
        results = engine.check("some user input")

    Or load from a YAML pack::

        engine = GuardrailEngine.from_pack("pii_pack.yaml")
    """

    def __init__(self, guardrails: list[Guardrail] | None = None) -> None:
        self._guardrails: list[Guardrail] = list(guardrails) if guardrails else []

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, guardrail: Guardrail) -> None:
        """Append a guardrail to the pipeline."""
        self._guardrails.append(guardrail)

    # ------------------------------------------------------------------
    # Inspection only
    # ------------------------------------------------------------------

    def check(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> list[GuardrailResult]:
        """Run all guardrails and return their results.

        Every guardrail is executed regardless of earlier results so the
        caller gets a complete picture of all findings.

        Args:
            content: The text to inspect.
            context: Optional metadata forwarded to each guardrail.
        """
        results: list[GuardrailResult] = []
        for guardrail in self._guardrails:
            results.append(guardrail.check(content, context=context))
        return results

    # ------------------------------------------------------------------
    # Inspection + transformation
    # ------------------------------------------------------------------

    def check_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[list[GuardrailResult], str]:
        """Run all guardrails, collecting results and applying transformations.

        Guardrails execute in order.  If any guardrail returns a
        ``"blocked"`` action the pipeline stops immediately — no further
        guardrails run, and the content is not transformed.

        Masking transformations are applied sequentially: the output of
        one guardrail becomes the input to the next.

        Args:
            content: The text to inspect and potentially transform.
            context: Optional metadata forwarded to each guardrail.

        Returns:
            A ``(results, final_content)`` tuple where *results* contains
            one entry per executed guardrail and *final_content* is the
            content after all transformations.
        """
        results: list[GuardrailResult] = []
        current = content

        for guardrail in self._guardrails:
            result, current = guardrail.check_and_transform(current, context=context)
            results.append(result)
            if result.action == "blocked":
                break

        return results, current

    # ------------------------------------------------------------------
    # Async variants (non-blocking for async-first runtimes)
    # ------------------------------------------------------------------

    async def acheck(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> list[GuardrailResult]:
        """Async version of :meth:`check`.

        Runs the synchronous guardrail pipeline in a thread-pool executor
        so it does not block the event loop.  When guardrails that natively
        support ``async`` are added in the future, this method will call
        them directly.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.check(content, context=context))

    async def acheck_and_transform(
        self,
        content: str,
        *,
        context: dict[str, object] | None = None,
    ) -> tuple[list[GuardrailResult], str]:
        """Async version of :meth:`check_and_transform`."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.check_and_transform(content, context=context)
        )

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_pack(cls, pack_path: str | Path) -> GuardrailEngine:
        """Create an engine from a YAML pack file.

        The pack is loaded via :meth:`aegis.packs.schema.Pack.from_yaml`
        and its rules are converted to guardrail instances.

        Args:
            pack_path: Path to the YAML pack file.

        Raises:
            FileNotFoundError: If the pack file does not exist.
        """
        from aegis.packs.schema import Pack

        pack = Pack.from_yaml(pack_path)
        guardrails = pack.to_guardrails()
        return cls(guardrails=guardrails)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def guardrails(self) -> list[Guardrail]:
        """Return a copy of the registered guardrails."""
        return list(self._guardrails)

    def __len__(self) -> int:
        return len(self._guardrails)

    def __repr__(self) -> str:
        names = [g.name for g in self._guardrails]
        return f"GuardrailEngine(guardrails={names!r})"
