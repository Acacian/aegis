"""Native Pydantic AI capability for Aegis governance.

Implements :class:`pydantic_ai.capabilities.AbstractCapability` so that Aegis
guardrails run as a first-class Pydantic AI capability — no monkey-patching.

Usage::

    from pydantic_ai import Agent
    from aegis.contrib.pydantic_ai import AegisCapability
    from aegis.guardrails import GuardrailEngine, InjectionGuardrail

    engine = GuardrailEngine()
    engine.add(InjectionGuardrail())  # type: ignore[arg-type]

    agent = Agent(
        "openai:gpt-4o-mini",
        capabilities=[AegisCapability(engine)],
    )
    result = await agent.run("Hello!")

All ``pydantic_ai`` imports are deferred so this module can be imported even
when ``pydantic-ai`` is not installed — it will raise :class:`ImportError` only
at instantiation time.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.guardrails.engine import GuardrailEngine

logger = logging.getLogger("aegis.contrib.pydantic_ai")


def _get_base_class() -> type:  # noqa: ANN401
    """Return AbstractCapability if pydantic-ai is installed, else object."""
    try:
        from pydantic_ai.capabilities import AbstractCapability

        return AbstractCapability  # type: ignore[no-any-return]
    except ImportError:
        return object


class AegisCapability(_get_base_class()):  # type: ignore[misc]
    """Pydantic AI capability that enforces Aegis guardrails.

    Checks user prompts before each model request and model responses
    after each model request.

    Args:
        engine: A :class:`~aegis.guardrails.engine.GuardrailEngine` that
            defines which guardrails to run.
        on_block: What to do when a guardrail blocks content.
            ``"raise"`` (default) raises
            :class:`~aegis.integrations.errors.AegisGuardrailError`.
            ``"warn"`` logs a warning and continues.
        check_input: Whether to check user prompts (default ``True``).
        check_output: Whether to check model responses (default ``True``).
    """

    def __init__(
        self,
        engine: GuardrailEngine,
        *,
        on_block: str = "raise",
        check_input: bool = True,
        check_output: bool = True,
    ) -> None:
        self.engine = engine
        self.on_block = on_block
        self.check_input = check_input
        self.check_output = check_output

    def __repr__(self) -> str:
        return (
            f"AegisCapability(on_block={self.on_block!r}, "
            f"check_input={self.check_input}, check_output={self.check_output})"
        )

    # ------------------------------------------------------------------
    # AbstractCapability interface
    # ------------------------------------------------------------------

    @staticmethod
    def get_serialization_name() -> str | None:
        return "Aegis"

    @classmethod
    def default(
        cls,
        *,
        on_block: str = "raise",
        check_input: bool = True,
        check_output: bool = True,
    ) -> AegisCapability:
        """Create with all built-in guardrails enabled.

        Includes: injection, PII, toxicity, prompt-leak, hallucination.

        Usage::

            from aegis.contrib.pydantic_ai import AegisCapability

            agent = Agent("openai:gpt-4o-mini", capabilities=[AegisCapability.default()])
        """
        return cls.from_guards(
            "injection",
            "pii",
            "toxicity",
            "prompt_leak",
            "hallucination",
            on_block=on_block,
            check_input=check_input,
            check_output=check_output,
        )

    @classmethod
    def from_guards(
        cls,
        *guards: str,
        on_block: str = "raise",
        check_input: bool = True,
        check_output: bool = True,
    ) -> AegisCapability:
        """Create with specific guardrails by name.

        Available guards: ``"injection"``, ``"pii"``, ``"toxicity"``,
        ``"prompt_leak"``, ``"hallucination"``, ``"keyword"``, ``"cot"``.

        Usage::

            from aegis.contrib.pydantic_ai import AegisCapability

            agent = Agent("openai:gpt-4o-mini", capabilities=[
                AegisCapability.from_guards("injection", "pii")
            ])
        """
        from aegis.guardrails import GuardrailEngine, InjectionGuardrail
        from aegis.guardrails.hallucination import HallucinationGuardrail
        from aegis.guardrails.pii import PIIGuardrail
        from aegis.guardrails.prompt_leak import PromptLeakGuardrail
        from aegis.guardrails.toxicity import ToxicityGuardrail

        registry: dict[str, type] = {
            "injection": InjectionGuardrail,
            "pii": PIIGuardrail,
            "toxicity": ToxicityGuardrail,
            "prompt_leak": PromptLeakGuardrail,
            "hallucination": HallucinationGuardrail,
        }

        engine = GuardrailEngine()
        for name in guards:
            guardrail_cls = registry.get(name)
            if guardrail_cls is None:
                raise ValueError(
                    f"Unknown guardrail {name!r}. Available: {sorted(registry.keys())}"
                )
            engine.add(guardrail_cls())  # type: ignore[arg-type]

        return cls(
            engine,
            on_block=on_block,
            check_input=check_input,
            check_output=check_output,
        )

    @classmethod
    def from_spec(
        cls,
        *,
        on_block: str = "raise",
        check_input: bool = True,
        check_output: bool = True,
    ) -> AegisCapability:
        """Create from an agent spec (YAML/JSON).

        Since :class:`GuardrailEngine` is not serialisable, ``from_spec``
        creates a default engine with the built-in injection guardrail.
        """
        from aegis.guardrails import GuardrailEngine, InjectionGuardrail

        engine = GuardrailEngine()
        engine.add(InjectionGuardrail())  # type: ignore[arg-type]
        return cls(
            engine,
            on_block=on_block,
            check_input=check_input,
            check_output=check_output,
        )

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    async def before_model_request(
        self,
        ctx: Any,
        request_context: Any,
    ) -> Any:
        """Check user prompt before sending to the model."""
        if not self.check_input:
            return request_context

        text = self._extract_user_text(request_context)
        if text:
            self._run_guardrails(text, direction="input")

        return request_context

    async def after_model_request(
        self,
        ctx: Any,
        *,
        request_context: Any,
        response: Any,
    ) -> Any:
        """Check model response after receiving from the model."""
        if not self.check_output:
            return response

        text = self._extract_response_text(response)
        if text:
            self._run_guardrails(text, direction="output")

        return response

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_user_text(request_context: Any) -> str:
        """Extract user prompt text from model request messages."""
        parts: list[str] = []
        messages = getattr(request_context, "messages", None)
        if not messages:
            return ""

        for msg in messages:
            msg_parts = getattr(msg, "parts", None)
            if not msg_parts:
                continue
            for part in msg_parts:
                kind = getattr(part, "part_kind", "")
                if kind == "user-prompt" or type(part).__name__ == "UserPromptPart":
                    content = getattr(part, "content", None)
                    if isinstance(content, str):
                        parts.append(content)
        return "\n".join(parts)

    @staticmethod
    def _extract_response_text(response: Any) -> str:
        """Extract text from model response."""
        text = getattr(response, "text", None)
        if isinstance(text, str) and text:
            return text

        parts = getattr(response, "parts", None)
        if not parts:
            return ""

        texts: list[str] = []
        for part in parts:
            kind = getattr(part, "part_kind", "")
            if kind == "text" or type(part).__name__ == "TextPart":
                content = getattr(part, "content", None)
                if isinstance(content, str):
                    texts.append(content)
        return "\n".join(texts)

    def _run_guardrails(self, text: str, *, direction: str) -> None:
        """Run guardrails, raise on block if configured."""
        try:
            results = self.engine.check(text)
        except Exception:
            logger.debug("Guardrail check failed for %s", direction, exc_info=True)
            return

        blocked = [r for r in results if getattr(r, "action", None) == "blocked"]
        if not blocked:
            return

        details = "; ".join(
            getattr(r, "details", "") or getattr(r, "guardrail_name", "unknown") for r in blocked
        )
        reason = f"Aegis blocked {direction}: {details}"

        if self.on_block == "raise":
            from aegis.integrations.errors import AegisGuardrailError

            raise AegisGuardrailError(reason, guardrail_results=blocked)

        logger.warning(reason)
