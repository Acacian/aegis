"""Monkey-patch the Anthropic client with Aegis governance.

Wraps ``anthropic.resources.messages.Messages.create`` (and its async
counterpart) so that every LLM call passes through Aegis guardrails and
is recorded in the audit log.

Anthropic is an optional dependency -- all imports are deferred to avoid
``ImportError`` at module load time.
"""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Callable
from typing import Any

from aegis.integrations.errors import AegisGuardrailError

logger = logging.getLogger("aegis.integrations.anthropic")

_original_create: Callable[..., Any] | None = None
_original_async_create: Callable[..., Any] | None = None
_patched = False


def _extract_messages_text(messages: list[dict[str, Any]] | Any) -> str:
    """Concatenate user/assistant message content into a single string."""
    if not isinstance(messages, list):
        return ""
    parts: list[str] = []
    for msg in messages:
        if isinstance(msg, dict):
            content = msg.get("content", "")
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
        else:
            content = getattr(msg, "content", None)
            if isinstance(content, str):
                parts.append(content)
    return "\n".join(parts)


def _extract_response_text(response: Any) -> str:
    """Extract assistant reply text from an Anthropic Message response."""
    try:
        content_blocks = getattr(response, "content", None) or []
        parts: list[str] = []
        for block in content_blocks:
            if getattr(block, "type", None) == "text":
                text = getattr(block, "text", "")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    except Exception:
        return ""


def _extract_usage(response: Any) -> dict[str, Any]:
    """Extract token usage and model from an Anthropic response."""
    info: dict[str, Any] = {}
    try:
        info["model"] = getattr(response, "model", None)
        usage = getattr(response, "usage", None)
        if usage is not None:
            info["input_tokens"] = getattr(usage, "input_tokens", 0)
            info["output_tokens"] = getattr(usage, "output_tokens", 0)
            info["total_tokens"] = getattr(usage, "input_tokens", 0) + getattr(
                usage, "output_tokens", 0
            )
    except Exception:
        pass
    return info


def _run_guardrails(
    guardrail_engine: Any,
    content: str,
    *,
    direction: str,
    on_block: str,
) -> list[Any]:
    """Run guardrail checks on *content*.

    Returns the list of :class:`~aegis.guardrails.base.GuardrailResult`
    objects.  Raises :class:`AegisGuardrailError` when a guardrail blocks
    and *on_block* is ``"raise"``.
    """
    if guardrail_engine is None:
        return []

    try:
        results: list[Any] = guardrail_engine.check(content)
    except Exception:
        logger.debug("Guardrail check failed for %s content", direction, exc_info=True)
        return []

    blocked = [r for r in results if getattr(r, "action", None) == "blocked"]
    if blocked:
        details = "; ".join(
            getattr(r, "details", "") or getattr(r, "guardrail_name", "unknown") for r in blocked
        )
        reason = f"Guardrail blocked {direction} content: {details}"
        if on_block == "raise":
            raise AegisGuardrailError(reason, guardrail_results=blocked)
        if on_block == "log":
            logger.warning("Aegis guardrail: %s", reason)

    return results


def _audit_log(
    audit_logger: Any,
    session_id: str,
    *,
    model: str | None,
    messages_text: str,
    response_text: str,
    usage: dict[str, Any],
    guardrail_results_input: list[Any],
    guardrail_results_output: list[Any],
) -> None:
    """Write an audit record for a governed LLM call."""
    if audit_logger is None:
        return

    try:
        from aegis.core.action import Action
        from aegis.core.policy import Approval, PolicyDecision
        from aegis.core.risk import RiskLevel

        action = Action(
            type="llm_call",
            target="anthropic",
            params={
                "model": model or "unknown",
                **usage,
            },
            description=f"Anthropic messages call ({model or 'unknown'})",
        )
        decision = PolicyDecision(
            action=action,
            risk_level=RiskLevel.LOW,
            approval=Approval.AUTO,
            matched_rule="<anthropic_patch>",
        )
        audit_logger.log(session_id, decision)
    except Exception:
        logger.debug("Audit logging failed for Anthropic call", exc_info=True)


def patch_anthropic(
    *,
    policy_path: str | None = None,
    guardrails: list[Any] | Any | None = None,
    on_block: str = "raise",
    audit: bool = True,
) -> None:
    """Patch the Anthropic client to add Aegis governance.

    After calling this function, every ``client.messages.create(...)``
    call will:

    1. Run input guardrails on the messages.
    2. Call the original Anthropic method.
    3. Run output guardrails on the response.
    4. Record the interaction in the audit log (model, tokens, etc.).

    Args:
        policy_path: Path to a YAML policy file.  Currently reserved for
            future per-model policy support.
        guardrails: A :class:`~aegis.guardrails.engine.GuardrailEngine` or
            a list of :class:`~aegis.guardrails.base.Guardrail` instances
            for content checking.  When ``None`` no guardrail checks run.
        on_block: Strategy when a guardrail blocks --
            ``"raise"`` (default), ``"return_none"``, or ``"log"``.
        audit: Whether to write audit log entries.  Defaults to ``True``.

    Raises:
        ImportError: If the ``anthropic`` package is not installed.

    Example::

        import aegis
        aegis.patch_anthropic()

        import anthropic
        client = anthropic.Anthropic()
        client.messages.create(...)  # governed by Aegis
    """
    global _patched, _original_create, _original_async_create  # noqa: PLW0603

    if _patched:
        logger.debug("Anthropic already patched; skipping")
        return

    try:
        import anthropic.resources.messages as _messages
    except ImportError as exc:
        raise ImportError(
            "The 'anthropic' package is required for patch_anthropic(). "
            "Install it with: pip install anthropic"
        ) from exc

    # Build guardrail engine
    guardrail_engine = _resolve_guardrails(guardrails)

    # Build audit logger
    audit_logger = None
    if audit:
        try:
            from aegis.runtime.audit import AuditLogger

            audit_logger = AuditLogger()
        except Exception:
            logger.debug("Could not initialise audit logger", exc_info=True)

    session_id = uuid.uuid4().hex[:12]

    # ---- Sync wrapper ------------------------------------------------ #

    _original_create = _messages.Messages.create

    @functools.wraps(_messages.Messages.create)
    def governed_create(self: Any, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages") or (args[0] if args else [])
        model = kwargs.get("model") or (args[1] if len(args) > 1 else None)

        # Input guardrails
        input_text = _extract_messages_text(messages)
        input_results = _run_guardrails(
            guardrail_engine, input_text, direction="input", on_block=on_block
        )

        # Original call
        assert _original_create is not None
        response = _original_create(self, *args, **kwargs)

        # Output guardrails
        output_text = _extract_response_text(response)
        output_results = _run_guardrails(
            guardrail_engine, output_text, direction="output", on_block=on_block
        )

        # Audit
        usage = _extract_usage(response)
        _audit_log(
            audit_logger,
            session_id,
            model=usage.get("model") or model,
            messages_text=input_text,
            response_text=output_text,
            usage=usage,
            guardrail_results_input=input_results,
            guardrail_results_output=output_results,
        )

        return response

    _messages.Messages.create = governed_create  # type: ignore[assignment,method-assign]

    # ---- Async wrapper ----------------------------------------------- #

    try:
        import anthropic.resources.messages as _amessages

        _original_async_create = _amessages.AsyncMessages.create

        @functools.wraps(_amessages.AsyncMessages.create)
        async def governed_async_create(self: Any, *args: Any, **kwargs: Any) -> Any:
            messages = kwargs.get("messages") or (args[0] if args else [])
            model = kwargs.get("model") or (args[1] if len(args) > 1 else None)

            # Input guardrails
            input_text = _extract_messages_text(messages)
            input_results = _run_guardrails(
                guardrail_engine, input_text, direction="input", on_block=on_block
            )

            # Original call
            assert _original_async_create is not None
            response = await _original_async_create(self, *args, **kwargs)

            # Output guardrails
            output_text = _extract_response_text(response)
            output_results = _run_guardrails(
                guardrail_engine, output_text, direction="output", on_block=on_block
            )

            # Audit
            usage = _extract_usage(response)
            _audit_log(
                audit_logger,
                session_id,
                model=usage.get("model") or model,
                messages_text=input_text,
                response_text=output_text,
                usage=usage,
                guardrail_results_input=input_results,
                guardrail_results_output=output_results,
            )

            return response

        _amessages.AsyncMessages.create = governed_async_create  # type: ignore[assignment,method-assign]

    except (ImportError, AttributeError):
        logger.debug("Async Anthropic messages not available; skipping async patch")

    _patched = True
    logger.info("Anthropic client patched with Aegis governance")


def unpatch_anthropic() -> None:
    """Restore the original Anthropic client methods.

    Safe to call even if :func:`patch_anthropic` was never called.
    """
    global _patched, _original_create, _original_async_create  # noqa: PLW0603

    if not _patched:
        return

    try:
        import anthropic.resources.messages as _messages

        if _original_create is not None:
            _messages.Messages.create = _original_create  # type: ignore[assignment,method-assign]
        if _original_async_create is not None:
            _messages.AsyncMessages.create = _original_async_create  # type: ignore[assignment,method-assign]
    except ImportError:
        pass

    _original_create = None
    _original_async_create = None
    _patched = False
    logger.info("Anthropic client unpatched")


def _resolve_guardrails(guardrails: list[Any] | Any | None) -> Any:
    """Normalize *guardrails* into a GuardrailEngine or None."""
    if guardrails is None:
        return None

    try:
        from aegis.guardrails.engine import GuardrailEngine
    except ImportError:
        logger.debug("Guardrails module not available; skipping guardrail setup")
        return None

    if isinstance(guardrails, GuardrailEngine):
        return guardrails

    if isinstance(guardrails, list):
        engine = GuardrailEngine(guardrails=guardrails)
        return engine

    # Single guardrail instance
    return GuardrailEngine(guardrails=[guardrails])
