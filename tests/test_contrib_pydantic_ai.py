"""Tests for aegis.contrib.pydantic_ai — native AegisCapability.

Covers:
- Construction and repr
- Serialization name and from_spec factory
- _extract_user_text / _extract_response_text helpers
- _run_guardrails (pass, block+raise, block+warn, engine exception)
- before_model_request / after_model_request lifecycle hooks
- check_input / check_output flags
- Base class resolution (with and without pydantic-ai installed)

All Pydantic AI dependencies are faked via sys.modules injection.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import types
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis.integrations.errors import AegisGuardrailError

# =========================================================================
# Helpers — fake pydantic_ai module
# =========================================================================


class _FakeAbstractCapability:
    """Stand-in for pydantic_ai.capabilities.AbstractCapability."""

    pass


def _install_fake_pydantic_ai() -> None:
    """Inject fake pydantic_ai and pydantic_ai.capabilities modules."""
    cap_mod = types.ModuleType("pydantic_ai.capabilities")
    cap_mod.AbstractCapability = _FakeAbstractCapability  # type: ignore[attr-defined]

    pai_mod = types.ModuleType("pydantic_ai")
    pai_mod.capabilities = cap_mod  # type: ignore[attr-defined]

    sys.modules["pydantic_ai"] = pai_mod
    sys.modules["pydantic_ai.capabilities"] = cap_mod


def _remove_fake_pydantic_ai() -> None:
    sys.modules.pop("pydantic_ai", None)
    sys.modules.pop("pydantic_ai.capabilities", None)


# =========================================================================
# Fake message types
# =========================================================================


@dataclass
class FakeUserPromptPart:
    content: str
    part_kind: str = "user-prompt"


@dataclass
class FakeSystemPromptPart:
    content: str
    part_kind: str = "system-prompt"


@dataclass
class FakeTextPart:
    content: str
    part_kind: str = "text"


@dataclass
class FakeToolCallPart:
    name: str = "some_tool"
    part_kind: str = "tool-call"


@dataclass
class FakeMessage:
    parts: list[Any]


@dataclass
class FakeRequestContext:
    messages: list[Any]


@dataclass
class FakeModelResponse:
    parts: list[Any]
    text: str | None = None


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _fake_pydantic_ai():
    """Install fake pydantic_ai for every test, clean up after."""
    _install_fake_pydantic_ai()
    # Ensure a fresh import of the module under test
    sys.modules.pop("aegis.contrib.pydantic_ai", None)
    yield
    _remove_fake_pydantic_ai()
    sys.modules.pop("aegis.contrib.pydantic_ai", None)


def _make_engine(*, action: str = "allowed", details: str = "") -> MagicMock:
    """Create a mock GuardrailEngine returning a single result."""

    @dataclass
    class FakeResult:
        passed: bool
        guardrail_name: str
        action: str
        details: str | None

    engine = MagicMock()
    engine.check.return_value = [
        FakeResult(
            passed=action == "allowed",
            guardrail_name="test_guard",
            action=action,
            details=details or None,
        )
    ]
    return engine


def _import_capability() -> type:
    """Import and return AegisCapability (forces fresh module load)."""
    mod = importlib.import_module("aegis.contrib.pydantic_ai")
    return mod.AegisCapability


# =========================================================================
# Construction
# =========================================================================


class TestConstruction:
    def test_basic_construction(self) -> None:
        cls = _import_capability()
        engine = MagicMock()
        cap = cls(engine)
        assert cap.engine is engine
        assert cap.on_block == "raise"
        assert cap.check_input is True
        assert cap.check_output is True

    def test_custom_params(self) -> None:
        cls = _import_capability()
        engine = MagicMock()
        cap = cls(engine, on_block="warn", check_input=False, check_output=False)
        assert cap.on_block == "warn"
        assert cap.check_input is False
        assert cap.check_output is False

    def test_repr(self) -> None:
        cls = _import_capability()
        cap = cls(MagicMock(), on_block="warn")
        r = repr(cap)
        assert "AegisCapability" in r
        assert "warn" in r

    def test_is_abstract_capability_subclass(self) -> None:
        cls = _import_capability()
        cap = cls(MagicMock())
        assert isinstance(cap, _FakeAbstractCapability)

    def test_serialization_name(self) -> None:
        cls = _import_capability()
        assert cls.get_serialization_name() == "Aegis"


class TestFromSpec:
    def test_from_spec_creates_engine(self) -> None:
        cls = _import_capability()
        cap = cls.from_spec()
        assert cap.engine is not None
        assert cap.on_block == "raise"

    def test_from_spec_custom_params(self) -> None:
        cls = _import_capability()
        cap = cls.from_spec(on_block="warn", check_input=False)
        assert cap.on_block == "warn"
        assert cap.check_input is False


# =========================================================================
# _extract_user_text
# =========================================================================


class TestExtractUserText:
    def test_single_user_prompt(self) -> None:
        cls = _import_capability()
        ctx = FakeRequestContext(messages=[FakeMessage(parts=[FakeUserPromptPart("hello")])])
        assert cls._extract_user_text(ctx) == "hello"

    def test_multiple_user_prompts(self) -> None:
        cls = _import_capability()
        ctx = FakeRequestContext(
            messages=[
                FakeMessage(parts=[FakeUserPromptPart("one")]),
                FakeMessage(parts=[FakeUserPromptPart("two")]),
            ]
        )
        assert cls._extract_user_text(ctx) == "one\ntwo"

    def test_ignores_system_prompt(self) -> None:
        cls = _import_capability()
        ctx = FakeRequestContext(
            messages=[
                FakeMessage(
                    parts=[
                        FakeSystemPromptPart("system"),
                        FakeUserPromptPart("user"),
                    ]
                )
            ]
        )
        assert cls._extract_user_text(ctx) == "user"

    def test_empty_messages(self) -> None:
        cls = _import_capability()
        ctx = FakeRequestContext(messages=[])
        assert cls._extract_user_text(ctx) == ""

    def test_no_messages_attr(self) -> None:
        cls = _import_capability()
        assert cls._extract_user_text(object()) == ""

    def test_no_parts_attr(self) -> None:
        cls = _import_capability()
        msg = MagicMock(spec=[])  # no .parts attribute
        ctx = FakeRequestContext(messages=[msg])
        assert cls._extract_user_text(ctx) == ""

    def test_non_string_content(self) -> None:
        cls = _import_capability()

        @dataclass
        class WeirdPart:
            content: int = 42
            part_kind: str = "user-prompt"

        ctx = FakeRequestContext(messages=[FakeMessage(parts=[WeirdPart()])])
        assert cls._extract_user_text(ctx) == ""


# =========================================================================
# _extract_response_text
# =========================================================================


class TestExtractResponseText:
    def test_text_property(self) -> None:
        cls = _import_capability()
        resp = FakeModelResponse(parts=[], text="hello from model")
        assert cls._extract_response_text(resp) == "hello from model"

    def test_text_parts_fallback(self) -> None:
        cls = _import_capability()
        resp = FakeModelResponse(
            parts=[FakeTextPart("part1"), FakeTextPart("part2")],
            text=None,
        )
        assert cls._extract_response_text(resp) == "part1\npart2"

    def test_ignores_tool_call_parts(self) -> None:
        cls = _import_capability()
        resp = FakeModelResponse(
            parts=[FakeToolCallPart(), FakeTextPart("text")],
            text=None,
        )
        assert cls._extract_response_text(resp) == "text"

    def test_empty_response(self) -> None:
        cls = _import_capability()
        resp = FakeModelResponse(parts=[], text=None)
        assert cls._extract_response_text(resp) == ""

    def test_no_parts_attr(self) -> None:
        cls = _import_capability()
        assert cls._extract_response_text(object()) == ""

    def test_empty_text_property_uses_parts(self) -> None:
        cls = _import_capability()
        resp = FakeModelResponse(
            parts=[FakeTextPart("fallback")],
            text="",
        )
        assert cls._extract_response_text(resp) == "fallback"


# =========================================================================
# _run_guardrails
# =========================================================================


class TestRunGuardrails:
    def test_pass(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="allowed")
        cap = cls(engine)
        # Should not raise
        cap._run_guardrails("hello", direction="input")

    def test_block_raises(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked", details="injection detected")
        cap = cls(engine, on_block="raise")
        with pytest.raises(AegisGuardrailError, match="injection detected"):
            cap._run_guardrails("bad input", direction="input")

    def test_block_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked", details="pii found")
        cap = cls(engine, on_block="warn")
        with caplog.at_level("WARNING", logger="aegis.contrib.pydantic_ai"):
            cap._run_guardrails("has pii", direction="output")
        assert "Aegis blocked output" in caplog.text

    def test_engine_exception_swallowed(self) -> None:
        cls = _import_capability()
        engine = MagicMock()
        engine.check.side_effect = RuntimeError("boom")
        cap = cls(engine)
        # Should not raise
        cap._run_guardrails("text", direction="input")

    def test_blocked_with_guardrail_name_fallback(self) -> None:
        cls = _import_capability()

        @dataclass
        class NoDetailsResult:
            passed: bool = False
            guardrail_name: str = "injection_guard"
            action: str = "blocked"
            details: str | None = None

        engine = MagicMock()
        engine.check.return_value = [NoDetailsResult()]
        cap = cls(engine, on_block="raise")
        with pytest.raises(AegisGuardrailError, match="injection_guard"):
            cap._run_guardrails("bad", direction="input")


# =========================================================================
# before_model_request
# =========================================================================


class TestBeforeModelRequest:
    def test_checks_input(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked")
        cap = cls(engine)
        ctx = FakeRequestContext(messages=[FakeMessage(parts=[FakeUserPromptPart("bad input")])])
        with pytest.raises(AegisGuardrailError):
            asyncio.run(cap.before_model_request(MagicMock(), ctx))

    def test_passes_clean_input(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="allowed")
        cap = cls(engine)
        ctx = FakeRequestContext(messages=[FakeMessage(parts=[FakeUserPromptPart("hello")])])
        result = asyncio.run(cap.before_model_request(MagicMock(), ctx))
        assert result is ctx

    def test_skip_when_check_input_false(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked")
        cap = cls(engine, check_input=False)
        ctx = FakeRequestContext(messages=[FakeMessage(parts=[FakeUserPromptPart("bad")])])
        result = asyncio.run(cap.before_model_request(MagicMock(), ctx))
        assert result is ctx
        engine.check.assert_not_called()

    def test_skip_empty_text(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked")
        cap = cls(engine)
        ctx = FakeRequestContext(messages=[])
        result = asyncio.run(cap.before_model_request(MagicMock(), ctx))
        assert result is ctx
        engine.check.assert_not_called()


# =========================================================================
# after_model_request
# =========================================================================


class TestAfterModelRequest:
    def test_checks_output(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked")
        cap = cls(engine)
        resp = FakeModelResponse(parts=[FakeTextPart("bad output")], text="bad output")
        with pytest.raises(AegisGuardrailError):
            asyncio.run(
                cap.after_model_request(MagicMock(), request_context=MagicMock(), response=resp)
            )

    def test_passes_clean_output(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="allowed")
        cap = cls(engine)
        resp = FakeModelResponse(parts=[FakeTextPart("ok")], text="ok")
        result = asyncio.run(
            cap.after_model_request(MagicMock(), request_context=MagicMock(), response=resp)
        )
        assert result is resp

    def test_skip_when_check_output_false(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked")
        cap = cls(engine, check_output=False)
        resp = FakeModelResponse(parts=[FakeTextPart("bad")], text="bad")
        result = asyncio.run(
            cap.after_model_request(MagicMock(), request_context=MagicMock(), response=resp)
        )
        assert result is resp
        engine.check.assert_not_called()

    def test_skip_empty_response(self) -> None:
        cls = _import_capability()
        engine = _make_engine(action="blocked")
        cap = cls(engine)
        resp = FakeModelResponse(parts=[], text=None)
        result = asyncio.run(
            cap.after_model_request(MagicMock(), request_context=MagicMock(), response=resp)
        )
        assert result is resp
        engine.check.assert_not_called()


# =========================================================================
# Without pydantic-ai installed
# =========================================================================


class TestWithoutPydanticAI:
    def test_base_class_is_object(self) -> None:
        """When pydantic-ai is not installed, AegisCapability inherits from object."""
        _remove_fake_pydantic_ai()
        sys.modules.pop("aegis.contrib.pydantic_ai", None)
        cls = _import_capability()
        # Should NOT be a subclass of our fake AbstractCapability
        assert not issubclass(cls, _FakeAbstractCapability)
        # But the class itself should still be importable and usable
        # (it just won't pass isinstance checks in pydantic-ai)
        assert cls.get_serialization_name() == "Aegis"
