"""Comprehensive tests for aegis.instrument._pydantic_ai.

Covers:
- _extract_input / _extract_output helpers
- _run_guardrails (no engine, no text, pass, block+raise, block+warn, engine exception)
- patch_pydantic_ai (mock Agent, idempotent, no-install fallback, Agent without run_sync)
- governed_run / governed_run_sync (async + sync wrappers with guardrail integration)
- unpatch_pydantic_ai (restore originals, no-op when not patched, ImportError path)

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

from aegis.instrument._state import InstrumentationState
from aegis.integrations.errors import AegisGuardrailError

# =========================================================================
# Helpers — fake pydantic_ai module
# =========================================================================


def _make_fake_agent_class(*, has_run_sync: bool = True) -> type:
    """Create a fake Agent class with async run and optional run_sync."""

    async def _run(self: Any, *args: Any, **kwargs: Any) -> Any:
        """Original async run — returns a fake RunResult."""

        @dataclass
        class RunResult:
            output: str = "original output"

        return RunResult()

    def _run_sync(self: Any, *args: Any, **kwargs: Any) -> Any:
        """Original sync run — returns a fake RunResult."""

        @dataclass
        class RunResult:
            output: str = "sync output"

        return RunResult()

    attrs: dict[str, Any] = {"run": _run}
    if has_run_sync:
        attrs["run_sync"] = _run_sync

    return type("Agent", (), attrs)


def _install_fake_pydantic_ai(*, has_run_sync: bool = True) -> type:
    """Inject a fake pydantic_ai module into sys.modules, return Agent class."""
    AgentClass = _make_fake_agent_class(has_run_sync=has_run_sync)
    mod = types.ModuleType("pydantic_ai")
    mod.Agent = AgentClass  # type: ignore[attr-defined]
    sys.modules["pydantic_ai"] = mod
    return AgentClass


def _remove_fake_pydantic_ai() -> None:
    sys.modules.pop("pydantic_ai", None)


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset module-level state and InstrumentationState between tests."""
    InstrumentationState.reset()

    import aegis.instrument._pydantic_ai as _pa

    _pa._patched = False
    _pa._originals.clear()

    yield

    # Teardown: unpatch, remove fake module, reset state
    _pa.unpatch_pydantic_ai()
    _pa._patched = False
    _pa._originals.clear()
    _remove_fake_pydantic_ai()
    InstrumentationState.reset()


@pytest.fixture()
def fake_agent_class():
    """Install fake pydantic_ai and return Agent class. Reload _pydantic_ai module."""
    AgentClass = _install_fake_pydantic_ai()
    importlib.reload(importlib.import_module("aegis.instrument._pydantic_ai"))
    return AgentClass


@pytest.fixture()
def fake_agent_class_no_run_sync():
    """Install fake pydantic_ai without run_sync and reload module."""
    AgentClass = _install_fake_pydantic_ai(has_run_sync=False)
    importlib.reload(importlib.import_module("aegis.instrument._pydantic_ai"))
    return AgentClass


def _make_guardrail_result(
    *, action: str = "blocked", details: str = "", guardrail_name: str = "test"
) -> Any:
    """Build a fake guardrail result object."""

    @dataclass
    class FakeGuardrailResult:
        action: str = "passed"
        details: str = ""
        guardrail_name: str = "unknown"

    return FakeGuardrailResult(action=action, details=details, guardrail_name=guardrail_name)


# =========================================================================
# _extract_input
# =========================================================================


class TestExtractInput:
    def test_positional_string(self):
        from aegis.instrument._pydantic_ai import _extract_input

        assert _extract_input(("hello world",), {}) == "hello world"

    def test_kwarg_user_prompt(self):
        from aegis.instrument._pydantic_ai import _extract_input

        assert _extract_input((), {"user_prompt": "from kwarg"}) == "from kwarg"

    def test_kwarg_takes_priority_over_positional(self):
        from aegis.instrument._pydantic_ai import _extract_input

        # user_prompt kwarg should take priority
        assert _extract_input(("positional",), {"user_prompt": "kwarg"}) == "kwarg"

    def test_empty_args_and_kwargs(self):
        from aegis.instrument._pydantic_ai import _extract_input

        assert _extract_input((), {}) == ""

    def test_non_string_prompt(self):
        from aegis.instrument._pydantic_ai import _extract_input

        assert _extract_input((42,), {}) == "42"

    def test_none_prompt_in_args(self):
        from aegis.instrument._pydantic_ai import _extract_input

        assert _extract_input((None,), {}) == ""

    def test_none_user_prompt_kwarg_falls_back_to_positional(self):
        from aegis.instrument._pydantic_ai import _extract_input

        # kwargs.get("user_prompt") returns None, so falls back to args[0]
        assert _extract_input(("fallback",), {"user_prompt": None}) == "fallback"

    def test_empty_string_user_prompt_falls_back(self):
        from aegis.instrument._pydantic_ai import _extract_input

        # "" is falsy, so falls back to args[0]
        assert _extract_input(("fallback",), {"user_prompt": ""}) == "fallback"

    def test_list_prompt(self):
        from aegis.instrument._pydantic_ai import _extract_input

        result = _extract_input(([{"role": "user", "content": "hi"}],), {})
        assert "hi" in result


# =========================================================================
# _extract_output
# =========================================================================


class TestExtractOutput:
    def test_output_attribute_string(self):
        from aegis.instrument._pydantic_ai import _extract_output

        @dataclass
        class RunResult:
            output: str = "result text"

        assert _extract_output(RunResult()) == "result text"

    def test_data_attribute_fallback(self):
        from aegis.instrument._pydantic_ai import _extract_output

        @dataclass
        class RunResult:
            data: str = "data text"

        assert _extract_output(RunResult()) == "data text"

    def test_output_takes_priority_over_data(self):
        from aegis.instrument._pydantic_ai import _extract_output

        @dataclass
        class RunResult:
            output: str = "output wins"
            data: str = "data loses"

        assert _extract_output(RunResult()) == "output wins"

    def test_no_output_or_data(self):
        from aegis.instrument._pydantic_ai import _extract_output

        assert _extract_output(object()) == ""

    def test_non_string_output_returns_empty(self):
        from aegis.instrument._pydantic_ai import _extract_output

        @dataclass
        class RunResult:
            output: int = 42

        assert _extract_output(RunResult()) == ""

    def test_none_result(self):
        from aegis.instrument._pydantic_ai import _extract_output

        assert _extract_output(None) == ""

    def test_output_none_data_string(self):
        from aegis.instrument._pydantic_ai import _extract_output

        @dataclass
        class RunResult:
            output: None = None
            data: str = "fallback data"

        assert _extract_output(RunResult()) == "fallback data"

    def test_output_none_data_none(self):
        from aegis.instrument._pydantic_ai import _extract_output

        @dataclass
        class RunResult:
            output: None = None
            data: None = None

        assert _extract_output(RunResult()) == ""


# =========================================================================
# _run_guardrails
# =========================================================================


class TestRunGuardrails:
    def test_no_engine_returns_none(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        # Should not raise
        _run_guardrails(None, "some text", direction="input", on_block="raise")

    def test_empty_text_returns_none(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        _run_guardrails(engine, "", direction="input", on_block="raise")
        engine.check.assert_not_called()

    def test_no_blocked_results(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="passed")]
        # Should not raise
        _run_guardrails(engine, "hello", direction="input", on_block="raise")

    def test_blocked_with_raise(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        engine.check.return_value = [
            _make_guardrail_result(action="blocked", details="injection detected")
        ]
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            _run_guardrails(engine, "bad input", direction="input", on_block="raise")

    def test_blocked_with_warn(self, caplog):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="blocked", details="pii found")]
        with caplog.at_level("WARNING", logger="aegis.instrument.pydantic_ai"):
            _run_guardrails(engine, "bad input", direction="output", on_block="warn")
        assert "Aegis blocked output" in caplog.text

    def test_blocked_details_from_guardrail_name(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        # details is empty string, should fall back to guardrail_name
        engine.check.return_value = [
            _make_guardrail_result(action="blocked", details="", guardrail_name="injection")
        ]
        with pytest.raises(AegisGuardrailError, match="injection"):
            _run_guardrails(engine, "bad", direction="input", on_block="raise")

    def test_multiple_blocked_results(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        engine.check.return_value = [
            _make_guardrail_result(action="blocked", details="injection"),
            _make_guardrail_result(action="passed"),
            _make_guardrail_result(action="blocked", details="pii"),
        ]
        with pytest.raises(AegisGuardrailError, match="injection; pii"):
            _run_guardrails(engine, "bad", direction="input", on_block="raise")

    def test_engine_check_exception_swallowed(self, caplog):
        from aegis.instrument._pydantic_ai import _run_guardrails

        engine = MagicMock()
        engine.check.side_effect = RuntimeError("engine boom")
        with caplog.at_level("DEBUG", logger="aegis.instrument.pydantic_ai"):
            # Should not raise
            _run_guardrails(engine, "text", direction="input", on_block="raise")
        assert "Guardrail check failed" in caplog.text

    def test_blocked_error_has_guardrail_results(self):
        from aegis.instrument._pydantic_ai import _run_guardrails

        blocked_result = _make_guardrail_result(action="blocked", details="bad")
        engine = MagicMock()
        engine.check.return_value = [blocked_result]
        with pytest.raises(AegisGuardrailError) as exc_info:
            _run_guardrails(engine, "text", direction="input", on_block="raise")
        assert exc_info.value.guardrail_results == [blocked_result]


# =========================================================================
# patch_pydantic_ai
# =========================================================================


class TestPatchPydanticAi:
    def test_patch_success(self, fake_agent_class):
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        result = patch_pydantic_ai()
        assert result.patched is True
        assert result.name == "pydantic_ai"
        assert "Agent.run" in result.targets
        assert "Agent.run_sync" in result.targets

    def test_patch_registers_with_state(self, fake_agent_class):
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        patch_pydantic_ai()
        state = InstrumentationState.get()
        assert state.is_patched("pydantic_ai")

    def test_patch_idempotent(self, fake_agent_class):
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        r1 = patch_pydantic_ai()
        r2 = patch_pydantic_ai()
        assert r1.patched is True
        assert r2.patched is True
        assert r1.targets == r2.targets

    def test_patch_without_pydantic_ai_installed(self):
        """When pydantic_ai is not importable, patch returns not-patched."""
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        result = patch_pydantic_ai()
        assert result.patched is False
        assert result.error == "pydantic-ai not installed"

    def test_patch_registers_even_on_failure(self):
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        patch_pydantic_ai()
        state = InstrumentationState.get()
        p = state.get_patch("pydantic_ai")
        assert p is not None
        assert p.patched is False

    def test_patch_agent_without_run_sync(self, fake_agent_class_no_run_sync):
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        result = patch_pydantic_ai()
        assert result.patched is True
        assert "Agent.run" in result.targets
        assert "Agent.run_sync" not in result.targets

    def test_patch_logs_info(self, fake_agent_class, caplog):
        from aegis.instrument._pydantic_ai import patch_pydantic_ai

        with caplog.at_level("INFO", logger="aegis.instrument.pydantic_ai"):
            patch_pydantic_ai()
        assert "Pydantic AI instrumented" in caplog.text


# =========================================================================
# unpatch_pydantic_ai
# =========================================================================


class TestUnpatchPydanticAi:
    def test_unpatch_restores_originals(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        original_run = fake_agent_class.run
        original_run_sync = fake_agent_class.run_sync

        _pa.patch_pydantic_ai()
        # After patching, methods should be different
        assert fake_agent_class.run is not original_run

        _pa.unpatch_pydantic_ai()
        # After unpatching, methods should be restored
        assert fake_agent_class.run is original_run
        assert fake_agent_class.run_sync is original_run_sync
        assert _pa._patched is False
        assert len(_pa._originals) == 0

    def test_unpatch_noop_when_not_patched(self):
        import aegis.instrument._pydantic_ai as _pa

        # Should not raise
        _pa.unpatch_pydantic_ai()
        assert _pa._patched is False

    def test_unpatch_logs_info(self, fake_agent_class, caplog):
        import aegis.instrument._pydantic_ai as _pa

        _pa.patch_pydantic_ai()
        with caplog.at_level("INFO", logger="aegis.instrument.pydantic_ai"):
            _pa.unpatch_pydantic_ai()
        assert "Pydantic AI unpatched" in caplog.text

    def test_unpatch_clears_originals(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        _pa.patch_pydantic_ai()
        assert len(_pa._originals) > 0
        _pa.unpatch_pydantic_ai()
        assert len(_pa._originals) == 0

    def test_unpatch_when_import_fails(self):
        """If pydantic_ai was patched but module disappeared, unpatch handles ImportError."""
        import aegis.instrument._pydantic_ai as _pa

        # Simulate: was patched but module is now gone
        _pa._patched = True
        _pa._originals["Agent.run"] = lambda: None
        _remove_fake_pydantic_ai()

        # Should not raise
        _pa.unpatch_pydantic_ai()
        assert _pa._patched is False
        assert len(_pa._originals) == 0


# =========================================================================
# governed_run (async wrapper)
# =========================================================================


class TestGovernedRun:
    def test_governed_run_no_guardrails(self, fake_agent_class):
        """governed_run passes through to original when no engine configured."""
        import aegis.instrument._pydantic_ai as _pa

        _pa.patch_pydantic_ai()

        agent = fake_agent_class()
        result = asyncio.get_event_loop().run_until_complete(agent.run("hello"))
        assert result.output == "original output"

    def test_governed_run_with_passing_guardrails(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="passed")]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        result = asyncio.get_event_loop().run_until_complete(agent.run("hello"))
        assert result.output == "original output"
        # Engine was called for both input and output
        assert engine.check.call_count == 2

    def test_governed_run_blocks_on_input(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="blocked", details="injection")]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            asyncio.get_event_loop().run_until_complete(agent.run("bad input"))

    def test_governed_run_blocks_on_output(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        call_count = 0

        def check_side_effect(text: str) -> list:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Input check passes
                return [_make_guardrail_result(action="passed")]
            else:
                # Output check blocks
                return [_make_guardrail_result(action="blocked", details="pii")]

        engine = MagicMock()
        engine.check.side_effect = check_side_effect

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked output"):
            asyncio.get_event_loop().run_until_complete(agent.run("hello"))

    def test_governed_run_with_user_prompt_kwarg(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = []

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        asyncio.get_event_loop().run_until_complete(agent.run(user_prompt="hello via kwarg"))
        # The first call should have been with "hello via kwarg"
        engine.check.assert_any_call("hello via kwarg")

    def test_governed_run_warn_mode(self, fake_agent_class, caplog):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = [
            _make_guardrail_result(action="blocked", details="warning test")
        ]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="warn")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        with caplog.at_level("WARNING", logger="aegis.instrument.pydantic_ai"):
            result = asyncio.get_event_loop().run_until_complete(agent.run("hello"))
        # Should not raise, result should be returned
        assert result.output == "original output"
        assert "Aegis blocked" in caplog.text


# =========================================================================
# governed_run_sync (sync wrapper)
# =========================================================================


class TestGovernedRunSync:
    def test_governed_run_sync_no_guardrails(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        result = agent.run_sync("hello")
        assert result.output == "sync output"

    def test_governed_run_sync_with_passing_guardrails(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="passed")]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        result = agent.run_sync("hello")
        assert result.output == "sync output"
        assert engine.check.call_count == 2

    def test_governed_run_sync_blocks_on_input(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="blocked", details="injection")]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            agent.run_sync("bad input")

    def test_governed_run_sync_blocks_on_output(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        call_count = 0

        def check_side_effect(text: str) -> list:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [_make_guardrail_result(action="passed")]
            else:
                return [_make_guardrail_result(action="blocked", details="pii")]

        engine = MagicMock()
        engine.check.side_effect = check_side_effect

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked output"):
            agent.run_sync("hello")

    def test_governed_run_sync_warn_mode(self, fake_agent_class, caplog):
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()
        engine.check.return_value = [_make_guardrail_result(action="blocked", details="warn test")]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="warn")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        with caplog.at_level("WARNING", logger="aegis.instrument.pydantic_ai"):
            result = agent.run_sync("hello")
        assert result.output == "sync output"
        assert "Aegis blocked" in caplog.text

    def test_governed_run_sync_empty_input(self, fake_agent_class):
        """Empty input should skip guardrail check."""
        import aegis.instrument._pydantic_ai as _pa

        engine = MagicMock()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        _pa.patch_pydantic_ai()
        agent = fake_agent_class()
        result = agent.run_sync()
        assert result.output == "sync output"
        # Engine check is only called for output (if output is non-empty)
        # But our fake returns "sync output" which is non-empty
        # Input is empty so skipped; output is a str attribute so _extract_output
        # returns "sync output" → check is called once for that
        assert engine.check.call_count == 1


# =========================================================================
# Edge cases — patch / unpatch cycles
# =========================================================================


class TestPatchUnpatchCycles:
    def test_patch_unpatch_patch(self, fake_agent_class):
        """Can re-patch after unpatching."""
        import aegis.instrument._pydantic_ai as _pa

        r1 = _pa.patch_pydantic_ai()
        assert r1.patched is True

        _pa.unpatch_pydantic_ai()
        assert _pa._patched is False

        r2 = _pa.patch_pydantic_ai()
        assert r2.patched is True
        assert "Agent.run" in r2.targets

    def test_multiple_unpatch_calls_safe(self, fake_agent_class):
        import aegis.instrument._pydantic_ai as _pa

        _pa.patch_pydantic_ai()
        _pa.unpatch_pydantic_ai()
        # Second unpatch should be a no-op
        _pa.unpatch_pydantic_ai()
        assert _pa._patched is False
