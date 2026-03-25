"""Comprehensive tests for aegis.instrument._dspy module.

Covers extraction helpers, guardrail runner, patch/unpatch lifecycle,
governed wrappers for LM.forward, LM.aforward, and Module.__call__,
idempotent patching, and edge cases.

All DSPy dependencies are faked via sys.modules injection.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import types
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from aegis.instrument._state import FrameworkPatch, InstrumentationState
from aegis.integrations.errors import AegisGuardrailError

# =========================================================================
# Helpers: fake DSPy modules
# =========================================================================


def _make_lm_class(*, has_aforward: bool = True):
    """Create a fake LM class with forward and optionally aforward."""

    def forward(self, *args, **kwargs):
        return [{"text": "lm_output"}]

    async def aforward(self, *args, **kwargs):
        return [{"text": "lm_async_output"}]

    attrs: dict[str, Any] = {"forward": forward}
    if has_aforward:
        attrs["aforward"] = aforward
    return type("LM", (), attrs)


def _make_module_class():
    """Create a fake Module class with __call__."""

    def __call__(self, *args, **kwargs):
        return "prediction_result"

    return type("Module", (), {"__call__": __call__})


def _install_fake_dspy(*, has_aforward: bool = True):
    """Inject fake dspy modules into sys.modules and return classes."""
    LMClass = _make_lm_class(has_aforward=has_aforward)
    ModuleClass = _make_module_class()

    lm_mod = types.ModuleType("dspy.clients.lm")
    lm_mod.LM = LMClass

    clients_mod = types.ModuleType("dspy.clients")
    clients_mod.lm = lm_mod

    dspy_mod = types.ModuleType("dspy")
    dspy_mod.Module = ModuleClass
    dspy_mod.clients = clients_mod

    sys.modules["dspy"] = dspy_mod
    sys.modules["dspy.clients"] = clients_mod
    sys.modules["dspy.clients.lm"] = lm_mod

    return LMClass, ModuleClass


def _remove_fake_dspy():
    """Remove fake dspy modules from sys.modules."""
    for k in list(sys.modules.keys()):
        if k.startswith("dspy"):
            sys.modules.pop(k, None)


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset instrumentation state and module-level flags before each test."""
    InstrumentationState.reset()

    import aegis.instrument._dspy as _ds

    _ds._patched = False
    _ds._originals.clear()

    yield

    # Teardown: unpatch and clean up
    import aegis.instrument._dspy as _ds2

    _ds2.unpatch_dspy()
    _ds2._patched = False
    _ds2._originals.clear()
    _remove_fake_dspy()
    InstrumentationState.reset()


@pytest.fixture()
def fake_dspy():
    """Install fake dspy and reload the _dspy module so imports resolve."""
    LMClass, ModuleClass = _install_fake_dspy()
    import aegis.instrument._dspy as _ds

    importlib.reload(_ds)
    yield LMClass, ModuleClass


@pytest.fixture()
def fake_dspy_no_aforward():
    """Install fake dspy without LM.aforward."""
    LMClass, ModuleClass = _install_fake_dspy(has_aforward=False)
    import aegis.instrument._dspy as _ds

    importlib.reload(_ds)
    yield LMClass, ModuleClass


# =========================================================================
# _extract_lm_input
# =========================================================================


class TestExtractLmInput:
    """Tests for _extract_lm_input."""

    def test_prompt_string(self):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({"prompt": "Hello DSPy"}) == "Hello DSPy"

    def test_prompt_empty_string_falls_through(self):
        from aegis.instrument._dspy import _extract_lm_input

        # Empty prompt falls through to messages
        result = _extract_lm_input({"prompt": "", "messages": [{"content": "msg"}]})
        assert result == "msg"

    def test_prompt_non_string_falls_through(self):
        from aegis.instrument._dspy import _extract_lm_input

        result = _extract_lm_input({"prompt": 123, "messages": [{"content": "msg"}]})
        assert result == "msg"

    def test_messages_list_of_dicts(self):
        from aegis.instrument._dspy import _extract_lm_input

        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "What is AI?"},
        ]
        result = _extract_lm_input({"messages": messages})
        assert "You are helpful." in result
        assert "What is AI?" in result

    def test_messages_with_non_string_content(self):
        from aegis.instrument._dspy import _extract_lm_input

        messages = [{"content": 42}, {"content": "valid"}]
        result = _extract_lm_input({"messages": messages})
        assert result == "valid"

    def test_messages_with_non_dict_items(self):
        from aegis.instrument._dspy import _extract_lm_input

        messages = ["not a dict", {"content": "ok"}]
        result = _extract_lm_input({"messages": messages})
        assert result == "ok"

    def test_messages_empty_list(self):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({"messages": []}) == ""

    def test_messages_not_a_list(self):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({"messages": "not a list"}) == ""

    def test_empty_kwargs(self):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({}) == ""

    def test_no_prompt_no_messages(self):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({"other": "value"}) == ""

    def test_messages_missing_content_key(self):
        from aegis.instrument._dspy import _extract_lm_input

        result = _extract_lm_input({"messages": [{"role": "user"}]})
        assert result == ""


# =========================================================================
# _extract_lm_output
# =========================================================================


class TestExtractLmOutput:
    """Tests for _extract_lm_output."""

    def test_list_with_dict_text_key(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output([{"text": "response"}]) == "response"

    def test_list_with_dict_content_key(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output([{"content": "answer"}]) == "answer"

    def test_list_with_dict_text_preferred_over_content(self):
        from aegis.instrument._dspy import _extract_lm_output

        # text is checked first via `or` — if text is truthy, content is ignored
        assert _extract_lm_output([{"text": "A", "content": "B"}]) == "A"

    def test_list_with_dict_text_empty_falls_to_content(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output([{"text": "", "content": "fallback"}]) == "fallback"

    def test_list_with_dict_neither_key(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output([{"other": "val"}]) == ""

    def test_list_with_string_first(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output(["plain text"]) == "plain text"

    def test_list_with_non_dict_non_string(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output([42]) == ""

    def test_empty_list(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output([]) == ""

    def test_string_result(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output("direct string") == "direct string"

    def test_none_result(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output(None) == ""

    def test_dict_result_not_list(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output({"text": "val"}) == ""

    def test_int_result(self):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output(42) == ""


# =========================================================================
# _extract_module_input
# =========================================================================


class TestExtractModuleInput:
    """Tests for _extract_module_input."""

    def test_string_values_joined(self):
        from aegis.instrument._dspy import _extract_module_input

        result = _extract_module_input({"question": "What?", "context": "Some context"})
        assert "What?" in result
        assert "Some context" in result

    def test_non_string_values_skipped(self):
        from aegis.instrument._dspy import _extract_module_input

        result = _extract_module_input({"num": 42, "text": "hello", "flag": True})
        assert result == "hello"

    def test_empty_kwargs(self):
        from aegis.instrument._dspy import _extract_module_input

        assert _extract_module_input({}) == ""

    def test_all_non_string(self):
        from aegis.instrument._dspy import _extract_module_input

        assert _extract_module_input({"a": 1, "b": [1, 2]}) == ""


# =========================================================================
# _extract_module_output
# =========================================================================


class TestExtractModuleOutput:
    """Tests for _extract_module_output."""

    def test_prediction_with_toDict(self):
        from aegis.instrument._dspy import _extract_module_output

        class FakePrediction:
            def toDict(self):
                return {"answer": "42", "reasoning": "because"}

        result = _extract_module_output(FakePrediction())
        assert "42" in result
        assert "because" in result

    def test_prediction_toDict_non_string_values(self):
        from aegis.instrument._dspy import _extract_module_output

        class FakePrediction:
            def toDict(self):
                return {"num": 42, "flag": True}

        # No string values, empty result
        assert _extract_module_output(FakePrediction()) == ""

    def test_prediction_toDict_empty(self):
        from aegis.instrument._dspy import _extract_module_output

        class FakePrediction:
            def toDict(self):
                return {}

        assert _extract_module_output(FakePrediction()) == ""

    def test_string_result(self):
        from aegis.instrument._dspy import _extract_module_output

        assert _extract_module_output("plain result") == "plain result"

    def test_none_result(self):
        from aegis.instrument._dspy import _extract_module_output

        assert _extract_module_output(None) == ""

    def test_int_result(self):
        from aegis.instrument._dspy import _extract_module_output

        assert _extract_module_output(123) == ""


# =========================================================================
# _run_guardrails
# =========================================================================


class TestRunGuardrails:
    """Tests for _run_guardrails."""

    def test_none_engine_no_op(self):
        from aegis.instrument._dspy import _run_guardrails

        # Should not raise
        _run_guardrails(None, "text", direction="input", on_block="raise")

    def test_empty_text_no_op(self):
        from aegis.instrument._dspy import _run_guardrails

        engine = MagicMock()
        _run_guardrails(engine, "", direction="input", on_block="raise")
        engine.check.assert_not_called()

    def test_no_blocked_results(self):
        from aegis.instrument._dspy import _run_guardrails

        result_obj = MagicMock()
        result_obj.action = "allowed"
        engine = MagicMock()
        engine.check.return_value = [result_obj]

        # Should not raise
        _run_guardrails(engine, "safe text", direction="input", on_block="raise")

    def test_blocked_with_raise(self):
        from aegis.instrument._dspy import _run_guardrails

        result_obj = MagicMock()
        result_obj.action = "blocked"
        result_obj.details = "injection detected"
        engine = MagicMock()
        engine.check.return_value = [result_obj]

        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            _run_guardrails(engine, "bad text", direction="input", on_block="raise")

    def test_blocked_with_warn(self):
        from aegis.instrument._dspy import _run_guardrails

        result_obj = MagicMock()
        result_obj.action = "blocked"
        result_obj.details = "pii found"
        engine = MagicMock()
        engine.check.return_value = [result_obj]

        # Should not raise when on_block="warn"
        _run_guardrails(engine, "bad text", direction="input", on_block="warn")

    def test_blocked_details_fallback_to_guardrail_name(self):
        from aegis.instrument._dspy import _run_guardrails

        result_obj = MagicMock()
        result_obj.action = "blocked"
        result_obj.details = ""
        result_obj.guardrail_name = "injection_guard"
        engine = MagicMock()
        engine.check.return_value = [result_obj]

        with pytest.raises(AegisGuardrailError, match="injection_guard"):
            _run_guardrails(engine, "text", direction="test", on_block="raise")

    def test_blocked_no_details_no_guardrail_name(self):
        from aegis.instrument._dspy import _run_guardrails

        result_obj = MagicMock(spec=[])
        result_obj.action = "blocked"
        # No details or guardrail_name attributes → getattr defaults
        engine = MagicMock()
        engine.check.return_value = [result_obj]

        with pytest.raises(AegisGuardrailError, match="unknown"):
            _run_guardrails(engine, "text", direction="test", on_block="raise")

    def test_engine_check_exception_handled(self):
        from aegis.instrument._dspy import _run_guardrails

        engine = MagicMock()
        engine.check.side_effect = RuntimeError("engine broke")

        # Should not raise — exception is caught and logged
        _run_guardrails(engine, "text", direction="input", on_block="raise")

    def test_multiple_blocked_results(self):
        from aegis.instrument._dspy import _run_guardrails

        r1 = MagicMock()
        r1.action = "blocked"
        r1.details = "reason1"
        r2 = MagicMock()
        r2.action = "blocked"
        r2.details = "reason2"
        engine = MagicMock()
        engine.check.return_value = [r1, r2]

        with pytest.raises(AegisGuardrailError, match="reason1.*reason2"):
            _run_guardrails(engine, "text", direction="input", on_block="raise")

    def test_mixed_blocked_and_allowed(self):
        from aegis.instrument._dspy import _run_guardrails

        r_ok = MagicMock()
        r_ok.action = "allowed"
        r_blocked = MagicMock()
        r_blocked.action = "blocked"
        r_blocked.details = "bad content"
        engine = MagicMock()
        engine.check.return_value = [r_ok, r_blocked]

        with pytest.raises(AegisGuardrailError):
            _run_guardrails(engine, "text", direction="input", on_block="raise")


# =========================================================================
# patch_dspy / unpatch_dspy lifecycle
# =========================================================================


class TestPatchDspy:
    """Tests for patch_dspy and unpatch_dspy."""

    def test_patch_success(self, fake_dspy):
        import aegis.instrument._dspy as _ds

        result = _ds.patch_dspy()
        assert result.patched is True
        assert result.name == "dspy"
        assert "LM.forward" in result.targets
        assert "LM.aforward" in result.targets
        assert "Module.__call__" in result.targets

    def test_patch_without_aforward(self, fake_dspy_no_aforward):
        import aegis.instrument._dspy as _ds

        result = _ds.patch_dspy()
        assert result.patched is True
        assert "LM.forward" in result.targets
        assert "LM.aforward" not in result.targets
        assert "Module.__call__" in result.targets

    def test_patch_idempotent(self, fake_dspy):
        import aegis.instrument._dspy as _ds

        r1 = _ds.patch_dspy()
        r2 = _ds.patch_dspy()
        assert r1.patched is True
        assert r2.patched is True
        # Both should have the same targets
        assert set(r1.targets) == set(r2.targets)

    def test_patch_without_dspy_installed(self):
        """When dspy is not in sys.modules, patch returns not-patched."""
        _remove_fake_dspy()
        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)
        result = _ds.patch_dspy()
        assert result.patched is False
        assert result.error == "dspy not installed"

    def test_patch_registers_with_state(self, fake_dspy):
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        s = InstrumentationState.get()
        assert s.is_patched("dspy")

    def test_patch_not_installed_registers_with_state(self):
        _remove_fake_dspy()
        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)
        _ds.patch_dspy()
        s = InstrumentationState.get()
        p = s.get_patch("dspy")
        assert p is not None
        assert p.patched is False

    def test_unpatch_restores_originals(self, fake_dspy):
        LMClass, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        original_forward = LMClass.forward
        original_aforward = LMClass.aforward
        original_call = ModuleClass.__call__

        _ds.patch_dspy()

        # After patching, methods should be different
        assert LMClass.forward is not original_forward
        assert LMClass.aforward is not original_aforward
        assert ModuleClass.__call__ is not original_call

        _ds.unpatch_dspy()

        # After unpatching, methods should be restored
        assert LMClass.forward is original_forward
        assert LMClass.aforward is original_aforward
        assert ModuleClass.__call__ is original_call
        assert _ds._patched is False

    def test_unpatch_when_not_patched(self):
        """unpatch_dspy should be a no-op when not patched."""
        import aegis.instrument._dspy as _ds

        # Should not raise
        _ds.unpatch_dspy()
        assert _ds._patched is False

    def test_unpatch_clears_originals(self, fake_dspy):
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        assert len(_ds._originals) > 0

        _ds.unpatch_dspy()
        assert len(_ds._originals) == 0

    def test_patch_only_lm_when_module_import_fails(self):
        """If dspy.Module import fails but LM works, only LM targets patched."""
        LMClass = _make_lm_class()

        lm_mod = types.ModuleType("dspy.clients.lm")
        lm_mod.LM = LMClass

        clients_mod = types.ModuleType("dspy.clients")
        clients_mod.lm = lm_mod

        # Create dspy module WITHOUT Module attribute
        dspy_mod = types.ModuleType("dspy")
        dspy_mod.clients = clients_mod
        # Deliberately do NOT add dspy_mod.Module

        sys.modules["dspy"] = dspy_mod
        sys.modules["dspy.clients"] = clients_mod
        sys.modules["dspy.clients.lm"] = lm_mod

        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)

        # Patch _dspy so that `from dspy import Module` raises ImportError
        original_import = (
            __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
        )

        def selective_import(name, *args, **kwargs):
            if name == "dspy" and args and args[0] is not None:
                # Check if "Module" is in the fromlist
                fromlist = kwargs.get("fromlist", args[2] if len(args) > 2 else None)
                if fromlist and "Module" in fromlist:
                    raise ImportError("no Module")
            return original_import(name, *args, **kwargs)

        # Instead, let's use a simpler approach: remove Module and make import fail
        with patch.dict(sys.modules, {"dspy": dspy_mod}):
            # Force ImportError for `from dspy import Module`
            # by making the module not have the attribute
            result = _ds.patch_dspy()

        # It should still patch LM targets
        assert result.patched is True
        assert "LM.forward" in result.targets

    def test_patch_only_module_when_lm_import_fails(self):
        """If dspy.clients.lm import fails but Module works, only Module patched."""
        ModuleClass = _make_module_class()

        dspy_mod = types.ModuleType("dspy")
        dspy_mod.Module = ModuleClass

        sys.modules["dspy"] = dspy_mod
        # Deliberately do NOT add dspy.clients or dspy.clients.lm

        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)
        result = _ds.patch_dspy()

        assert result.patched is True
        assert "Module.__call__" in result.targets
        assert "LM.forward" not in result.targets


# =========================================================================
# Governed wrappers (LM.forward, LM.aforward, Module.__call__)
# =========================================================================


class TestGovernedLmForward:
    """Tests for the governed LM.forward wrapper."""

    def test_calls_original_and_returns_result(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()

        lm = LMClass()
        result = lm.forward(prompt="hello")
        assert result == [{"text": "lm_output"}]

    def test_guardrails_invoked_on_input_and_output(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()
        lm.forward(prompt="test input")

        # Engine should be called twice: once for input, once for output
        assert engine.check.call_count == 2

    def test_input_blocked_raises(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [blocked_result]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()

        with pytest.raises(AegisGuardrailError, match="lm_input"):
            lm.forward(prompt="malicious input")

    def test_output_blocked_raises(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        allowed = MagicMock()
        allowed.action = "allowed"
        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "toxic output"

        engine = MagicMock()
        # First call (input) → allowed, second call (output) → blocked
        engine.check.side_effect = [[allowed], [blocked]]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()

        with pytest.raises(AegisGuardrailError, match="lm_output"):
            lm.forward(prompt="test")

    def test_no_engine_passes_through(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        # No guardrail engine configured
        _ds.patch_dspy()
        lm = LMClass()
        result = lm.forward(prompt="hello")
        assert result == [{"text": "lm_output"}]


class TestGovernedLmAforward:
    """Tests for the governed LM.aforward async wrapper."""

    def test_calls_original_and_returns_result(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        lm = LMClass()
        result = asyncio.get_event_loop().run_until_complete(lm.aforward(prompt="hello"))
        assert result == [{"text": "lm_async_output"}]

    def test_guardrails_invoked_on_async(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()
        asyncio.get_event_loop().run_until_complete(lm.aforward(prompt="test"))

        assert engine.check.call_count == 2

    def test_input_blocked_raises_async(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "bad input"
        engine = MagicMock()
        engine.check.return_value = [blocked_result]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()

        with pytest.raises(AegisGuardrailError, match="lm_input"):
            asyncio.get_event_loop().run_until_complete(lm.aforward(prompt="bad"))

    def test_output_blocked_raises_async(self, fake_dspy):
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        allowed = MagicMock()
        allowed.action = "allowed"
        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "toxic"

        engine = MagicMock()
        engine.check.side_effect = [[allowed], [blocked]]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()

        with pytest.raises(AegisGuardrailError, match="lm_output"):
            asyncio.get_event_loop().run_until_complete(lm.aforward(prompt="test"))


class TestGovernedModuleCall:
    """Tests for the governed Module.__call__ wrapper."""

    def test_calls_original_and_returns_result(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        mod = ModuleClass()
        result = mod(question="What is AI?")
        assert result == "prediction_result"

    def test_guardrails_invoked(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        mod = ModuleClass()
        mod(question="test question")

        assert engine.check.call_count == 2

    def test_input_blocked_raises(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        mod = ModuleClass()

        with pytest.raises(AegisGuardrailError, match="module_input"):
            mod(question="malicious")

    def test_output_blocked_raises(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        allowed = MagicMock()
        allowed.action = "allowed"
        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "pii leaked"

        engine = MagicMock()
        engine.check.side_effect = [[allowed], [blocked]]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        mod = ModuleClass()

        with pytest.raises(AegisGuardrailError, match="module_output"):
            mod(question="test")

    def test_no_string_kwargs_skips_input_guardrail(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        mod = ModuleClass()
        # Only non-string kwargs → empty input text → _run_guardrails skips
        mod(num=42)

        # Only output guardrail should be called (input skipped due to empty text)
        # Actually, module output is "prediction_result" which is a string
        # So output guardrail runs but input doesn't
        assert engine.check.call_count == 1

    def test_warn_mode_does_not_raise(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "warning only"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="warn")

        _ds.patch_dspy()
        mod = ModuleClass()

        # Should not raise even though blocked
        result = mod(question="test")
        assert result == "prediction_result"

    def test_module_output_with_toDict_prediction(self, fake_dspy):
        """Module returning a Prediction-like object with toDict."""
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        class FakePrediction:
            def toDict(self):
                return {"answer": "The answer is 42"}

        # Override Module.__call__ to return a FakePrediction
        def patched_call(self, *args, **kwargs):
            return FakePrediction()

        ModuleClass.__call__ = patched_call

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        # Re-store the patched call as the original so the governed wrapper
        # calls it correctly
        _ds.patch_dspy()
        mod = ModuleClass()
        result = mod(question="What?")

        assert hasattr(result, "toDict")
        # Both input and output guardrails should run
        assert engine.check.call_count == 2
        # Output check should receive the toDict-extracted text
        output_check_text = engine.check.call_args_list[1][0][0]
        assert "The answer is 42" in output_check_text


# =========================================================================
# Edge cases and integration-like tests
# =========================================================================


class TestEdgeCases:
    """Edge cases and misc behavior."""

    def test_patch_then_repatch_after_unpatch(self, fake_dspy):
        """Can patch → unpatch → patch again."""
        import aegis.instrument._dspy as _ds

        r1 = _ds.patch_dspy()
        assert r1.patched is True

        _ds.unpatch_dspy()
        assert _ds._patched is False

        # Need to reset state so patch can re-register
        InstrumentationState.reset()
        r2 = _ds.patch_dspy()
        assert r2.patched is True

    def test_unpatch_without_dspy_modules(self, fake_dspy):
        """unpatch_dspy handles missing dspy modules gracefully."""
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()

        # Remove dspy from sys.modules to simulate uninstall scenario
        _remove_fake_dspy()

        # Should not raise
        _ds.unpatch_dspy()
        assert _ds._patched is False

    def test_lm_forward_with_messages_kwargs(self, fake_dspy):
        """LM.forward called with messages kwarg (not prompt)."""
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        lm = LMClass()
        lm.forward(messages=[{"role": "user", "content": "Hello via messages"}])

        # Input guardrail should receive the messages content
        input_text = engine.check.call_args_list[0][0][0]
        assert "Hello via messages" in input_text

    def test_framework_patch_info(self, fake_dspy):
        """Verify FrameworkPatch details are correct."""
        import aegis.instrument._dspy as _ds

        result = _ds.patch_dspy()
        assert isinstance(result, FrameworkPatch)
        assert result.name == "dspy"
        assert result.error is None
        assert len(result.targets) >= 2  # At least LM.forward + Module.__call__

    def test_idempotent_returns_same_targets(self, fake_dspy):
        """Second call to patch_dspy returns same targets as first."""
        import aegis.instrument._dspy as _ds

        r1 = _ds.patch_dspy()
        r2 = _ds.patch_dspy()
        assert r1.targets == r2.targets

    def test_governed_forward_passes_args(self, fake_dspy):
        """Positional args are forwarded correctly to the original."""
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        call_log = []
        original = LMClass.forward

        def tracking_forward(self, *args, **kwargs):
            call_log.append((args, kwargs))
            return original(self, *args, **kwargs)

        LMClass.forward = tracking_forward

        # Re-reload so patch picks up the tracking version
        importlib.reload(_ds)
        _ds.patch_dspy()

        lm = LMClass()
        lm.forward("pos_arg", prompt="kw_arg")

        assert len(call_log) == 1
        assert call_log[0][0] == ("pos_arg",)
        assert call_log[0][1] == {"prompt": "kw_arg"}
