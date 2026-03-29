"""Tests for aegis.instrument._dspy module.

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

# -- Helpers: fake DSPy modules ------------------------------------------------


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
    for k in list(sys.modules.keys()):
        if k.startswith("dspy"):
            sys.modules.pop(k, None)


def _invoke_method(obj, method_name, kwargs):
    """Invoke a method by name, handling async for aforward."""
    method = getattr(obj, method_name)
    if method_name == "aforward":
        return asyncio.get_event_loop().run_until_complete(method(**kwargs))
    if method_name == "__call__":
        return obj(**kwargs)
    return method(**kwargs)


# -- Fixtures ------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset instrumentation state and module-level flags before each test."""
    InstrumentationState.reset()
    import aegis.instrument._dspy as _ds

    _ds._patched = False
    _ds._originals.clear()
    yield
    import aegis.instrument._dspy as _ds2

    _ds2.unpatch_dspy()
    _ds2._patched = False
    _ds2._originals.clear()
    _remove_fake_dspy()
    InstrumentationState.reset()


@pytest.fixture()
def fake_dspy():
    LMClass, ModuleClass = _install_fake_dspy()
    import aegis.instrument._dspy as _ds

    importlib.reload(_ds)
    yield LMClass, ModuleClass


@pytest.fixture()
def fake_dspy_no_aforward():
    LMClass, ModuleClass = _install_fake_dspy(has_aforward=False)
    import aegis.instrument._dspy as _ds

    importlib.reload(_ds)
    yield LMClass, ModuleClass


# -- _extract_lm_input ---------------------------------------------------------


class TestExtractLmInput:
    def test_prompt_string(self):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({"prompt": "Hello DSPy"}) == "Hello DSPy"

    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            pytest.param(
                {"prompt": "", "messages": [{"content": "msg"}]}, "msg", id="empty_prompt"
            ),
            pytest.param(
                {"prompt": 123, "messages": [{"content": "msg"}]}, "msg", id="non_string_prompt"
            ),
        ],
    )
    def test_prompt_falls_through_to_messages(self, kwargs, expected):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input(kwargs) == expected

    def test_messages_list_of_dicts(self):
        from aegis.instrument._dspy import _extract_lm_input

        messages = [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "What is AI?"},
        ]
        result = _extract_lm_input({"messages": messages})
        assert "You are helpful." in result
        assert "What is AI?" in result

    @pytest.mark.parametrize(
        "messages, expected",
        [
            pytest.param(
                [{"content": 42}, {"content": "valid"}], "valid", id="non_string_content"
            ),
            pytest.param(["not a dict", {"content": "ok"}], "ok", id="non_dict_items"),
            pytest.param([{"role": "user"}], "", id="missing_content_key"),
        ],
    )
    def test_messages_edge_cases(self, messages, expected):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input({"messages": messages}) == expected

    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({"messages": []}, id="empty_messages"),
            pytest.param({"messages": "not a list"}, id="messages_not_list"),
            pytest.param({}, id="empty_kwargs"),
            pytest.param({"other": "value"}, id="no_prompt_no_messages"),
        ],
    )
    def test_returns_empty_string(self, kwargs):
        from aegis.instrument._dspy import _extract_lm_input

        assert _extract_lm_input(kwargs) == ""


# -- _extract_lm_output --------------------------------------------------------


class TestExtractLmOutput:
    @pytest.mark.parametrize(
        "result, expected",
        [
            pytest.param([{"text": "response"}], "response", id="dict_text"),
            pytest.param([{"content": "answer"}], "answer", id="dict_content"),
            pytest.param([{"text": "A", "content": "B"}], "A", id="text_over_content"),
            pytest.param([{"text": "", "content": "fb"}], "fb", id="empty_text_fallback"),
            pytest.param(["plain text"], "plain text", id="string_in_list"),
            pytest.param("direct string", "direct string", id="string_result"),
        ],
    )
    def test_extracts_output(self, result, expected):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output(result) == expected

    @pytest.mark.parametrize(
        "result",
        [
            pytest.param([{"other": "val"}], id="dict_no_key"),
            pytest.param([42], id="non_dict_non_str"),
            pytest.param([], id="empty_list"),
            pytest.param(None, id="none"),
            pytest.param({"text": "val"}, id="dict_not_list"),
            pytest.param(42, id="int"),
        ],
    )
    def test_returns_empty_string(self, result):
        from aegis.instrument._dspy import _extract_lm_output

        assert _extract_lm_output(result) == ""


# -- _extract_module_input / _extract_module_output ----------------------------


class TestExtractModuleInput:
    def test_string_values_joined(self):
        from aegis.instrument._dspy import _extract_module_input

        result = _extract_module_input({"question": "What?", "context": "Some context"})
        assert "What?" in result
        assert "Some context" in result

    @pytest.mark.parametrize(
        "kwargs, expected",
        [
            pytest.param(
                {"num": 42, "text": "hello", "flag": True}, "hello", id="non_string_skipped"
            ),
            pytest.param({}, "", id="empty"),
            pytest.param({"a": 1, "b": [1, 2]}, "", id="all_non_string"),
        ],
    )
    def test_extraction_cases(self, kwargs, expected):
        from aegis.instrument._dspy import _extract_module_input

        assert _extract_module_input(kwargs) == expected


class TestExtractModuleOutput:
    def test_prediction_with_toDict(self):
        from aegis.instrument._dspy import _extract_module_output

        class FakePrediction:
            def toDict(self):
                return {"answer": "42", "reasoning": "because"}

        result = _extract_module_output(FakePrediction())
        assert "42" in result
        assert "because" in result

    @pytest.mark.parametrize(
        "to_dict_return",
        [
            pytest.param({"num": 42, "flag": True}, id="non_string_values"),
            pytest.param({}, id="empty_dict"),
        ],
    )
    def test_prediction_toDict_returns_empty(self, to_dict_return):
        from aegis.instrument._dspy import _extract_module_output

        class FakePrediction:
            def toDict(self_):
                return to_dict_return

        assert _extract_module_output(FakePrediction()) == ""

    @pytest.mark.parametrize(
        "result, expected",
        [
            pytest.param("plain result", "plain result", id="string"),
            pytest.param(None, "", id="none"),
            pytest.param(123, "", id="int"),
        ],
    )
    def test_non_prediction_results(self, result, expected):
        from aegis.instrument._dspy import _extract_module_output

        assert _extract_module_output(result) == expected


# -- _run_guardrails -----------------------------------------------------------


class TestRunGuardrails:
    def test_none_engine_no_op(self):
        from aegis.instrument._dspy import _run_guardrails

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
        _run_guardrails(engine, "safe text", direction="input", on_block="raise")

    @pytest.mark.parametrize(
        "on_block, should_raise",
        [
            pytest.param("raise", True, id="raise_mode"),
            pytest.param("warn", False, id="warn_mode"),
        ],
    )
    def test_blocked_on_block_modes(self, on_block, should_raise):
        from aegis.instrument._dspy import _run_guardrails

        result_obj = MagicMock()
        result_obj.action = "blocked"
        result_obj.details = "injection detected"
        engine = MagicMock()
        engine.check.return_value = [result_obj]

        if should_raise:
            with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
                _run_guardrails(engine, "bad text", direction="input", on_block=on_block)
        else:
            _run_guardrails(engine, "bad text", direction="input", on_block=on_block)

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
        engine = MagicMock()
        engine.check.return_value = [result_obj]
        with pytest.raises(AegisGuardrailError, match="unknown"):
            _run_guardrails(engine, "text", direction="test", on_block="raise")

    def test_engine_check_exception_handled(self):
        from aegis.instrument._dspy import _run_guardrails

        engine = MagicMock()
        engine.check.side_effect = RuntimeError("engine broke")
        _run_guardrails(engine, "text", direction="input", on_block="raise")

    @pytest.mark.parametrize(
        "results, match_pattern",
        [
            pytest.param(
                [("blocked", "reason1"), ("blocked", "reason2")],
                "reason1.*reason2",
                id="multiple_blocked",
            ),
            pytest.param(
                [("allowed", ""), ("blocked", "bad content")],
                "bad content",
                id="mixed",
            ),
        ],
    )
    def test_multi_result_blocked_raises(self, results, match_pattern):
        from aegis.instrument._dspy import _run_guardrails

        mock_results = []
        for action, details in results:
            r = MagicMock()
            r.action = action
            r.details = details
            mock_results.append(r)
        engine = MagicMock()
        engine.check.return_value = mock_results
        with pytest.raises(AegisGuardrailError, match=match_pattern):
            _run_guardrails(engine, "text", direction="input", on_block="raise")


# -- patch_dspy / unpatch_dspy lifecycle ---------------------------------------


class TestPatchDspy:
    def test_patch_success(self, fake_dspy):
        import aegis.instrument._dspy as _ds

        result = _ds.patch_dspy()
        assert isinstance(result, FrameworkPatch)
        assert result.patched is True
        assert result.name == "dspy"
        assert result.error is None
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
        assert r1.targets == r2.targets

    def test_patch_without_dspy_installed(self):
        """Patch returns not-patched and registers when dspy is absent."""
        _remove_fake_dspy()
        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)
        result = _ds.patch_dspy()
        assert result.patched is False
        assert result.error == "dspy not installed"
        p = InstrumentationState.get().get_patch("dspy")
        assert p is not None
        assert p.patched is False

    def test_patch_registers_with_state(self, fake_dspy):
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        assert InstrumentationState.get().is_patched("dspy")

    def test_unpatch_restores_originals(self, fake_dspy):
        LMClass, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        original_forward = LMClass.forward
        original_aforward = LMClass.aforward
        original_call = ModuleClass.__call__

        _ds.patch_dspy()
        assert LMClass.forward is not original_forward
        assert LMClass.aforward is not original_aforward
        assert ModuleClass.__call__ is not original_call

        _ds.unpatch_dspy()
        assert LMClass.forward is original_forward
        assert LMClass.aforward is original_aforward
        assert ModuleClass.__call__ is original_call
        assert _ds._patched is False
        assert len(_ds._originals) == 0

    def test_unpatch_when_not_patched(self):
        import aegis.instrument._dspy as _ds

        _ds.unpatch_dspy()
        assert _ds._patched is False

    def test_unpatch_without_dspy_modules(self, fake_dspy):
        """unpatch handles missing dspy modules gracefully."""
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        _remove_fake_dspy()
        _ds.unpatch_dspy()
        assert _ds._patched is False

    def test_patch_then_repatch_after_unpatch(self, fake_dspy):
        """Can patch -> unpatch -> patch again."""
        import aegis.instrument._dspy as _ds

        r1 = _ds.patch_dspy()
        assert r1.patched is True
        _ds.unpatch_dspy()
        assert _ds._patched is False
        InstrumentationState.reset()
        r2 = _ds.patch_dspy()
        assert r2.patched is True

    def test_patch_only_lm_when_module_import_fails(self):
        """If dspy.Module import fails but LM works, only LM targets patched."""
        LMClass = _make_lm_class()
        lm_mod = types.ModuleType("dspy.clients.lm")
        lm_mod.LM = LMClass
        clients_mod = types.ModuleType("dspy.clients")
        clients_mod.lm = lm_mod
        dspy_mod = types.ModuleType("dspy")
        dspy_mod.clients = clients_mod

        sys.modules["dspy"] = dspy_mod
        sys.modules["dspy.clients"] = clients_mod
        sys.modules["dspy.clients.lm"] = lm_mod

        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)
        with patch.dict(sys.modules, {"dspy": dspy_mod}):
            result = _ds.patch_dspy()
        assert result.patched is True
        assert "LM.forward" in result.targets

    def test_patch_only_module_when_lm_import_fails(self):
        """If dspy.clients.lm import fails but Module works, only Module patched."""
        ModuleClass = _make_module_class()
        dspy_mod = types.ModuleType("dspy")
        dspy_mod.Module = ModuleClass
        sys.modules["dspy"] = dspy_mod

        import aegis.instrument._dspy as _ds

        importlib.reload(_ds)
        result = _ds.patch_dspy()
        assert result.patched is True
        assert "Module.__call__" in result.targets
        assert "LM.forward" not in result.targets


# -- Governed wrappers (parametrized) ------------------------------------------

_WRAPPER_CASES = [
    pytest.param(
        0,
        "forward",
        {"prompt": "hello"},
        [{"text": "lm_output"}],
        "lm_input",
        "lm_output",
        id="LM.forward",
    ),
    pytest.param(
        0,
        "aforward",
        {"prompt": "hello"},
        [{"text": "lm_async_output"}],
        "lm_input",
        "lm_output",
        id="LM.aforward",
    ),
    pytest.param(
        1,
        "__call__",
        {"question": "What is AI?"},
        "prediction_result",
        "module_input",
        "module_output",
        id="Module.__call__",
    ),
]


class TestGovernedWrappers:
    @pytest.mark.parametrize("idx, method, kwargs, expected, _idir, _odir", _WRAPPER_CASES)
    def test_calls_original_and_returns_result(
        self, fake_dspy, idx, method, kwargs, expected, _idir, _odir
    ):
        import aegis.instrument._dspy as _ds

        _ds.patch_dspy()
        assert _invoke_method(fake_dspy[idx](), method, kwargs) == expected

    @pytest.mark.parametrize("idx, method, kwargs, _exp, _idir, _odir", _WRAPPER_CASES)
    def test_guardrails_invoked_on_input_and_output(
        self, fake_dspy, idx, method, kwargs, _exp, _idir, _odir
    ):
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        _ds.patch_dspy()
        _invoke_method(fake_dspy[idx](), method, kwargs)
        assert engine.check.call_count == 2

    @pytest.mark.parametrize("idx, method, kwargs, _exp, idir, _odir", _WRAPPER_CASES)
    def test_input_blocked_raises(self, fake_dspy, idx, method, kwargs, _exp, idir, _odir):
        import aegis.instrument._dspy as _ds

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [blocked]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        _ds.patch_dspy()
        with pytest.raises(AegisGuardrailError, match=idir):
            _invoke_method(fake_dspy[idx](), method, kwargs)

    @pytest.mark.parametrize("idx, method, kwargs, _exp, _idir, odir", _WRAPPER_CASES)
    def test_output_blocked_raises(self, fake_dspy, idx, method, kwargs, _exp, _idir, odir):
        import aegis.instrument._dspy as _ds

        allowed = MagicMock()
        allowed.action = "allowed"
        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "toxic output"
        engine = MagicMock()
        engine.check.side_effect = [[allowed], [blocked]]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        _ds.patch_dspy()
        with pytest.raises(AegisGuardrailError, match=odir):
            _invoke_method(fake_dspy[idx](), method, kwargs)

    def test_lm_forward_with_messages_kwargs(self, fake_dspy):
        """LM.forward called with messages kwarg (not prompt)."""
        LMClass, _ = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        _ds.patch_dspy()
        LMClass().forward(messages=[{"role": "user", "content": "Hello via messages"}])
        assert "Hello via messages" in engine.check.call_args_list[0][0][0]

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
        importlib.reload(_ds)
        _ds.patch_dspy()
        LMClass().forward("pos_arg", prompt="kw_arg")
        assert len(call_log) == 1
        assert call_log[0] == (("pos_arg",), {"prompt": "kw_arg"})


# -- Module.__call__-specific tests --------------------------------------------


class TestGovernedModuleCall:
    def test_no_string_kwargs_skips_input_guardrail(self, fake_dspy):
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        _ds.patch_dspy()
        ModuleClass()(num=42)
        assert engine.check.call_count == 1  # only output guardrail

    def test_module_output_with_toDict_prediction(self, fake_dspy):
        """Module returning a Prediction-like object with toDict."""
        _, ModuleClass = fake_dspy
        import aegis.instrument._dspy as _ds

        class FakePrediction:
            def toDict(self):
                return {"answer": "The answer is 42"}

        ModuleClass.__call__ = lambda self, *a, **kw: FakePrediction()
        engine = MagicMock()
        allowed = MagicMock()
        allowed.action = "allowed"
        engine.check.return_value = [allowed]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")

        _ds.patch_dspy()
        result = ModuleClass()(question="What?")
        assert hasattr(result, "toDict")
        assert engine.check.call_count == 2
        assert "The answer is 42" in engine.check.call_args_list[1][0][0]
