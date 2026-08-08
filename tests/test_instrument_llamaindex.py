"""Tests for aegis.instrument._llamaindex auto-instrumentation.

Covers all extraction helpers, _run_guardrails, patch/unpatch lifecycle,
sync and async governed wrappers for LLM and BaseQueryEngine.

LlamaIndex is NOT installed — we inject fake modules into sys.modules.
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

# --- Fake LlamaIndex classes ---


@dataclass
class FakeChatMessage:
    content: str = ""
    role: str = "user"


@dataclass
class FakeChatResponse:
    message: FakeChatMessage | None = None


@dataclass
class FakeCompletionResponse:
    text: str = ""


@dataclass
class FakeQueryResponse:
    response: str = ""


@dataclass
class FakeQueryBundle:
    query_str: str = ""


class FakeLLM:
    """Fake LlamaIndex LLM with chat/complete/achat/acomplete methods."""

    def chat(self, *args: Any, **kwargs: Any) -> FakeChatResponse:
        return FakeChatResponse(message=FakeChatMessage(content="llm chat reply"))

    async def achat(self, *args: Any, **kwargs: Any) -> FakeChatResponse:
        return FakeChatResponse(message=FakeChatMessage(content="llm achat reply"))

    def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
        return FakeCompletionResponse(text="llm complete reply")

    async def acomplete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
        return FakeCompletionResponse(text="llm acomplete reply")


class FakeBaseQueryEngine:
    """Fake LlamaIndex BaseQueryEngine with query/aquery methods."""

    def query(self, *args: Any, **kwargs: Any) -> FakeQueryResponse:
        return FakeQueryResponse(response="query reply")

    async def aquery(self, *args: Any, **kwargs: Any) -> FakeQueryResponse:
        return FakeQueryResponse(response="aquery reply")


# --- Fixtures ---


def _inject_fake_llamaindex() -> dict[str, types.ModuleType]:
    """Inject fake llama_index modules into sys.modules and return them."""
    # llama_index (top-level)
    llama_index = types.ModuleType("llama_index")
    llama_index_core = types.ModuleType("llama_index.core")
    llama_index_core_llms = types.ModuleType("llama_index.core.llms")
    llama_index_core_base = types.ModuleType("llama_index.core.base")
    llama_index_core_base_bqe = types.ModuleType("llama_index.core.base.base_query_engine")

    llama_index_core_llms.LLM = FakeLLM
    llama_index_core_base_bqe.BaseQueryEngine = FakeBaseQueryEngine

    # Wire up module hierarchy
    llama_index.core = llama_index_core
    llama_index_core.llms = llama_index_core_llms
    llama_index_core.base = llama_index_core_base
    llama_index_core_base.base_query_engine = llama_index_core_base_bqe

    mods = {
        "llama_index": llama_index,
        "llama_index.core": llama_index_core,
        "llama_index.core.llms": llama_index_core_llms,
        "llama_index.core.base": llama_index_core_base,
        "llama_index.core.base.base_query_engine": llama_index_core_base_bqe,
    }
    for name, mod in mods.items():
        sys.modules[name] = mod
    return mods


def _remove_fake_llamaindex(mod_names: list[str]) -> None:
    """Remove fake modules from sys.modules."""
    for name in mod_names:
        sys.modules.pop(name, None)


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset instrumentation state and module flags before each test."""
    InstrumentationState.reset()

    import aegis.instrument._llamaindex as _li

    _li._patched = False
    _li._originals.clear()
    _li._patched_methods.clear()

    yield

    _li.unpatch_llamaindex()
    InstrumentationState.reset()


@pytest.fixture()
def fake_llamaindex():
    """Inject fake LlamaIndex modules, reload _llamaindex, yield, then clean up."""
    mods = _inject_fake_llamaindex()
    mod_names = list(mods.keys())

    import aegis.instrument._llamaindex as _li

    _li._patched = False
    _li._originals.clear()
    importlib.reload(_li)

    yield _li

    _li.unpatch_llamaindex()
    _li._patched = False
    _li._originals.clear()
    _remove_fake_llamaindex(mod_names)
    importlib.reload(_li)


# --- Mock guardrail engine ---


def _make_engine(*, action: str = "allowed") -> MagicMock:
    """Return a mock guardrail engine.

    action="allowed" means all results pass.
    action="blocked" means all results are blocked.
    """
    result = MagicMock()
    result.action = action
    result.details = "test guardrail detail"
    result.guardrail_name = "test_guardrail"
    engine = MagicMock()
    engine.check.return_value = [result]
    return engine


# --- Extraction helpers ---


class TestExtractInputs:
    """Tests for _extract_chat_input, _extract_prompt, _extract_query_input."""

    @pytest.mark.parametrize(
        "func_name, args, kwargs, expected",
        [
            # _extract_chat_input
            pytest.param(
                "_extract_chat_input",
                ([FakeChatMessage(content="hello world")],),
                {},
                "hello world",
                id="chat_positional",
            ),
            pytest.param(
                "_extract_chat_input",
                (),
                {"messages": [FakeChatMessage(content="from kwarg")]},
                "from kwarg",
                id="chat_kwargs",
            ),
            pytest.param(
                "_extract_chat_input",
                ([{"content": "dict content", "role": "user"}],),
                {},
                "dict content",
                id="chat_dict",
            ),
            pytest.param(
                "_extract_chat_input",
                ([{"content": 123, "role": "user"}],),
                {},
                "",
                id="chat_dict_non_string",
            ),
            pytest.param(
                "_extract_chat_input",
                ([FakeChatMessage(content="first"), FakeChatMessage(content="second")],),
                {},
                "first\nsecond",
                id="chat_multiple_joined",
            ),
            pytest.param("_extract_chat_input", (), {}, "", id="chat_empty"),
            pytest.param(
                "_extract_chat_input", ("raw string",), {}, "raw string", id="chat_non_list"
            ),
            pytest.param("_extract_chat_input", ([],), {}, "", id="chat_empty_list"),
            # _extract_prompt
            pytest.param(
                "_extract_prompt", ("hello prompt",), {}, "hello prompt", id="prompt_positional"
            ),
            pytest.param(
                "_extract_prompt",
                (),
                {"prompt": "kwarg prompt"},
                "kwarg prompt",
                id="prompt_kwarg",
            ),
            pytest.param("_extract_prompt", (12345,), {}, "12345", id="prompt_non_string"),
            pytest.param("_extract_prompt", (), {}, "", id="prompt_no_args"),
            pytest.param("_extract_prompt", (None,), {}, "", id="prompt_none"),
            # _extract_query_input
            pytest.param("_extract_query_input", ("my query",), {}, "my query", id="query_string"),
            pytest.param(
                "_extract_query_input",
                (FakeQueryBundle(query_str="bundle query"),),
                {},
                "bundle query",
                id="query_bundle",
            ),
            pytest.param(
                "_extract_query_input",
                (),
                {"str_or_query_bundle": "kwarg query"},
                "kwarg query",
                id="query_kwarg",
            ),
            pytest.param("_extract_query_input", (), {}, "", id="query_empty"),
        ],
    )
    def test_input_extraction(self, func_name, args, kwargs, expected):
        import aegis.instrument._llamaindex as _li

        assert getattr(_li, func_name)(args, kwargs) == expected

    def test_chat_input_message_without_content_attr(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        assert _extract_chat_input(([MagicMock(spec=[])],), {}) == ""

    def test_query_input_non_string_non_bundle(self):
        from aegis.instrument._llamaindex import _extract_query_input

        assert isinstance(_extract_query_input((MagicMock(spec=[]),), {}), str)

    def test_query_input_bundle_non_string_query_str(self):
        from aegis.instrument._llamaindex import _extract_query_input

        bundle = MagicMock()
        bundle.query_str = 999
        assert isinstance(_extract_query_input((bundle,), {}), str)


class TestExtractOutputs:
    """Tests for _extract_chat_output, _extract_completion_output, _extract_query_output."""

    @pytest.mark.parametrize(
        "func_name, response, expected",
        [
            pytest.param(
                "_extract_chat_output",
                FakeChatResponse(message=FakeChatMessage(content="output text")),
                "output text",
                id="chat_normal",
            ),
            pytest.param(
                "_extract_chat_output", FakeChatResponse(message=None), "", id="chat_no_message"
            ),
            pytest.param("_extract_chat_output", object(), "", id="chat_no_message_attr"),
            pytest.param(
                "_extract_completion_output",
                FakeCompletionResponse(text="completion text"),
                "completion text",
                id="completion_normal",
            ),
            pytest.param("_extract_completion_output", object(), "", id="completion_no_text_attr"),
            pytest.param(
                "_extract_query_output",
                FakeQueryResponse(response="query response text"),
                "query response text",
                id="query_normal",
            ),
            pytest.param("_extract_query_output", object(), "", id="query_no_response_attr"),
        ],
    )
    def test_output_extraction(self, func_name, response, expected):
        import aegis.instrument._llamaindex as _li

        assert getattr(_li, func_name)(response) == expected

    @pytest.mark.parametrize(
        "func_name, attr_name, bad_value",
        [
            pytest.param("_extract_completion_output", "text", 123, id="completion_non_string"),
            pytest.param("_extract_query_output", "response", 42, id="query_non_string"),
        ],
    )
    def test_non_string_output_returns_empty(self, func_name, attr_name, bad_value):
        import aegis.instrument._llamaindex as _li

        obj = MagicMock()
        setattr(obj, attr_name, bad_value)
        assert getattr(_li, func_name)(obj) == ""

    @pytest.mark.parametrize("content_value", [None, 42], ids=["none", "non_string"])
    def test_chat_output_non_string_content(self, content_value):
        from aegis.instrument._llamaindex import _extract_chat_output

        msg, resp = MagicMock(), MagicMock()
        msg.content = content_value
        resp.message = msg
        assert _extract_chat_output(resp) == ""


# --- _run_guardrails ---


class TestRunGuardrails:
    @pytest.fixture(autouse=True)
    def _import(self):
        from aegis.instrument._llamaindex import _run_guardrails

        self._run = _run_guardrails

    def test_noop_when_engine_is_none(self):
        self._run(None, "some text", direction="input", on_block="raise")

    def test_noop_when_text_is_empty(self):
        engine = _make_engine()
        self._run(engine, "", direction="input", on_block="raise")
        engine.check.assert_not_called()

    def test_allowed_passes(self):
        engine = _make_engine(action="allowed")
        self._run(engine, "safe text", direction="input", on_block="raise")
        engine.check.assert_called_once_with("safe text")

    def test_blocked_raises_when_on_block_raise(self):
        engine = _make_engine(action="blocked")
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            self._run(engine, "bad text", direction="input", on_block="raise")

    def test_blocked_warns_when_on_block_warn(self):
        engine = _make_engine(action="blocked")
        self._run(engine, "bad text", direction="output", on_block="warn")

    def test_engine_exception_handled_gracefully(self):
        engine = MagicMock()
        engine.check.side_effect = RuntimeError("boom")
        self._run(engine, "text", direction="input", on_block="raise")

    def test_blocked_result_details_fallback_to_guardrail_name(self):
        result = MagicMock()
        result.action = "blocked"
        result.details = ""
        result.guardrail_name = "fallback_name"
        engine = MagicMock()
        engine.check.return_value = [result]
        with pytest.raises(AegisGuardrailError, match="fallback_name"):
            self._run(engine, "bad text", direction="input", on_block="raise")


# --- patch/unpatch without LlamaIndex ---


class TestPatchWithoutLlamaIndex:
    def test_patch_returns_not_patched_and_registers(self):
        from aegis.instrument._llamaindex import patch_llamaindex

        result = patch_llamaindex()
        assert result.patched is False
        assert result.error == "llama-index-core not installed"
        assert result.name == "llamaindex"
        p = InstrumentationState.get().get_patch("llamaindex")
        assert p is not None and p.patched is False


# --- patch/unpatch with fake LlamaIndex ---

_ALL_TARGETS = {
    "LLM.chat",
    "LLM.achat",
    "LLM.complete",
    "LLM.acomplete",
    "BaseQueryEngine.query",
    "BaseQueryEngine.aquery",
}


class TestPatchWithFakeLlamaIndex:
    def test_patch_succeeds(self, fake_llamaindex):
        result = fake_llamaindex.patch_llamaindex()
        assert result.patched is True and result.name == "llamaindex"
        assert set(result.targets) >= _ALL_TARGETS

    def test_patch_idempotent(self, fake_llamaindex):
        r1 = fake_llamaindex.patch_llamaindex()
        r2 = fake_llamaindex.patch_llamaindex()
        assert r1.patched and r2.patched and r1.targets == r2.targets

    def test_unpatch_restores_originals(self, fake_llamaindex):
        fake_llamaindex.patch_llamaindex()
        assert fake_llamaindex._patched is True
        fake_llamaindex.unpatch_llamaindex()
        assert fake_llamaindex._patched is False
        assert len(fake_llamaindex._originals) == 0

    def test_unpatch_noop_if_not_patched(self, fake_llamaindex):
        fake_llamaindex.unpatch_llamaindex()
        assert fake_llamaindex._patched is False

    def test_registered_in_state(self, fake_llamaindex):
        fake_llamaindex.patch_llamaindex()
        assert InstrumentationState.get().is_patched("llamaindex")


# --- Governed wrappers ---

# Each tuple: (cls, method_name, call_args, call_kwargs,
#   response_accessor, expected_value, is_async, block_match)
_GOVERNED_METHODS = [
    pytest.param(
        FakeLLM,
        "chat",
        [FakeChatMessage(content="hello")],
        {},
        lambda r: r.message.content,
        "llm chat reply",
        False,
        "blocked input",
        id="LLM.chat",
    ),
    pytest.param(
        FakeLLM,
        "achat",
        [FakeChatMessage(content="hello")],
        {},
        lambda r: r.message.content,
        "llm achat reply",
        True,
        "blocked input",
        id="LLM.achat",
    ),
    pytest.param(
        FakeLLM,
        "complete",
        "hello prompt",
        {},
        lambda r: r.text,
        "llm complete reply",
        False,
        "blocked input",
        id="LLM.complete",
    ),
    pytest.param(
        FakeLLM,
        "acomplete",
        "hello prompt",
        {},
        lambda r: r.text,
        "llm acomplete reply",
        True,
        "blocked input",
        id="LLM.acomplete",
    ),
    pytest.param(
        FakeBaseQueryEngine,
        "query",
        "my query",
        {},
        lambda r: r.response,
        "query reply",
        False,
        "blocked query_input",
        id="BaseQueryEngine.query",
    ),
    pytest.param(
        FakeBaseQueryEngine,
        "aquery",
        "async query",
        {},
        lambda r: r.response,
        "aquery reply",
        True,
        "blocked query_input",
        id="BaseQueryEngine.aquery",
    ),
]


def _invoke(cls, method_name, instance, call_args, call_kwargs, is_async):
    """Invoke a sync or async governed method on the patched class."""
    method = getattr(cls, method_name)
    if is_async:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(method(instance, call_args, **call_kwargs))
        finally:
            loop.close()
    return method(instance, call_args, **call_kwargs)


class TestGovernedWrappers:
    """Parametrized tests for all governed wrappers (sync + async)."""

    _PARAMS = (
        "cls, method_name, call_args, call_kwargs,"
        " response_accessor, expected, is_async, block_match"
    )

    @pytest.mark.parametrize(_PARAMS, _GOVERNED_METHODS)
    def test_passthrough_no_engine(
        self,
        fake_llamaindex,
        cls,
        method_name,
        call_args,
        call_kwargs,
        response_accessor,
        expected,
        is_async,
        block_match,
    ):
        fake_llamaindex.patch_llamaindex()
        InstrumentationState.get().configure(guardrail_engine=None)
        resp = _invoke(cls, method_name, cls(), call_args, call_kwargs, is_async)
        assert response_accessor(resp) == expected

    @pytest.mark.parametrize(_PARAMS, _GOVERNED_METHODS)
    def test_allowed_guardrail(
        self,
        fake_llamaindex,
        cls,
        method_name,
        call_args,
        call_kwargs,
        response_accessor,
        expected,
        is_async,
        block_match,
    ):
        fake_llamaindex.patch_llamaindex()
        engine = _make_engine(action="allowed")
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        resp = _invoke(cls, method_name, cls(), call_args, call_kwargs, is_async)
        assert response_accessor(resp) == expected
        assert engine.check.call_count == 2  # input + output

    @pytest.mark.parametrize(_PARAMS, _GOVERNED_METHODS)
    def test_blocked_input_raises(
        self,
        fake_llamaindex,
        cls,
        method_name,
        call_args,
        call_kwargs,
        response_accessor,
        expected,
        is_async,
        block_match,
    ):
        fake_llamaindex.patch_llamaindex()
        engine = _make_engine(action="blocked")
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        with pytest.raises(AegisGuardrailError, match=block_match):
            _invoke(cls, method_name, cls(), call_args, call_kwargs, is_async)

    def test_chat_blocked_warn_mode(self, fake_llamaindex):
        """Blocked guardrail in warn mode does not raise."""
        fake_llamaindex.patch_llamaindex()
        engine = _make_engine(action="blocked")
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="warn")
        llm = FakeLLM()
        resp = FakeLLM.chat(llm, [FakeChatMessage(content="bad input")])
        assert resp.message.content == "llm chat reply"

    def test_query_with_bundle(self, fake_llamaindex):
        """Query with a QueryBundle extracts query_str for guardrail check."""
        fake_llamaindex.patch_llamaindex()
        engine = _make_engine(action="allowed")
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        qe = FakeBaseQueryEngine()
        bundle = FakeQueryBundle(query_str="bundled query")
        resp = FakeBaseQueryEngine.query(qe, bundle)
        assert resp.response == "query reply"
        engine.check.assert_any_call("bundled query")


# --- Partial import failure ---


def _setup_partial_modules(*, include_llm: bool, include_query_engine: bool):
    """Inject partial fake LlamaIndex modules and return (mod_names, _li)."""
    llama_index = types.ModuleType("llama_index")
    llama_index_core = types.ModuleType("llama_index.core")
    llama_index.core = llama_index_core

    mod_map: dict[str, types.ModuleType] = {
        "llama_index": llama_index,
        "llama_index.core": llama_index_core,
    }

    if include_llm:
        llama_index_core_llms = types.ModuleType("llama_index.core.llms")
        llama_index_core_llms.LLM = FakeLLM
        llama_index_core.llms = llama_index_core_llms
        mod_map["llama_index.core.llms"] = llama_index_core_llms

    if include_query_engine:
        llama_index_core_base = types.ModuleType("llama_index.core.base")
        llama_index_core_base_bqe = types.ModuleType("llama_index.core.base.base_query_engine")
        llama_index_core_base_bqe.BaseQueryEngine = FakeBaseQueryEngine
        llama_index_core.base = llama_index_core_base
        llama_index_core_base.base_query_engine = llama_index_core_base_bqe
        mod_map["llama_index.core.base"] = llama_index_core_base
        mod_map["llama_index.core.base.base_query_engine"] = llama_index_core_base_bqe

    # Remove opposite modules to force ImportError
    for name in [
        "llama_index.core.llms",
        "llama_index.core.base",
        "llama_index.core.base.base_query_engine",
    ]:
        if name not in mod_map:
            sys.modules.pop(name, None)

    for name, mod in mod_map.items():
        sys.modules[name] = mod

    import aegis.instrument._llamaindex as _li

    _li._patched = False
    _li._originals.clear()
    importlib.reload(_li)
    return list(mod_map.keys()), _li


class TestPartialImportFailure:
    @pytest.mark.parametrize(
        "include_llm, include_qe, expected_in, expected_not_in",
        [
            pytest.param(
                True,
                False,
                ["LLM.chat"],
                ["BaseQueryEngine.query"],
                id="only_llm",
            ),
            pytest.param(
                False,
                True,
                ["BaseQueryEngine.query", "BaseQueryEngine.aquery"],
                ["LLM.chat"],
                id="only_query_engine",
            ),
        ],
    )
    def test_partial_import(
        self,
        include_llm,
        include_qe,
        expected_in,
        expected_not_in,
    ):
        mod_names, _li = _setup_partial_modules(
            include_llm=include_llm,
            include_query_engine=include_qe,
        )
        try:
            result = _li.patch_llamaindex()
            assert result.patched is True
            for target in expected_in:
                assert target in result.targets
            for target in expected_not_in:
                assert target not in result.targets
        finally:
            _li.unpatch_llamaindex()
            _li._patched = False
            _li._originals.clear()
            for name in mod_names:
                sys.modules.pop(name, None)
            importlib.reload(_li)


# --- Edge cases ---


def _make_result(*, action: str, details: str = "", name: str = "g") -> MagicMock:
    """Build a mock guardrail result."""
    r = MagicMock()
    r.action, r.details, r.guardrail_name = action, details, name
    return r


class TestEdgeCases:
    @pytest.mark.parametrize(
        "cls, method, kwargs, accessor, expected, check_input",
        [
            pytest.param(
                FakeLLM,
                "chat",
                {"messages": [FakeChatMessage(content="kwarg msg")]},
                lambda r: r.message.content,
                "llm chat reply",
                None,
                id="chat",
            ),
            pytest.param(
                FakeLLM,
                "complete",
                {"prompt": "kwarg prompt"},
                lambda r: r.text,
                "llm complete reply",
                "kwarg prompt",
                id="complete",
            ),
            pytest.param(
                FakeBaseQueryEngine,
                "query",
                {"str_or_query_bundle": "kwarg query"},
                lambda r: r.response,
                "query reply",
                "kwarg query",
                id="query",
            ),
        ],
    )
    def test_kwarg_invocation(
        self, fake_llamaindex, cls, method, kwargs, accessor, expected, check_input
    ):
        fake_llamaindex.patch_llamaindex()
        engine = _make_engine(action="allowed")
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        resp = getattr(cls, method)(cls(), **kwargs)
        assert accessor(resp) == expected
        if check_input is not None:
            engine.check.assert_any_call(check_input)

    @pytest.mark.parametrize(
        "cls, method, call_args, output_match",
        [
            pytest.param(
                FakeLLM, "chat", [FakeChatMessage(content="ok")], "blocked output", id="chat"
            ),
            pytest.param(FakeLLM, "complete", "safe prompt", "blocked output", id="complete"),
            pytest.param(
                FakeBaseQueryEngine, "query", "safe query", "blocked query_output", id="query"
            ),
        ],
    )
    def test_blocked_output(self, fake_llamaindex, cls, method, call_args, output_match):
        fake_llamaindex.patch_llamaindex()
        engine = MagicMock()
        engine.check.side_effect = [
            [_make_result(action="allowed")],
            [_make_result(action="blocked", details="blocked", name="test")],
        ]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")
        with pytest.raises(AegisGuardrailError, match=output_match):
            getattr(cls, method)(cls(), call_args)

    def test_multiple_blocked_results_joined(self):
        from aegis.instrument._llamaindex import _run_guardrails

        engine = MagicMock()
        engine.check.return_value = [
            _make_result(action="blocked", details="detail1", name="g1"),
            _make_result(action="blocked", details="detail2", name="g2"),
        ]
        with pytest.raises(AegisGuardrailError, match="detail1; detail2"):
            _run_guardrails(engine, "bad text", direction="input", on_block="raise")


class TestSubclassOverrideGovernance:
    """Concrete LlamaIndex LLMs override chat/complete, bypassing a base patch.

    ``llama_index.llms.openai.OpenAI`` defines both methods in its own module,
    so attribute lookup never reaches the governed base method and prompts went
    out ungoverned.  The adapter walks the subclass tree and installs an
    ``__init_subclass__`` hook to cover classes defined later.
    """

    def test_existing_override_is_governed(self, fake_llamaindex):
        """A subclass defined before patching has its override wrapped."""

        class OverridingLLM(FakeLLM):
            def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
                return FakeCompletionResponse(text="subclass reply")

        result = fake_llamaindex.patch_llamaindex()

        key = f"{OverridingLLM.__module__}.{OverridingLLM.__qualname__}.complete"
        assert key in result.targets

        InstrumentationState.get().configure(
            guardrail_engine=_make_engine(action="blocked"), on_block="raise"
        )
        with pytest.raises(AegisGuardrailError):
            OverridingLLM().complete("bad prompt")

    def test_override_defined_after_patching_is_governed(self, fake_llamaindex):
        """The __init_subclass__ hook covers classes imported after instrumenting.

        This is the documented usage: ``aegis.auto_instrument()`` at the top of
        the file, framework imports below it.
        """
        fake_llamaindex.patch_llamaindex()

        class LateLLM(FakeLLM):
            def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
                return FakeCompletionResponse(text="late reply")

        InstrumentationState.get().configure(
            guardrail_engine=_make_engine(action="blocked"), on_block="raise"
        )
        with pytest.raises(AegisGuardrailError):
            LateLLM().complete("bad prompt")

    def test_benign_call_through_override_still_works(self, fake_llamaindex):
        """Governance must not change the result of an allowed call."""

        class OverridingLLM(FakeLLM):
            def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
                return FakeCompletionResponse(text="subclass reply")

        fake_llamaindex.patch_llamaindex()
        InstrumentationState.get().configure(
            guardrail_engine=_make_engine(action="allowed"), on_block="raise"
        )

        assert OverridingLLM().complete("hello").text == "subclass reply"

    def test_unpatch_restores_overrides_and_hook(self, fake_llamaindex):
        """Unpatch restores subclass overrides and stops governing new classes."""

        class OverridingLLM(FakeLLM):
            def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
                return FakeCompletionResponse(text="subclass reply")

        original = OverridingLLM.__dict__["complete"]
        fake_llamaindex.patch_llamaindex()
        assert OverridingLLM.__dict__["complete"] is not original

        fake_llamaindex.unpatch_llamaindex()
        assert OverridingLLM.__dict__["complete"] is original
        assert fake_llamaindex._patched_methods == []

        InstrumentationState.get().configure(
            guardrail_engine=_make_engine(action="blocked"), on_block="raise"
        )

        class AfterUnpatchLLM(FakeLLM):
            def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
                return FakeCompletionResponse(text="not governed")

        assert AfterUnpatchLLM().complete("bad prompt").text == "not governed"

    def test_double_patch_does_not_rewrap(self, fake_llamaindex):
        """Re-patching must not stack wrappers on the same override."""

        class OverridingLLM(FakeLLM):
            def complete(self, *args: Any, **kwargs: Any) -> FakeCompletionResponse:
                return FakeCompletionResponse(text="subclass reply")

        r1 = fake_llamaindex.patch_llamaindex()
        wrapped_once = OverridingLLM.__dict__["complete"]
        r2 = fake_llamaindex.patch_llamaindex()

        assert r1.targets == r2.targets
        assert OverridingLLM.__dict__["complete"] is wrapped_once
