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

# =========================================================================
# Helpers — Fake LlamaIndex classes
# =========================================================================


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


# =========================================================================
# Fixtures
# =========================================================================


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


# =========================================================================
# Helper to build a mock guardrail engine
# =========================================================================


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


# =========================================================================
# Extraction helpers
# =========================================================================


class TestExtractChatInput:
    def test_from_positional_args_with_content_attr(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        msg = FakeChatMessage(content="hello world")
        result = _extract_chat_input(([msg],), {})
        assert result == "hello world"

    def test_from_kwargs(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        msg = FakeChatMessage(content="from kwarg")
        result = _extract_chat_input((), {"messages": [msg]})
        assert result == "from kwarg"

    def test_dict_messages(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        msgs = [{"content": "dict content", "role": "user"}]
        result = _extract_chat_input((msgs,), {})
        assert result == "dict content"

    def test_dict_message_non_string_content(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        msgs = [{"content": 123, "role": "user"}]
        result = _extract_chat_input((msgs,), {})
        assert result == ""

    def test_multiple_messages_joined(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        msgs = [
            FakeChatMessage(content="first"),
            FakeChatMessage(content="second"),
        ]
        result = _extract_chat_input((msgs,), {})
        assert result == "first\nsecond"

    def test_empty_messages(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        result = _extract_chat_input((), {})
        assert result == ""

    def test_non_list_messages(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        result = _extract_chat_input(("raw string",), {})
        assert result == "raw string"

    def test_empty_list(self):
        from aegis.instrument._llamaindex import _extract_chat_input

        result = _extract_chat_input(([],), {})
        assert result == ""

    def test_message_without_content_attr(self):
        """Object in list that has no .content and is not a dict."""
        from aegis.instrument._llamaindex import _extract_chat_input

        obj = MagicMock(spec=[])  # no attributes
        result = _extract_chat_input(([obj],), {})
        assert result == ""


class TestExtractPrompt:
    def test_from_positional_arg(self):
        from aegis.instrument._llamaindex import _extract_prompt

        result = _extract_prompt(("hello prompt",), {})
        assert result == "hello prompt"

    def test_from_kwarg(self):
        from aegis.instrument._llamaindex import _extract_prompt

        result = _extract_prompt((), {"prompt": "kwarg prompt"})
        assert result == "kwarg prompt"

    def test_non_string_prompt(self):
        from aegis.instrument._llamaindex import _extract_prompt

        result = _extract_prompt((12345,), {})
        assert result == "12345"

    def test_none_prompt(self):
        from aegis.instrument._llamaindex import _extract_prompt

        result = _extract_prompt((), {})
        assert result == ""

    def test_none_value_prompt(self):
        from aegis.instrument._llamaindex import _extract_prompt

        result = _extract_prompt((None,), {})
        assert result == ""


class TestExtractChatOutput:
    def test_normal_response(self):
        from aegis.instrument._llamaindex import _extract_chat_output

        resp = FakeChatResponse(message=FakeChatMessage(content="output text"))
        result = _extract_chat_output(resp)
        assert result == "output text"

    def test_no_message(self):
        from aegis.instrument._llamaindex import _extract_chat_output

        resp = FakeChatResponse(message=None)
        result = _extract_chat_output(resp)
        assert result == ""

    def test_no_content(self):
        from aegis.instrument._llamaindex import _extract_chat_output

        msg = MagicMock()
        msg.content = None
        resp = MagicMock()
        resp.message = msg
        result = _extract_chat_output(resp)
        assert result == ""

    def test_non_string_content(self):
        from aegis.instrument._llamaindex import _extract_chat_output

        msg = MagicMock()
        msg.content = 42
        resp = MagicMock()
        resp.message = msg
        result = _extract_chat_output(resp)
        assert result == ""

    def test_no_message_attr(self):
        from aegis.instrument._llamaindex import _extract_chat_output

        result = _extract_chat_output(object())
        assert result == ""


class TestExtractCompletionOutput:
    def test_normal(self):
        from aegis.instrument._llamaindex import _extract_completion_output

        resp = FakeCompletionResponse(text="completion text")
        result = _extract_completion_output(resp)
        assert result == "completion text"

    def test_no_text(self):
        from aegis.instrument._llamaindex import _extract_completion_output

        result = _extract_completion_output(object())
        assert result == ""

    def test_non_string_text(self):
        from aegis.instrument._llamaindex import _extract_completion_output

        obj = MagicMock()
        obj.text = 123
        result = _extract_completion_output(obj)
        assert result == ""


class TestExtractQueryInput:
    def test_string_query(self):
        from aegis.instrument._llamaindex import _extract_query_input

        result = _extract_query_input(("my query",), {})
        assert result == "my query"

    def test_query_bundle(self):
        from aegis.instrument._llamaindex import _extract_query_input

        bundle = FakeQueryBundle(query_str="bundle query")
        result = _extract_query_input((bundle,), {})
        assert result == "bundle query"

    def test_from_kwarg(self):
        from aegis.instrument._llamaindex import _extract_query_input

        result = _extract_query_input((), {"str_or_query_bundle": "kwarg query"})
        assert result == "kwarg query"

    def test_empty(self):
        from aegis.instrument._llamaindex import _extract_query_input

        result = _extract_query_input((), {})
        assert result == ""

    def test_non_string_non_bundle(self):
        from aegis.instrument._llamaindex import _extract_query_input

        obj = MagicMock(spec=[])  # no query_str
        result = _extract_query_input((obj,), {})
        assert isinstance(result, str)

    def test_query_bundle_non_string_query_str(self):
        from aegis.instrument._llamaindex import _extract_query_input

        bundle = MagicMock()
        bundle.query_str = 999
        result = _extract_query_input((bundle,), {})
        assert isinstance(result, str)


class TestExtractQueryOutput:
    def test_normal(self):
        from aegis.instrument._llamaindex import _extract_query_output

        resp = FakeQueryResponse(response="query response text")
        result = _extract_query_output(resp)
        assert result == "query response text"

    def test_no_response_attr(self):
        from aegis.instrument._llamaindex import _extract_query_output

        result = _extract_query_output(object())
        assert result == ""

    def test_non_string_response(self):
        from aegis.instrument._llamaindex import _extract_query_output

        obj = MagicMock()
        obj.response = 42
        result = _extract_query_output(obj)
        assert result == ""


# =========================================================================
# _run_guardrails
# =========================================================================


class TestRunGuardrails:
    def test_noop_when_engine_is_none(self):
        from aegis.instrument._llamaindex import _run_guardrails

        # Should not raise
        _run_guardrails(None, "some text", direction="input", on_block="raise")

    def test_noop_when_text_is_empty(self):
        from aegis.instrument._llamaindex import _run_guardrails

        engine = _make_engine()
        _run_guardrails(engine, "", direction="input", on_block="raise")
        engine.check.assert_not_called()

    def test_allowed_passes(self):
        from aegis.instrument._llamaindex import _run_guardrails

        engine = _make_engine(action="allowed")
        _run_guardrails(engine, "safe text", direction="input", on_block="raise")
        engine.check.assert_called_once_with("safe text")

    def test_blocked_raises_when_on_block_raise(self):
        from aegis.instrument._llamaindex import _run_guardrails

        engine = _make_engine(action="blocked")
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            _run_guardrails(engine, "bad text", direction="input", on_block="raise")

    def test_blocked_warns_when_on_block_warn(self):
        from aegis.instrument._llamaindex import _run_guardrails

        engine = _make_engine(action="blocked")
        # Should NOT raise, just log warning
        _run_guardrails(engine, "bad text", direction="output", on_block="warn")

    def test_engine_exception_handled_gracefully(self):
        from aegis.instrument._llamaindex import _run_guardrails

        engine = MagicMock()
        engine.check.side_effect = RuntimeError("boom")
        # Should not raise
        _run_guardrails(engine, "text", direction="input", on_block="raise")

    def test_blocked_result_details_fallback_to_guardrail_name(self):
        from aegis.instrument._llamaindex import _run_guardrails

        result = MagicMock()
        result.action = "blocked"
        result.details = ""
        result.guardrail_name = "fallback_name"
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="fallback_name"):
            _run_guardrails(engine, "bad text", direction="input", on_block="raise")


# =========================================================================
# patch_llamaindex / unpatch_llamaindex — without LlamaIndex
# =========================================================================


class TestPatchWithoutLlamaIndex:
    def test_patch_returns_not_patched(self):
        from aegis.instrument._llamaindex import patch_llamaindex

        result = patch_llamaindex()
        assert result.patched is False
        assert result.error == "llama-index-core not installed"
        assert result.name == "llamaindex"

    def test_registered_in_state(self):
        from aegis.instrument._llamaindex import patch_llamaindex

        patch_llamaindex()
        s = InstrumentationState.get()
        p = s.get_patch("llamaindex")
        assert p is not None
        assert p.patched is False


# =========================================================================
# patch_llamaindex / unpatch_llamaindex — with fake LlamaIndex
# =========================================================================


class TestPatchWithFakeLlamaIndex:
    def test_patch_succeeds(self, fake_llamaindex):
        _li = fake_llamaindex
        result = _li.patch_llamaindex()
        assert result.patched is True
        assert result.name == "llamaindex"
        assert "LLM.chat" in result.targets
        assert "LLM.achat" in result.targets
        assert "LLM.complete" in result.targets
        assert "LLM.acomplete" in result.targets
        assert "BaseQueryEngine.query" in result.targets
        assert "BaseQueryEngine.aquery" in result.targets

    def test_patch_idempotent(self, fake_llamaindex):
        _li = fake_llamaindex
        r1 = _li.patch_llamaindex()
        r2 = _li.patch_llamaindex()
        assert r1.patched is True
        assert r2.patched is True
        assert r1.targets == r2.targets

    def test_unpatch_restores_originals(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()
        assert _li._patched is True

        _li.unpatch_llamaindex()
        assert _li._patched is False
        assert len(_li._originals) == 0

    def test_unpatch_noop_if_not_patched(self, fake_llamaindex):
        _li = fake_llamaindex
        # Should not raise
        _li.unpatch_llamaindex()
        assert _li._patched is False

    def test_registered_in_state(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()
        s = InstrumentationState.get()
        assert s.is_patched("llamaindex")


# =========================================================================
# Governed wrappers — sync
# =========================================================================


class TestGovernedChat:
    def test_chat_passthrough_no_engine(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=None, on_block="raise")

        llm = FakeLLM()
        msgs = [FakeChatMessage(content="hello")]
        resp = FakeLLM.chat(llm, msgs)
        assert resp.message.content == "llm chat reply"

    def test_chat_with_allowed_guardrail(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        msgs = [FakeChatMessage(content="hello")]
        resp = FakeLLM.chat(llm, msgs)
        assert resp.message.content == "llm chat reply"
        assert engine.check.call_count == 2  # input + output

    def test_chat_blocked_input_raises(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        msgs = [FakeChatMessage(content="bad input")]
        with pytest.raises(AegisGuardrailError, match="blocked input"):
            FakeLLM.chat(llm, msgs)

    def test_chat_blocked_warn_mode(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="warn")

        llm = FakeLLM()
        msgs = [FakeChatMessage(content="bad input")]
        resp = FakeLLM.chat(llm, msgs)
        assert resp.message.content == "llm chat reply"


class TestGovernedComplete:
    def test_complete_passthrough(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=None)

        llm = FakeLLM()
        resp = FakeLLM.complete(llm, "hello prompt")
        assert resp.text == "llm complete reply"

    def test_complete_with_guardrail(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        resp = FakeLLM.complete(llm, "prompt text")
        assert resp.text == "llm complete reply"
        assert engine.check.call_count == 2

    def test_complete_blocked_raises(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        with pytest.raises(AegisGuardrailError, match="blocked input"):
            FakeLLM.complete(llm, "bad prompt")


class TestGovernedQuery:
    def test_query_passthrough(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=None)

        qe = FakeBaseQueryEngine()
        resp = FakeBaseQueryEngine.query(qe, "my query")
        assert resp.response == "query reply"

    def test_query_with_guardrail(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        resp = FakeBaseQueryEngine.query(qe, "my query")
        assert resp.response == "query reply"
        assert engine.check.call_count == 2

    def test_query_blocked_raises(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        with pytest.raises(AegisGuardrailError, match="blocked query_input"):
            FakeBaseQueryEngine.query(qe, "bad query")

    def test_query_with_bundle(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        bundle = FakeQueryBundle(query_str="bundled query")
        resp = FakeBaseQueryEngine.query(qe, bundle)
        assert resp.response == "query reply"
        engine.check.assert_any_call("bundled query")


# =========================================================================
# Governed wrappers — async
# =========================================================================


class TestGovernedAchat:
    def test_achat_passthrough(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=None)

        llm = FakeLLM()
        resp = asyncio.get_event_loop().run_until_complete(
            FakeLLM.achat(llm, [FakeChatMessage(content="hi")])
        )
        assert resp.message.content == "llm achat reply"

    def test_achat_blocked_raises(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        with pytest.raises(AegisGuardrailError, match="blocked input"):
            asyncio.get_event_loop().run_until_complete(
                FakeLLM.achat(llm, [FakeChatMessage(content="bad")])
            )

    def test_achat_with_allowed_guardrail(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        resp = asyncio.get_event_loop().run_until_complete(
            FakeLLM.achat(llm, [FakeChatMessage(content="hello")])
        )
        assert resp.message.content == "llm achat reply"
        assert engine.check.call_count == 2


class TestGovernedAcomplete:
    def test_acomplete_passthrough(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=None)

        llm = FakeLLM()
        resp = asyncio.get_event_loop().run_until_complete(FakeLLM.acomplete(llm, "prompt"))
        assert resp.text == "llm acomplete reply"

    def test_acomplete_blocked_raises(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        with pytest.raises(AegisGuardrailError, match="blocked input"):
            asyncio.get_event_loop().run_until_complete(FakeLLM.acomplete(llm, "bad prompt"))


class TestGovernedAquery:
    def test_aquery_passthrough(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        state = InstrumentationState.get()
        state.configure(guardrail_engine=None)

        qe = FakeBaseQueryEngine()
        resp = asyncio.get_event_loop().run_until_complete(
            FakeBaseQueryEngine.aquery(qe, "async query")
        )
        assert resp.response == "aquery reply"

    def test_aquery_blocked_raises(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="blocked")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        with pytest.raises(AegisGuardrailError, match="blocked query_input"):
            asyncio.get_event_loop().run_until_complete(
                FakeBaseQueryEngine.aquery(qe, "bad async query")
            )

    def test_aquery_with_allowed_guardrail(self, fake_llamaindex):
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        resp = asyncio.get_event_loop().run_until_complete(
            FakeBaseQueryEngine.aquery(qe, "safe query")
        )
        assert resp.response == "aquery reply"
        assert engine.check.call_count == 2


# =========================================================================
# Partial import failure (only LLM available, no BaseQueryEngine)
# =========================================================================


class TestPartialImportFailure:
    def test_only_llm_available(self):
        """When BaseQueryEngine import fails, only LLM targets are patched."""
        llama_index = types.ModuleType("llama_index")
        llama_index_core = types.ModuleType("llama_index.core")
        llama_index_core_llms = types.ModuleType("llama_index.core.llms")
        llama_index_core_llms.LLM = FakeLLM

        llama_index.core = llama_index_core
        llama_index_core.llms = llama_index_core_llms

        mod_names = [
            "llama_index",
            "llama_index.core",
            "llama_index.core.llms",
        ]
        for name in mod_names:
            sys.modules[name] = {
                "llama_index": llama_index,
                "llama_index.core": llama_index_core,
                "llama_index.core.llms": llama_index_core_llms,
            }[name]

        # Remove base query engine modules to force ImportError
        sys.modules.pop("llama_index.core.base", None)
        sys.modules.pop("llama_index.core.base.base_query_engine", None)

        import aegis.instrument._llamaindex as _li

        _li._patched = False
        _li._originals.clear()
        importlib.reload(_li)

        try:
            result = _li.patch_llamaindex()
            assert result.patched is True
            assert "LLM.chat" in result.targets
            assert "BaseQueryEngine.query" not in result.targets
        finally:
            _li.unpatch_llamaindex()
            _li._patched = False
            _li._originals.clear()
            for name in mod_names:
                sys.modules.pop(name, None)
            importlib.reload(_li)

    def test_only_query_engine_available(self):
        """When LLM import fails, only BaseQueryEngine targets are patched."""
        llama_index = types.ModuleType("llama_index")
        llama_index_core = types.ModuleType("llama_index.core")
        llama_index_core_base = types.ModuleType("llama_index.core.base")
        llama_index_core_base_bqe = types.ModuleType("llama_index.core.base.base_query_engine")
        llama_index_core_base_bqe.BaseQueryEngine = FakeBaseQueryEngine

        llama_index.core = llama_index_core
        llama_index_core.base = llama_index_core_base
        llama_index_core_base.base_query_engine = llama_index_core_base_bqe

        mod_names = [
            "llama_index",
            "llama_index.core",
            "llama_index.core.base",
            "llama_index.core.base.base_query_engine",
        ]
        mod_map = {
            "llama_index": llama_index,
            "llama_index.core": llama_index_core,
            "llama_index.core.base": llama_index_core_base,
            "llama_index.core.base.base_query_engine": llama_index_core_base_bqe,
        }
        for name in mod_names:
            sys.modules[name] = mod_map[name]

        # Remove LLM modules
        sys.modules.pop("llama_index.core.llms", None)

        import aegis.instrument._llamaindex as _li

        _li._patched = False
        _li._originals.clear()
        importlib.reload(_li)

        try:
            result = _li.patch_llamaindex()
            assert result.patched is True
            assert "BaseQueryEngine.query" in result.targets
            assert "BaseQueryEngine.aquery" in result.targets
            assert "LLM.chat" not in result.targets
        finally:
            _li.unpatch_llamaindex()
            _li._patched = False
            _li._originals.clear()
            for name in mod_names:
                sys.modules.pop(name, None)
            importlib.reload(_li)


# =========================================================================
# Edge cases
# =========================================================================


class TestEdgeCases:
    def test_chat_with_kwargs_messages(self, fake_llamaindex):
        """Chat called with messages as keyword argument."""
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        msgs = [FakeChatMessage(content="kwarg message")]
        resp = FakeLLM.chat(llm, messages=msgs)
        assert resp.message.content == "llm chat reply"

    def test_complete_with_kwargs_prompt(self, fake_llamaindex):
        """Complete called with prompt as keyword argument."""
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        resp = FakeLLM.complete(llm, prompt="kwarg prompt")
        assert resp.text == "llm complete reply"
        engine.check.assert_any_call("kwarg prompt")

    def test_query_with_kwargs(self, fake_llamaindex):
        """Query called with str_or_query_bundle as keyword argument."""
        _li = fake_llamaindex
        _li.patch_llamaindex()

        engine = _make_engine(action="allowed")
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        resp = FakeBaseQueryEngine.query(qe, str_or_query_bundle="kwarg query")
        assert resp.response == "query reply"
        engine.check.assert_any_call("kwarg query")

    def test_blocked_output_on_chat(self, fake_llamaindex):
        """Guardrail allows input but blocks output."""
        _li = fake_llamaindex
        _li.patch_llamaindex()

        # First call (input) returns allowed, second call (output) returns blocked
        allowed_result = MagicMock()
        allowed_result.action = "allowed"
        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "toxic output"
        blocked_result.guardrail_name = "toxicity"

        engine = MagicMock()
        engine.check.side_effect = [[allowed_result], [blocked_result]]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        msgs = [FakeChatMessage(content="ok input")]
        with pytest.raises(AegisGuardrailError, match="blocked output"):
            FakeLLM.chat(llm, msgs)

    def test_blocked_output_on_complete(self, fake_llamaindex):
        """Guardrail allows input but blocks output on complete."""
        _li = fake_llamaindex
        _li.patch_llamaindex()

        allowed_result = MagicMock()
        allowed_result.action = "allowed"
        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "sensitive output"
        blocked_result.guardrail_name = "pii"

        engine = MagicMock()
        engine.check.side_effect = [[allowed_result], [blocked_result]]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        llm = FakeLLM()
        with pytest.raises(AegisGuardrailError, match="blocked output"):
            FakeLLM.complete(llm, "safe prompt")

    def test_blocked_output_on_query(self, fake_llamaindex):
        """Guardrail allows input but blocks output on query."""
        _li = fake_llamaindex
        _li.patch_llamaindex()

        allowed_result = MagicMock()
        allowed_result.action = "allowed"
        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "leaked info"
        blocked_result.guardrail_name = "leak"

        engine = MagicMock()
        engine.check.side_effect = [[allowed_result], [blocked_result]]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        qe = FakeBaseQueryEngine()
        with pytest.raises(AegisGuardrailError, match="blocked query_output"):
            FakeBaseQueryEngine.query(qe, "safe query")

    def test_multiple_blocked_results_joined(self):
        """Multiple blocked results have their details joined with semicolons."""
        from aegis.instrument._llamaindex import _run_guardrails

        r1 = MagicMock()
        r1.action = "blocked"
        r1.details = "detail1"
        r1.guardrail_name = "g1"

        r2 = MagicMock()
        r2.action = "blocked"
        r2.details = "detail2"
        r2.guardrail_name = "g2"

        engine = MagicMock()
        engine.check.return_value = [r1, r2]

        with pytest.raises(AegisGuardrailError, match="detail1; detail2"):
            _run_guardrails(engine, "bad text", direction="input", on_block="raise")
