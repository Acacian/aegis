"""Comprehensive tests for aegis.instrument._google_adk module.

Covers:
- AegisPlugin: construction, engine resolution, on_block inheritance
- before_model_callback / after_model_callback: guardrail flow
- before_tool_callback / after_tool_callback: tool governance
- before_agent_callback / after_agent_callback: audit logging
- on_event_callback: event audit (transfers, state deltas)
- _extract_llm_request_text: contents + system_instruction
- _extract_llm_response_text: content.parts text extraction
- _extract_tool_text: tool name + args formatting
- _run_guardrails: engine=None, empty text, blocked raise/warn
- patch_google_adk / unpatch_google_adk: Runner patching, idempotent, no SDK
"""

from __future__ import annotations

import importlib
import logging
import sys
import types
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import pytest

from aegis.instrument._state import InstrumentationState

# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset instrumentation state and module flags before each test."""
    InstrumentationState.reset()

    import aegis.instrument._google_adk as _ga

    _ga._patched = False
    _ga._originals.clear()

    yield

    import aegis.instrument._google_adk as _ga2

    _ga2._patched = False
    _ga2._originals.clear()
    InstrumentationState.reset()


# =========================================================================
# Helper stubs
# =========================================================================


@dataclass
class FakePart:
    text: str | None = None


@dataclass
class FakeContent:
    parts: list[FakePart] = field(default_factory=list)


@dataclass
class FakeLlmRequest:
    contents: list[FakeContent] = field(default_factory=list)
    config: Any = None


@dataclass
class FakeLlmResponse:
    content: FakeContent | None = None


@dataclass
class FakeConfig:
    system_instruction: str | None = None


@dataclass
class FakeTool:
    name: str = "web_search"


@dataclass
class FakeActions:
    transfer_to_agent: str | None = None
    state_delta: dict[str, Any] | None = None


@dataclass
class FakeEvent:
    actions: FakeActions | None = None


@dataclass
class FakeAgent:
    name: str = "test_agent"


@dataclass
class FakeCallbackContext:
    agent: FakeAgent | None = None


class FakeBlockedResult:
    action = "blocked"
    details = "injection detected"
    guardrail_name = "injection"


class FakePassResult:
    action = "allowed"
    details = ""
    guardrail_name = "injection"


class FakeEngine:
    def __init__(self, results: list[Any] | None = None, error: bool = False):
        self._results = results or []
        self._error = error
        self.checked: list[str] = []

    def check(self, text: str) -> list[Any]:
        self.checked.append(text)
        if self._error:
            raise RuntimeError("engine error")
        return self._results


# =========================================================================
# Tests: _extract_llm_request_text
# =========================================================================


class TestExtractLlmRequestText:
    def test_empty_request(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        req = FakeLlmRequest()
        assert _extract_llm_request_text(req) == ""

    def test_single_content_single_part(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        req = FakeLlmRequest(contents=[FakeContent(parts=[FakePart(text="hello")])])
        assert _extract_llm_request_text(req) == "hello"

    def test_multiple_contents_multiple_parts(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        req = FakeLlmRequest(
            contents=[
                FakeContent(parts=[FakePart(text="a"), FakePart(text="b")]),
                FakeContent(parts=[FakePart(text="c")]),
            ]
        )
        assert _extract_llm_request_text(req) == "a\nb\nc"

    def test_with_system_instruction(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        req = FakeLlmRequest(
            contents=[FakeContent(parts=[FakePart(text="query")])],
            config=FakeConfig(system_instruction="be helpful"),
        )
        assert _extract_llm_request_text(req) == "query\nbe helpful"

    def test_none_parts_skipped(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        req = FakeLlmRequest(
            contents=[FakeContent(parts=[FakePart(text=None), FakePart(text="real")])]
        )
        assert _extract_llm_request_text(req) == "real"

    def test_no_contents_attribute(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        assert _extract_llm_request_text(object()) == ""

    def test_non_string_system_instruction_ignored(self):
        from aegis.instrument._google_adk import _extract_llm_request_text

        req = FakeLlmRequest(config=FakeConfig(system_instruction=12345))
        assert _extract_llm_request_text(req) == ""


# =========================================================================
# Tests: _extract_llm_response_text
# =========================================================================


class TestExtractLlmResponseText:
    def test_empty_response(self):
        from aegis.instrument._google_adk import _extract_llm_response_text

        resp = FakeLlmResponse()
        assert _extract_llm_response_text(resp) == ""

    def test_single_part(self):
        from aegis.instrument._google_adk import _extract_llm_response_text

        resp = FakeLlmResponse(content=FakeContent(parts=[FakePart(text="answer")]))
        assert _extract_llm_response_text(resp) == "answer"

    def test_returns_first_text(self):
        from aegis.instrument._google_adk import _extract_llm_response_text

        resp = FakeLlmResponse(
            content=FakeContent(parts=[FakePart(text="first"), FakePart(text="second")])
        )
        assert _extract_llm_response_text(resp) == "first"

    def test_no_content(self):
        from aegis.instrument._google_adk import _extract_llm_response_text

        assert _extract_llm_response_text(object()) == ""


# =========================================================================
# Tests: _extract_tool_text
# =========================================================================


class TestExtractToolText:
    def test_tool_with_args(self):
        from aegis.instrument._google_adk import _extract_tool_text

        tool = FakeTool(name="search")
        assert _extract_tool_text(tool, {"q": "test"}) == "search: {'q': 'test'}"

    def test_tool_without_args(self):
        from aegis.instrument._google_adk import _extract_tool_text

        tool = FakeTool(name="get_time")
        assert _extract_tool_text(tool, None) == "get_time"

    def test_tool_empty_args(self):
        from aegis.instrument._google_adk import _extract_tool_text

        tool = FakeTool(name="ping")
        assert _extract_tool_text(tool, {}) == "ping"

    def test_tool_no_name_attr(self):
        from aegis.instrument._google_adk import _extract_tool_text

        assert "object" in _extract_tool_text(object(), {"a": 1})


# =========================================================================
# Tests: _run_guardrails
# =========================================================================


class TestRunGuardrails:
    def test_none_engine(self):
        from aegis.instrument._google_adk import _run_guardrails

        _run_guardrails(None, "text", direction="input", on_block="raise")

    def test_empty_text(self):
        from aegis.instrument._google_adk import _run_guardrails

        engine = FakeEngine(results=[FakeBlockedResult()])
        _run_guardrails(engine, "", direction="input", on_block="raise")
        assert engine.checked == []

    def test_no_blocked_results(self):
        from aegis.instrument._google_adk import _run_guardrails

        engine = FakeEngine(results=[FakePassResult()])
        _run_guardrails(engine, "hello", direction="input", on_block="raise")
        assert engine.checked == ["hello"]

    def test_blocked_raise(self):
        from aegis.instrument._google_adk import _run_guardrails
        from aegis.integrations.errors import AegisGuardrailError

        engine = FakeEngine(results=[FakeBlockedResult()])
        with pytest.raises(AegisGuardrailError, match="injection detected"):
            _run_guardrails(engine, "attack", direction="input", on_block="raise")

    def test_blocked_warn(self, caplog):
        from aegis.instrument._google_adk import _run_guardrails

        engine = FakeEngine(results=[FakeBlockedResult()])
        with caplog.at_level(logging.WARNING, logger="aegis.instrument.google_adk"):
            _run_guardrails(engine, "attack", direction="input", on_block="warn")
        assert "Aegis blocked input" in caplog.text

    def test_engine_error_handled(self):
        from aegis.instrument._google_adk import _run_guardrails

        engine = FakeEngine(error=True)
        _run_guardrails(engine, "text", direction="input", on_block="raise")


# =========================================================================
# Tests: AegisPlugin construction & properties
# =========================================================================


class TestAegisPluginConstruction:
    def test_default_construction(self):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin()
        assert plugin.name == "aegis"
        assert plugin._guardrails is None
        assert plugin._on_block is None
        assert plugin._audit is True

    def test_custom_guardrails(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine()
        plugin = AegisPlugin(guardrails=engine, on_block="warn", audit=False)
        assert plugin._get_engine() is engine
        assert plugin._effective_on_block == "warn"
        assert plugin._audit is False

    def test_inherits_from_state(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine()
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="log")

        plugin = AegisPlugin()
        assert plugin._get_engine() is engine
        assert plugin._effective_on_block == "log"

    def test_on_block_default_when_inactive(self):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin()
        assert plugin._effective_on_block == "raise"


# =========================================================================
# Tests: AegisPlugin callbacks (async)
# =========================================================================


class TestAegisPluginBeforeModelCallback:
    @pytest.mark.asyncio
    async def test_passes_clean_input(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine(results=[FakePassResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")
        req = FakeLlmRequest(contents=[FakeContent(parts=[FakePart(text="hello")])])

        result = await plugin.before_model_callback(
            callback_context=FakeCallbackContext(), llm_request=req
        )
        assert result is None
        assert engine.checked == ["hello"]

    @pytest.mark.asyncio
    async def test_blocks_injection(self):
        from aegis.instrument._google_adk import AegisPlugin
        from aegis.integrations.errors import AegisGuardrailError

        engine = FakeEngine(results=[FakeBlockedResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")
        req = FakeLlmRequest(contents=[FakeContent(parts=[FakePart(text="ignore rules")])])

        with pytest.raises(AegisGuardrailError):
            await plugin.before_model_callback(
                callback_context=FakeCallbackContext(), llm_request=req
            )

    @pytest.mark.asyncio
    async def test_no_engine_passes(self):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin()
        req = FakeLlmRequest(contents=[FakeContent(parts=[FakePart(text="hello")])])

        result = await plugin.before_model_callback(
            callback_context=FakeCallbackContext(), llm_request=req
        )
        assert result is None


class TestAegisPluginAfterModelCallback:
    @pytest.mark.asyncio
    async def test_passes_clean_output(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine(results=[FakePassResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")
        resp = FakeLlmResponse(content=FakeContent(parts=[FakePart(text="response text")]))

        result = await plugin.after_model_callback(
            callback_context=FakeCallbackContext(), llm_response=resp
        )
        assert result is None
        assert engine.checked == ["response text"]

    @pytest.mark.asyncio
    async def test_blocks_output(self):
        from aegis.instrument._google_adk import AegisPlugin
        from aegis.integrations.errors import AegisGuardrailError

        engine = FakeEngine(results=[FakeBlockedResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")
        resp = FakeLlmResponse(content=FakeContent(parts=[FakePart(text="leaked secret")]))

        with pytest.raises(AegisGuardrailError):
            await plugin.after_model_callback(
                callback_context=FakeCallbackContext(), llm_response=resp
            )


class TestAegisPluginToolCallbacks:
    @pytest.mark.asyncio
    async def test_before_tool_passes(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine(results=[FakePassResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")

        result = await plugin.before_tool_callback(
            tool=FakeTool(name="search"),
            args={"query": "weather"},
            tool_context=MagicMock(),
        )
        assert result is None
        assert "search: {'query': 'weather'}" in engine.checked[0]

    @pytest.mark.asyncio
    async def test_before_tool_blocks(self):
        from aegis.instrument._google_adk import AegisPlugin
        from aegis.integrations.errors import AegisGuardrailError

        engine = FakeEngine(results=[FakeBlockedResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")

        with pytest.raises(AegisGuardrailError):
            await plugin.before_tool_callback(
                tool=FakeTool(name="exec"),
                args={"cmd": "rm -rf /"},
                tool_context=MagicMock(),
            )

    @pytest.mark.asyncio
    async def test_after_tool_passes(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine(results=[FakePassResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")

        result = await plugin.after_tool_callback(
            tool=FakeTool(name="search"),
            args={"query": "test"},
            tool_context=MagicMock(),
            tool_response={"results": ["page1"]},
        )
        assert result is None
        assert engine.checked  # checked the response text

    @pytest.mark.asyncio
    async def test_after_tool_empty_response(self):
        from aegis.instrument._google_adk import AegisPlugin

        engine = FakeEngine(results=[FakeBlockedResult()])
        plugin = AegisPlugin(guardrails=engine, on_block="raise")

        # Empty response should not trigger guardrails
        result = await plugin.after_tool_callback(
            tool=FakeTool(name="noop"),
            args={},
            tool_context=MagicMock(),
            tool_response=None,
        )
        assert result is None
        assert engine.checked == []


class TestAegisPluginAgentCallbacks:
    @pytest.mark.asyncio
    async def test_before_agent_logs(self, caplog):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=True)
        ctx = FakeCallbackContext(agent=FakeAgent(name="router"))

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.google_adk"):
            result = await plugin.before_agent_callback(callback_context=ctx)
        assert result is None
        assert "router" in caplog.text

    @pytest.mark.asyncio
    async def test_after_agent_logs(self, caplog):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=True)
        ctx = FakeCallbackContext(agent=FakeAgent(name="worker"))

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.google_adk"):
            result = await plugin.after_agent_callback(callback_context=ctx)
        assert result is None
        assert "worker" in caplog.text

    @pytest.mark.asyncio
    async def test_no_audit_skips_logging(self, caplog):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=False)
        ctx = FakeCallbackContext(agent=FakeAgent(name="secret"))

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.google_adk"):
            await plugin.before_agent_callback(callback_context=ctx)
        assert "secret" not in caplog.text


class TestAegisPluginEventCallback:
    @pytest.mark.asyncio
    async def test_logs_agent_transfer(self, caplog):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=True)
        event = FakeEvent(actions=FakeActions(transfer_to_agent="specialist"))

        with caplog.at_level(logging.INFO, logger="aegis.instrument.google_adk"):
            result = await plugin.on_event_callback(
                event=event, callback_context=FakeCallbackContext()
            )
        assert result is None
        assert "specialist" in caplog.text

    @pytest.mark.asyncio
    async def test_logs_state_delta(self, caplog):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=True)
        event = FakeEvent(actions=FakeActions(state_delta={"key1": "val1", "key2": "val2"}))

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.google_adk"):
            await plugin.on_event_callback(event=event, callback_context=FakeCallbackContext())
        assert "2 keys" in caplog.text

    @pytest.mark.asyncio
    async def test_no_actions(self):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=True)
        event = FakeEvent(actions=None)

        result = await plugin.on_event_callback(
            event=event, callback_context=FakeCallbackContext()
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_audit_off_skips(self, caplog):
        from aegis.instrument._google_adk import AegisPlugin

        plugin = AegisPlugin(audit=False)
        event = FakeEvent(actions=FakeActions(transfer_to_agent="x"))

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.google_adk"):
            await plugin.on_event_callback(event=event, callback_context=FakeCallbackContext())
        assert "x" not in caplog.text


# =========================================================================
# Tests: patch_google_adk / unpatch_google_adk
# =========================================================================


@pytest.fixture()
def mock_adk():
    """Inject fake google.adk into sys.modules and reload the instrument module.

    Returns (RunnerClass, teardown_fn).
    """
    saved = {}
    for k in list(sys.modules.keys()):
        if k.startswith("google.adk"):
            saved[k] = sys.modules.pop(k)

    # Build fake module tree: google.adk.runners, google.adk.plugins.base_plugin
    google = sys.modules.get("google") or types.ModuleType("google")
    adk = types.ModuleType("google.adk")
    runners = types.ModuleType("google.adk.runners")
    plugins = types.ModuleType("google.adk.plugins")
    base_plugin = types.ModuleType("google.adk.plugins.base_plugin")

    class BasePlugin:
        def __init__(self, name: str = ""):
            self._name = name

        @property
        def name(self) -> str:
            return self._name

    base_plugin.BasePlugin = BasePlugin  # type: ignore[attr-defined]

    class Runner:
        def __init__(self, *, app: Any = None, **kwargs: Any):
            self._app = app

    runners.Runner = Runner  # type: ignore[attr-defined]

    # Wire up module tree
    google.adk = adk  # type: ignore[attr-defined]
    adk.runners = runners  # type: ignore[attr-defined]
    adk.plugins = plugins  # type: ignore[attr-defined]
    plugins.base_plugin = base_plugin  # type: ignore[attr-defined]

    sys.modules["google"] = google
    sys.modules["google.adk"] = adk
    sys.modules["google.adk.runners"] = runners
    sys.modules["google.adk.plugins"] = plugins
    sys.modules["google.adk.plugins.base_plugin"] = base_plugin

    # Reload the module so it picks up the fake SDK
    import aegis.instrument._google_adk as _ga

    _ga._patched = False
    _ga._originals.clear()
    importlib.reload(_ga)

    def teardown():
        _ga._patched = False
        _ga._originals.clear()
        # Clean up fake modules
        for k in list(sys.modules.keys()):
            if k.startswith("google.adk"):
                sys.modules.pop(k, None)
        for k, v in saved.items():
            sys.modules[k] = v
        importlib.reload(_ga)

    yield Runner, teardown

    teardown()


class TestPatchGoogleAdk:
    def test_patch_with_adk(self, mock_adk):
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        state = InstrumentationState.get()
        engine = FakeEngine(results=[FakePassResult()])
        state.configure(guardrail_engine=engine, on_block="raise")

        result = _ga.patch_google_adk()
        assert result.patched is True
        assert "Runner.__init__" in result.targets
        assert _ga._patched is True

    def test_idempotent(self, mock_adk):
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        state = InstrumentationState.get()
        state.configure(guardrail_engine=FakeEngine())

        r1 = _ga.patch_google_adk()
        r2 = _ga.patch_google_adk()
        assert r1.patched is True
        assert r2.patched is True
        assert r1.targets == r2.targets

    def test_no_sdk(self):
        """When google-adk is not installed, patch records a skip."""
        import aegis.instrument._google_adk as _ga

        result = _ga.patch_google_adk()
        assert result.patched is False
        assert "not installed" in (result.error or "")

    def test_runner_auto_injects_plugin(self, mock_adk):
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        engine = FakeEngine(results=[FakePassResult()])
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="warn")

        _ga.patch_google_adk()

        # Create a fake app with mutable plugins list
        app = MagicMock()
        app.plugins = []

        # Runner creation should auto-inject AegisPlugin
        from google.adk.runners import Runner

        Runner(app=app)
        assert len(app.plugins) == 1
        assert app.plugins[0].name == "aegis"

    def test_runner_no_duplicate_injection(self, mock_adk):
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        state = InstrumentationState.get()
        state.configure(guardrail_engine=FakeEngine())
        _ga.patch_google_adk()

        # App already has AegisPlugin
        existing = _ga.AegisPlugin()
        app = MagicMock()
        app.plugins = [existing]

        from google.adk.runners import Runner

        Runner(app=app)
        assert len(app.plugins) == 1  # no duplicate

    def test_runner_none_app(self, mock_adk):
        """Runner without app should not crash."""
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        state = InstrumentationState.get()
        state.configure(guardrail_engine=FakeEngine())
        _ga.patch_google_adk()

        from google.adk.runners import Runner

        Runner(app=None)  # should not raise


class TestUnpatchGoogleAdk:
    def test_unpatch_restores(self, mock_adk):
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        state = InstrumentationState.get()
        state.configure(guardrail_engine=FakeEngine())

        _ga.patch_google_adk()
        assert _ga._patched is True

        _ga.unpatch_google_adk()
        assert _ga._patched is False
        assert len(_ga._originals) == 0

    def test_unpatch_noop_when_not_patched(self):
        import aegis.instrument._google_adk as _ga

        _ga.unpatch_google_adk()  # should not raise


# =========================================================================
# Tests: State registration
# =========================================================================


class TestStateRegistration:
    def test_patch_registers_state(self, mock_adk):
        RunnerClass, teardown = mock_adk

        import aegis.instrument._google_adk as _ga

        state = InstrumentationState.get()
        state.configure(guardrail_engine=FakeEngine())

        _ga.patch_google_adk()
        assert state.is_patched("google_adk")
        p = state.get_patch("google_adk")
        assert p is not None
        assert p.patched is True

    def test_skip_registers_state(self):
        import aegis.instrument._google_adk as _ga

        _ga.patch_google_adk()
        state = InstrumentationState.get()
        p = state.get_patch("google_adk")
        assert p is not None
        assert p.patched is False


# =========================================================================
# Tests: Integration with auto_instrument registry
# =========================================================================


class TestRegistryIntegration:
    def test_registered_in_framework_registry(self):
        from aegis.instrument import _FRAMEWORK_REGISTRY

        assert "google_adk" in _FRAMEWORK_REGISTRY
        patch_fn, unpatch_fn = _FRAMEWORK_REGISTRY["google_adk"]
        assert callable(patch_fn)
        assert callable(unpatch_fn)

    def test_in_all_exports(self):
        from aegis.instrument import __all__

        assert "patch_google_adk" in __all__
        assert "unpatch_google_adk" in __all__
