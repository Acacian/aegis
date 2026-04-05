"""Comprehensive tests for aegis.integrations.patch_anthropic.

Covers helper functions, guardrail logic, audit logging, resolve_guardrails,
sync/async wrappers, and ImportError handling.

Since the anthropic package may not be installed, we create mock module
structures and patch sys.modules so the patch functions can import them.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from aegis.integrations.errors import AegisGuardrailError

# ====================================================================== #
# Helpers
# ====================================================================== #


def _get_module():
    """Return the aegis.integrations.patch_anthropic *module*."""
    importlib.import_module("aegis.integrations.patch_anthropic")
    return sys.modules["aegis.integrations.patch_anthropic"]


def _build_fake_anthropic():
    """Build a fake ``anthropic.resources.messages`` module tree."""
    messages_mod = types.ModuleType("anthropic.resources.messages")

    class FakeMessages:
        def create(self, *args, **kwargs):
            text_block = MagicMock(type="text", text="anthropic response")
            return MagicMock(
                content=[text_block],
                model="claude-3-opus",
                usage=MagicMock(input_tokens=8, output_tokens=4),
            )

    class FakeAsyncMessages:
        async def create(self, *args, **kwargs):
            text_block = MagicMock(type="text", text="async anthropic response")
            return MagicMock(
                content=[text_block],
                model="claude-3-opus",
                usage=MagicMock(input_tokens=8, output_tokens=4),
            )

    messages_mod.Messages = FakeMessages
    messages_mod.AsyncMessages = FakeAsyncMessages

    anthropic_mod = types.ModuleType("anthropic")
    resources_mod = types.ModuleType("anthropic.resources")

    return {
        "anthropic": anthropic_mod,
        "anthropic.resources": resources_mod,
        "anthropic.resources.messages": messages_mod,
    }


# ====================================================================== #
# Fixtures
# ====================================================================== #


@pytest.fixture()
def fake_anthropic():
    """Install fake anthropic modules and reset patch state for each test."""
    mods = _build_fake_anthropic()
    originals = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)

    mod = _get_module()
    mod._patched = False
    mod._original_create = None
    mod._original_async_create = None

    yield mods

    for k, v in originals.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v

    mod._patched = False
    mod._original_create = None
    mod._original_async_create = None


# ====================================================================== #
# _extract_messages_text
# ====================================================================== #


class TestExtractMessagesText:
    def test_simple_string_content(self):
        mod = _get_module()
        messages = [
            {"role": "user", "content": "Hello Claude!"},
            {"role": "assistant", "content": "Hi there."},
        ]
        result = mod._extract_messages_text(messages)
        assert "Hello Claude!" in result
        assert "Hi there." in result

    def test_multipart_content_blocks(self):
        mod = _get_module()
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this."},
                    {"type": "image", "source": {"data": "base64..."}},
                ],
            }
        ]
        result = mod._extract_messages_text(messages)
        assert "Describe this." in result

    def test_non_list_input_returns_empty(self):
        mod = _get_module()
        assert mod._extract_messages_text("not a list") == ""
        assert mod._extract_messages_text(None) == ""
        assert mod._extract_messages_text(42) == ""

    def test_pydantic_like_objects(self):
        mod = _get_module()
        msg = MagicMock()
        msg.content = "pydantic message"
        result = mod._extract_messages_text([msg])
        assert "pydantic message" in result

    def test_pydantic_object_non_string_content(self):
        mod = _get_module()
        msg = MagicMock(spec=[])
        msg.content = 12345
        result = mod._extract_messages_text([msg])
        assert result == ""

    def test_dict_with_non_string_non_list_content(self):
        mod = _get_module()
        messages = [{"role": "user", "content": 999}]
        result = mod._extract_messages_text(messages)
        assert result == ""

    def test_empty_messages_list(self):
        mod = _get_module()
        assert mod._extract_messages_text([]) == ""

    def test_multipart_missing_text_key(self):
        mod = _get_module()
        messages = [
            {
                "role": "user",
                "content": [{"type": "text"}],  # no "text" key
            }
        ]
        result = mod._extract_messages_text(messages)
        assert result == ""

    def test_multipart_non_dict_block(self):
        mod = _get_module()
        messages = [
            {
                "role": "user",
                "content": ["raw string", {"type": "text", "text": "actual"}],
            }
        ]
        result = mod._extract_messages_text(messages)
        assert "actual" in result

    def test_dict_missing_content_key(self):
        mod = _get_module()
        messages = [{"role": "user"}]
        result = mod._extract_messages_text(messages)
        assert result == ""


# ====================================================================== #
# _extract_response_text
# ====================================================================== #


class TestExtractResponseText:
    def test_normal_response(self):
        mod = _get_module()
        block = MagicMock(type="text", text="Hello from Claude")
        response = MagicMock(content=[block])
        assert mod._extract_response_text(response) == "Hello from Claude"

    def test_multiple_content_blocks(self):
        mod = _get_module()
        block1 = MagicMock(type="text", text="First block")
        block2 = MagicMock(type="text", text="Second block")
        response = MagicMock(content=[block1, block2])
        result = mod._extract_response_text(response)
        assert "First block" in result
        assert "Second block" in result

    def test_non_text_blocks_skipped(self):
        mod = _get_module()
        text_block = MagicMock(type="text", text="Hello")
        tool_block = MagicMock(type="tool_use", text="should be skipped")
        response = MagicMock(content=[text_block, tool_block])
        result = mod._extract_response_text(response)
        assert "Hello" in result
        assert "should be skipped" not in result

    def test_no_content(self):
        mod = _get_module()
        response = MagicMock(content=None)
        assert mod._extract_response_text(response) == ""

    def test_empty_content(self):
        mod = _get_module()
        response = MagicMock(content=[])
        assert mod._extract_response_text(response) == ""

    def test_non_string_text_in_block(self):
        mod = _get_module()
        block = MagicMock(type="text", text=None)
        response = MagicMock(content=[block])
        assert mod._extract_response_text(response) == ""

    def test_exception_returns_empty(self):
        mod = _get_module()
        broken = MagicMock()
        broken.content.__iter__ = MagicMock(side_effect=RuntimeError("broken"))
        assert mod._extract_response_text(broken) == ""


# ====================================================================== #
# _extract_usage
# ====================================================================== #


class TestExtractUsage:
    def test_normal_usage(self):
        mod = _get_module()
        response = MagicMock(
            model="claude-3-opus",
            usage=MagicMock(input_tokens=8, output_tokens=4),
        )
        usage = mod._extract_usage(response)
        assert usage["model"] == "claude-3-opus"
        assert usage["input_tokens"] == 8
        assert usage["output_tokens"] == 4
        assert usage["total_tokens"] == 12

    def test_no_usage(self):
        mod = _get_module()
        response = MagicMock(model="claude-3-opus", usage=None)
        usage = mod._extract_usage(response)
        assert usage["model"] == "claude-3-opus"
        assert "input_tokens" not in usage

    def test_no_model(self):
        mod = _get_module()
        response = MagicMock(spec=[])
        usage = mod._extract_usage(response)
        assert usage.get("model") is None


# ====================================================================== #
# _run_guardrails
# ====================================================================== #


class TestRunGuardrails:
    def test_none_engine_returns_empty(self):
        mod = _get_module()
        result = mod._run_guardrails(None, "some text", direction="input", on_block="raise")
        assert result == []

    def test_engine_returns_results(self):
        mod = _get_module()
        engine = MagicMock()
        result_obj = MagicMock(action="allowed")
        engine.check.return_value = [result_obj]
        results = mod._run_guardrails(engine, "hello", direction="input", on_block="raise")
        assert len(results) == 1
        engine.check.assert_called_once_with("hello")

    def test_blocked_with_raise(self):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="bad content", guardrail_name="toxicity")
        engine.check.return_value = [blocked]

        with pytest.raises(AegisGuardrailError, match="input"):
            mod._run_guardrails(engine, "bad", direction="input", on_block="raise")

    def test_blocked_with_log(self):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="bad content", guardrail_name="toxicity")
        engine.check.return_value = [blocked]

        results = mod._run_guardrails(engine, "bad", direction="input", on_block="log")
        assert len(results) == 1  # returns results, does not raise

    def test_blocked_with_other_strategy(self):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="bad", guardrail_name="test")
        engine.check.return_value = [blocked]

        results = mod._run_guardrails(engine, "bad", direction="input", on_block="return_none")
        assert len(results) == 1

    def test_engine_exception_returns_blocking_result(self):
        mod = _get_module()
        engine = MagicMock()
        engine.check.side_effect = RuntimeError("engine crashed")

        results = mod._run_guardrails(engine, "text", direction="input", on_block="raise")
        assert len(results) == 1
        assert results[0].passed is False
        assert results[0].action == "blocked"
        assert results[0].guardrail_name == "aegis.error"

    def test_blocked_details_fallback_to_guardrail_name(self):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="", guardrail_name="pii_detector")
        engine.check.return_value = [blocked]

        with pytest.raises(AegisGuardrailError, match="pii_detector"):
            mod._run_guardrails(engine, "text", direction="output", on_block="raise")

    def test_blocked_no_details_no_name(self):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(spec=[])
        blocked.action = "blocked"
        engine.check.return_value = [blocked]

        with pytest.raises(AegisGuardrailError, match="unknown"):
            mod._run_guardrails(engine, "text", direction="output", on_block="raise")


# ====================================================================== #
# _audit_log
# ====================================================================== #


class TestAuditLog:
    def test_none_logger_is_noop(self):
        mod = _get_module()
        mod._audit_log(
            None,
            "session123",
            model="claude-3-opus",
            messages_text="hello",
            response_text="world",
            usage={},
            guardrail_results_input=[],
            guardrail_results_output=[],
        )

    def test_with_logger_calls_log(self):
        mod = _get_module()
        audit_logger = MagicMock()

        mod._audit_log(
            audit_logger,
            "session123",
            model="claude-3-opus",
            messages_text="hello",
            response_text="world",
            usage={"input_tokens": 8},
            guardrail_results_input=[],
            guardrail_results_output=[],
        )

        audit_logger.log.assert_called_once()
        call_args = audit_logger.log.call_args
        assert call_args[0][0] == "session123"

    def test_with_none_model(self):
        mod = _get_module()
        audit_logger = MagicMock()

        mod._audit_log(
            audit_logger,
            "session123",
            model=None,
            messages_text="hello",
            response_text="world",
            usage={},
            guardrail_results_input=[],
            guardrail_results_output=[],
        )

        audit_logger.log.assert_called_once()

    def test_exception_during_log_swallowed(self):
        mod = _get_module()
        audit_logger = MagicMock()
        audit_logger.log.side_effect = RuntimeError("log failed")

        # Should not raise
        mod._audit_log(
            audit_logger,
            "session123",
            model="claude-3-opus",
            messages_text="hello",
            response_text="world",
            usage={},
            guardrail_results_input=[],
            guardrail_results_output=[],
        )


# ====================================================================== #
# _resolve_guardrails
# ====================================================================== #


class TestResolveGuardrails:
    def test_none_returns_none(self):
        mod = _get_module()
        assert mod._resolve_guardrails(None) is None

    def test_engine_instance_passed_through(self):
        mod = _get_module()
        from aegis.guardrails.engine import GuardrailEngine

        engine = GuardrailEngine(guardrails=[])
        result = mod._resolve_guardrails(engine)
        assert result is engine

    def test_list_of_guardrails_creates_engine(self):
        mod = _get_module()
        from aegis.guardrails.engine import GuardrailEngine

        fake_guardrail = MagicMock()
        result = mod._resolve_guardrails([fake_guardrail])
        assert isinstance(result, GuardrailEngine)

    def test_single_guardrail_creates_engine(self):
        mod = _get_module()
        from aegis.guardrails.engine import GuardrailEngine

        fake_guardrail = MagicMock()
        result = mod._resolve_guardrails(fake_guardrail)
        assert isinstance(result, GuardrailEngine)


# ====================================================================== #
# patch_anthropic / unpatch_anthropic integration
# ====================================================================== #


class TestPatchAnthropic:
    def test_import_error_when_anthropic_missing(self):
        mod = _get_module()
        saved = {}
        keys_to_remove = [k for k in sys.modules if k.startswith("anthropic")]
        for k in keys_to_remove:
            saved[k] = sys.modules.pop(k)
        # Block re-import by setting to None
        sys.modules["anthropic"] = None  # type: ignore[assignment]

        mod._patched = False
        try:
            with pytest.raises(ImportError, match="anthropic"):
                mod.patch_anthropic()
        finally:
            sys.modules.pop("anthropic", None)
            sys.modules.update(saved)
            mod._patched = False

    def test_patch_with_audit_enabled(self, fake_anthropic):
        mod = _get_module()
        mock_audit = MagicMock()
        with patch("aegis.runtime.audit.AuditLogger", return_value=mock_audit):
            mod.patch_anthropic(audit=True)

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.Messages()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="claude-3-opus",
        )
        assert response is not None

    def test_patch_with_audit_logger_init_failure(self, fake_anthropic):
        mod = _get_module()
        with patch("aegis.runtime.audit.AuditLogger", side_effect=RuntimeError("no audit")):
            mod.patch_anthropic(audit=True)

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.Messages()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="claude-3-opus",
        )
        assert response is not None

    def test_sync_wrapper_calls_original(self, fake_anthropic):
        mod = _get_module()
        mod.patch_anthropic(audit=False)

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.Messages()
        response = client.create(
            messages=[{"role": "user", "content": "hi"}],
            model="claude-3-opus",
        )
        assert response is not None

    def test_async_wrapper_calls_original(self, fake_anthropic):
        mod = _get_module()
        mod.patch_anthropic(audit=False)

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.AsyncMessages()
        response = asyncio.get_event_loop().run_until_complete(
            client.create(
                messages=[{"role": "user", "content": "async hi"}],
                model="claude-3-opus",
            )
        )
        assert response is not None

    def test_async_wrapper_with_guardrail_raise(self, fake_anthropic):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="bad input", guardrail_name="test")
        engine.check.return_value = [blocked]

        with patch.object(mod, "_resolve_guardrails", return_value=engine):
            mod.patch_anthropic(audit=False, on_block="raise")

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.AsyncMessages()

        with pytest.raises(AegisGuardrailError, match="input"):
            asyncio.get_event_loop().run_until_complete(
                client.create(
                    messages=[{"role": "user", "content": "bad stuff"}],
                    model="claude-3-opus",
                )
            )

    def test_async_wrapper_output_guardrail_raise(self, fake_anthropic):
        mod = _get_module()
        call_count = 0
        engine = MagicMock()

        def check_side_effect(content):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            blocked = MagicMock(action="blocked", details="toxic", guardrail_name="tox")
            return [blocked]

        engine.check.side_effect = check_side_effect

        with patch.object(mod, "_resolve_guardrails", return_value=engine):
            mod.patch_anthropic(audit=False, on_block="raise")

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.AsyncMessages()

        with pytest.raises(AegisGuardrailError, match="output"):
            asyncio.get_event_loop().run_until_complete(
                client.create(
                    messages=[{"role": "user", "content": "hello"}],
                    model="claude-3-opus",
                )
            )

    def test_on_block_log_does_not_raise(self, fake_anthropic):
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="warning only", guardrail_name="test")
        engine.check.return_value = [blocked]

        with patch.object(mod, "_resolve_guardrails", return_value=engine):
            mod.patch_anthropic(audit=False, on_block="log")

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.Messages()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="claude-3-opus",
        )
        assert response is not None

    def test_unpatch_restores_and_resets_state(self, fake_anthropic):
        mod = _get_module()
        messages_mod = fake_anthropic["anthropic.resources.messages"]
        original = messages_mod.Messages.create

        mod.patch_anthropic(audit=False)
        assert mod._patched is True
        assert mod._original_create is not None

        mod.unpatch_anthropic()
        assert mod._patched is False
        assert mod._original_create is None
        assert mod._original_async_create is None
        assert messages_mod.Messages.create is original

    def test_unpatch_noop_when_not_patched(self, fake_anthropic):
        mod = _get_module()
        mod.unpatch_anthropic()  # should not raise

    def test_idempotent_double_patch(self, fake_anthropic):
        mod = _get_module()
        messages_mod = fake_anthropic["anthropic.resources.messages"]

        mod.patch_anthropic(audit=False)
        first = messages_mod.Messages.create

        mod.patch_anthropic(audit=False)
        second = messages_mod.Messages.create

        assert first is second

    def test_guardrails_with_list(self, fake_anthropic):
        mod = _get_module()
        fake_guardrail = MagicMock()

        mod.patch_anthropic(audit=False, guardrails=[fake_guardrail])

        messages_mod = fake_anthropic["anthropic.resources.messages"]
        client = messages_mod.Messages()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="claude-3-opus",
        )
        assert response is not None

    def test_unpatch_when_anthropic_import_fails(self, fake_anthropic):
        mod = _get_module()
        mod.patch_anthropic(audit=False)

        saved = {}
        keys_to_remove = [k for k in sys.modules if k.startswith("anthropic")]
        for k in keys_to_remove:
            saved[k] = sys.modules.pop(k)

        try:
            mod.unpatch_anthropic()  # should not raise
            assert mod._patched is False
        finally:
            sys.modules.update(saved)
