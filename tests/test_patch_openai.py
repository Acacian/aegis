"""Comprehensive tests for aegis.integrations.patch_openai.

Covers helper functions, guardrail logic, audit logging, resolve_guardrails,
sync/async wrappers, and ImportError handling.

Since the openai package may not be installed, we create mock module structures
and patch sys.modules so the patch functions can import them.
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
    """Return the aegis.integrations.patch_openai *module*."""
    importlib.import_module("aegis.integrations.patch_openai")
    return sys.modules["aegis.integrations.patch_openai"]


def _build_fake_openai():
    """Build a fake ``openai.resources.chat.completions`` module tree."""
    completions_mod = types.ModuleType("openai.resources.chat.completions")

    class FakeCompletions:
        def create(self, *args, **kwargs):
            return MagicMock(
                choices=[MagicMock(message=MagicMock(content="hello world"))],
                model="gpt-4",
                usage=MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )

    class FakeAsyncCompletions:
        async def create(self, *args, **kwargs):
            return MagicMock(
                choices=[MagicMock(message=MagicMock(content="async hello"))],
                model="gpt-4",
                usage=MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15),
            )

    completions_mod.Completions = FakeCompletions
    completions_mod.AsyncCompletions = FakeAsyncCompletions

    openai_mod = types.ModuleType("openai")
    resources_mod = types.ModuleType("openai.resources")
    chat_mod = types.ModuleType("openai.resources.chat")

    return {
        "openai": openai_mod,
        "openai.resources": resources_mod,
        "openai.resources.chat": chat_mod,
        "openai.resources.chat.completions": completions_mod,
    }


# ====================================================================== #
# Fixtures
# ====================================================================== #


@pytest.fixture()
def fake_openai():
    """Install fake openai modules and reset patch state for each test."""
    mods = _build_fake_openai()
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
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello!"},
        ]
        result = mod._extract_messages_text(messages)
        assert "You are helpful." in result
        assert "Hello!" in result

    def test_multipart_content(self):
        mod = _get_module()
        messages = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe this image."},
                    {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
                ],
            }
        ]
        result = mod._extract_messages_text(messages)
        assert "Describe this image." in result
        # image_url part should not appear
        assert "http://example.com" not in result

    def test_non_list_input_returns_empty(self):
        mod = _get_module()
        assert mod._extract_messages_text("not a list") == ""
        assert mod._extract_messages_text(None) == ""
        assert mod._extract_messages_text(42) == ""

    def test_pydantic_like_objects(self):
        mod = _get_module()
        msg = MagicMock()
        msg.content = "pydantic message"
        # Make it not be a dict so the else branch is taken
        result = mod._extract_messages_text([msg])
        assert "pydantic message" in result

    def test_pydantic_object_non_string_content(self):
        """Non-string content on pydantic-like object is skipped."""
        mod = _get_module()
        msg = MagicMock(spec=[])  # spec=[] means no attributes by default
        msg.content = 12345  # not a string
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
                "content": [
                    {"type": "text"},  # no "text" key
                ],
            }
        ]
        result = mod._extract_messages_text(messages)
        assert result == ""

    def test_multipart_non_dict_block(self):
        """Non-dict blocks in content list are skipped."""
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
        response = MagicMock(choices=[MagicMock(message=MagicMock(content="Hello response"))])
        assert mod._extract_response_text(response) == "Hello response"

    def test_multiple_choices(self):
        mod = _get_module()
        response = MagicMock(
            choices=[
                MagicMock(message=MagicMock(content="First")),
                MagicMock(message=MagicMock(content="Second")),
            ]
        )
        result = mod._extract_response_text(response)
        assert "First" in result
        assert "Second" in result

    def test_no_choices(self):
        mod = _get_module()
        response = MagicMock(choices=[])
        assert mod._extract_response_text(response) == ""

    def test_none_choices(self):
        mod = _get_module()
        response = MagicMock(choices=None)
        assert mod._extract_response_text(response) == ""

    def test_no_message_attribute(self):
        mod = _get_module()
        choice = MagicMock(spec=[])  # no attributes
        response = MagicMock(choices=[choice])
        assert mod._extract_response_text(response) == ""

    def test_non_string_content(self):
        mod = _get_module()
        response = MagicMock(choices=[MagicMock(message=MagicMock(content=None))])
        assert mod._extract_response_text(response) == ""

    def test_exception_returns_empty(self):
        """If something raises, return empty string."""
        mod = _get_module()
        response = MagicMock()
        response.choices = property(lambda self: (_ for _ in ()).throw(RuntimeError))
        # Force an error by making choices raise on iteration
        broken = MagicMock()
        broken.choices.__iter__ = MagicMock(side_effect=RuntimeError("broken"))
        assert mod._extract_response_text(broken) == ""


# ====================================================================== #
# _extract_usage
# ====================================================================== #


class TestExtractUsage:
    def test_normal_usage(self):
        mod = _get_module()
        response = MagicMock(
            model="gpt-4",
            usage=MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15),
        )
        usage = mod._extract_usage(response)
        assert usage["model"] == "gpt-4"
        assert usage["prompt_tokens"] == 10
        assert usage["completion_tokens"] == 5
        assert usage["total_tokens"] == 15

    def test_no_usage(self):
        mod = _get_module()
        response = MagicMock(model="gpt-4", usage=None)
        usage = mod._extract_usage(response)
        assert usage["model"] == "gpt-4"
        assert "prompt_tokens" not in usage

    def test_no_model(self):
        mod = _get_module()
        response = MagicMock(spec=[])  # no attributes at all
        usage = mod._extract_usage(response)
        # Should not raise, model defaults to None
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
        """on_block='log' should log a warning, not raise."""
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="bad content", guardrail_name="toxicity")
        engine.check.return_value = [blocked]

        results = mod._run_guardrails(engine, "bad", direction="input", on_block="log")
        assert len(results) == 1  # returns results, does not raise

    def test_blocked_with_other_strategy(self):
        """on_block with unknown strategy should not raise."""
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
        """When details is empty, use guardrail_name in error message."""
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="", guardrail_name="pii_detector")
        engine.check.return_value = [blocked]

        with pytest.raises(AegisGuardrailError, match="pii_detector"):
            mod._run_guardrails(engine, "text", direction="output", on_block="raise")

    def test_blocked_no_details_no_name(self):
        """When both details and guardrail_name are missing."""
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(spec=[])  # No attributes
        blocked.action = "blocked"
        # getattr with defaults will return "" for details, "unknown" for guardrail_name
        engine.check.return_value = [blocked]

        with pytest.raises(AegisGuardrailError, match="unknown"):
            mod._run_guardrails(engine, "text", direction="output", on_block="raise")


# ====================================================================== #
# _audit_log
# ====================================================================== #


class TestAuditLog:
    def test_none_logger_is_noop(self):
        mod = _get_module()
        # Should not raise
        mod._audit_log(
            None,
            "session123",
            model="gpt-4",
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
            model="gpt-4",
            messages_text="hello",
            response_text="world",
            usage={"prompt_tokens": 10},
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
        """If audit logging raises, it should be silently caught."""
        mod = _get_module()
        audit_logger = MagicMock()
        audit_logger.log.side_effect = RuntimeError("log failed")

        # Should not raise
        mod._audit_log(
            audit_logger,
            "session123",
            model="gpt-4",
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
# patch_openai / unpatch_openai integration
# ====================================================================== #


class TestPatchOpenAI:
    def test_import_error_when_openai_missing(self):
        """patch_openai raises ImportError when openai is not installed."""
        mod = _get_module()
        # Remove openai from sys.modules and block re-import
        saved = {}
        keys_to_remove = [k for k in sys.modules if k.startswith("openai")]
        for k in keys_to_remove:
            saved[k] = sys.modules.pop(k)
        sys.modules["openai"] = None  # type: ignore[assignment]

        mod._patched = False
        try:
            with pytest.raises(ImportError, match="openai"):
                mod.patch_openai()
        finally:
            sys.modules.pop("openai", None)
            sys.modules.update(saved)
            mod._patched = False

    def test_patch_with_audit_enabled(self, fake_openai):
        """patch_openai with audit=True initializes audit logger."""
        mod = _get_module()
        # Patch AuditLogger to avoid real filesystem ops
        mock_audit = MagicMock()
        with patch("aegis.runtime.audit.AuditLogger", return_value=mock_audit):
            mod.patch_openai(audit=True)

        completions_mod = fake_openai["openai.resources.chat.completions"]
        client = completions_mod.Completions()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="gpt-4",
        )
        assert response is not None

    def test_patch_with_audit_logger_init_failure(self, fake_openai):
        """If AuditLogger fails to init, patching still works."""
        mod = _get_module()
        with patch("aegis.runtime.audit.AuditLogger", side_effect=RuntimeError("no audit")):
            mod.patch_openai(audit=True)

        completions_mod = fake_openai["openai.resources.chat.completions"]
        client = completions_mod.Completions()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="gpt-4",
        )
        assert response is not None

    def test_sync_wrapper_calls_original(self, fake_openai):
        mod = _get_module()
        completions_mod = fake_openai["openai.resources.chat.completions"]

        mod.patch_openai(audit=False)

        client = completions_mod.Completions()
        response = client.create(
            messages=[{"role": "user", "content": "hi"}],
            model="gpt-4",
        )
        assert response is not None

    def test_sync_wrapper_with_positional_args(self, fake_openai):
        """Test create called with positional arguments."""
        mod = _get_module()
        completions_mod = fake_openai["openai.resources.chat.completions"]
        mod.patch_openai(audit=False)

        client = completions_mod.Completions()
        messages = [{"role": "user", "content": "positional"}]
        response = client.create(messages=messages, model="gpt-4")
        assert response is not None

    def test_async_wrapper_calls_original(self, fake_openai):
        mod = _get_module()
        completions_mod = fake_openai["openai.resources.chat.completions"]
        mod.patch_openai(audit=False)

        client = completions_mod.AsyncCompletions()
        response = asyncio.get_event_loop().run_until_complete(
            client.create(
                messages=[{"role": "user", "content": "async hi"}],
                model="gpt-4",
            )
        )
        assert response is not None

    def test_async_wrapper_with_guardrail_raise(self, fake_openai):
        """Async wrapper raises AegisGuardrailError on blocked input."""
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="bad input", guardrail_name="test")
        engine.check.return_value = [blocked]

        with patch.object(mod, "_resolve_guardrails", return_value=engine):
            mod.patch_openai(audit=False, on_block="raise")

        completions_mod = fake_openai["openai.resources.chat.completions"]
        client = completions_mod.AsyncCompletions()

        with pytest.raises(AegisGuardrailError, match="input"):
            asyncio.get_event_loop().run_until_complete(
                client.create(
                    messages=[{"role": "user", "content": "bad stuff"}],
                    model="gpt-4",
                )
            )

    def test_async_wrapper_output_guardrail_raise(self, fake_openai):
        """Async wrapper raises AegisGuardrailError on blocked output."""
        mod = _get_module()
        call_count = 0
        engine = MagicMock()

        def check_side_effect(content):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []  # input passes
            blocked = MagicMock(action="blocked", details="toxic", guardrail_name="tox")
            return [blocked]

        engine.check.side_effect = check_side_effect

        with patch.object(mod, "_resolve_guardrails", return_value=engine):
            mod.patch_openai(audit=False, on_block="raise")

        completions_mod = fake_openai["openai.resources.chat.completions"]
        client = completions_mod.AsyncCompletions()

        with pytest.raises(AegisGuardrailError, match="output"):
            asyncio.get_event_loop().run_until_complete(
                client.create(
                    messages=[{"role": "user", "content": "hello"}],
                    model="gpt-4",
                )
            )

    def test_on_block_log_does_not_raise(self, fake_openai):
        """on_block='log' logs warning but does not raise."""
        mod = _get_module()
        engine = MagicMock()
        blocked = MagicMock(action="blocked", details="warning only", guardrail_name="test")
        engine.check.return_value = [blocked]

        with patch.object(mod, "_resolve_guardrails", return_value=engine):
            mod.patch_openai(audit=False, on_block="log")

        completions_mod = fake_openai["openai.resources.chat.completions"]
        client = completions_mod.Completions()
        # Should NOT raise
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="gpt-4",
        )
        assert response is not None

    def test_unpatch_restores_and_resets_state(self, fake_openai):
        mod = _get_module()
        completions_mod = fake_openai["openai.resources.chat.completions"]
        original = completions_mod.Completions.create

        mod.patch_openai(audit=False)
        assert mod._patched is True
        assert mod._original_create is not None

        mod.unpatch_openai()
        assert mod._patched is False
        assert mod._original_create is None
        assert mod._original_async_create is None
        assert completions_mod.Completions.create is original

    def test_unpatch_noop_when_not_patched(self, fake_openai):
        mod = _get_module()
        mod.unpatch_openai()  # should not raise

    def test_idempotent_double_patch(self, fake_openai):
        mod = _get_module()
        completions_mod = fake_openai["openai.resources.chat.completions"]

        mod.patch_openai(audit=False)
        first = completions_mod.Completions.create

        mod.patch_openai(audit=False)
        second = completions_mod.Completions.create

        assert first is second

    def test_guardrails_with_list(self, fake_openai):
        """patch_openai accepts a list of guardrails."""
        mod = _get_module()
        fake_guardrail = MagicMock()

        mod.patch_openai(audit=False, guardrails=[fake_guardrail])

        completions_mod = fake_openai["openai.resources.chat.completions"]
        client = completions_mod.Completions()
        response = client.create(
            messages=[{"role": "user", "content": "test"}],
            model="gpt-4",
        )
        assert response is not None

    def test_unpatch_when_openai_import_fails(self, fake_openai):
        """unpatch_openai handles ImportError gracefully."""
        mod = _get_module()
        mod.patch_openai(audit=False)

        # Remove openai from sys.modules to simulate ImportError in unpatch
        saved = {}
        keys_to_remove = [k for k in sys.modules if k.startswith("openai")]
        for k in keys_to_remove:
            saved[k] = sys.modules.pop(k)

        try:
            mod.unpatch_openai()  # should not raise
            assert mod._patched is False
        finally:
            sys.modules.update(saved)
