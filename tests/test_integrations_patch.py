"""Tests for aegis.integrations.patch_openai and patch_anthropic.

Since the openai and anthropic packages may not be installed, we create
mock module structures and patch sys.modules so the patch functions can
import them.
"""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from aegis.integrations.errors import AegisGuardrailError

# ====================================================================== #
# Helpers to access the *module* (not the function) from sys.modules
# ====================================================================== #


def _get_po_module():
    """Return the aegis.integrations.patch_openai *module*."""
    # Force-import to populate sys.modules, then grab the real module
    importlib.import_module("aegis.integrations.patch_openai")
    return sys.modules["aegis.integrations.patch_openai"]


def _get_pa_module():
    """Return the aegis.integrations.patch_anthropic *module*."""
    importlib.import_module("aegis.integrations.patch_anthropic")
    return sys.modules["aegis.integrations.patch_anthropic"]


# ====================================================================== #
# Fake OpenAI module hierarchy
# ====================================================================== #


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
                choices=[MagicMock(message=MagicMock(content="hello world"))],
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
# Fake Anthropic module hierarchy
# ====================================================================== #


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
            text_block = MagicMock(type="text", text="anthropic response")
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
def fake_openai_modules():
    """Install fake openai modules and reset patch state for each test."""
    mods = _build_fake_openai()
    originals = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)

    po = _get_po_module()
    po._patched = False
    po._original_create = None
    po._original_async_create = None

    yield mods

    for k, v in originals.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v

    po._patched = False
    po._original_create = None
    po._original_async_create = None


@pytest.fixture()
def fake_anthropic_modules():
    """Install fake anthropic modules and reset patch state for each test."""
    mods = _build_fake_anthropic()
    originals = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)

    pa = _get_pa_module()
    pa._patched = False
    pa._original_create = None
    pa._original_async_create = None

    yield mods

    for k, v in originals.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v

    pa._patched = False
    pa._original_create = None
    pa._original_async_create = None


# ====================================================================== #
# patch_openai tests
# ====================================================================== #


class TestPatchOpenAI:
    def test_patches_create_method(self, fake_openai_modules):
        """patch_openai replaces Completions.create with a wrapper."""
        po = _get_po_module()

        completions_mod = fake_openai_modules["openai.resources.chat.completions"]
        original = completions_mod.Completions.create

        po.patch_openai(audit=False)

        assert completions_mod.Completions.create is not original

    def test_unpatch_restores_original(self, fake_openai_modules):
        """unpatch_openai restores the original create method."""
        po = _get_po_module()

        completions_mod = fake_openai_modules["openai.resources.chat.completions"]
        original = completions_mod.Completions.create

        po.patch_openai(audit=False)
        assert completions_mod.Completions.create is not original

        po.unpatch_openai()
        assert completions_mod.Completions.create is original

    def test_idempotent_double_patch(self, fake_openai_modules):
        """Calling patch_openai twice is safe -- second call is a no-op."""
        po = _get_po_module()

        completions_mod = fake_openai_modules["openai.resources.chat.completions"]

        po.patch_openai(audit=False)
        first_wrapper = completions_mod.Completions.create

        po.patch_openai(audit=False)  # second call
        second_wrapper = completions_mod.Completions.create

        assert first_wrapper is second_wrapper

    def test_unpatch_noop_when_not_patched(self, fake_openai_modules):
        """unpatch_openai is safe to call even when not patched."""
        po = _get_po_module()
        po.unpatch_openai()  # should not raise

    def test_patched_create_calls_through(self, fake_openai_modules):
        """The patched create still returns a response from the original."""
        po = _get_po_module()

        completions_mod = fake_openai_modules["openai.resources.chat.completions"]
        po.patch_openai(audit=False)

        client = completions_mod.Completions()
        response = client.create(
            messages=[{"role": "user", "content": "hi"}],
            model="gpt-4",
        )
        assert response is not None
        assert hasattr(response, "choices")

    def test_patch_runs_input_guardrails(self, fake_openai_modules):
        """When guardrails are provided, input content is checked."""
        po = _get_po_module()

        mock_engine = MagicMock()
        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "PII detected"
        blocked_result.guardrail_name = "pii_detector"
        mock_engine.check.return_value = [blocked_result]

        with patch.object(po, "_resolve_guardrails", return_value=mock_engine):
            po.patch_openai(audit=False, on_block="raise")

        completions_mod = fake_openai_modules["openai.resources.chat.completions"]
        client = completions_mod.Completions()

        with pytest.raises(AegisGuardrailError, match="input"):
            client.create(
                messages=[{"role": "user", "content": "my SSN is 123-45-6789"}],
                model="gpt-4",
            )

    def test_patch_runs_output_guardrails(self, fake_openai_modules):
        """When guardrails are provided, output content is checked."""
        po = _get_po_module()

        call_count = 0
        mock_engine = MagicMock()

        def check_side_effect(content):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []  # Input check passes
            blocked_result = MagicMock()
            blocked_result.action = "blocked"
            blocked_result.details = "toxic content"
            blocked_result.guardrail_name = "toxicity"
            return [blocked_result]

        mock_engine.check.side_effect = check_side_effect

        with patch.object(po, "_resolve_guardrails", return_value=mock_engine):
            po.patch_openai(audit=False, on_block="raise")

        completions_mod = fake_openai_modules["openai.resources.chat.completions"]
        client = completions_mod.Completions()

        with pytest.raises(AegisGuardrailError, match="output"):
            client.create(
                messages=[{"role": "user", "content": "hello"}],
                model="gpt-4",
            )


# ====================================================================== #
# patch_anthropic tests
# ====================================================================== #


class TestPatchAnthropic:
    def test_patches_create_method(self, fake_anthropic_modules):
        """patch_anthropic replaces Messages.create with a wrapper."""
        pa = _get_pa_module()

        messages_mod = fake_anthropic_modules["anthropic.resources.messages"]
        original = messages_mod.Messages.create

        pa.patch_anthropic(audit=False)

        assert messages_mod.Messages.create is not original

    def test_unpatch_restores_original(self, fake_anthropic_modules):
        """unpatch_anthropic restores the original create method."""
        pa = _get_pa_module()

        messages_mod = fake_anthropic_modules["anthropic.resources.messages"]
        original = messages_mod.Messages.create

        pa.patch_anthropic(audit=False)
        assert messages_mod.Messages.create is not original

        pa.unpatch_anthropic()
        assert messages_mod.Messages.create is original

    def test_idempotent_double_patch(self, fake_anthropic_modules):
        """Calling patch_anthropic twice is safe -- second call is a no-op."""
        pa = _get_pa_module()

        messages_mod = fake_anthropic_modules["anthropic.resources.messages"]

        pa.patch_anthropic(audit=False)
        first_wrapper = messages_mod.Messages.create

        pa.patch_anthropic(audit=False)  # second call
        second_wrapper = messages_mod.Messages.create

        assert first_wrapper is second_wrapper

    def test_unpatch_noop_when_not_patched(self, fake_anthropic_modules):
        """unpatch_anthropic is safe to call even when not patched."""
        pa = _get_pa_module()
        pa.unpatch_anthropic()  # should not raise

    def test_patched_create_calls_through(self, fake_anthropic_modules):
        """The patched create still returns a response from the original."""
        pa = _get_pa_module()

        messages_mod = fake_anthropic_modules["anthropic.resources.messages"]
        pa.patch_anthropic(audit=False)

        client = messages_mod.Messages()
        response = client.create(
            messages=[{"role": "user", "content": "hi"}],
            model="claude-3-opus",
        )
        assert response is not None
        assert hasattr(response, "content")

    def test_patch_runs_input_guardrails(self, fake_anthropic_modules):
        """When guardrails are provided, input content is checked."""
        pa = _get_pa_module()

        mock_engine = MagicMock()
        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "PII detected"
        blocked_result.guardrail_name = "pii_detector"
        mock_engine.check.return_value = [blocked_result]

        with patch.object(pa, "_resolve_guardrails", return_value=mock_engine):
            pa.patch_anthropic(audit=False, on_block="raise")

        messages_mod = fake_anthropic_modules["anthropic.resources.messages"]
        client = messages_mod.Messages()

        with pytest.raises(AegisGuardrailError, match="input"):
            client.create(
                messages=[{"role": "user", "content": "my SSN is 123-45-6789"}],
                model="claude-3-opus",
            )

    def test_patch_runs_output_guardrails(self, fake_anthropic_modules):
        """When guardrails are provided, output content is checked."""
        pa = _get_pa_module()

        call_count = 0
        mock_engine = MagicMock()

        def check_side_effect(content):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []
            blocked_result = MagicMock()
            blocked_result.action = "blocked"
            blocked_result.details = "toxic content"
            blocked_result.guardrail_name = "toxicity"
            return [blocked_result]

        mock_engine.check.side_effect = check_side_effect

        with patch.object(pa, "_resolve_guardrails", return_value=mock_engine):
            pa.patch_anthropic(audit=False, on_block="raise")

        messages_mod = fake_anthropic_modules["anthropic.resources.messages"]
        client = messages_mod.Messages()

        with pytest.raises(AegisGuardrailError, match="output"):
            client.create(
                messages=[{"role": "user", "content": "hello"}],
                model="claude-3-opus",
            )
