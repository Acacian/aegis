"""Comprehensive tests for aegis.instrument._google_genai module.

Covers:
- _extract_contents: all input shapes
- _extract_response_text: response.text, candidates path, empty
- _run_guardrails: engine=None, empty text, check exception, blocked raise/warn
- patch_google_genai: new SDK, legacy SDK, both, idempotent, no SDK
- governed wrappers: input/output guardrail flow
- unpatch_google_genai: restores originals
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

    import aegis.instrument._google_genai as _gg

    _gg._patched = False
    _gg._originals.clear()

    yield

    # Unpatch and clean up
    import aegis.instrument._google_genai as _gg2

    _gg2._patched = False
    _gg2._originals.clear()
    InstrumentationState.reset()


@pytest.fixture()
def mock_new_sdk():
    """Inject fake google.genai into sys.modules and reload the instrument module.

    Returns (ModelsClass, teardown_fn).
    """
    saved = {}
    for k in list(sys.modules.keys()):
        if k.startswith("google"):
            saved[k] = sys.modules.pop(k)

    original_generate = MagicMock(return_value="raw-response")

    ModelsClass = type(
        "Models",
        (),
        {"generate_content": original_generate},
    )

    models_mod = types.ModuleType("google.genai.models")
    models_mod.Models = ModelsClass

    genai_mod = types.ModuleType("google.genai")
    genai_mod.models = models_mod

    google_mod = types.ModuleType("google")
    google_mod.genai = genai_mod

    sys.modules["google"] = google_mod
    sys.modules["google.genai"] = genai_mod
    sys.modules["google.genai.models"] = models_mod

    import aegis.instrument._google_genai as _gg

    importlib.reload(_gg)

    yield ModelsClass, original_generate

    _gg._patched = False
    _gg._originals.clear()
    for k in list(sys.modules.keys()):
        if k.startswith("google"):
            sys.modules.pop(k, None)
    for k, v in saved.items():
        sys.modules[k] = v
    importlib.reload(_gg)


@pytest.fixture()
def mock_legacy_sdk():
    """Inject fake google.generativeai into sys.modules and reload.

    Returns (GenerativeModelClass, teardown_fn).
    """
    saved = {}
    for k in list(sys.modules.keys()):
        if k.startswith("google"):
            saved[k] = sys.modules.pop(k)

    original_generate = MagicMock(return_value="legacy-response")

    GenerativeModelClass = type(
        "GenerativeModel",
        (),
        {"generate_content": original_generate},
    )

    generativeai_mod = types.ModuleType("google.generativeai")
    generativeai_mod.GenerativeModel = GenerativeModelClass

    google_mod = sys.modules.get("google") or types.ModuleType("google")
    google_mod.generativeai = generativeai_mod

    sys.modules["google"] = google_mod
    sys.modules["google.generativeai"] = generativeai_mod

    import aegis.instrument._google_genai as _gg

    importlib.reload(_gg)

    yield GenerativeModelClass, original_generate

    _gg._patched = False
    _gg._originals.clear()
    for k in list(sys.modules.keys()):
        if k.startswith("google"):
            sys.modules.pop(k, None)
    for k, v in saved.items():
        sys.modules[k] = v
    importlib.reload(_gg)


@pytest.fixture()
def mock_both_sdks():
    """Inject both new and legacy Google SDKs."""
    saved = {}
    for k in list(sys.modules.keys()):
        if k.startswith("google"):
            saved[k] = sys.modules.pop(k)

    new_original = MagicMock(return_value="new-response")
    legacy_original = MagicMock(return_value="legacy-response")

    ModelsClass = type("Models", (), {"generate_content": new_original})
    GenerativeModelClass = type("GenerativeModel", (), {"generate_content": legacy_original})

    models_mod = types.ModuleType("google.genai.models")
    models_mod.Models = ModelsClass

    genai_mod = types.ModuleType("google.genai")
    genai_mod.models = models_mod

    generativeai_mod = types.ModuleType("google.generativeai")
    generativeai_mod.GenerativeModel = GenerativeModelClass

    google_mod = types.ModuleType("google")
    google_mod.genai = genai_mod
    google_mod.generativeai = generativeai_mod

    sys.modules["google"] = google_mod
    sys.modules["google.genai"] = genai_mod
    sys.modules["google.genai.models"] = models_mod
    sys.modules["google.generativeai"] = generativeai_mod

    import aegis.instrument._google_genai as _gg

    importlib.reload(_gg)

    yield ModelsClass, GenerativeModelClass, new_original, legacy_original

    _gg._patched = False
    _gg._originals.clear()
    for k in list(sys.modules.keys()):
        if k.startswith("google"):
            sys.modules.pop(k, None)
    for k, v in saved.items():
        sys.modules[k] = v
    importlib.reload(_gg)


# =========================================================================
# _extract_contents
# =========================================================================


class TestExtractContents:
    def test_string_contents(self):
        from aegis.instrument._google_genai import _extract_contents

        assert _extract_contents({"contents": "Hello Gemini"}) == "Hello Gemini"

    def test_list_of_strings(self):
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": ["Hello", "World"]})
        assert result == "Hello\nWorld"

    def test_list_with_text_attr_objects(self):
        from aegis.instrument._google_genai import _extract_contents

        @dataclass
        class Part:
            text: str

        items = [Part(text="Part one"), Part(text="Part two")]
        result = _extract_contents({"contents": items})
        assert "Part one" in result
        assert "Part two" in result

    def test_list_with_dict_items(self):
        from aegis.instrument._google_genai import _extract_contents

        items = [{"text": "dict part 1"}, {"text": "dict part 2"}]
        result = _extract_contents({"contents": items})
        assert "dict part 1" in result
        assert "dict part 2" in result

    def test_list_with_dict_non_string_text(self):
        """Dict items with non-string 'text' should be skipped (empty string appended)."""
        from aegis.instrument._google_genai import _extract_contents

        items = [{"text": 123}, {"text": "valid"}]
        result = _extract_contents({"contents": items})
        assert "valid" in result

    def test_list_mixed_types(self):
        from aegis.instrument._google_genai import _extract_contents

        @dataclass
        class Part:
            text: str

        items = ["plain", Part(text="obj"), {"text": "dct"}]
        result = _extract_contents({"contents": items})
        assert "plain" in result
        assert "obj" in result
        assert "dct" in result

    def test_list_with_non_matching_items(self):
        """Items that are not str, don't have .text, and are not dict are skipped."""
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": [42, None]})
        # These items don't match any branch; nothing is appended
        assert result == ""

    def test_empty_string_contents(self):
        from aegis.instrument._google_genai import _extract_contents

        assert _extract_contents({"contents": ""}) == ""

    def test_missing_contents_key(self):
        from aegis.instrument._google_genai import _extract_contents

        assert _extract_contents({}) == ""

    def test_non_string_non_list_contents(self):
        """Falls through to str(contents)."""
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": 42})
        assert result == "42"

    def test_none_contents(self):
        """contents=None → empty string."""
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": None})
        assert result == ""

    def test_empty_list(self):
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": []})
        assert result == ""

    def test_dict_with_empty_text(self):
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": [{"text": ""}]})
        assert result == ""

    def test_dict_without_text_key(self):
        from aegis.instrument._google_genai import _extract_contents

        result = _extract_contents({"contents": [{"role": "user"}]})
        assert result == ""


# =========================================================================
# _extract_response_text
# =========================================================================


class TestExtractResponseText:
    def test_response_with_text_attr(self):
        from aegis.instrument._google_genai import _extract_response_text

        @dataclass
        class Response:
            text: str = "Hello from Gemini"

        assert _extract_response_text(Response()) == "Hello from Gemini"

    def test_response_text_non_string(self):
        """If response.text is not a string, fall through to candidates path."""
        from aegis.instrument._google_genai import _extract_response_text

        @dataclass
        class Part:
            text: str = "from candidates"

        @dataclass
        class Content:
            parts: list = field(default_factory=lambda: [Part()])

        @dataclass
        class Candidate:
            content: Content = field(default_factory=Content)

        @dataclass
        class Response:
            text: int = 0  # not a string → skip
            candidates: list = field(default_factory=lambda: [Candidate()])

        result = _extract_response_text(Response())
        assert result == "from candidates"

    def test_legacy_candidates_path(self):
        from aegis.instrument._google_genai import _extract_response_text

        @dataclass
        class Part:
            text: str = "candidate text"

        @dataclass
        class Content:
            parts: list = field(default_factory=lambda: [Part()])

        @dataclass
        class Candidate:
            content: Content = field(default_factory=Content)

        # No .text attribute
        response = MagicMock(spec=[])
        response.candidates = [Candidate()]
        # Remove 'text' from the mock so getattr returns None
        del response.text

        result = _extract_response_text(response)
        assert result == "candidate text"

    def test_empty_candidates(self):
        from aegis.instrument._google_genai import _extract_response_text

        response = MagicMock(spec=[])
        del response.text
        response.candidates = []
        assert _extract_response_text(response) == ""

    def test_no_candidates_no_text(self):
        from aegis.instrument._google_genai import _extract_response_text

        response = MagicMock(spec=[])
        del response.text
        del response.candidates
        assert _extract_response_text(response) == ""

    def test_candidate_without_content(self):
        from aegis.instrument._google_genai import _extract_response_text

        @dataclass
        class Candidate:
            content: Any = None

        response = MagicMock(spec=[])
        del response.text
        response.candidates = [Candidate()]
        assert _extract_response_text(response) == ""

    def test_candidate_with_empty_parts(self):
        from aegis.instrument._google_genai import _extract_response_text

        @dataclass
        class Content:
            parts: list = field(default_factory=list)

        @dataclass
        class Candidate:
            content: Content = field(default_factory=Content)

        response = MagicMock(spec=[])
        del response.text
        response.candidates = [Candidate()]
        assert _extract_response_text(response) == ""

    def test_none_candidates_attribute(self):
        """candidates attribute exists but is None."""
        from aegis.instrument._google_genai import _extract_response_text

        response = MagicMock(spec=[])
        del response.text
        response.candidates = None
        assert _extract_response_text(response) == ""


# =========================================================================
# _run_guardrails
# =========================================================================


class TestRunGuardrails:
    def test_no_engine(self):
        """Should return immediately when engine is None."""
        from aegis.instrument._google_genai import _run_guardrails

        # Should not raise
        _run_guardrails(None, "some text", direction="input", on_block="raise")

    def test_empty_text(self):
        """Should return immediately when text is empty."""
        from aegis.instrument._google_genai import _run_guardrails

        engine = MagicMock()
        _run_guardrails(engine, "", direction="input", on_block="raise")
        engine.check.assert_not_called()

    def test_no_blocked_results(self):
        """When no results have action='blocked', should pass silently."""
        from aegis.instrument._google_genai import _run_guardrails

        result = MagicMock()
        result.action = "passed"
        engine = MagicMock()
        engine.check.return_value = [result]

        _run_guardrails(engine, "hello", direction="input", on_block="raise")

    def test_blocked_raise(self):
        """Should raise AegisGuardrailError when on_block='raise' and result is blocked."""
        from aegis.instrument._google_genai import _run_guardrails
        from aegis.integrations.errors import AegisGuardrailError

        result = MagicMock()
        result.action = "blocked"
        result.details = "injection detected"
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            _run_guardrails(engine, "malicious", direction="input", on_block="raise")

    def test_blocked_warn(self, caplog):
        """Should log a warning when on_block='warn' and result is blocked."""
        from aegis.instrument._google_genai import _run_guardrails

        result = MagicMock()
        result.action = "blocked"
        result.details = "pii found"
        engine = MagicMock()
        engine.check.return_value = [result]

        with caplog.at_level(logging.WARNING, logger="aegis.instrument.google_genai"):
            _run_guardrails(engine, "some pii", direction="output", on_block="warn")

        assert "Aegis blocked output" in caplog.text
        assert "pii found" in caplog.text

    def test_blocked_uses_guardrail_name_fallback(self):
        """When result has no .details, falls back to .guardrail_name."""
        from aegis.instrument._google_genai import _run_guardrails
        from aegis.integrations.errors import AegisGuardrailError

        result = MagicMock()
        result.action = "blocked"
        result.details = ""
        result.guardrail_name = "toxicity"
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="toxicity"):
            _run_guardrails(engine, "bad text", direction="input", on_block="raise")

    def test_check_exception_is_caught(self, caplog):
        """If engine.check raises, it should be caught and logged."""
        from aegis.instrument._google_genai import _run_guardrails

        engine = MagicMock()
        engine.check.side_effect = RuntimeError("check failed")

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.google_genai"):
            # Should NOT raise
            _run_guardrails(engine, "test", direction="input", on_block="raise")

        assert "Guardrail check failed" in caplog.text

    def test_multiple_blocked_results(self):
        """Details from all blocked results should be joined."""
        from aegis.instrument._google_genai import _run_guardrails
        from aegis.integrations.errors import AegisGuardrailError

        r1 = MagicMock()
        r1.action = "blocked"
        r1.details = "injection"
        r2 = MagicMock()
        r2.action = "blocked"
        r2.details = "pii"
        r3 = MagicMock()
        r3.action = "passed"
        engine = MagicMock()
        engine.check.return_value = [r1, r2, r3]

        with pytest.raises(AegisGuardrailError, match="injection.*pii"):
            _run_guardrails(engine, "evil", direction="input", on_block="raise")

    def test_blocked_no_details_no_guardrail_name(self):
        """Falls back to 'unknown' when both details and guardrail_name are missing."""
        from aegis.instrument._google_genai import _run_guardrails
        from aegis.integrations.errors import AegisGuardrailError

        result = MagicMock(spec=[])
        result.action = "blocked"
        # Neither details nor guardrail_name exist
        del result.details
        del result.guardrail_name
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="unknown"):
            _run_guardrails(engine, "text", direction="input", on_block="raise")


# =========================================================================
# patch_google_genai — New SDK
# =========================================================================


class TestPatchNewSDK:
    def test_patch_new_sdk(self, mock_new_sdk):
        import aegis.instrument._google_genai as _gg

        result = _gg.patch_google_genai()
        assert result.patched is True
        assert "Models.generate_content" in result.targets

    def test_idempotent(self, mock_new_sdk):
        import aegis.instrument._google_genai as _gg

        r1 = _gg.patch_google_genai()
        r2 = _gg.patch_google_genai()
        assert r1.patched is True
        assert r2.patched is True
        assert r1.targets == r2.targets

    def test_governed_wrapper_calls_original(self, mock_new_sdk):
        ModelsClass, original_generate = mock_new_sdk
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()

        instance = ModelsClass()
        instance.generate_content(contents="test prompt")
        original_generate.assert_called_once()

    def test_governed_wrapper_runs_input_guardrails(self, mock_new_sdk):
        ModelsClass, _ = mock_new_sdk
        import aegis.instrument._google_genai as _gg
        from aegis.integrations.errors import AegisGuardrailError

        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [blocked_result]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = ModelsClass()
        with pytest.raises(AegisGuardrailError, match="input"):
            instance.generate_content(contents="malicious input")

    def test_governed_wrapper_runs_output_guardrails(self, mock_new_sdk):
        ModelsClass, original_generate = mock_new_sdk
        import aegis.instrument._google_genai as _gg
        from aegis.integrations.errors import AegisGuardrailError

        # Make response have .text attribute
        response = MagicMock()
        response.text = "toxic output"
        original_generate.return_value = response

        call_count = 0

        def check_side_effect(text):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Input check passes
                return [MagicMock(action="passed")]
            else:
                # Output check blocks
                r = MagicMock()
                r.action = "blocked"
                r.details = "toxicity"
                return [r]

        engine = MagicMock()
        engine.check.side_effect = check_side_effect

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = ModelsClass()
        with pytest.raises(AegisGuardrailError, match="output"):
            instance.generate_content(contents="prompt")

    def test_governed_wrapper_no_engine(self, mock_new_sdk):
        """Without engine configured, original is called without guardrails."""
        ModelsClass, original_generate = mock_new_sdk
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()

        instance = ModelsClass()
        result = instance.generate_content(contents="hello")
        original_generate.assert_called_once()
        assert result == original_generate.return_value


# =========================================================================
# patch_google_genai — Legacy SDK
# =========================================================================


class TestPatchLegacySDK:
    def test_patch_legacy_sdk(self, mock_legacy_sdk):
        import aegis.instrument._google_genai as _gg

        result = _gg.patch_google_genai()
        assert result.patched is True
        assert "GenerativeModel.generate_content" in result.targets

    def test_governed_legacy_wrapper_calls_original(self, mock_legacy_sdk):
        GenerativeModelClass, original_generate = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()

        instance = GenerativeModelClass()
        instance.generate_content("test prompt")
        original_generate.assert_called_once()

    def test_legacy_wrapper_input_from_positional_arg(self, mock_legacy_sdk):
        GenerativeModelClass, _ = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg
        from aegis.integrations.errors import AegisGuardrailError

        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [blocked_result]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = GenerativeModelClass()
        with pytest.raises(AegisGuardrailError, match="input"):
            instance.generate_content("malicious prompt")

    def test_legacy_wrapper_input_from_kwarg(self, mock_legacy_sdk):
        GenerativeModelClass, _ = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg
        from aegis.integrations.errors import AegisGuardrailError

        blocked_result = MagicMock()
        blocked_result.action = "blocked"
        blocked_result.details = "blocked"
        engine = MagicMock()
        engine.check.return_value = [blocked_result]

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = GenerativeModelClass()
        with pytest.raises(AegisGuardrailError):
            instance.generate_content(contents="malicious prompt")

    def test_legacy_wrapper_no_args_no_contents(self, mock_legacy_sdk):
        """When no args and no contents kwarg, should use empty string."""
        GenerativeModelClass, original_generate = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg

        engine = MagicMock()
        engine.check.return_value = []

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = GenerativeModelClass()
        instance.generate_content()
        # Empty string → _run_guardrails returns early, engine.check not called
        engine.check.assert_not_called()

    def test_legacy_wrapper_non_string_contents(self, mock_legacy_sdk):
        """When contents is not a string, it's converted via str()."""
        GenerativeModelClass, original_generate = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg

        engine = MagicMock()
        engine.check.return_value = []

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = GenerativeModelClass()
        instance.generate_content(["part1", "part2"])
        # str(["part1", "part2"]) is truthy, so check is called
        engine.check.assert_called()

    def test_legacy_wrapper_runs_output_guardrails(self, mock_legacy_sdk):
        GenerativeModelClass, original_generate = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg
        from aegis.integrations.errors import AegisGuardrailError

        response = MagicMock()
        response.text = "bad output"
        original_generate.return_value = response

        call_count = 0

        def check_side_effect(text):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return []  # input passes
            r = MagicMock()
            r.action = "blocked"
            r.details = "toxicity"
            return [r]

        engine = MagicMock()
        engine.check.side_effect = check_side_effect

        s = InstrumentationState.get()
        s.configure(guardrail_engine=engine, on_block="raise")

        _gg.patch_google_genai()

        instance = GenerativeModelClass()
        with pytest.raises(AegisGuardrailError, match="output"):
            instance.generate_content("hello")


# =========================================================================
# patch_google_genai — Both SDKs
# =========================================================================


class TestPatchBothSDKs:
    def test_both_sdks_patched(self, mock_both_sdks):
        ModelsClass, GenerativeModelClass, _, _ = mock_both_sdks
        import aegis.instrument._google_genai as _gg

        result = _gg.patch_google_genai()
        assert result.patched is True
        assert "Models.generate_content" in result.targets
        assert "GenerativeModel.generate_content" in result.targets


# =========================================================================
# patch_google_genai — No SDK installed
# =========================================================================


class TestPatchNoSDK:
    def test_no_sdk_installed(self):
        """When neither SDK is installed, returns patched=False with error."""
        # Ensure no google modules
        saved = {}
        for k in list(sys.modules.keys()):
            if k.startswith("google"):
                saved[k] = sys.modules.pop(k)
        try:
            import aegis.instrument._google_genai as _gg

            importlib.reload(_gg)
            result = _gg.patch_google_genai()
            assert result.patched is False
            assert result.error is not None
            assert "not installed" in result.error
        finally:
            for k in list(sys.modules.keys()):
                if k.startswith("google"):
                    sys.modules.pop(k, None)
            for k, v in saved.items():
                sys.modules[k] = v
            importlib.reload(_gg)

    def test_registers_patch_in_state(self):
        """Even when not installed, the patch is registered in state."""
        saved = {}
        for k in list(sys.modules.keys()):
            if k.startswith("google"):
                saved[k] = sys.modules.pop(k)
        try:
            import aegis.instrument._google_genai as _gg

            importlib.reload(_gg)
            _gg.patch_google_genai()
            s = InstrumentationState.get()
            p = s.get_patch("google_genai")
            assert p is not None
            assert p.patched is False
        finally:
            for k in list(sys.modules.keys()):
                if k.startswith("google"):
                    sys.modules.pop(k, None)
            for k, v in saved.items():
                sys.modules[k] = v
            importlib.reload(_gg)


# =========================================================================
# unpatch_google_genai
# =========================================================================


class TestUnpatchGoogleGenAI:
    def test_unpatch_new_sdk(self, mock_new_sdk):
        ModelsClass, original_generate = mock_new_sdk
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()
        assert _gg._patched is True

        _gg.unpatch_google_genai()
        assert _gg._patched is False
        # Original should be restored
        assert ModelsClass.generate_content is original_generate

    def test_unpatch_legacy_sdk(self, mock_legacy_sdk):
        GenerativeModelClass, original_generate = mock_legacy_sdk
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()
        assert _gg._patched is True

        _gg.unpatch_google_genai()
        assert _gg._patched is False
        assert GenerativeModelClass.generate_content is original_generate

    def test_unpatch_when_not_patched(self):
        """Calling unpatch when not patched is a no-op."""
        import aegis.instrument._google_genai as _gg

        # Should not raise
        _gg.unpatch_google_genai()
        assert _gg._patched is False

    def test_unpatch_both_sdks(self, mock_both_sdks):
        ModelsClass, GenerativeModelClass, new_orig, legacy_orig = mock_both_sdks
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()
        _gg.unpatch_google_genai()

        assert _gg._patched is False
        assert ModelsClass.generate_content is new_orig
        assert GenerativeModelClass.generate_content is legacy_orig
        assert len(_gg._originals) == 0

    def test_unpatch_clears_originals(self, mock_new_sdk):
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()
        assert len(_gg._originals) > 0

        _gg.unpatch_google_genai()
        assert len(_gg._originals) == 0


# =========================================================================
# State registration
# =========================================================================


class TestStateRegistration:
    def test_patch_registers_in_state(self, mock_new_sdk):
        import aegis.instrument._google_genai as _gg

        _gg.patch_google_genai()
        s = InstrumentationState.get()
        assert s.is_patched("google_genai")
        p = s.get_patch("google_genai")
        assert p is not None
        assert p.name == "google_genai"
        assert p.patched is True

    def test_idempotent_returns_same_targets(self, mock_new_sdk):
        import aegis.instrument._google_genai as _gg

        r1 = _gg.patch_google_genai()
        r2 = _gg.patch_google_genai()
        assert r1.targets == r2.targets
