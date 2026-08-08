"""Comprehensive tests for aegis.instrument._instructor module.

Covers:
- _extract_input: dict messages, object messages, non-list, empty
- _extract_output: str, pydantic model_dump, generic objects, None
- _run_guardrails: no engine, empty text, pass, block+raise, block+warn, exception
- patch_instructor: patching sync/async, idempotent re-patch, no-instructor fallback
- governed_create / governed_async_create: full flow with guardrails
- unpatch_instructor: restores originals, noop when unpatched
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import sys
import types
from unittest.mock import MagicMock

import pytest

from aegis.instrument._state import InstrumentationState
from aegis.integrations.errors import AegisGuardrailError

# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset instrumentation state and module-level flags before each test."""
    InstrumentationState.reset()

    import aegis.instrument._instructor as _ins

    _ins._patched = False
    _ins._originals.clear()

    yield

    _ins.unpatch_instructor()
    InstrumentationState.reset()

    # Clean up any injected fake modules
    sys.modules.pop("instructor", None)
    sys.modules.pop("instructor.client", None)


def _make_fake_instructor():
    """Create fake instructor module with Instructor and AsyncInstructor classes.

    Returns (InstructorClass, AsyncInstructorClass, client_module).
    """
    InstructorClass = type(
        "Instructor",
        (),
        {"create": lambda self, *a, **kw: "sync_result"},
    )

    async def _async_create(self, *a, **kw):
        return "async_result"

    AsyncInstructorClass = type(
        "AsyncInstructor",
        (),
        {"create": _async_create},
    )

    client_mod = types.ModuleType("instructor.client")
    client_mod.Instructor = InstructorClass
    client_mod.AsyncInstructor = AsyncInstructorClass

    instructor_mod = types.ModuleType("instructor")
    instructor_mod.client = client_mod

    sys.modules["instructor"] = instructor_mod
    sys.modules["instructor.client"] = client_mod

    return InstructorClass, AsyncInstructorClass, client_mod


def _reload_instructor():
    """Reload the _instructor module after injecting fakes."""
    import aegis.instrument._instructor as _ins

    importlib.reload(_ins)
    return _ins


# =========================================================================
# _extract_input tests
# =========================================================================


class TestExtractInput:
    """Test _extract_input helper."""

    def test_dict_messages_with_string_content(self):
        from aegis.instrument._instructor import _extract_input

        kwargs = {
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello world"},
            ]
        }
        result = _extract_input(kwargs)
        assert result == "You are helpful.\nHello world"

    def test_dict_messages_with_non_string_content(self):
        from aegis.instrument._instructor import _extract_input

        kwargs = {
            "messages": [
                {"role": "user", "content": ["list", "content"]},
            ]
        }
        result = _extract_input(kwargs)
        # Non-string content in dict is skipped
        assert result == ""

    def test_dict_messages_missing_content_key(self):
        from aegis.instrument._instructor import _extract_input

        kwargs = {"messages": [{"role": "system"}]}
        result = _extract_input(kwargs)
        # msg.get("content", "") returns "", which is a str, so it's appended but empty
        assert result == ""

    def test_object_messages_with_content_attr(self):
        from aegis.instrument._instructor import _extract_input

        msg = MagicMock()
        msg.content = "object content"
        # Ensure isinstance(msg, dict) is False
        kwargs = {"messages": [msg]}
        result = _extract_input(kwargs)
        assert result == "object content"

    def test_object_messages_non_string_content_attr(self):
        from aegis.instrument._instructor import _extract_input

        msg = MagicMock()
        msg.content = 42  # not a string
        kwargs = {"messages": [msg]}
        result = _extract_input(kwargs)
        assert result == ""

    def test_object_messages_no_content_attr(self):
        from aegis.instrument._instructor import _extract_input

        class NoContent:
            pass

        msg = NoContent()
        kwargs = {"messages": [msg]}
        result = _extract_input(kwargs)
        assert result == ""

    def test_non_list_messages(self):
        from aegis.instrument._instructor import _extract_input

        kwargs = {"messages": "just a string"}
        result = _extract_input(kwargs)
        assert result == "just a string"

    def test_empty_messages(self):
        from aegis.instrument._instructor import _extract_input

        kwargs = {"messages": []}
        result = _extract_input(kwargs)
        assert result == ""

    def test_no_messages_key(self):
        from aegis.instrument._instructor import _extract_input

        result = _extract_input({})
        assert result == ""

    def test_messages_none(self):
        from aegis.instrument._instructor import _extract_input

        kwargs = {"messages": None}
        # None is falsy, so returns ""
        result = _extract_input(kwargs)
        assert result == ""

    def test_mixed_dict_and_object_messages(self):
        from aegis.instrument._instructor import _extract_input

        msg_obj = MagicMock()
        msg_obj.content = "from object"

        kwargs = {
            "messages": [
                {"role": "user", "content": "from dict"},
                msg_obj,
            ]
        }
        result = _extract_input(kwargs)
        assert result == "from dict\nfrom object"


# =========================================================================
# _extract_output tests
# =========================================================================


class TestExtractOutput:
    """Test _extract_output helper."""

    def test_string_result(self):
        from aegis.instrument._instructor import _extract_output

        assert _extract_output("hello") == "hello"

    def test_pydantic_model_dump(self):
        from aegis.instrument._instructor import _extract_output

        mock_model = MagicMock()
        mock_model.model_dump.return_value = {"name": "test", "value": 42}
        result = _extract_output(mock_model)
        assert result == str({"name": "test", "value": 42})

    def test_generic_object(self):
        from aegis.instrument._instructor import _extract_output

        class MyObj:
            def __str__(self):
                return "my_obj_str"

        result = _extract_output(MyObj())
        assert result == "my_obj_str"

    def test_none_result(self):
        from aegis.instrument._instructor import _extract_output

        assert _extract_output(None) == ""

    def test_non_string_no_model_dump(self):
        from aegis.instrument._instructor import _extract_output

        result = _extract_output(12345)
        assert result == "12345"


# =========================================================================
# _run_guardrails tests
# =========================================================================


class TestRunGuardrails:
    """Test _run_guardrails helper."""

    def test_no_engine(self):
        from aegis.instrument._instructor import _run_guardrails

        # Should return cleanly without error
        _run_guardrails(None, "some text", direction="input", on_block="raise")

    def test_empty_text(self):
        from aegis.instrument._instructor import _run_guardrails

        engine = MagicMock()
        _run_guardrails(engine, "", direction="input", on_block="raise")
        engine.check.assert_not_called()

    def test_no_blocked_results(self):
        from aegis.instrument._instructor import _run_guardrails

        result = MagicMock()
        result.action = "passed"
        engine = MagicMock()
        engine.check.return_value = [result]

        # Should not raise
        _run_guardrails(engine, "some text", direction="input", on_block="raise")

    def test_blocked_with_raise(self):
        from aegis.instrument._instructor import _run_guardrails

        result = MagicMock()
        result.action = "blocked"
        result.details = "PII detected"
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            _run_guardrails(engine, "some text", direction="input", on_block="raise")

    def test_blocked_with_warn(self, caplog):
        from aegis.instrument._instructor import _run_guardrails

        result = MagicMock()
        result.action = "blocked"
        result.details = "injection detected"
        engine = MagicMock()
        engine.check.return_value = [result]

        with caplog.at_level(logging.WARNING, logger="aegis.instrument.instructor"):
            _run_guardrails(engine, "bad text", direction="output", on_block="warn")

        assert any("Aegis blocked output" in msg for msg in caplog.messages)

    def test_blocked_uses_guardrail_name_when_no_details(self):
        from aegis.instrument._instructor import _run_guardrails

        result = MagicMock()
        result.action = "blocked"
        result.details = ""
        result.guardrail_name = "pii_detector"
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="pii_detector"):
            _run_guardrails(engine, "text", direction="input", on_block="raise")

    def test_blocked_falls_back_to_unknown(self):
        from aegis.instrument._instructor import _run_guardrails

        result = MagicMock(spec=[])  # empty spec, so no attributes
        result.action = "blocked"
        engine = MagicMock()
        engine.check.return_value = [result]

        with pytest.raises(AegisGuardrailError, match="unknown"):
            _run_guardrails(engine, "text", direction="input", on_block="raise")

    def test_engine_check_exception(self, caplog):
        from aegis.instrument._instructor import _run_guardrails

        engine = MagicMock()
        engine.check.side_effect = RuntimeError("connection failed")

        with caplog.at_level(logging.DEBUG, logger="aegis.instrument.instructor"):
            # Should not raise even with on_block="raise"
            _run_guardrails(engine, "text", direction="input", on_block="raise")

        assert any("Guardrail check failed" in msg for msg in caplog.messages)

    def test_multiple_blocked_results_join_details(self):
        from aegis.instrument._instructor import _run_guardrails

        r1 = MagicMock()
        r1.action = "blocked"
        r1.details = "PII"
        r2 = MagicMock()
        r2.action = "blocked"
        r2.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [r1, r2]

        with pytest.raises(AegisGuardrailError, match="PII; injection"):
            _run_guardrails(engine, "text", direction="input", on_block="raise")

    def test_mixed_blocked_and_passed(self):
        from aegis.instrument._instructor import _run_guardrails

        r1 = MagicMock()
        r1.action = "passed"
        r2 = MagicMock()
        r2.action = "blocked"
        r2.details = "bad stuff"
        engine = MagicMock()
        engine.check.return_value = [r1, r2]

        with pytest.raises(AegisGuardrailError, match="bad stuff"):
            _run_guardrails(engine, "text", direction="input", on_block="raise")


# =========================================================================
# patch_instructor tests
# =========================================================================


class TestPatchInstructor:
    """Test patch_instructor function."""

    def test_patch_without_instructor_installed(self):
        """When instructor is not installed, patch returns patched=False."""
        import aegis.instrument._instructor as _ins

        result = _ins.patch_instructor()
        assert result.patched is False
        assert result.name == "instructor"
        assert result.error == "instructor not installed"

    def test_patch_registers_in_state(self):
        """Patch result is registered in InstrumentationState."""
        import aegis.instrument._instructor as _ins

        _ins.patch_instructor()
        state = InstrumentationState.get()
        p = state.get_patch("instructor")
        assert p is not None
        assert p.name == "instructor"

    def test_patch_with_mock_instructor(self):
        """Patching with a fake instructor module succeeds."""
        _make_fake_instructor()
        _ins = _reload_instructor()

        result = _ins.patch_instructor()
        assert result.patched is True
        assert "Instructor.create" in result.targets
        assert "AsyncInstructor.create" in result.targets

    def test_patch_idempotent(self):
        """Calling patch_instructor twice returns the same result."""
        _make_fake_instructor()
        _ins = _reload_instructor()

        r1 = _ins.patch_instructor()
        r2 = _ins.patch_instructor()
        assert r1.patched is True
        assert r2.patched is True
        assert r1.targets == r2.targets

    def test_patch_only_sync_when_async_missing(self):
        """If AsyncInstructor is not available, only sync is patched."""
        InstructorClass = type(
            "Instructor",
            (),
            {"create": lambda self, *a, **kw: "result"},
        )

        client_mod = types.ModuleType("instructor.client")
        client_mod.Instructor = InstructorClass
        # No AsyncInstructor attribute at all

        instructor_mod = types.ModuleType("instructor")
        instructor_mod.client = client_mod

        sys.modules["instructor"] = instructor_mod
        sys.modules["instructor.client"] = client_mod

        _ins = _reload_instructor()

        # The import of AsyncInstructor will succeed (it's in client_mod),
        # but there's no AsyncInstructor, so we need to actually remove it.
        # Since the import does `from instructor.client import AsyncInstructor`,
        # we need to make that fail. Let's use a different approach: make the module
        # raise ImportError for AsyncInstructor specifically.
        delattr(client_mod, "AsyncInstructor") if hasattr(client_mod, "AsyncInstructor") else None

        # Since `from instructor.client import AsyncInstructor` succeeds if the
        # attribute doesn't exist? No — it raises ImportError.
        # Actually with types.ModuleType, missing attr → ImportError on `from X import Y`.
        _ins._patched = False
        _ins._originals.clear()

        result = _ins.patch_instructor()
        assert result.patched is True
        assert "Instructor.create" in result.targets
        assert "AsyncInstructor.create" not in result.targets

    def test_patch_logs_info(self, caplog):
        """Patching logs an info message."""
        _make_fake_instructor()
        _ins = _reload_instructor()

        with caplog.at_level(logging.INFO, logger="aegis.instrument.instructor"):
            _ins.patch_instructor()

        assert any("Instructor instrumented" in msg for msg in caplog.messages)


# =========================================================================
# governed_create (sync) tests
# =========================================================================


class TestGovernedCreate:
    """Test the patched sync Instructor.create method."""

    def test_sync_create_passthrough(self):
        """Patched create calls original and returns result."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        inst = InstructorCls()
        result = inst.create(messages=[{"role": "user", "content": "hi"}])
        assert result == "sync_result"

    def test_sync_create_with_guardrails_pass(self):
        """Guardrails pass → original result returned."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        engine = MagicMock()
        passed_result = MagicMock()
        passed_result.action = "passed"
        engine.check.return_value = [passed_result]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = InstructorCls()
        result = inst.create(messages=[{"role": "user", "content": "hello"}])
        assert result == "sync_result"
        assert engine.check.call_count == 2  # input + output

    def test_sync_create_input_blocked(self):
        """Guardrails block input → AegisGuardrailError raised."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "harmful content"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = InstructorCls()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            inst.create(messages=[{"role": "user", "content": "bad input"}])

    def test_sync_create_output_blocked(self):
        """Guardrails pass input but block output."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        call_count = [0]
        passed = MagicMock()
        passed.action = "passed"
        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "output violation"

        engine = MagicMock()

        def check_side_effect(text):
            call_count[0] += 1
            if call_count[0] == 1:
                return [passed]  # input check passes
            return [blocked]  # output check blocks

        engine.check.side_effect = check_side_effect

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = InstructorCls()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked output"):
            inst.create(messages=[{"role": "user", "content": "innocent input"}])

    def test_sync_create_warn_mode(self, caplog):
        """On block=warn, create returns result + logs warning."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "suspect content"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="warn")

        inst = InstructorCls()
        with caplog.at_level(logging.WARNING, logger="aegis.instrument.instructor"):
            result = inst.create(messages=[{"role": "user", "content": "test"}])

        # Result still returned in warn mode
        assert result == "sync_result"
        assert any("Aegis blocked" in msg for msg in caplog.messages)

    def test_sync_create_no_engine(self):
        """No guardrail engine → passthrough without checks."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        # Default state has no engine
        inst = InstructorCls()
        result = inst.create(messages=[{"role": "user", "content": "hello"}])
        assert result == "sync_result"

    def test_sync_create_empty_messages(self):
        """Empty messages → guardrails get empty string → no check."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        engine = MagicMock()
        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = InstructorCls()
        result = inst.create(messages=[])
        assert result == "sync_result"
        # Engine should not have been called for input (empty string),
        # but may be called for output
        # Actually _run_guardrails returns early if text is empty
        # Input is empty, so no input check. Output is "sync_result", so output check happens.
        assert engine.check.call_count == 1  # only output check

    def test_sync_create_with_pydantic_output(self):
        """Output is a pydantic-like model with model_dump."""
        pydantic_result = MagicMock()
        pydantic_result.model_dump.return_value = {"answer": "42"}

        InstructorClass = type(
            "Instructor",
            (),
            {"create": lambda self, *a, **kw: pydantic_result},
        )

        async def _async_create(self, *a, **kw):
            return "async_result"

        AsyncInstructorClass = type(
            "AsyncInstructor",
            (),
            {"create": _async_create},
        )

        client_mod = types.ModuleType("instructor.client")
        client_mod.Instructor = InstructorClass
        client_mod.AsyncInstructor = AsyncInstructorClass

        instructor_mod = types.ModuleType("instructor")
        instructor_mod.client = client_mod

        sys.modules["instructor"] = instructor_mod
        sys.modules["instructor.client"] = client_mod

        _ins = _reload_instructor()
        _ins.patch_instructor()

        engine = MagicMock()
        passed = MagicMock()
        passed.action = "passed"
        engine.check.return_value = [passed]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = InstructorClass()
        result = inst.create(messages=[{"role": "user", "content": "what is 6*7?"}])
        assert result is pydantic_result

        # Verify the output check received model_dump result
        calls = engine.check.call_args_list
        assert len(calls) == 2
        output_check_text = calls[1][0][0]
        assert "answer" in output_check_text
        assert "42" in output_check_text


# =========================================================================
# governed_async_create tests
# =========================================================================


class TestGovernedAsyncCreate:
    """Test the patched async AsyncInstructor.create method."""

    def test_async_create_passthrough(self):
        """Patched async create calls original and returns result."""
        _, AsyncCls, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        inst = AsyncCls()
        result = asyncio.run(inst.create(messages=[{"role": "user", "content": "hi"}]))
        assert result == "async_result"

    def test_async_create_with_guardrails_pass(self):
        """Guardrails pass → async result returned."""
        _, AsyncCls, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        passed = MagicMock()
        passed.action = "passed"
        engine = MagicMock()
        engine.check.return_value = [passed]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = AsyncCls()
        result = asyncio.run(inst.create(messages=[{"role": "user", "content": "hello async"}]))
        assert result == "async_result"
        assert engine.check.call_count == 2

    def test_async_create_input_blocked(self):
        """Guardrails block input on async create."""
        _, AsyncCls, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "dangerous"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = AsyncCls()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked input"):
            asyncio.run(inst.create(messages=[{"role": "user", "content": "danger"}]))

    def test_async_create_output_blocked(self):
        """Guardrails pass input but block output on async create."""
        _, AsyncCls, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        call_count = [0]
        passed = MagicMock()
        passed.action = "passed"
        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "async output bad"

        engine = MagicMock()

        def check_side_effect(text):
            call_count[0] += 1
            if call_count[0] == 1:
                return [passed]
            return [blocked]

        engine.check.side_effect = check_side_effect

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = AsyncCls()
        with pytest.raises(AegisGuardrailError, match="Aegis blocked output"):
            asyncio.run(inst.create(messages=[{"role": "user", "content": "ok"}]))

    def test_async_create_warn_mode(self, caplog):
        """On block=warn, async create returns result + logs warning."""
        _, AsyncCls, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "mild concern"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="warn")

        inst = AsyncCls()
        with caplog.at_level(logging.WARNING, logger="aegis.instrument.instructor"):
            result = asyncio.run(inst.create(messages=[{"role": "user", "content": "test"}]))

        assert result == "async_result"
        assert any("Aegis blocked" in msg for msg in caplog.messages)

    def test_async_create_no_engine(self):
        """No guardrail engine → async passthrough."""
        _, AsyncCls, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        inst = AsyncCls()
        result = asyncio.run(inst.create(messages=[{"role": "user", "content": "hello"}]))
        assert result == "async_result"


# =========================================================================
# unpatch_instructor tests
# =========================================================================


class TestUnpatchInstructor:
    """Test unpatch_instructor function."""

    def test_unpatch_restores_original(self):
        """After unpatch, Instructor.create is the original method."""
        InstructorCls, AsyncCls, client_mod = _make_fake_instructor()
        _ins = _reload_instructor()

        original_sync = InstructorCls.create
        original_async = AsyncCls.create

        _ins.patch_instructor()

        # After patching, methods should be different
        assert InstructorCls.create is not original_sync

        _ins.unpatch_instructor()

        # After unpatching, methods should be restored
        assert InstructorCls.create is original_sync
        assert AsyncCls.create is original_async
        assert _ins._patched is False
        assert len(_ins._originals) == 0

    def test_unpatch_noop_when_not_patched(self):
        """Calling unpatch when not patched is a no-op."""
        import aegis.instrument._instructor as _ins

        # Should not raise
        _ins.unpatch_instructor()
        assert _ins._patched is False

    def test_unpatch_clears_originals(self):
        """unpatch clears the _originals dict."""
        _make_fake_instructor()
        _ins = _reload_instructor()

        _ins.patch_instructor()
        assert len(_ins._originals) > 0

        _ins.unpatch_instructor()
        assert len(_ins._originals) == 0

    def test_unpatch_logs_info(self, caplog):
        """Unpatching logs an info message."""
        _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        with caplog.at_level(logging.INFO, logger="aegis.instrument.instructor"):
            _ins.unpatch_instructor()

        assert any("Instructor unpatched" in msg for msg in caplog.messages)

    def test_patch_unpatch_patch_cycle(self):
        """Can patch, unpatch, and patch again."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()

        # First patch
        r1 = _ins.patch_instructor()
        assert r1.patched is True

        # Unpatch
        _ins.unpatch_instructor()
        assert _ins._patched is False

        # Second patch
        r2 = _ins.patch_instructor()
        assert r2.patched is True

        # Verify it works
        inst = InstructorCls()
        result = inst.create(messages=[{"role": "user", "content": "test"}])
        assert result == "sync_result"


# =========================================================================
# Edge case / integration tests
# =========================================================================


class TestEdgeCases:
    """Edge cases and integration scenarios."""

    def test_guardrail_error_has_results_attribute(self):
        """AegisGuardrailError stores blocked guardrail results."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "violation"
        engine = MagicMock()
        engine.check.return_value = [blocked]

        state = InstrumentationState.get()
        state.configure(guardrail_engine=engine, on_block="raise")

        inst = InstructorCls()
        with pytest.raises(AegisGuardrailError) as exc_info:
            inst.create(messages=[{"role": "user", "content": "bad"}])

        assert len(exc_info.value.guardrail_results) == 1
        assert exc_info.value.guardrail_results[0] is blocked

    def test_create_with_positional_args(self):
        """Positional args are passed through to the original."""
        InstructorCls, _, _ = _make_fake_instructor()
        _ins = _reload_instructor()
        _ins.patch_instructor()

        inst = InstructorCls()
        # No messages kwarg → empty input → no guardrail check on input
        result = inst.create()
        assert result == "sync_result"

    def test_state_on_block_default(self):
        """Default on_block is 'raise'."""
        state = InstrumentationState.get()
        assert state.on_block == "raise"

    def test_non_list_messages_value(self):
        """Non-list messages value is converted to string."""
        from aegis.instrument._instructor import _extract_input

        kwargs = {"messages": 42}
        result = _extract_input(kwargs)
        assert result == "42"


def _make_fake_instructor_modern():
    """Fake instructor with the >=1.15 layout: no ``instructor.client`` submodule.

    Instructor 1.15 moved the client classes to ``instructor.v2.core.client`` and
    re-exports them from the package root only.  Resolving through the old
    submodule raises ``ModuleNotFoundError``, which used to be swallowed as
    "instructor not installed".
    """
    InstructorClass = type(
        "Instructor",
        (),
        {"create": lambda self, *a, **kw: "sync_result"},
    )

    async def _async_create(self, *a, **kw):
        return "async_result"

    AsyncInstructorClass = type(
        "AsyncInstructor",
        (),
        {"create": _async_create},
    )

    instructor_mod = types.ModuleType("instructor")
    instructor_mod.Instructor = InstructorClass
    instructor_mod.AsyncInstructor = AsyncInstructorClass

    sys.modules["instructor"] = instructor_mod
    sys.modules.pop("instructor.client", None)

    return InstructorClass, AsyncInstructorClass


class TestModernInstructorLayout:
    """Regression: instructor >=1.15 dropped the ``instructor.client`` submodule."""

    def test_patches_without_client_submodule(self):
        """Both classes are patched when only the package root exports them."""
        InstructorCls, AsyncCls = _make_fake_instructor_modern()
        _ins = _reload_instructor()

        patch = _ins.patch_instructor()

        assert patch.patched is True
        assert patch.targets == ["Instructor.create", "AsyncInstructor.create"]
        assert patch.error is None
        assert InstructorCls.create is not None
        assert hasattr(InstructorCls.create, "__wrapped__")
        assert hasattr(AsyncCls.create, "__wrapped__")

    def test_guardrail_fires_without_client_submodule(self):
        """A blocked prompt raises even though ``instructor.client`` is absent."""
        InstructorCls, _ = _make_fake_instructor_modern()
        _ins = _reload_instructor()

        blocked = MagicMock()
        blocked.action = "blocked"
        blocked.details = "injection"
        engine = MagicMock()
        engine.check.return_value = [blocked]
        InstrumentationState.get().configure(guardrail_engine=engine, on_block="raise")

        _ins.patch_instructor()

        with pytest.raises(AegisGuardrailError):
            InstructorCls().create(messages=[{"role": "user", "content": "bad"}])

    def test_unpatch_without_client_submodule(self):
        """Unpatch restores the original create when resolved from the root."""
        InstructorCls, AsyncCls = _make_fake_instructor_modern()
        _ins = _reload_instructor()

        original = InstructorCls.create
        _ins.patch_instructor()
        assert InstructorCls.create is not original

        _ins.unpatch_instructor()
        assert InstructorCls.create is original
        assert not hasattr(AsyncCls.create, "__wrapped__")

    def test_installed_but_unresolvable_is_not_reported_as_missing(self):
        """An instructor without either layout reports an unsupported version."""
        sys.modules["instructor"] = types.ModuleType("instructor")
        sys.modules.pop("instructor.client", None)
        _ins = _reload_instructor()

        patch = _ins.patch_instructor()

        assert patch.patched is False
        assert patch.error is not None
        assert "not installed" not in patch.error
        assert "unsupported version" in patch.error
