"""Tests for StreamingGuardrailEngine."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from aegis.guardrails.base import Guardrail, GuardrailResult
from aegis.guardrails.engine import GuardrailEngine
from aegis.guardrails.pattern import PatternGuardrail
from aegis.guardrails.streaming import (
    StreamChunk,
    StreamingGuardrailEngine,
    StreamStrategy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _chunks(*parts: str) -> AsyncIterator[str]:
    """Create an async iterator from string arguments."""
    for p in parts:
        yield p


async def _collect(engine: StreamingGuardrailEngine, stream, **kw) -> list[StreamChunk]:
    """Collect all StreamChunks from scan_stream into a list."""
    result = []
    async for chunk in engine.scan_stream(stream, **kw):
        result.append(chunk)
    return result


class FullBufferGuardrail(Guardrail):
    """A guardrail that requires full buffering (e.g. PII-like)."""

    def __init__(self, name: str = "full_buffer_guard", block_keyword: str | None = None):
        super().__init__(name=name, severity="high", requires_full_buffer=True)
        self._block_keyword = block_keyword

    def check(self, content, *, context=None):
        if self._block_keyword and self._block_keyword in content:
            return GuardrailResult(
                passed=False,
                guardrail_name=self.name,
                action="blocked",
                severity=self.severity,
                details=f"Found {self._block_keyword!r}",
            )
        return GuardrailResult(
            passed=True, guardrail_name=self.name, action="allowed", severity=self.severity
        )

    def check_and_transform(self, content, *, context=None):
        result = self.check(content, context=context)
        return result, content


# ---------------------------------------------------------------------------
# Strategy selection
# ---------------------------------------------------------------------------


class TestStrategySelection:
    def test_windowed_when_no_full_buffer_guardrails(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="kw", pattern=r"bad", action="block"))
        streaming = StreamingGuardrailEngine(engine)
        assert streaming.strategy == StreamStrategy.WINDOWED

    def test_full_buffer_when_any_guardrail_requires_it(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="kw", pattern=r"bad", action="block"))
        engine.add(FullBufferGuardrail())
        streaming = StreamingGuardrailEngine(engine)
        assert streaming.strategy == StreamStrategy.FULL_BUFFER

    def test_windowed_with_empty_engine(self):
        engine = GuardrailEngine()
        streaming = StreamingGuardrailEngine(engine)
        assert streaming.strategy == StreamStrategy.WINDOWED


# ---------------------------------------------------------------------------
# Windowed mode
# ---------------------------------------------------------------------------


class TestWindowedMode:
    @pytest.mark.asyncio
    async def test_clean_stream_yields_all_chunks(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=2)

        chunks = await _collect(streaming, _chunks("Hello ", "world ", "!"))
        contents = [c.content for c in chunks]
        assert "".join(contents) == "Hello world !"
        assert all(not c.blocked for c in chunks)
        assert all(c.strategy == StreamStrategy.WINDOWED for c in chunks)

    @pytest.mark.asyncio
    async def test_blocked_stream_stops_early(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=2)

        chunks = await _collect(streaming, _chunks("Hello ", "EVIL ", "world"))
        # Should have yielded "Hello " then blocked when window saw "EVIL "
        assert any(c.blocked for c in chunks)
        # No content after the block
        blocked_chunk = next(c for c in chunks if c.blocked)
        assert blocked_chunk.content == ""

    @pytest.mark.asyncio
    async def test_violation_in_flush_phase(self):
        """Violation detected during the final buffer flush."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=3)

        # Only 2 chunks, both in buffer at flush time
        chunks = await _collect(streaming, _chunks("fine ", "EVIL"))
        assert any(c.blocked for c in chunks)

    @pytest.mark.asyncio
    async def test_empty_stream(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=2)

        chunks = await _collect(streaming, _chunks())
        assert chunks == []

    @pytest.mark.asyncio
    async def test_single_chunk_stream(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=2)

        chunks = await _collect(streaming, _chunks("Hello"))
        assert len(chunks) == 1
        assert chunks[0].content == "Hello"
        assert not chunks[0].blocked

    @pytest.mark.asyncio
    async def test_window_size_1(self):
        """Window size 1 means every chunk is scanned immediately."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=1)

        chunks = await _collect(streaming, _chunks("A", "B", "EVIL", "D"))
        contents = [c.content for c in chunks if not c.blocked]
        assert "A" in contents
        assert "B" in contents
        assert any(c.blocked for c in chunks)

    @pytest.mark.asyncio
    async def test_pattern_spanning_chunks_detected_in_window(self):
        """A pattern split across two chunks is caught when both are in the window."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="bad", pattern=r"EVIL", action="block"))
        streaming = StreamingGuardrailEngine(engine, window_size=2)

        # "EV" and "IL" together form "EVIL"
        chunks = await _collect(streaming, _chunks("safe ", "EV", "IL", " ok"))
        assert any(c.blocked for c in chunks)


# ---------------------------------------------------------------------------
# Full-buffer mode
# ---------------------------------------------------------------------------


class TestFullBufferMode:
    @pytest.mark.asyncio
    async def test_clean_stream_yields_full_content(self):
        engine = GuardrailEngine()
        engine.add(FullBufferGuardrail(block_keyword="SECRET"))
        streaming = StreamingGuardrailEngine(engine)

        chunks = await _collect(streaming, _chunks("Hello ", "world ", "!"))
        assert len(chunks) == 1
        assert chunks[0].content == "Hello world !"
        assert not chunks[0].blocked
        assert chunks[0].buffered is True
        assert chunks[0].strategy == StreamStrategy.FULL_BUFFER

    @pytest.mark.asyncio
    async def test_blocked_stream_returns_empty_content(self):
        engine = GuardrailEngine()
        engine.add(FullBufferGuardrail(block_keyword="SECRET"))
        streaming = StreamingGuardrailEngine(engine)

        chunks = await _collect(streaming, _chunks("The SECRET is ", "here"))
        assert len(chunks) == 1
        assert chunks[0].blocked is True
        assert chunks[0].content == ""
        assert chunks[0].buffered is True

    @pytest.mark.asyncio
    async def test_empty_stream(self):
        engine = GuardrailEngine()
        engine.add(FullBufferGuardrail())
        streaming = StreamingGuardrailEngine(engine)

        chunks = await _collect(streaming, _chunks())
        assert chunks == []

    @pytest.mark.asyncio
    async def test_masking_in_full_buffer_mode(self):
        """PatternGuardrail with mask action transforms content in full-buffer mode."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="mask_num", pattern=r"\d+", action="mask"))
        engine.add(FullBufferGuardrail())  # forces full-buffer mode
        streaming = StreamingGuardrailEngine(engine)

        chunks = await _collect(streaming, _chunks("call ", "123-", "4567"))
        assert len(chunks) == 1
        assert "123" not in chunks[0].content
        assert "***" in chunks[0].content
        assert not chunks[0].blocked

    @pytest.mark.asyncio
    async def test_results_populated_in_full_buffer(self):
        engine = GuardrailEngine()
        engine.add(FullBufferGuardrail(block_keyword="BAD"))
        streaming = StreamingGuardrailEngine(engine)

        chunks = await _collect(streaming, _chunks("BAD stuff"))
        assert len(chunks) == 1
        assert chunks[0].results
        assert chunks[0].results[0].action == "blocked"


# ---------------------------------------------------------------------------
# Mixed guardrails
# ---------------------------------------------------------------------------


class TestMixedGuardrails:
    @pytest.mark.asyncio
    async def test_full_buffer_guardrail_forces_full_buffer_mode(self):
        """When mixing windowed + full-buffer guardrails, full-buffer wins."""
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="toxicity", pattern=r"toxic", action="block"))
        engine.add(FullBufferGuardrail(block_keyword="PII_DATA"))
        streaming = StreamingGuardrailEngine(engine, window_size=2)

        assert streaming.strategy == StreamStrategy.FULL_BUFFER

        # Clean content passes
        chunks = await _collect(streaming, _chunks("hello ", "there"))
        assert len(chunks) == 1
        assert chunks[0].content == "hello there"
        assert not chunks[0].blocked

    @pytest.mark.asyncio
    async def test_mixed_guardrails_block_on_either(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="toxicity", pattern=r"toxic", action="block"))
        engine.add(FullBufferGuardrail(block_keyword="PII_DATA"))
        streaming = StreamingGuardrailEngine(engine)

        # Blocked by pattern guardrail
        chunks = await _collect(streaming, _chunks("this is ", "toxic"))
        assert chunks[0].blocked

        # Blocked by full-buffer guardrail
        chunks = await _collect(streaming, _chunks("has ", "PII_DATA"))
        assert chunks[0].blocked


# ---------------------------------------------------------------------------
# Edge cases and configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    def test_window_size_must_be_positive(self):
        engine = GuardrailEngine()
        with pytest.raises(ValueError, match="window_size must be >= 1"):
            StreamingGuardrailEngine(engine, window_size=0)

    def test_repr(self):
        engine = GuardrailEngine()
        engine.add(PatternGuardrail(name="a", pattern=r"x"))
        streaming = StreamingGuardrailEngine(engine, window_size=3)
        r = repr(streaming)
        assert "StreamingGuardrailEngine" in r
        assert "windowed" in r
        assert "3" in r

    def test_engine_property(self):
        engine = GuardrailEngine()
        streaming = StreamingGuardrailEngine(engine)
        assert streaming.engine is engine

    def test_window_size_property(self):
        engine = GuardrailEngine()
        streaming = StreamingGuardrailEngine(engine, window_size=7)
        assert streaming.window_size == 7

    @pytest.mark.asyncio
    async def test_context_forwarded_to_guardrails(self):
        """Verify that context dict is passed through to guardrails."""

        class ContextCapture(Guardrail):
            captured_context = None

            def __init__(self):
                super().__init__(name="ctx_capture")

            def check(self, content, *, context=None):
                ContextCapture.captured_context = context
                return GuardrailResult(passed=True, guardrail_name=self.name, action="allowed")

            def check_and_transform(self, content, *, context=None):
                return self.check(content, context=context), content

        engine = GuardrailEngine()
        engine.add(ContextCapture())
        streaming = StreamingGuardrailEngine(engine, window_size=1)

        ctx = {"user_id": "u123", "session": "s456"}
        await _collect(streaming, _chunks("hello"), context=ctx)
        assert ContextCapture.captured_context == ctx
