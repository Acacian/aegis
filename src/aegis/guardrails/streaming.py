"""Streaming-aware guardrail engine.

Applies guardrails to streaming LLM responses with automatic strategy
selection based on guardrail requirements:

- **Full-buffer mode**: When any guardrail sets ``requires_full_buffer=True``
  (e.g. PII detection where partial exposure is a violation), the engine
  buffers the entire response, runs all guardrails, then yields the
  scanned content.

- **Windowed mode**: When all guardrails support incremental scanning,
  chunks are accumulated in a sliding window.  Once the window is full
  the oldest chunk is released after the accumulated buffer passes all
  guardrails.

Usage::

    engine = GuardrailEngine()
    engine.add(ToxicityGuardrail())  # requires_full_buffer=False

    streaming = StreamingGuardrailEngine(engine, window_size=4)

    async for chunk in streaming.scan_stream(llm_stream):
        if chunk.blocked:
            print("[BLOCKED]")
            break
        print(chunk.content, end="", flush=True)

When a guardrail that requires full buffering is present::

    engine.add(pii_guardrail)  # requires_full_buffer=True

    # Automatically switches to full-buffer mode
    async for chunk in streaming.scan_stream(llm_stream):
        # Content only arrives after the full response has been scanned
        print(chunk.content, end="", flush=True)
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

from aegis.guardrails.base import GuardrailResult
from aegis.guardrails.engine import GuardrailEngine


class StreamStrategy(Enum):
    """Strategy used by the streaming engine."""

    FULL_BUFFER = "full_buffer"
    WINDOWED = "windowed"


@dataclass
class StreamChunk:
    """A chunk emitted by :class:`StreamingGuardrailEngine`.

    Attributes:
        content: The text content of this chunk (may be transformed).
        blocked: ``True`` if a guardrail blocked the stream at this point.
        results: Guardrail results associated with this chunk.  Empty
            for clean windowed chunks; populated on block or flush.
        buffered: ``True`` when full-buffer mode was used, meaning this
            chunk was held until the entire response was scanned.
        strategy: The strategy that produced this chunk.
    """

    content: str
    blocked: bool = False
    results: list[GuardrailResult] = field(default_factory=list)
    buffered: bool = False
    strategy: StreamStrategy = StreamStrategy.WINDOWED


class StreamingGuardrailEngine:
    """Wrap a :class:`GuardrailEngine` to scan streaming responses.

    The engine inspects the registered guardrails' ``requires_full_buffer``
    flags and automatically picks the safest strategy:

    * If **any** guardrail requires full buffering the entire stream is
      collected first, scanned via
      :meth:`~GuardrailEngine.check_and_transform`, and then yielded.
    * Otherwise a **windowed** approach is used: chunks accumulate up to
      *window_size* before the oldest one is released.

    Args:
        engine: The guardrail engine whose pipeline to apply.
        window_size: Number of chunks to hold in the sliding window
            before releasing the oldest.  Only used in windowed mode.
            Must be at least ``1``.
    """

    def __init__(
        self,
        engine: GuardrailEngine,
        *,
        window_size: int = 4,
    ) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self._engine = engine
        self._window_size = window_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def strategy(self) -> StreamStrategy:
        """Return the strategy that will be used based on current guardrails."""
        if any(g.requires_full_buffer for g in self._engine.guardrails):
            return StreamStrategy.FULL_BUFFER
        return StreamStrategy.WINDOWED

    async def scan_stream(
        self,
        stream: AsyncIterator[str],
        *,
        context: dict[str, object] | None = None,
    ) -> AsyncIterator[StreamChunk]:
        """Scan *stream* through the guardrail pipeline.

        Yields :class:`StreamChunk` instances.  If a guardrail blocks
        the content a final chunk with ``blocked=True`` is yielded and
        iteration stops.

        Args:
            stream: An async iterator of text chunks (e.g. from an LLM).
            context: Optional metadata forwarded to each guardrail.
        """
        if self.strategy == StreamStrategy.FULL_BUFFER:
            async for chunk in self._scan_full_buffer(stream, context):
                yield chunk
        else:
            async for chunk in self._scan_windowed(stream, context):
                yield chunk

    # ------------------------------------------------------------------
    # Full-buffer strategy
    # ------------------------------------------------------------------

    async def _scan_full_buffer(
        self,
        stream: AsyncIterator[str],
        context: dict[str, object] | None,
    ) -> AsyncIterator[StreamChunk]:
        """Collect the entire stream, scan, then yield."""
        chunks: list[str] = []
        async for raw in stream:
            chunks.append(raw)

        if not chunks:
            return

        full_text = "".join(chunks)
        results, transformed = self._engine.check_and_transform(full_text, context=context)

        blocked = any(r.action == "blocked" for r in results)

        if blocked:
            yield StreamChunk(
                content="",
                blocked=True,
                results=results,
                buffered=True,
                strategy=StreamStrategy.FULL_BUFFER,
            )
        else:
            yield StreamChunk(
                content=transformed,
                blocked=False,
                results=results,
                buffered=True,
                strategy=StreamStrategy.FULL_BUFFER,
            )

    # ------------------------------------------------------------------
    # Windowed strategy
    # ------------------------------------------------------------------

    async def _scan_windowed(
        self,
        stream: AsyncIterator[str],
        context: dict[str, object] | None,
    ) -> AsyncIterator[StreamChunk]:
        """Sliding-window scan: release oldest chunk once window is full."""
        buffer: list[str] = []

        async for raw in stream:
            buffer.append(raw)

            if len(buffer) >= self._window_size:
                window_text = "".join(buffer)
                results = self._engine.check(window_text, context=context)

                if any(not r.passed for r in results):
                    yield StreamChunk(
                        content="",
                        blocked=True,
                        results=results,
                        strategy=StreamStrategy.WINDOWED,
                    )
                    return

                yield StreamChunk(
                    content=buffer.pop(0),
                    blocked=False,
                    strategy=StreamStrategy.WINDOWED,
                )

        # Flush remaining buffered chunks.
        if buffer:
            remaining = "".join(buffer)
            results = self._engine.check(remaining, context=context)

            if any(not r.passed for r in results):
                yield StreamChunk(
                    content="",
                    blocked=True,
                    results=results,
                    strategy=StreamStrategy.WINDOWED,
                )
            else:
                for piece in buffer:
                    yield StreamChunk(
                        content=piece,
                        blocked=False,
                        strategy=StreamStrategy.WINDOWED,
                    )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def engine(self) -> GuardrailEngine:
        """The underlying guardrail engine."""
        return self._engine

    @property
    def window_size(self) -> int:
        """The configured window size."""
        return self._window_size

    def __repr__(self) -> str:
        return (
            f"StreamingGuardrailEngine(strategy={self.strategy.value!r}, "
            f"window_size={self._window_size}, "
            f"guardrails={len(self._engine)})"
        )
