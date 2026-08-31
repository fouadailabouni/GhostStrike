"""
GhostStrike AI Engine — OpenTelemetry Tracer
=============================================
Wraps every agent action in an OpenTelemetry span so every tool call,
LLM completion, and token count is captured in the evidence chain.
Falls back to a no-op tracer when opentelemetry packages are absent,
so the rest of the engine never needs to guard against ImportError.

Span attributes written
-----------------------
  phantomops.agent.name
  phantomops.agent.iteration
  phantomops.tool.name
  phantomops.tool.success
  phantomops.llm.backend
  phantomops.llm.model
  phantomops.llm.input_tokens
  phantomops.llm.output_tokens
  phantomops.engagement.id

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Optional


# ── Try to import OpenTelemetry — degrade gracefully if absent ────────────────
try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )
    _OTel_AVAILABLE = True
except ImportError:
    _OTel_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Lightweight span record (used even when OTel is unavailable)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GhostSpan:
    name:        str
    attributes:  Dict[str, Any] = field(default_factory=dict)
    start_time:  float          = field(default_factory=time.time)
    end_time:    Optional[float] = None
    status:      str             = "OK"
    error:       Optional[str]   = None

    def finish(self, error: Optional[str] = None) -> None:
        self.end_time = time.time()
        if error:
            self.status = "ERROR"
            self.error  = error

    @property
    def duration_ms(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time) * 1_000
        return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Main tracer
# ─────────────────────────────────────────────────────────────────────────────

class GhostStrikeTracer:
    """
    OpenTelemetry-backed tracer for the GhostStrike AI engine.

    When opentelemetry-sdk is installed, spans are exported to the
    configured exporter (Console by default, Phoenix / Jaeger via
    OTEL_EXPORTER_OTLP_ENDPOINT).  When the SDK is absent the tracer
    falls back to a simple in-memory log.
    """

    def __init__(
        self,
        service_name: str = "phantomops-ai-engine",
        engagement_id: Optional[str] = None,
        console_export: bool = False,
    ) -> None:
        self.service_name  = service_name
        self.engagement_id = engagement_id or "unset"
        self._span_log: List[GhostSpan] = []

        if _OTel_AVAILABLE:
            resource = Resource({SERVICE_NAME: service_name})
            provider = TracerProvider(resource=resource)

            if console_export:
                provider.add_span_processor(
                    SimpleSpanProcessor(ConsoleSpanExporter())
                )

            otlp_endpoint = __import__("os").getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
            if otlp_endpoint:
                try:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )
                    provider.add_span_processor(
                        BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint))
                    )
                except ImportError:
                    pass

            trace.set_tracer_provider(provider)
            self._otel_tracer = trace.get_tracer(service_name)
        else:
            self._otel_tracer = None

    # ── Span helpers ──────────────────────────────────────────────────────────

    @contextmanager
    def agent_span(
        self,
        agent_name: str,
        iteration: int = 0,
    ) -> Generator[GhostSpan, None, None]:
        span = GhostSpan(
            name=f"agent.{agent_name}",
            attributes={
                "phantomops.agent.name":      agent_name,
                "phantomops.agent.iteration": iteration,
                "phantomops.engagement.id":   self.engagement_id,
            },
        )
        self._span_log.append(span)

        if self._otel_tracer:
            with self._otel_tracer.start_as_current_span(span.name) as otel_span:
                for k, v in span.attributes.items():
                    otel_span.set_attribute(k, v)
                try:
                    yield span
                    span.finish()
                except Exception as exc:
                    span.finish(error=str(exc))
                    otel_span.record_exception(exc)
                    raise
        else:
            try:
                yield span
                span.finish()
            except Exception as exc:
                span.finish(error=str(exc))
                raise

    @contextmanager
    def tool_span(
        self,
        tool_name: str,
        agent_name: str = "",
    ) -> Generator[GhostSpan, None, None]:
        span = GhostSpan(
            name=f"tool.{tool_name}",
            attributes={
                "phantomops.tool.name":     tool_name,
                "phantomops.agent.name":    agent_name,
                "phantomops.engagement.id": self.engagement_id,
                "phantomops.tool.success":  True,
            },
        )
        self._span_log.append(span)

        if self._otel_tracer:
            with self._otel_tracer.start_as_current_span(span.name) as otel_span:
                for k, v in span.attributes.items():
                    otel_span.set_attribute(k, v)
                try:
                    yield span
                    span.finish()
                    otel_span.set_attribute("phantomops.tool.success", True)
                except Exception as exc:
                    span.finish(error=str(exc))
                    span.attributes["phantomops.tool.success"] = False
                    otel_span.set_attribute("phantomops.tool.success", False)
                    otel_span.record_exception(exc)
                    raise
        else:
            try:
                yield span
                span.finish()
            except Exception as exc:
                span.attributes["phantomops.tool.success"] = False
                span.finish(error=str(exc))
                raise

    def record_llm_call(
        self,
        backend: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        agent_name: str = "",
    ) -> None:
        span = GhostSpan(
            name="llm.call",
            attributes={
                "phantomops.llm.backend":       backend,
                "phantomops.llm.model":         model,
                "phantomops.llm.input_tokens":  input_tokens,
                "phantomops.llm.output_tokens": output_tokens,
                "phantomops.agent.name":        agent_name,
                "phantomops.engagement.id":     self.engagement_id,
            },
        )
        span.finish()
        self._span_log.append(span)

    # ── Summary helpers ───────────────────────────────────────────────────────

    def total_tokens(self) -> Dict[str, int]:
        inp = sum(
            s.attributes.get("phantomops.llm.input_tokens", 0)
            for s in self._span_log
            if s.name == "llm.call"
        )
        out = sum(
            s.attributes.get("phantomops.llm.output_tokens", 0)
            for s in self._span_log
            if s.name == "llm.call"
        )
        return {"input": inp, "output": out, "total": inp + out}

    def tool_calls(self) -> List[Dict]:
        return [
            {
                "tool":     s.attributes.get("phantomops.tool.name"),
                "duration": round(s.duration_ms, 1),
                "success":  s.attributes.get("phantomops.tool.success", True),
                "error":    s.error,
            }
            for s in self._span_log
            if s.name.startswith("tool.")
        ]

    def export_log(self) -> List[Dict]:
        return [
            {
                "span":       s.name,
                "attributes": s.attributes,
                "duration_ms": round(s.duration_ms, 1),
                "status":      s.status,
                "error":       s.error,
            }
            for s in self._span_log
        ]
