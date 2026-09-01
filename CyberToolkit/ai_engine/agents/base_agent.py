"""
GhostStrike AI Engine — Base Agent
====================================
Foundation class for all GhostStrike AI agents.

Implements a ReACT (Reasoning + Acting) loop:
  1. LLM receives system prompt + user message + conversation history
  2. LLM decides to call a tool or stop
  3. Tool result is appended to history
  4. Repeat until stop or max_iterations reached

Every tool call is traced via GhostStrikeTracer and validated through GhostStrikeGuardrails.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..guardrails    import GhostStrikeGuardrails
from ..model_provider import GhostStrikeModelProvider
from ..tracer        import GhostStrikeTracer


# ─────────────────────────────────────────────────────────────────────────────
# Result container
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    agent_name:    str
    final_answer:  str
    tool_calls:    List[Dict]          = field(default_factory=list)
    findings:      List[Dict]          = field(default_factory=list)
    total_tokens:  Dict[str, int]      = field(default_factory=dict)
    iterations:    int                 = 0
    success:       bool                = True
    error:         Optional[str]       = None


# ─────────────────────────────────────────────────────────────────────────────
# Base agent
# ─────────────────────────────────────────────────────────────────────────────

class GhostStrikeAgent:
    """
    Base class for all GhostStrike AI agents.

    Subclasses set ``name``, ``description``, ``prompt_file``, and ``tools``
    — the base class handles the entire ReACT loop, token tracking, and tracing.
    """

    name:         str = "Ghost Agent"
    description:  str = "Base GhostStrike agent."
    prompt_file:  str = ""           # filename inside ai_engine/prompts/

    def __init__(
        self,
        model_provider: GhostStrikeModelProvider,
        tracer: Optional[GhostStrikeTracer] = None,
        guardrails: Optional[GhostStrikeGuardrails] = None,
        output_callback: Optional[Callable[[str], None]] = None,
        max_iterations: int = 30,
        engagement_id: str = "",
        autonomy_tier: str = "recommend",
        approval_callback: Optional[Callable[[Dict], bool]] = None,
    ) -> None:
        self._model          = model_provider
        self._tracer         = tracer or GhostStrikeTracer(engagement_id=engagement_id)
        self._guardrails     = guardrails or GhostStrikeGuardrails()
        self._output_cb      = output_callback
        self._max_iterations = max_iterations
        self._engagement_id  = engagement_id
        # Stored before _register_tools() runs (see below) so subclasses can
        # pass these straight through to GhostStrikeRunner when they build
        # it -- see tools/module_runner.py for what the tier/callback do.
        self._autonomy_tier    = autonomy_tier
        self._approval_cb      = approval_callback
        self._system_prompt  = self._load_prompt()
        self._tools: List[Dict]           = []     # OpenAI-format tool schemas
        self._handlers: Dict[str, Any]    = {}     # tool_name → callable
        self._register_tools()

    # ── Subclass hooks ────────────────────────────────────────────────────────

    def _register_tools(self) -> None:
        """Subclasses call _add_tool() here to register their tools."""
        pass

    def _add_tool(self, schema: Dict, handler: Any) -> None:
        """Register a tool schema + its handler callable."""
        self._tools.append(schema)
        fn_name = schema["function"]["name"]
        self._handlers[fn_name] = handler

    # ── Main entry point ─────────────────────────────────────────────────────

    def run(self, user_message: str) -> AgentResult:
        """
        Run the ReACT loop for the given user message.
        Streams output to ``output_callback`` if set.
        """
        self._emit(f"\n[{self.name}] Starting...\n")
        messages: List[Dict] = [{"role": "user", "content": user_message}]
        tool_call_log: List[Dict] = []
        iteration = 0

        with self._tracer.agent_span(self.name, iteration=0):
            while iteration < self._max_iterations:
                iteration += 1
                self._emit(f"\n--- Iteration {iteration} ---\n")

                with self._tracer.agent_span(self.name, iteration=iteration):
                    resp = self._model.complete(
                        messages=messages,
                        tools=self._tools or None,
                        system_prompt=self._system_prompt,
                    )

                self._tracer.record_llm_call(
                    backend=self._model.backend.value,
                    model=self._model.model_name,
                    input_tokens=resp.get("usage", {}).get("input_tokens", 0),
                    output_tokens=resp.get("usage", {}).get("output_tokens", 0),
                    agent_name=self.name,
                )

                content       = resp.get("content", "")
                tool_calls    = resp.get("tool_calls")
                finish_reason = resp.get("finish_reason", "stop")

                if content:
                    self._emit(content + "\n")

                # ── Stopped — final answer ─────────────────────────────────
                if finish_reason == "stop" or not tool_calls:
                    return AgentResult(
                        agent_name=self.name,
                        final_answer=content,
                        tool_calls=tool_call_log,
                        total_tokens=self._tracer.total_tokens(),
                        iterations=iteration,
                    )

                # ── Tool calls ────────────────────────────────────────────
                messages.append({
                    "role":       "assistant",
                    "content":    content,
                    "tool_calls": tool_calls,
                })

                for tc in tool_calls:
                    result = self._dispatch_tool(tc)
                    tool_call_log.append({
                        "tool":   tc["name"],
                        "args":   tc.get("args", {}),
                        "result": result[:500],
                    })
                    messages.append({
                        "role":         "tool",
                        "tool_call_id": tc["id"],
                        "content":      result,
                    })

            # Exhausted iterations
            return AgentResult(
                agent_name=self.name,
                final_answer=f"Max iterations ({self._max_iterations}) reached.",
                tool_calls=tool_call_log,
                total_tokens=self._tracer.total_tokens(),
                iterations=iteration,
                success=False,
            )

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    def _dispatch_tool(self, tool_call: Dict) -> str:
        tool_name = tool_call.get("name", "")
        args      = tool_call.get("args", {})
        handler   = self._handlers.get(tool_name)

        if not handler:
            return f"Error: tool '{tool_name}' not registered for {self.name}."

        self._emit(f"\n[TOOL] {tool_name}({self._format_args(args)})\n")

        with self._tracer.tool_span(tool_name, agent_name=self.name):
            try:
                result = handler(**args) if isinstance(args, dict) else handler(args)
                result = str(result)
            except Exception as exc:
                result = f"Tool error: {exc}"

        self._emit(result[:1000] + ("\n[...truncated]" if len(result) > 1000 else "") + "\n")
        return result

    # ── System prompt loading ─────────────────────────────────────────────────

    def _load_prompt(self) -> str:
        if not self.prompt_file:
            return f"You are {self.name}. {self.description}"
        prompt_dir = Path(__file__).resolve().parent.parent / "prompts"
        path = prompt_dir / self.prompt_file
        if path.exists():
            return path.read_text(encoding="utf-8")
        return f"You are {self.name}. {self.description}"

    # ── Output emission ───────────────────────────────────────────────────────

    def _emit(self, text: str) -> None:
        if self._output_cb:
            self._output_cb(text)

    @staticmethod
    def _format_args(args: Dict) -> str:
        if not args:
            return ""
        short = {k: (str(v)[:40] + "...") if len(str(v)) > 40 else v for k, v in args.items()}
        return ", ".join(f"{k}={repr(v)}" for k, v in short.items())


# ─────────────────────────────────────────────────────────────────────────────
# Convenience runner
# ─────────────────────────────────────────────────────────────────────────────

def run_agent(
    agent: GhostStrikeAgent,
    task: str,
) -> AgentResult:
    """Simple wrapper to run an agent and return its result."""
    return agent.run(task)
