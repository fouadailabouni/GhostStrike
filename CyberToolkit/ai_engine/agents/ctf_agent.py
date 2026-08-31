"""
GhostStrike AI Engine — CTF Solver Agent
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations
from ..tools.shell_executor    import ShellExecutor,     TOOL_SCHEMA as SHELL_SCHEMA
from ..tools.code_runner       import CodeRunner,        TOOL_SCHEMA as CODE_SCHEMA
from ..tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA
from ..tools.http_analyzer     import HttpAnalyzer,      TOOL_SCHEMA as HTTP_SCHEMA
from ..tools.js_analyzer       import JsAnalyzer,        TOOL_SCHEMA as JS_SCHEMA
from ..tools.reasoning_engine  import ReasoningEngine,   TOOL_SCHEMA as REASON_SCHEMA
from .base_agent import GhostStrikeAgent


class CTFAgent(GhostStrikeAgent):
    """
    CTF (Capture the Flag) competition solver.
    Covers web, pwn, crypto, forensics, reversing, OSINT, and misc categories.
    Optimised for speed: enumerate → exploit → capture flag loop.
    """

    name        = "CTF Solver"
    description = "CTF challenge solver. Web, pwn, crypto, forensics, reversing. Fast flag capture loop."
    prompt_file = "ctf_prompt.md"

    def _register_tools(self) -> None:
        shell  = ShellExecutor(guardrails=self._guardrails, output_callback=self._output_cb)
        code   = CodeRunner(output_callback=self._output_cb)
        ghost  = GhostStrikeRunner(output_callback=self._output_cb)
        http   = HttpAnalyzer()
        js     = JsAnalyzer()
        reason = ReasoningEngine()

        self._add_tool(SHELL_SCHEMA,  shell.run)
        self._add_tool(CODE_SCHEMA,   code.run)
        self._add_tool(GHOST_SCHEMA,  ghost.run)
        self._add_tool(HTTP_SCHEMA,   http.analyse)
        self._add_tool(JS_SCHEMA,     js.analyse)
        self._add_tool(REASON_SCHEMA, reason.think)
