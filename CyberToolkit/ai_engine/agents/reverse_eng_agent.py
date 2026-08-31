"""
GhostStrike AI Engine — Reverse Engineering Agent
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations
from ..tools.shell_executor    import ShellExecutor,     TOOL_SCHEMA as SHELL_SCHEMA
from ..tools.code_runner       import CodeRunner,        TOOL_SCHEMA as CODE_SCHEMA
from ..tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA
from ..tools.reasoning_engine  import ReasoningEngine,   TOOL_SCHEMA as REASON_SCHEMA
from .base_agent import GhostStrikeAgent


class ReverseEngAgent(GhostStrikeAgent):
    """
    Binary analysis and reverse engineering agent.
    Uses Ghidra headless, radare2, binwalk, strings, GDB, Frida, angr.
    Specialises in firmware extraction, vulnerability discovery, and malware analysis.
    """

    name        = "Reverse Engineering"
    description = "Binary analysis, firmware reversing, Ghidra/radare2/binwalk, vulnerability discovery."
    prompt_file = "reverse_eng_prompt.md"

    def _register_tools(self) -> None:
        shell  = ShellExecutor(guardrails=self._guardrails, output_callback=self._output_cb)
        code   = CodeRunner(output_callback=self._output_cb)
        ghost  = GhostStrikeRunner(output_callback=self._output_cb)
        reason = ReasoningEngine()

        self._add_tool(SHELL_SCHEMA,  shell.run)
        self._add_tool(CODE_SCHEMA,   code.run)
        self._add_tool(GHOST_SCHEMA,  ghost.run)
        self._add_tool(REASON_SCHEMA, reason.think)
