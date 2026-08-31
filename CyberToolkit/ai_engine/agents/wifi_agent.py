"""
GhostStrike AI Engine — WiFi Security Agent
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations
from ..tools.shell_executor    import ShellExecutor,     TOOL_SCHEMA as SHELL_SCHEMA
from ..tools.code_runner       import CodeRunner,        TOOL_SCHEMA as CODE_SCHEMA
from ..tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA
from ..tools.reasoning_engine  import ReasoningEngine,   TOOL_SCHEMA as REASON_SCHEMA
from .base_agent import GhostStrikeAgent


class WifiAgent(GhostStrikeAgent):
    """
    Wireless security testing agent.
    WPA2/WPA3 handshake capture, password cracking, WPS attacks,
    rogue AP detection, Bluetooth and BLE assessment.
    """

    name        = "WiFi Security"
    description = "Wireless penetration testing. WPA2 cracking, WPS attacks, rogue AP detection, Bluetooth scanning."
    prompt_file = "wifi_prompt.md"

    def _register_tools(self) -> None:
        shell  = ShellExecutor(guardrails=self._guardrails, output_callback=self._output_cb)
        code   = CodeRunner(output_callback=self._output_cb)
        ghost  = GhostStrikeRunner(output_callback=self._output_cb)
        reason = ReasoningEngine()

        self._add_tool(SHELL_SCHEMA,  shell.run)
        self._add_tool(CODE_SCHEMA,   code.run)
        self._add_tool(GHOST_SCHEMA,  ghost.run)
        self._add_tool(REASON_SCHEMA, reason.think)
