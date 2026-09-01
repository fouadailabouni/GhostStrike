"""
GhostStrike AI Engine — DFIR Agent
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations
from ..tools.shell_executor    import ShellExecutor,      TOOL_SCHEMA as SHELL_SCHEMA
from ..tools.code_runner       import CodeRunner,         TOOL_SCHEMA as CODE_SCHEMA
from ..tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA
from ..tools.network_capture   import NetworkCapture,     TOOL_SCHEMA as CAPTURE_SCHEMA
from ..tools.shodan_censys      import ShodanCensysProbe, TOOL_SCHEMA as SHODAN_SCHEMA
from ..tools.reasoning_engine  import ReasoningEngine,    TOOL_SCHEMA as REASON_SCHEMA
from .base_agent import GhostStrikeAgent


class DFIRAgent(GhostStrikeAgent):
    """
    Digital Forensics and Incident Response agent.
    Memory forensics (Volatility), disk forensics, log analysis,
    malware analysis, network traffic investigation, timeline reconstruction.
    """

    name        = "DFIR Agent"
    description = "Digital forensics and incident response. Volatility, tshark, log analysis, IOC extraction, timeline reconstruction."
    prompt_file = "dfir_prompt.md"

    def _register_tools(self) -> None:
        shell   = ShellExecutor(guardrails=self._guardrails, output_callback=self._output_cb)
        code    = CodeRunner(output_callback=self._output_cb)
        ghost   = GhostStrikeRunner(output_callback=self._output_cb, autonomy_tier=self._autonomy_tier, approval_callback=self._approval_cb)
        capture = NetworkCapture()
        shodan  = ShodanCensysProbe()
        reason  = ReasoningEngine()

        self._add_tool(SHELL_SCHEMA,   shell.run)
        self._add_tool(CODE_SCHEMA,    code.run)
        self._add_tool(GHOST_SCHEMA,   ghost.run)
        self._add_tool(CAPTURE_SCHEMA, capture.capture)
        self._add_tool(SHODAN_SCHEMA,  shodan.probe)
        self._add_tool(REASON_SCHEMA,  reason.think)
