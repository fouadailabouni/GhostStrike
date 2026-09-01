"""
GhostStrike AI Engine — Bug Bounty / OSINT Agent
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations
from ..tools.shell_executor    import ShellExecutor,     TOOL_SCHEMA as SHELL_SCHEMA
from ..tools.code_runner       import CodeRunner,        TOOL_SCHEMA as CODE_SCHEMA
from ..tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA
from ..tools.shodan_censys      import ShodanCensysProbe, TOOL_SCHEMA as SHODAN_SCHEMA
from ..tools.osint_orchestrator import OsintOrchestrator, TOOL_SCHEMA as OSINT_SCHEMA
from ..tools.http_analyzer     import HttpAnalyzer,      TOOL_SCHEMA as HTTP_SCHEMA
from ..tools.js_analyzer       import JsAnalyzer,        TOOL_SCHEMA as JS_SCHEMA
from ..tools.reasoning_engine  import ReasoningEngine,   TOOL_SCHEMA as REASON_SCHEMA
from .base_agent import GhostStrikeAgent


class BugBountyAgent(GhostStrikeAgent):
    """
    Bug bounty hunter and OSINT specialist.
    Wide attack surface discovery → OSINT → high-impact vuln finding.
    Integrates Shodan, Censys, theHarvester, crt.sh, Google dorking.
    """

    name        = "Bug Bounty / OSINT"
    description = "Bug bounty hunting with OSINT. Shodan, Censys, subdomain enum, credential leaks, vuln discovery."
    prompt_file = "bug_bounty_prompt.md"

    def _register_tools(self) -> None:
        shell  = ShellExecutor(guardrails=self._guardrails, output_callback=self._output_cb)
        code   = CodeRunner(output_callback=self._output_cb)
        ghost  = GhostStrikeRunner(output_callback=self._output_cb, autonomy_tier=self._autonomy_tier, approval_callback=self._approval_cb)
        shodan = ShodanCensysProbe()
        osint  = OsintOrchestrator()
        http   = HttpAnalyzer()
        js     = JsAnalyzer()
        reason = ReasoningEngine()

        self._add_tool(SHELL_SCHEMA,  shell.run)
        self._add_tool(CODE_SCHEMA,   code.run)
        self._add_tool(GHOST_SCHEMA,  ghost.run)
        self._add_tool(SHODAN_SCHEMA, shodan.probe)
        self._add_tool(OSINT_SCHEMA,  osint.recon)
        self._add_tool(HTTP_SCHEMA,   http.analyse)
        self._add_tool(JS_SCHEMA,     js.analyse)
        self._add_tool(REASON_SCHEMA, reason.think)
