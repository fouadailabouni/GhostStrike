"""
GhostStrike AI Engine — Red Team Agent
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations
from ..tools.shell_executor    import ShellExecutor,    TOOL_SCHEMA as SHELL_SCHEMA
from ..tools.code_runner       import CodeRunner,       TOOL_SCHEMA as CODE_SCHEMA
from ..tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA
from ..tools.shodan_censys      import ShodanCensysProbe, TOOL_SCHEMA as SHODAN_SCHEMA
from ..tools.reasoning_engine  import ReasoningEngine,  TOOL_SCHEMA as REASON_SCHEMA
from .base_agent import GhostStrikeAgent


class RedTeamAgent(GhostStrikeAgent):
    """
    Full offensive red team agent.
    Conducts end-to-end penetration tests: recon → exploit → privesc → impact.
    Calls GhostStrike's 103 bash modules for each attack phase.
    """

    name        = "Red Team Agent"
    description = "Autonomous offensive security agent. Recon, exploit, privilege escalation, lateral movement."
    prompt_file = "red_team_prompt.md"

    def _register_tools(self) -> None:
        shell   = ShellExecutor(guardrails=self._guardrails, output_callback=self._output_cb)
        code    = CodeRunner(output_callback=self._output_cb)
        ghost   = GhostStrikeRunner(output_callback=self._output_cb, autonomy_tier=self._autonomy_tier, approval_callback=self._approval_cb)
        shodan  = ShodanCensysProbe()
        reason  = ReasoningEngine()

        self._add_tool(SHELL_SCHEMA,  shell.run)
        self._add_tool(CODE_SCHEMA,   code.run)
        self._add_tool(GHOST_SCHEMA,  ghost.run)
        self._add_tool(SHODAN_SCHEMA, shodan.probe)
        self._add_tool(REASON_SCHEMA, reason.think)
