"""
GhostStrike AI Engine — Agents Package
Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""
from .base_agent          import GhostStrikeAgent, AgentResult, run_agent
from .red_team_agent      import RedTeamAgent
from .blue_team_agent     import BlueTeamAgent
from .web_pentest_agent   import WebPentestAgent
from .bug_bounty_agent    import BugBountyAgent
from .dfir_agent          import DFIRAgent
from .reverse_eng_agent   import ReverseEngAgent
from .wifi_agent          import WifiAgent
from .ctf_agent           import CTFAgent
from .purple_team_agent   import PurpleTeamAgent
from .nlp_router_agent    import NLPRouterAgent
from .output_analyst_agent import OutputAnalystAgent

# Registry used by the GUI to populate the agent selector
AGENT_REGISTRY = {
    "Red Team":           RedTeamAgent,
    "Blue Team":          BlueTeamAgent,
    "Web Pentester":      WebPentestAgent,
    "Bug Bounty / OSINT": BugBountyAgent,
    "DFIR":               DFIRAgent,
    "Reverse Engineering":ReverseEngAgent,
    "WiFi Security":      WifiAgent,
    "CTF Solver":         CTFAgent,
    "Purple Team":        PurpleTeamAgent,
}

__all__ = [
    "GhostStrikeAgent", "AgentResult", "run_agent",
    "RedTeamAgent", "BlueTeamAgent", "WebPentestAgent",
    "BugBountyAgent", "DFIRAgent", "ReverseEngAgent",
    "WifiAgent", "CTFAgent", "PurpleTeamAgent",
    "NLPRouterAgent", "OutputAnalystAgent",
    "AGENT_REGISTRY",
]
