"""
GhostStrike AI Engine — Reasoning Engine
==========================================
Gives AI agents an explicit "think before acting" step.  The agent
calls this tool when it needs to reason through a complex situation
before choosing its next action — inspired by the ReACT methodology.

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

from typing import Dict

TOOL_SCHEMA: Dict = {
    "type": "function",
    "function": {
        "name": "think",
        "description": (
            "Use this tool to reason step-by-step before taking a complex action. "
            "Write out your current understanding of the situation, what you have found, "
            "what you are uncertain about, and what your next steps should be. "
            "This does NOT execute anything — it is a structured thinking space. "
            "Use it when you have multiple possible paths or are stuck."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "situation":   {"type": "string", "description": "What you currently know about the target/situation."},
                "findings":    {"type": "string", "description": "Findings collected so far."},
                "hypotheses":  {"type": "string", "description": "Possible vulnerabilities or attack paths to investigate."},
                "blockers":    {"type": "string", "description": "What is blocking progress (if anything)."},
                "next_action": {"type": "string", "description": "The specific next tool call or action you plan to take."},
            },
            "required": ["situation", "next_action"],
        },
    },
}


class ReasoningEngine:
    """Structured reasoning tool — returns a formatted thinking summary."""

    def think(
        self,
        situation: str,
        next_action: str,
        findings: str = "",
        hypotheses: str = "",
        blockers: str = "",
    ) -> str:
        sections = ["=== GhostStrike Agent: Reasoning Step ===\n"]

        sections.append(f"SITUATION:\n{situation.strip()}")

        if findings.strip():
            sections.append(f"\nFINDINGS SO FAR:\n{findings.strip()}")

        if hypotheses.strip():
            sections.append(f"\nHYPOTHESES / ATTACK PATHS:\n{hypotheses.strip()}")

        if blockers.strip():
            sections.append(f"\nBLOCKERS:\n{blockers.strip()}")

        sections.append(f"\nNEXT ACTION:\n{next_action.strip()}")
        sections.append("\n=== (Reasoning complete — proceed with next_action) ===")

        return "\n".join(sections)
