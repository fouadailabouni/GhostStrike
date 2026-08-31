"""
GhostStrike AI Engine — Output Analyst Agent
=============================================
Pipes raw tool output through the LLM to:
  1. Extract structured findings (severity, CVSS, description, remediation)
  2. Map findings to MITRE ATT&CK techniques
  3. Suggest the next GhostStrike module to run
  4. Auto-populate the GhostStrike findings JSON

Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..model_provider   import GhostStrikeModelProvider
from ..findings_extractor import FindingsExtractor
from ..mitre_mapper     import MitreMapper

_ANALYST_SYSTEM_PROMPT = """You are the GhostStrike Output Analyst.

You receive raw output from penetration testing tools and produce:

1. A brief summary of what the tool found (2-3 sentences)
2. FINDINGS — structured list of vulnerabilities or notable items
3. MITRE ATT&CK techniques observed
4. NEXT STEPS — the 2-3 most logical GhostStrike modules to run next

Format your response as:

## Summary
<2-3 sentence summary>

## Findings
| Severity | Title | Affected Asset | Evidence |
|----------|-------|---------------|---------|
| HIGH | ... | ... | ... |

## MITRE ATT&CK
- T1046 — Network Service Discovery
- ...

## Next Steps
1. `module_name.sh` — reason why
2. `module_name.sh` — reason why

Be concise. Focus on actionable intelligence."""


class OutputAnalystAgent:
    """
    Single-shot output analysis agent.

    The GUI calls ``analyse()`` after every script execution to get
    an AI interpretation of the raw output.
    """

    def __init__(self, model_provider: GhostStrikeModelProvider) -> None:
        self._model     = model_provider
        self._extractor = FindingsExtractor(model_provider)
        self._mitre     = MitreMapper()

    def analyse(
        self,
        tool_output: str,
        tool_name: str = "",
        target: str = "",
        engagement_id: str = "",
    ) -> Dict:
        """
        Analyse raw tool output.

        Returns:
        {
            "summary":         str,
            "ai_analysis":     str,   # full markdown analysis
            "findings":        list,  # structured finding dicts
            "mitre":           list,  # MITRE technique dicts
            "next_steps":      list,  # suggested module names
        }
        """
        # Structured extraction
        findings = self._extractor.extract(
            tool_output=tool_output,
            tool_name=tool_name,
            target=target,
            engagement_id=engagement_id,
        )

        # MITRE mapping from raw output
        mitre_hits = self._mitre.map_output(tool_output)

        # LLM narrative analysis
        context = (
            f"Tool: {tool_name}\nTarget: {target}\n\n"
            f"Output:\n{tool_output[:4000]}"
        )
        try:
            resp = self._model.complete(
                messages=[{"role": "user", "content": context}],
                system_prompt=_ANALYST_SYSTEM_PROMPT,
            )
            ai_text = resp.get("content", "")
        except Exception as exc:
            ai_text = f"AI analysis unavailable: {exc}"

        next_steps = self._extract_next_steps(ai_text)

        return {
            "summary":     self._extract_summary(ai_text),
            "ai_analysis": ai_text,
            "findings":    findings,
            "mitre":       mitre_hits,
            "next_steps":  next_steps,
        }

    def quick_summary(self, tool_output: str, tool_name: str = "") -> str:
        """Return a one-paragraph AI summary of tool output."""
        result = self.analyse(tool_output, tool_name=tool_name)
        return result.get("summary", "No summary available.")

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_summary(text: str) -> str:
        import re
        match = re.search(r"## Summary\s*\n(.*?)(?=\n##|\Z)", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        lines = text.strip().splitlines()
        return " ".join(lines[:3]) if lines else text[:200]

    @staticmethod
    def _extract_next_steps(text: str) -> List[str]:
        import re
        steps: List[str] = []
        match = re.search(r"## Next Steps\s*\n(.*?)(?=\n##|\Z)", text, re.DOTALL)
        if match:
            block = match.group(1)
            for line in block.splitlines():
                m = re.search(r"`([a-z_]+\.sh)`", line)
                if m:
                    steps.append(m.group(1))
        return steps[:3]
