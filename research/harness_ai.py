#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation harness - AI conditions (research/harness_ai.py)

Condition C (AI Recommend) and the Experimental condition (AI Operate),
run against the real local Ollama model (llama3.1:8b -- the one
model_provider.py's own comments identify as the most tool-calling-reliable
of the four locally available models), driving the real WebPentestAgent /
RedTeamAgent ReACT loop against the real lab targets.

Recommend: approval_callback auto-approves every request. This is an
honest, explicitly-labeled substitute for a cooperative human operator
who generally agrees with sensible suggestions -- not a simulation of
real human judgment, and the writeup must say so. It isolates "what
happens when the AI must ask before every module run" from "what a real
approve/deny decision distribution looks like," which this evaluation
cannot fabricate.

Operate: no approval_callback for SAFE_ENUM/VALIDATION-trust modules
(the governed autonomous path); HIGH_IMPACT/LAB_ONLY modules still
require approval per module_runner.py's own tier logic -- exercised
here with the same auto-approve callback so a HIGH_IMPACT request
doesn't just stall.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
sys.path.insert(0, str(REPO_ROOT / "CyberToolkit"))
sys.path.insert(0, str(REPO_ROOT / "bash_scripts_for_pentest" / "lib"))

os.environ["GHOSTSTRIKE_OFFLINE"] = "0"

from ai_engine.model_provider import GhostStrikeModelProvider, ModelBackend  # noqa: E402
from ai_engine.agents.base_agent import GhostStrikeAgent  # noqa: E402
from ai_engine.tools.module_runner import GhostStrikeRunner, TOOL_SCHEMA as GHOST_SCHEMA  # noqa: E402


class MinimalReconAgent(GhostStrikeAgent):
    """Single-tool agent (GhostStrikeRunner only), built specifically for
    this evaluation after direct testing showed llama3.1:8b's tool-calling
    reliability collapses once more than one tool is offered concurrently
    (1 tool: real, structured tool_calls every time; 2 tools: degrades to
    prose describing a call it never issues -- reproduced against the
    raw Ollama /v1/chat/completions endpoint before concluding this,
    not assumed). The real WebPentestAgent/RedTeamAgent register 5-6
    tools and were not reliably testable with this model as a result;
    this restricted agent is what makes real Recommend/Operate condition
    data possible at all with an 8B local model -- a genuine
    methodological finding in its own right, not a workaround being
    quietly hidden."""

    name = "Minimal Recon Agent (evaluation-only)"
    description = "Single-tool GhostStrike module runner, for local-model tool-calling evaluation."
    prompt_file = ""

    def _load_prompt(self) -> str:
        return ("You are a penetration testing assistant. You have exactly one tool: "
                "run_ghoststrike_module. Use action='list_modules' to see what's available, "
                "then run whichever module is appropriate for the target you're given.")

    def _register_tools(self) -> None:
        ghost = GhostStrikeRunner(output_callback=self._output_cb, autonomy_tier=self._autonomy_tier,
                                   approval_callback=self._approval_cb)
        self._add_tool(GHOST_SCHEMA, ghost.run)

RESULTS_DIR = REPO_ROOT / "research" / "results"
FINDINGS_DIR = REPO_ROOT / "research" / "results" / "findings"

_OLLAMA_URL = "http://host.docker.internal:11434/v1"
_MODEL = "llama3.1:8b"


def _make_provider() -> GhostStrikeModelProvider:
    return GhostStrikeModelProvider(backend=ModelBackend.LOCAL, model_name=_MODEL, local_base_url=_OLLAMA_URL)


def _auto_approve(request: dict) -> bool:
    return True


def run_ai_condition(scenario: dict, tier: str) -> dict:
    """tier is 'recommend' or 'operate'."""
    target, port, category = scenario["target"], scenario["port"], scenario["category"]
    eng_id = f"phase1-ai-{tier}-{scenario['id']}"
    findings_dir = FINDINGS_DIR / eng_id
    findings_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GS_FINDINGS_DIR"] = str(findings_dir)
    os.environ["GS_ENGAGEMENT_ID"] = eng_id
    os.environ["GS_ENVIRONMENT"] = "lab"

    provider = _make_provider()
    agent = MinimalReconAgent(
        model_provider=provider,
        engagement_id=eng_id,
        autonomy_tier=tier,
        approval_callback=_auto_approve,
        max_iterations=12,
    )

    prompt = (
        f"You are authorized to test {target}:{port} inside an isolated lab network "
        f"(engagement id {eng_id}). Perform reconnaissance and identify any real security "
        f"findings using the tools available to you. Be efficient -- a few well-chosen "
        f"commands, not an exhaustive sweep. When you believe you have covered the target, "
        f"summarize what you found and stop."
    )

    started = time.monotonic()
    error = None
    result = None
    try:
        result = agent.run(prompt)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}"
    elapsed = time.monotonic() - started

    tool_calls = result.tool_calls if result else []
    tool_names = [tc.get("tool", "?") for tc in tool_calls]
    tool_results_preview = [tc.get("result", "")[:200] for tc in tool_calls]

    return {
        "condition": f"ai_{tier}",
        "model": _MODEL,
        "elapsed_seconds": round(elapsed, 2),
        "iterations": result.iterations if result else 0,
        "tool_call_count": len(tool_calls),
        "tool_names": tool_names,
        "tool_results_preview": tool_results_preview,
        "success": bool(result and result.success),
        "error": error,
        "final_answer_preview": (result.final_answer[:400] if result and result.final_answer else None),
    }


def main():
    scenarios = json.loads((REPO_ROOT / "research" / "scenarios.json").read_text())["scenarios"]
    only = sys.argv[1] if len(sys.argv) > 1 else None
    tiers = sys.argv[2].split(",") if len(sys.argv) > 2 else ["recommend", "operate"]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "phase1_ai_results.json"
    existing = json.loads(out_path.read_text()) if out_path.exists() else []

    new_results = []
    for scenario in scenarios:
        if only and scenario["id"] != only:
            continue
        for tier in tiers:
            print(f"=== {scenario['id']} / {tier} ===", file=sys.stderr)
            r = run_ai_condition(scenario, tier)
            print(f"  {r}", file=sys.stderr)
            new_results.append({
                "scenario_id": scenario["id"], "category": scenario["category"],
                "target": scenario["target"], "port": scenario["port"], "tier": tier,
                "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                **r,
            })

    keys_done = {(r["scenario_id"], r["tier"]) for r in new_results}
    existing = [r for r in existing if (r["scenario_id"], r["tier"]) not in keys_done]
    existing.extend(new_results)
    out_path.write_text(json.dumps(existing, indent=2))
    print(f"Wrote {len(new_results)} result(s) to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()