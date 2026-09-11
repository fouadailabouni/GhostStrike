#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- broader scenario corpus, approved 3-target
core (research/broader_scenarios_condition_ab.py)

Runs Condition A (raw nmap/nikto) and Condition B (GhostStrike, no AI)
against the 3 approved new targets by IMPORTING research/harness.py's real
run_condition_a()/run_condition_b() functions DIRECTLY -- not shelling out,
not reimplementing, not editing harness.py itself (out of scope: a
concurrent peer session owns AI-runtime-metadata work touching
harness_ai.py, and this script must not risk any collision with that or
with a second peer session's concurrent work on lib/reproducibility.sh /
repro_scale_runner.sh).

No collision risk with either peer's work by construction: harness.py's
Condition A/B pipeline (nmap/nikto subprocess calls -> import_engine ->
EngagementRepository -> attack_graph_builder -> ghost_score) never sources
lib/reproducibility.sh and never touches repro_scale_runner.sh -- confirmed
by reading harness.py directly (it calls subprocess.run() on nmap/nikto
itself, with no dependency on the reproducibility-scoring subsystem at all).
scenarios.json is also left untouched -- the 3 new target definitions are
inline dicts here, not appended to the shared file.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
sys.path.insert(0, str(REPO_ROOT / "research"))
sys.path.insert(0, str(REPO_ROOT / "CyberToolkit"))
sys.path.insert(0, str(REPO_ROOT / "bash_scripts_for_pentest" / "lib"))

import harness  # noqa: E402 -- the real, unmodified research/harness.py

RESULTS_DIR = REPO_ROOT / "research" / "results"

# Approved 3-target core only (the 2 optional stretch targets -- genuine
# anon FTP and a second SSH weak-cred profile on vulnerable_services --
# were explicitly NOT approved and are not included here).
NEW_SCENARIOS = [
    {"id": "broader-vulnsvc-rce", "category": "web", "target": "vulnerable_services", "port": 80},
    {"id": "broader-vulnsvc-smb", "category": "network", "target": "vulnerable_services", "port": 445},
    {"id": "broader-postgres", "category": "network", "target": "postgres", "port": 5432},
]


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for scenario in NEW_SCENARIOS:
        print(f"=== {scenario['id']} ({scenario['category']}: {scenario['target']}:{scenario['port']}) ===",
              file=sys.stderr)
        a = harness.run_condition_a(scenario)
        print(f"  A: {a}", file=sys.stderr)
        b = harness.run_condition_b(scenario)
        print(f"  B: {b}", file=sys.stderr)
        results.append({
            "scenario_id": scenario["id"], "category": scenario["category"],
            "target": scenario["target"], "port": scenario["port"],
            "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "condition_a": a, "condition_b": b,
        })

    out_path = RESULTS_DIR / "phase1_broader_scenarios_results.json"
    out_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "note": (
            "Condition A/B results for the 3 approved new targets, produced by importing and "
            "calling research/harness.py's real run_condition_a()/run_condition_b() functions "
            "directly -- harness.py itself was not modified. This is a companion file, separate "
            "from the original 10-scenario phase1_results.json."
        ),
        "scenarios": NEW_SCENARIOS,
        "results": results,
    }, indent=2))
    print(f"Wrote {len(results)} scenario result(s) to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()