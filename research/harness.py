#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation harness (research/harness.py)

Runs inside the ghoststrike-phase1-runner container, which has real
nmap/nikto/nuclei and network access to the already-running pentest_lab
targets. Two real, executed conditions per scenario:

  A (raw tool-chain baseline): nmap/nikto run directly, no GhostStrike
    involvement. Proxy for "conventional tool-driven workflow" -- an
    automatable substitute for a human manual baseline (which this
    evaluation cannot fabricate), explicitly labeled as such.

  B (GhostStrike, no AI): the identical underlying scan, but its
    structured output is run through EngagementRepository/import_engine
    (real dedup, evidence-tracked add_finding), then
    attack_graph_builder and ghost_score -- isolating what the
    framework's correlation layer adds over the raw tool output.

No condition here is simulated or invented -- every number comes from an
actual subprocess run and actual GhostStrike code paths, executed at
harness run time.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
sys.path.insert(0, str(REPO_ROOT / "CyberToolkit"))
sys.path.insert(0, str(REPO_ROOT / "bash_scripts_for_pentest" / "lib"))

RESULTS_DIR = REPO_ROOT / "research" / "results"
FINDINGS_DIR = REPO_ROOT / "research" / "results" / "findings"


def _run(cmd, timeout=90):
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout + proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        rc = -1
    elapsed = time.monotonic() - started
    return out, rc, elapsed


_ISSUE_LINE_PATTERNS = [
    re.compile(r"^\+ "),                      # nikto finding lines
    re.compile(r"VULNERABLE", re.IGNORECASE),
    re.compile(r"State: VULNERABLE"),
]


def _count_raw_issue_lines(text: str) -> int:
    """Honest proxy metric for condition A: counts lines that LOOK like a
    tool-reported issue in raw, unstructured output -- not equivalent to
    expert triage, just an automatable signal for 'how much did the raw
    tool surface.' Documented as a proxy, not a ground-truth count."""
    return sum(1 for line in text.splitlines() if any(p.search(line) for p in _ISSUE_LINE_PATTERNS))


def run_condition_a(scenario: dict) -> dict:
    """Raw tool-chain baseline: nmap service/script scan + nikto (web only).
    No GhostStrike code involved at all in this condition."""
    target, port, category = scenario["target"], scenario["port"], scenario["category"]
    combined_output = []
    total_elapsed = 0.0
    commands_run = 0

    nmap_cmd = ["nmap", "-sV", "-sC", "-p", str(port), target]
    out, rc, elapsed = _run(nmap_cmd, timeout=90)
    combined_output.append(out)
    total_elapsed += elapsed
    commands_run += 1

    if category == "web":
        nikto_cmd = ["nikto", "-h", f"http://{target}:{port}", "-Tuning", "x", "-timeout", "8"]
        out, rc, elapsed = _run(nikto_cmd, timeout=90)
        combined_output.append(out)
        total_elapsed += elapsed
        commands_run += 1

    full_text = "\n".join(combined_output)
    return {
        "condition": "A_raw_toolchain",
        "commands_run": commands_run,
        "elapsed_seconds": round(total_elapsed, 2),
        "raw_issue_lines": _count_raw_issue_lines(full_text),
        "output_bytes": len(full_text.encode("utf-8", errors="replace")),
    }


def run_condition_b(scenario: dict) -> dict:
    """GhostStrike, no AI: the IDENTICAL underlying tool invocations as
    condition A (nmap, plus nikto for web scenarios -- not nmap alone),
    captured as structured output and run through the real import
    engine / EngagementRepository / dedup / attack graph / GhostScore
    pipeline. Using the same tools as condition A is deliberate: an
    earlier version of this harness ran nikto only in condition A, which
    made condition B look faster for the wrong reason (it simply did
    less work, not because structuring adds no overhead) -- fixed so the
    timing comparison isolates the correlation/structuring step itself."""
    import import_engine
    from engagement_repository import EngagementRepository
    import attack_graph_builder as agb
    import ghost_score as gscore
    import os
    import tempfile

    target, port, category = scenario["target"], scenario["port"], scenario["category"]
    eng_id = f"phase1-{scenario['id']}"
    findings_dir = FINDINGS_DIR / eng_id
    findings_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GS_FINDINGS_DIR"] = str(findings_dir)

    started = time.monotonic()
    commands_run = 0
    all_parsed = []

    nmap_xml_cmd = ["nmap", "-sV", "-sC", "-p", str(port), "-oX", "-", target]
    out, rc, _ = _run(nmap_xml_cmd, timeout=90)
    commands_run += 1
    try:
        all_parsed.extend(import_engine.parse_nmap_xml(out))
    except Exception:
        pass

    if category == "web":
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            nikto_xml_path = tf.name
        nikto_cmd = ["nikto", "-h", f"http://{target}:{port}", "-Tuning", "x", "-timeout", "8",
                     "-Format", "xml", "-o", nikto_xml_path]
        _run(nikto_cmd, timeout=90)
        commands_run += 1
        try:
            nikto_xml = Path(nikto_xml_path).read_text(encoding="utf-8", errors="replace")
            all_parsed.extend(import_engine.parse_nikto_xml(nikto_xml))
        except Exception:
            pass
        finally:
            Path(nikto_xml_path).unlink(missing_ok=True)

    repo = EngagementRepository(eng_id, backend="json")
    findings_created = 0
    merged = 0
    try:
        if all_parsed:
            summary = import_engine.import_findings(repo, all_parsed)
            findings_created = summary["findings_created"]
            merged = summary["observations_merged"]

        graph = agb.build_graph(eng_id)
        try:
            scored = gscore.score_engagement(eng_id, [])
        except Exception:
            scored = []
    finally:
        repo.close()

    elapsed = time.monotonic() - started
    return {
        "condition": "B_ghoststrike_no_ai",
        "commands_run": commands_run,
        "elapsed_seconds": round(elapsed, 2),
        "findings_created": findings_created,
        "observations_merged": merged,
        "graph_nodes": len(graph.get("nodes", [])),
        "graph_edges": len(graph.get("edges", [])),
        "top_ghost_score": max((s["ghost_score"] for s in scored), default=None),
    }


def main():
    scenarios = json.loads((REPO_ROOT / "research" / "scenarios.json").read_text())["scenarios"]
    only = sys.argv[1] if len(sys.argv) > 1 else None

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for scenario in scenarios:
        if only and scenario["id"] != only:
            continue
        print(f"=== {scenario['id']} ({scenario['category']}: {scenario['target']}:{scenario['port']}) ===",
              file=sys.stderr)

        a = run_condition_a(scenario)
        print(f"  A: {a}", file=sys.stderr)
        b = run_condition_b(scenario)
        print(f"  B: {b}", file=sys.stderr)

        results.append({
            "scenario_id": scenario["id"], "category": scenario["category"],
            "target": scenario["target"], "port": scenario["port"],
            "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "condition_a": a, "condition_b": b,
        })

    out_path = RESULTS_DIR / "phase1_results.json"
    existing = []
    if out_path.exists():
        try:
            existing = json.loads(out_path.read_text())
        except json.JSONDecodeError:
            existing = []
    existing = [r for r in existing if r["scenario_id"] not in {r2["scenario_id"] for r2 in results}]
    existing.extend(results)
    out_path.write_text(json.dumps(existing, indent=2))
    print(f"Wrote {len(results)} scenario result(s) to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()