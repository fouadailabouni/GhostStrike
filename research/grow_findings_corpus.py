#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- findings-corpus growth helper (research/grow_findings_corpus.py)

Reuses the exact same real, already-proven pipeline research/harness.py's
run_condition_b() uses (nmap -oX / nikto -Format xml -> import_engine's real
parsers -> EngagementRepository.add_finding, the same path that produced the
original 58 findings under research/results/findings/) to run it several
more times against the same 10 lab scenarios under fresh engagement IDs, so
the dedup benchmark (experiment 5) has a larger real corpus to draw
hand-labeled pairs from -- repeated real scans of the same live target also
give genuinely real near-duplicate finding pairs "for free," which is
exactly the kind of example a dedup benchmark needs.

Adds `--script vuln` to the nmap invocation (harness.py's own condition B
does not) specifically to give experiment 6 (GhostScore vs CVSS) a real
chance at CVE-tagged NSE script output, since import_engine.parse_nmap_xml
already extracts CVE IDs from script output when present. Whether any lab
target actually trips a vuln script is an open, honestly-reported question,
not assumed.

NOTE on a real bug found while building this: EngagementRepository.add_finding()
has no cve_ids/cvss_score parameter at all, so even though parse_nmap_xml can
extract real CVE IDs from NSE output, they are silently dropped before
reaching a persisted finding record. This script therefore ALSO writes a
side-channel raw-parsed-findings file (see RAW_PARSED_PATH) capturing
whatever parse_nmap_xml/parse_nikto_xml actually returned, cve_ids included,
so experiment 6 can use the real (pre-persistence-bug) data directly instead
of being silently capped at zero by a bug in an unrelated part of the
pipeline.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
sys.path.insert(0, str(REPO_ROOT / "CyberToolkit"))
sys.path.insert(0, str(REPO_ROOT / "bash_scripts_for_pentest" / "lib"))

RESULTS_DIR = REPO_ROOT / "research" / "results"
FINDINGS_DIR = RESULTS_DIR / "findings"
RAW_PARSED_PATH = RESULTS_DIR / "phase1_growth_raw_parsed.json"

REPEATS = 3


def _run(cmd, timeout=90):
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout + proc.stderr
        rc = proc.returncode
    except subprocess.TimeoutExpired as e:
        def _dec(x):
            if x is None:
                return ""
            return x.decode("utf-8", errors="replace") if isinstance(x, bytes) else x
        out = _dec(e.stdout) + _dec(e.stderr)
        rc = -1
    elapsed = time.monotonic() - started
    return out, rc, elapsed


def grow_one(scenario: dict, run_idx: int, raw_parsed_accum: list) -> dict:
    import import_engine
    from engagement_repository import EngagementRepository
    import os

    target, port, category = scenario["target"], scenario["port"], scenario["category"]
    eng_id = f"phase1-growth-{scenario['id']}-run{run_idx}"
    findings_dir = FINDINGS_DIR / eng_id
    already_done = findings_dir.is_dir() and any(findings_dir.glob("*.json"))
    findings_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GS_FINDINGS_DIR"] = str(findings_dir)

    if already_done:
        existing = list(findings_dir.glob("*.json"))
        return {
            "engagement_id": eng_id, "scenario_id": scenario["id"], "run_idx": run_idx,
            "commands_run": 0, "findings_created": len(existing), "observations_merged": 0,
            "cve_bearing_count": 0, "skipped_already_done": True,
            "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    all_parsed = []
    commands_run = 0

    nmap_xml_cmd = ["nmap", "-sV", "-sC", "--script", "vuln", "-p", str(port), "-oX", "-", target]
    out, rc, elapsed_nmap = _run(nmap_xml_cmd, timeout=90)
    commands_run += 1
    nmap_parsed = []
    try:
        nmap_parsed = import_engine.parse_nmap_xml(out)
        all_parsed.extend(nmap_parsed)
    except Exception as exc:
        nmap_parsed = [{"parse_error": f"{type(exc).__name__}: {exc}"}]

    nikto_parsed = []
    if category == "web":
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            nikto_xml_path = tf.name
        nikto_cmd = ["nikto", "-h", f"http://{target}:{port}", "-Tuning", "x", "-timeout", "8",
                     "-Format", "xml", "-o", nikto_xml_path]
        _run(nikto_cmd, timeout=90)
        commands_run += 1
        try:
            nikto_xml = Path(nikto_xml_path).read_text(encoding="utf-8", errors="replace")
            nikto_parsed = import_engine.parse_nikto_xml(nikto_xml)
            all_parsed.extend(nikto_parsed)
        except Exception as exc:
            nikto_parsed = [{"parse_error": f"{type(exc).__name__}: {exc}"}]
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
    finally:
        repo.close()

    # Side-channel raw capture -- includes cve_ids/cvss_score exactly as the
    # real parser produced them, independent of add_finding()'s persistence
    # gap (see module docstring).
    cve_bearing = [f for f in (nmap_parsed + nikto_parsed) if f.get("cve_ids")]
    raw_parsed_accum.append({
        "engagement_id": eng_id, "scenario_id": scenario["id"], "run_idx": run_idx,
        "target": target, "port": port,
        "nmap_findings_parsed": nmap_parsed, "nikto_findings_parsed": nikto_parsed,
        "cve_bearing_findings": cve_bearing,
    })

    return {
        "engagement_id": eng_id, "scenario_id": scenario["id"], "run_idx": run_idx,
        "commands_run": commands_run, "findings_created": findings_created,
        "observations_merged": merged, "cve_bearing_count": len(cve_bearing),
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main():
    scenarios = json.loads((REPO_ROOT / "research" / "scenarios.json").read_text())["scenarios"]
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    raw_parsed_accum = json.loads(RAW_PARSED_PATH.read_text()) if RAW_PARSED_PATH.exists() else []
    summaries = []
    for run_idx in range(1, REPEATS + 1):
        for scenario in scenarios:
            print(f"=== growth run{run_idx} :: {scenario['id']} ===", file=sys.stderr)
            r = grow_one(scenario, run_idx, raw_parsed_accum)
            print(f"  {r}", file=sys.stderr)
            summaries.append(r)
            RAW_PARSED_PATH.write_text(json.dumps(raw_parsed_accum, indent=2))

    total_created = sum(r["findings_created"] for r in summaries)
    total_cve = sum(r["cve_bearing_count"] for r in summaries)
    print(f"TOTAL findings_created={total_created} cve_bearing={total_cve}", file=sys.stderr)

    summary_path = RESULTS_DIR / "phase1_growth_summary.json"
    summary_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repeats_per_scenario": REPEATS,
        "runs": summaries,
        "total_findings_created": total_created,
        "total_cve_bearing_raw_findings": total_cve,
    }, indent=2))
    print(f"Wrote growth summary to {summary_path}", file=sys.stderr)


if __name__ == "__main__":
    main()