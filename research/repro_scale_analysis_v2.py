#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- experiment 2b analysis
(research/repro_scale_analysis_v2.py)

Same analysis as research/repro_scale_analysis.py, adapted for the
corrected reproducibility re-run (research/repro_scale_runner_v2.sh,
research/results/repro_scale_v2_sessions/) that fixes the two
instrumentation gaps identified in the original 200-session study:
GS_SCOPE_FILE now set to a real scope.yml, and 5 real commands logged
per session instead of 1.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
RESULTS_DIR = REPO_ROOT / "research" / "results"
SESSIONS_DIR = RESULTS_DIR / "repro_scale_v2_sessions"

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
_ENG_ID_RE = re.compile(r"^phase1-repro-v2-(.+)-rep(\d+)$")

_FINDING_LINE_PATTERNS = [
    re.compile(r"MISSING:\s*(.+)", re.IGNORECASE),
    re.compile(r"Cookie missing \S+ flag", re.IGNORECASE),
    re.compile(r"^\s*(\d+/(?:tcp|udp))\s+(open|filtered)\s+(\S+)", re.MULTILINE),
    re.compile(r"VULNERABLE", re.IGNORECASE),
    re.compile(r"CVE-\d{4}-\d{4,}"),
]


def _extract_finding_set(log_text: str) -> set:
    text = _ANSI_RE.sub("", log_text)
    findings = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for pat in _FINDING_LINE_PATTERNS:
            m = pat.search(stripped)
            if m:
                findings.add(stripped.lower())
                break
    return findings


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def main():
    session_files = sorted(SESSIONS_DIR.glob("*.json")) if SESSIONS_DIR.exists() else []
    # Session JSON files land in the shared metrics/repro_sessions dir
    # (gs_repro_start's default), not SESSIONS_DIR itself (that dir only
    # holds this run's *_output.log capture files) -- read from there,
    # filtered to this run's engagement_id prefix.
    shared_sessions_dir = REPO_ROOT / "bash_scripts_for_pentest" / "metrics" / "repro_sessions"
    session_files = sorted(shared_sessions_dir.glob("*.json"))

    sessions = []
    for p in session_files:
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not d.get("engagement_id", "").startswith("phase1-repro-v2-"):
            continue
        if "reproducibility_score" not in d:
            continue
        sessions.append(d)

    print(f"Loaded {len(sessions)} v2 session files from {shared_sessions_dir}", file=sys.stderr)

    completed = [s for s in sessions if s.get("reproducibility_score") is not None]
    incomplete = [s for s in sessions if s.get("reproducibility_score") is None]

    scores = [s["reproducibility_score"] for s in completed]
    median_score = statistics.median(scores) if scores else None
    pct_ge_90 = (sum(1 for s in scores if s >= 90) / len(scores)) if scores else None

    by_scenario = defaultdict(list)
    for s in completed:
        eng_id = s.get("engagement_id", "")
        m = _ENG_ID_RE.match(eng_id)
        if not m:
            continue
        scenario_id, rep = m.group(1), int(m.group(2))
        log_path = None
        for art in s.get("artifacts", []):
            if art.get("label") == "module_stdout_stderr":
                log_path = art.get("path")
                break
        finding_set = set()
        log_exists = False
        if log_path and Path(log_path).exists():
            log_exists = True
            finding_set = _extract_finding_set(Path(log_path).read_text(encoding="utf-8", errors="replace"))
        by_scenario[scenario_id].append({
            "engagement_id": eng_id, "rep": rep, "session_id": s["session_id"],
            "reproducibility_score": s["reproducibility_score"],
            "score_breakdown": s.get("score_breakdown"),
            "log_path": log_path, "log_exists": log_exists,
            "finding_set_size": len(finding_set), "finding_set": sorted(finding_set),
        })

    per_scenario_jaccard = {}
    all_pairwise = []
    for scenario_id, runs in sorted(by_scenario.items()):
        runs_sorted = sorted(runs, key=lambda r: r["rep"])
        pairs = list(combinations(runs_sorted, 2))
        pairwise_scores = []
        for a, b in pairs:
            j = _jaccard(set(a["finding_set"]), set(b["finding_set"]))
            pairwise_scores.append(j)
            all_pairwise.append(j)
        per_scenario_jaccard[scenario_id] = {
            "n_runs": len(runs_sorted),
            "n_pairs": len(pairs),
            "mean_pairwise_jaccard": round(statistics.mean(pairwise_scores), 4) if pairwise_scores else None,
            "min_pairwise_jaccard": round(min(pairwise_scores), 4) if pairwise_scores else None,
            "max_pairwise_jaccard": round(max(pairwise_scores), 4) if pairwise_scores else None,
            "finding_set_sizes_by_rep": {r["rep"]: r["finding_set_size"] for r in runs_sorted},
        }

    overall_mean_jaccard = round(statistics.mean(all_pairwise), 4) if all_pairwise else None

    breakdown_by_module = defaultdict(list)
    for s in completed:
        bd = s.get("score_breakdown")
        if bd:
            breakdown_by_module[s.get("module_name", "?")].append(bd)

    module_score_stats = {}
    for module_name, breakdowns in breakdown_by_module.items():
        totals = [sum(bd.get(k, 0) for k in (
            "tool_versions_recorded", "commands_logged", "scope_documented", "artifacts_hashed"
        )) for bd in breakdowns]
        module_score_stats[module_name] = {
            "n_sessions": len(breakdowns),
            "example_breakdown": breakdowns[0] if breakdowns else None,
        }

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "purpose": (
            "Re-run of the reproducibility-at-scale study (research/repro_scale_runner.sh, "
            "200 sessions, phase1_repro_scale.json -- NOT overwritten) with the two "
            "identified instrumentation gaps fixed: GS_SCOPE_FILE now points at a real "
            "scope.yml, and each session logs 5 real, actually-executed commands (tool "
            "version check, reachability probe, the module invocation, a confirmatory "
            "second probe, and a post-run artifact hash check) instead of 1."
        ),
        "original_results_file": "phase1_repro_scale.json (NOT overwritten or touched)",
        "total_sessions_found": len(sessions),
        "completed_sessions": len(completed),
        "incomplete_sessions": len(incomplete),
        "median_reproducibility_score": median_score,
        "pct_sessions_score_ge_90": round(pct_ge_90, 4) if pct_ge_90 is not None else None,
        "score_distribution": {str(k): scores.count(k) for k in sorted(set(scores))},
        "overall_mean_pairwise_jaccard_across_scenarios": overall_mean_jaccard,
        "per_scenario_jaccard": per_scenario_jaccard,
        "module_score_stats": module_score_stats,
        "methodology": (
            f"{len(completed)} real repeated runs across the 10 scenarios in scenarios.json, "
            "via research/repro_scale_runner_v2.sh (real gs_repro_start/_record_cmd/_end "
            "scoring, real GS_SCOPE_FILE, 5 real commands logged per session). "
            "median_reproducibility_score and pct_sessions_score_ge_90 are computed directly "
            "from each session's real reproducibility_score field. Jaccard similarity uses "
            "the same text-line proxy method as the original study for direct comparability."
        ),
        "limitations": [
            "Jaccard similarity is a text-line proxy over real captured output, not a "
            "ground-truth finding-identity comparison, same caveat as the original study.",
            "N per scenario is 5 repeats here versus 20 in the original 200-session study, a "
            "smaller but still real and multiply-repeated sample, disclosed as a scope "
            "difference rather than presented as equivalent scale.",
            "artifacts_hashed remains capped for http_security_headers.sh (only the "
            "stdout/stderr log is ever produced, since that module never calls "
            "gs_setup_output) and nmap_automation.sh's 25/25 there still reflects framework "
            "bookkeeping-file coverage, not real scan-evidence coverage (Section on evidence "
            "integrity) -- fixing commands_logged and scope_documented did not touch this "
            "pre-existing, separately-documented gap.",
        ],
    }

    out_path = RESULTS_DIR / "phase1_repro_scale_v2.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Wrote {out_path}", file=sys.stderr)
    print(f"median_score={median_score} pct_ge_90={pct_ge_90} "
          f"overall_mean_jaccard={overall_mean_jaccard} incomplete={len(incomplete)}",
          file=sys.stderr)


if __name__ == "__main__":
    main()
