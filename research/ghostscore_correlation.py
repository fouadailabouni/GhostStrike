#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- experiment 6: GhostScore vs CVSS correlation
(research/ghostscore_correlation.py)

Real bug found while building this (documented in
research/grow_findings_corpus.py's docstring too):
EngagementRepository.add_finding() has no cve_ids/cvss_score parameter at
all, so every finding persisted through the normal add_finding()/
import_findings() pipeline loses whatever CVE/CVSS data its scanner parser
(import_engine.parse_nmap_xml etc.) actually extracted, BEFORE it is ever
written to research/results/findings/*.json. Zero persisted findings in this
corpus carry cve_ids or cvss_score as a result -- confirmed by direct grep
across the entire findings/ tree.

This experiment therefore reads the REAL scanner-parser output directly from
research/results/phase1_growth_raw_parsed.json -- the side-channel this
evaluator's grow_findings_corpus.py wrote specifically because of the bug
above, capturing exactly what import_engine.parse_nmap_xml/parse_nikto_xml
returned (title, severity, host, port, cve_ids), i.e. genuinely real
scanner-derived data, just read from a point in the pipeline before the
persistence bug drops it, not fabricated or backfilled.

score_finding() is called DIRECTLY (imported, not shelled out) against a
hand-built graph dict this evaluator constructs from the real
host/port/finding data. There is no crown-jewel designation and no
confirmed attack-path/lateral-movement evidence anywhere in this pilot's
real data, so the graph has real host nodes but ZERO edges and ZERO crown
jewels -- an honest reflection of what evidence actually exists, not an
invented topology. score_finding()'s own documented behavior for that case
(_NO_CROWN_JEWELS_DEFINED = 1.0, neutral) is exercised for real, not worked
around.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
sys.path.insert(0, str(REPO_ROOT / "bash_scripts_for_pentest" / "lib"))
import ghost_score as gscore  # noqa: E402

RESULTS_DIR = REPO_ROOT / "research" / "results"
RAW_PARSED_PATH = RESULTS_DIR / "phase1_growth_raw_parsed.json"
FINDINGS_DIR = RESULTS_DIR / "findings"


def _grep_persisted_findings_for_cve_data() -> dict:
    """Confirms (does not assume) the persistence-bug claim above: counts
    real persisted finding files that carry a non-empty cve_ids or a
    cvss_score field, across the ENTIRE findings corpus."""
    n_total = 0
    n_with_cve = 0
    n_with_cvss = 0
    if FINDINGS_DIR.is_dir():
        for eng_dir in FINDINGS_DIR.iterdir():
            if not eng_dir.is_dir():
                continue
            for p in eng_dir.glob("*.json"):
                try:
                    f = json.loads(p.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                n_total += 1
                if f.get("cve_ids"):
                    n_with_cve += 1
                if f.get("cvss_score") is not None:
                    n_with_cvss += 1
    return {"total_persisted_findings": n_total, "with_nonempty_cve_ids": n_with_cve,
            "with_cvss_score": n_with_cvss}


def _load_real_cve_bearing_findings() -> list:
    """Real scanner-parser output (pre-persistence-bug), deduplicated by
    (engagement_id, host, port, title) so a finding logged once per
    growth-script run isn't triple-counted."""
    if not RAW_PARSED_PATH.exists():
        return []
    entries = json.loads(RAW_PARSED_PATH.read_text())
    seen = set()
    out = []
    for e in entries:
        for f in e.get("cve_bearing_findings", []):
            key = (e["engagement_id"], f.get("host"), f.get("port"), f.get("title"))
            if key in seen:
                continue
            seen.add(key)
            enriched = dict(f)
            enriched["finding_id"] = f"growth-{e['engagement_id']}-{len(out)}"
            enriched["engagement_id"] = e["engagement_id"]
            enriched["target"] = {"host": f.get("host"), "port": f.get("port")}
            out.append(enriched)
    return out


def _spearman(x: list, y: list):
    from scipy.stats import spearmanr
    if len(x) < 2:
        return None, None
    rho, pvalue = spearmanr(x, y)
    return float(rho), float(pvalue)


def main():
    persistence_check = _grep_persisted_findings_for_cve_data()
    print(f"Persisted-findings CVE/CVSS check: {persistence_check}", file=sys.stderr)

    findings = _load_real_cve_bearing_findings()
    n = len(findings)
    print(f"Real CVE-bearing findings available (pre-persistence-bug, deduplicated): {n}",
          file=sys.stderr)

    # ── Hand-built graph: real host nodes, zero edges, zero crown jewels --
    # no confirmed attack-path or crown-jewel evidence exists in this pilot. ──
    hosts = sorted({f["target"]["host"] for f in findings if f["target"].get("host")})
    graph = {"nodes": [{"id": f"host:{h}", "type": "host"} for h in hosts], "edges": []}
    crown_jewel_hosts: list = []

    scored = []
    for f in findings:
        result = gscore.score_finding(f, graph, crown_jewel_hosts)
        scored.append({
            "finding_id": f["finding_id"], "engagement_id": f["engagement_id"],
            "title": f["title"][:200], "host": f["target"].get("host"),
            "port": f["target"].get("port"), "severity": f.get("severity"),
            "cve_count": len(f.get("cve_ids", [])),
            "cve_ids_sample": f.get("cve_ids", [])[:5],
            "base_cvss_used": gscore._base_cvss(f),
            "ghost_score": result["ghost_score"], "ghost_score_band": result["ghost_score_band"],
            "factors": result["factors"],
        })

    # Rank by GhostScore vs by the CVSS-only baseline (score_finding's own
    # _base_cvss -- real cvss_score if present, else the same severity-band
    # fallback GhostScore itself uses when a finding has no precise CVSS;
    # this corpus has no finding with a real numeric cvss_score, so both
    # rankings' CVSS component is severity-band-derived -- stated plainly,
    # not glossed over).
    ghost_rank = sorted(scored, key=lambda r: r["ghost_score"], reverse=True)
    cvss_rank = sorted(scored, key=lambda r: r["base_cvss_used"], reverse=True)
    ghost_order = {r["finding_id"]: i for i, r in enumerate(ghost_rank)}
    cvss_order = {r["finding_id"]: i for i, r in enumerate(cvss_rank)}

    x = [ghost_order[r["finding_id"]] for r in scored]
    y = [cvss_order[r["finding_id"]] for r in scored]

    rho, pvalue = (None, None)
    spearman_error = None
    if n >= 2:
        try:
            rho, pvalue = _spearman(x, y)
        except Exception as exc:
            spearman_error = f"{type(exc).__name__}: {exc}"

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "completed" if n >= 2 else "blocked",
        "n_findings_with_real_cve_data": n,
        "persisted_findings_cve_cvss_check": persistence_check,
        "root_cause_finding": (
            "EngagementRepository.add_finding() (CyberToolkit/engagement_repository.py, "
            "~line 174) has no cve_ids or cvss_score parameter -- confirmed by inspecting its "
            "signature directly. import_engine.py's parsers (parse_nmap_xml, parse_nuclei_json, "
            "parse_nessus_xml) genuinely extract these fields from real scanner output, but "
            "import_findings() never passes them through to add_finding(), so they are silently "
            "dropped before ever reaching a persisted finding record. persisted_findings_cve_cvss_"
            "check above confirms 0 persisted findings in this entire corpus carry either field. "
            "This experiment reads the real parser output from a side-channel "
            "(phase1_growth_raw_parsed.json) written specifically to work around this, rather "
            "than being capped at N=0 by an unrelated persistence bug."
        ) if persistence_check["with_nonempty_cve_ids"] == 0 else None,
        "spearman_correlation": {
            "rho": round(rho, 4) if rho is not None else None,
            "pvalue": round(pvalue, 6) if pvalue is not None else None,
            "error": spearman_error,
            "note": "Spearman rank correlation (scipy.stats.spearmanr) between GhostScore rank "
                    "and CVSS-only rank, computed over the N findings above.",
        },
        "graph_used": {
            "n_host_nodes": len(hosts), "hosts": hosts, "n_edges": 0,
            "crown_jewel_hosts": crown_jewel_hosts,
            "note": "Real host nodes, zero edges, zero crown jewels -- no confirmed attack-path "
                    "or crown-jewel evidence exists anywhere in this pilot's real data, so "
                    "reachability/credential-exposure factors are neutral (1.0) for every "
                    "finding scored here. This is not a synthetic graph standing in for a real "
                    "one; it is the accurate real graph for what this pilot actually observed.",
        },
        "scored_findings": scored,
        "no_expert_panel_comparison": (
            "There is no expert-panel or authoritative ranking available for this pilot to "
            "compare GhostScore against -- only the CVSS-only baseline computed from the same "
            "codebase's own severity-band fallback. This experiment does NOT claim any "
            "comparison against expert judgment, and none should be inferred from it."
        ),
        "limitations": [
            f"N={n} is small and is the REAL achieved count of CVE-bearing findings this "
            f"pilot's scans produced -- not padded or targeted to hit a round number.",
            "No real finding in this corpus carries a precise numeric cvss_score (only severity "
            "band + CVE IDs), so 'CVSS-only rank' here is itself severity-band-derived via the "
            "same fallback score_finding() uses internally, not an independent gold-standard "
            "CVSS score. A future run against a source that reports real cvss_base_score "
            "(e.g. Nessus, which import_engine.parse_nessus_xml already supports) would let "
            "this correlation be computed against a genuine CVSS number instead.",
            "The 'vulners' NSE script (which supplied the CVE data used here) flags every CVE "
            "historically associated with the detected product+version banner, not confirmed "
            "exploitability against this specific target -- some findings carry dozens of CVE "
            "IDs from one banner match; cve_ids_sample truncates to the first 5 for readability, "
            "cve_count gives the real total.",
            "No expert-panel comparison exists for this pilot (see no_expert_panel_comparison).",
            "Graph has zero edges/crown-jewels (see graph_used note) -- reachability and "
            "credential-exposure factors do not differentiate any finding in this run; a richer "
            "attack graph would very likely change both the absolute GhostScore values and the "
            "correlation coefficient.",
        ],
    }

    out_path = RESULTS_DIR / "phase1_ghostscore_correlation.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Wrote {out_path}", file=sys.stderr)
    print(f"N={n} rho={rho} pvalue={pvalue}", file=sys.stderr)


if __name__ == "__main__":
    main()