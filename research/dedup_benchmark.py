#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- experiment 5: dedup pilot benchmark
(research/dedup_benchmark.py)

Builds a hand-labeled pair dataset mixing:
  (a) REAL findings from research/results/findings/ (the original 58 plus
      the corpus grown by research/grow_findings_corpus.py -- repeated real
      scans of the same live lab target across independent engagement runs,
      which is exactly what makes near-duplicate ground truth possible
      without inventing anything: the SAME real vulnerability, discovered
      by the SAME real tool, across DIFFERENT real scans of the SAME real
      target, is a genuine duplicate pair).
  (b) SYNTHETIC pairs this evaluator authored directly (near-dup wording
      variations, CVE-overlap tier-1 cases, MITRE-technique tier-3 cases --
      real findings never carry a mitre_attack field, so tier 3 cannot be
      exercised on real data alone) -- clearly tagged "source":
      "synthetic_authored" per pair, vs "source": "real_corpus".

Calls bash_scripts_for_pentest/lib/finding_dedup.py's _find_pairs() DIRECTLY
in memory (imported, not shelled out) against a 2-item {finding_id: (dict,
path)} map built for each labeled pair -- this is exactly the function's own
real signature and matching logic, just invoked per-pair instead of over an
entire findings directory, so precision/recall can be computed against this
evaluator's ground-truth label for that specific pair.

*** GROUND TRUTH CAVEAT (methodology, not sample size): every "is_duplicate"
label in this dataset was assigned by this evaluator's own reading of the
finding content -- it has NOT been independently adjudicated by a second
human or an authoritative source. This is a self-authored pilot label set,
regardless of how large the achieved N is. ***

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import itertools
import json
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
sys.path.insert(0, str(REPO_ROOT / "bash_scripts_for_pentest" / "lib"))
import finding_dedup as fd  # noqa: E402

FINDINGS_DIR = REPO_ROOT / "research" / "results" / "findings"
RESULTS_DIR = REPO_ROOT / "research" / "results"

random.seed(20260902)

MAX_DUP_PAIRS_PER_GROUP = 10
MAX_REAL_DUPLICATE_PAIRS = 260
MAX_REAL_NONDUP_SAME_HOST_PAIRS = 160
MAX_REAL_NONDUP_CROSS_HOST_PAIRS = 60


def _load_all_real_findings() -> list:
    """Every finding across every engagement dir, including superseded ones
    (unlike finding_dedup.load_findings, which filters those) -- for
    benchmark-pair CONSTRUCTION we want the full raw corpus, not the
    already-deduplicated view."""
    out = []
    if not FINDINGS_DIR.is_dir():
        return out
    for eng_dir in sorted(FINDINGS_DIR.iterdir()):
        if not eng_dir.is_dir():
            continue
        for p in sorted(eng_dir.glob("*.json")):
            try:
                f = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if "finding_id" not in f:
                continue
            out.append(f)
    return out


def _scenario_family(engagement_id: str) -> str:
    """'phase1-growth-web-dvwa-sqli-run2' -> 'web-dvwa-sqli';
    'phase1-web-dvwa-sqli' -> 'web-dvwa-sqli'; used to group repeats of the
    SAME real scenario across different engagement runs."""
    e = engagement_id
    for prefix in ("phase1-growth-", "phase1-ai-recommend-", "phase1-ai-operate-", "phase1-"):
        if e.startswith(prefix):
            e = e[len(prefix):]
            break
    # strip a trailing "-runN" if present
    if "-run" in e and e.rsplit("-run", 1)[1].isdigit():
        e = e.rsplit("-run", 1)[0]
    return e


def build_real_pairs(findings: list) -> list:
    pairs = []

    # ── Real duplicates: identical (host, port, title) discovered under
    # DIFFERENT engagement runs of the SAME scenario family -- genuinely the
    # same real vulnerability, independently rediscovered by repeated real
    # scans, not a hand-invented duplicate. ──
    by_key = defaultdict(list)
    for f in findings:
        host = (f.get("target") or {}).get("host", "")
        port = (f.get("target") or {}).get("port")
        key = (_scenario_family(f.get("engagement_id", "")), host, port, f.get("title", ""))
        by_key[key].append(f)

    dup_pairs = []
    for (_scenario, host, port, title), group in by_key.items():
        distinct_engagements = {}
        for f in group:
            distinct_engagements.setdefault(f["engagement_id"], f)
        items = list(distinct_engagements.values())
        if len(items) < 2:
            continue
        combos = list(itertools.combinations(items, 2))[:MAX_DUP_PAIRS_PER_GROUP]
        for a, b in combos:
            dup_pairs.append({
                "finding_a": a, "finding_b": b, "is_duplicate": True,
                "expected_tier": 2,  # same host+port, identical title -> jaccard 1.0, tier 2 auto-merge
                "source": "real_corpus",
                "rationale": (f"Same title/host/port ('{title}' @ {host}:{port}) rediscovered by "
                              f"independent real scans of the same live target under different "
                              f"engagement runs -- the same underlying observation, not invented."),
            })
    random.shuffle(dup_pairs)
    pairs.extend(dup_pairs[:MAX_REAL_DUPLICATE_PAIRS])

    # ── Real non-duplicates, same host: different titles on the same
    # host(:port) -- distinct real vulnerabilities/observations that must
    # NOT be merged (a genuine hard-negative test for tier 2's title-Jaccard
    # threshold). ──
    by_host = defaultdict(list)
    for f in findings:
        host = (f.get("target") or {}).get("host", "")
        if host:
            by_host[host].append(f)

    nondup_same_host = []
    for host, group in by_host.items():
        titles_seen = {}
        for f in group:
            t = f.get("title", "")
            titles_seen.setdefault(t, f)
        items = list(titles_seen.values())
        if len(items) < 2:
            continue
        combos = list(itertools.combinations(items, 2))
        random.shuffle(combos)
        for a, b in combos[:8]:
            if a["title"] == b["title"]:
                continue
            nondup_same_host.append({
                "finding_a": a, "finding_b": b, "is_duplicate": False,
                "expected_tier": None,
                "source": "real_corpus",
                "rationale": (f"Same host ({host}) but genuinely different findings "
                              f"('{a['title']}' vs '{b['title']}') -- distinct real "
                              f"observations, must not be merged."),
            })
    random.shuffle(nondup_same_host)
    pairs.extend(nondup_same_host[:MAX_REAL_NONDUP_SAME_HOST_PAIRS])

    # ── Real non-duplicates, cross-host: unambiguous negatives (different
    # target entirely) for baseline volume/precision context. ──
    hosts = list(by_host.keys())
    cross_pairs = []
    if len(hosts) >= 2:
        host_combos = list(itertools.combinations(hosts, 2))
        random.shuffle(host_combos)
        for h1, h2 in host_combos:
            if len(cross_pairs) >= MAX_REAL_NONDUP_CROSS_HOST_PAIRS:
                break
            a = random.choice(by_host[h1])
            b = random.choice(by_host[h2])
            cross_pairs.append({
                "finding_a": a, "finding_b": b, "is_duplicate": False,
                "expected_tier": None,
                "source": "real_corpus",
                "rationale": f"Different real targets ({h1} vs {h2}) -- unambiguous non-duplicate.",
            })
    pairs.extend(cross_pairs)

    return pairs


def _mk(title, host, port, severity="MEDIUM", cve_ids=None, mitre_technique=None,
        discovered_at="2026-09-02T12:00:00Z", finding_id=None, description=""):
    fid = finding_id or f"synthetic-{abs(hash((title, host, port, discovered_at))) % 10**8}"
    d = {
        "finding_id": fid, "title": title, "severity": severity,
        "description": description or title,
        "discovered_at": discovered_at, "engagement_id": "phase1-dedup-synthetic",
        "module": "synthetic", "target": {"host": host, "port": port},
        "cve_ids": cve_ids or [],
    }
    if mitre_technique:
        d["mitre_attack"] = {"technique_id": mitre_technique, "tactic": "discovery"}
    return d


def build_synthetic_pairs() -> list:
    """Hand-authored edge cases, self-labeled by this evaluator. Covers the
    two matching dimensions real data alone cannot exercise (tier-1 CVE
    overlap with clean wording variation, and tier-3 MITRE-technique
    co-occurrence), plus deliberately hard near-miss/false-merge-trap cases
    referencing finding_dedup.py's own documented false-merge history."""
    pairs = []

    # --- Tier 1: shared CVE, different wording -> HIGH, auto-mergeable ---
    for i, (cve, host, port) in enumerate([
        ("CVE-2021-44228", "10.0.1.5", 443), ("CVE-2017-5638", "10.0.1.6", 8080),
        ("CVE-2019-11510", "10.0.1.7", 443), ("CVE-2014-0160", "10.0.1.8", 443),
        ("CVE-2020-1472", "10.0.1.9", 445), ("CVE-2021-34527", "10.0.1.10", 445),
        ("CVE-2018-7600", "10.0.1.11", 80), ("CVE-2022-22965", "10.0.1.12", 8080),
        ("CVE-2021-26855", "10.0.1.13", 443), ("CVE-2023-23397", "10.0.1.14", 443),
    ]):
        a = _mk(f"Vulnerable service flagged for {cve}", host, port, "CRITICAL", cve_ids=[cve])
        b = _mk(f"Nessus plugin detected {cve} on this host", host, port, "CRITICAL", cve_ids=[cve])
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": True, "expected_tier": 1,
                      "source": "synthetic_authored",
                      "rationale": f"Shared CVE {cve} on the same host, worded completely "
                                   f"differently by two hypothetical sources -- tier 1 should "
                                   f"catch this on CVE overlap alone, independent of title text."})

    # --- Tier 1 negative: DIFFERENT CVEs, same host, similar wording ---
    for i, (cve_a, cve_b, host, port) in enumerate([
        ("CVE-2021-44228", "CVE-2021-45046", "10.0.2.1", 443),
        ("CVE-2014-0160", "CVE-2014-3566", "10.0.2.2", 443),
    ]):
        a = _mk(f"Vulnerable service flagged for {cve_a}", host, port, "CRITICAL", cve_ids=[cve_a])
        b = _mk(f"Vulnerable service flagged for {cve_b}", host, port, "CRITICAL", cve_ids=[cve_b])
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": False, "expected_tier": None,
                      "source": "synthetic_authored",
                      "rationale": f"Similar wording and same host, but genuinely different CVEs "
                                   f"({cve_a} vs {cve_b}) -- must not be auto-merged on text "
                                   f"similarity alone; title Jaccard on 'vulnerable service flagged "
                                   f"for' is high, so this specifically tests that tier 1's CVE "
                                   f"check doesn't get bypassed into a tier-2 false merge."})

    # --- Tier 2: same host:port, near-identical title wording (>=0.6 jaccard) ---
    near_dup_titles = [
        ("Missing Header: Content-Security-Policy on http://target:80",
         "Missing Header: Content-Security-Policy detected on http://target:80"),
        ("Outdated Apache 2.4.41 detected", "Apache 2.4.41 appears outdated"),
        ("SQL Injection vulnerability in login.php", "Potential SQL Injection found in login.php"),
        ("Anonymous FTP login allowed", "FTP anonymous login allowed on server"),
        ("Weak SSH ciphers enabled", "SSH server allows weak ciphers"),
        ("Cookie missing Secure flag", "Session cookie missing Secure flag"),
        ("Directory listing enabled on /uploads/", "Directory listing enabled at /uploads/"),
        ("X-Frame-Options header missing", "Missing X-Frame-Options header"),
    ]
    for i, (t1, t2) in enumerate(near_dup_titles):
        host, port = f"10.0.3.{i+1}", 80
        a = _mk(t1, host, port, "MEDIUM")
        b = _mk(t2, host, port, "MEDIUM")
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": True, "expected_tier": 2,
                      "source": "synthetic_authored",
                      "rationale": "Same host:port, clearly the same underlying issue worded "
                                   "slightly differently -- should clear the 0.6 title-Jaccard "
                                   "auto-merge threshold."})

    # --- Tier 2 boundary: moderate overlap (0.35-0.6), review-only not auto-merge ---
    boundary_titles = [
        ("Outdated jQuery library version detected in page", "Client-side library version disclosed via script tag"),
        ("Server discloses PHP version in error page", "Verbose error messages reveal stack trace"),
        ("robots.txt reveals internal path structure", "sitemap.xml discloses internal URL structure"),
    ]
    for i, (t1, t2) in enumerate(boundary_titles):
        host, port = f"10.0.4.{i+1}", 80
        a = _mk(t1, host, port, "LOW")
        b = _mk(t2, host, port, "LOW")
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": True, "expected_tier": 2,
                      "source": "synthetic_authored",
                      "rationale": "Same host:port, related-but-not-identical information "
                                   "disclosure issues -- labeled duplicate-in-spirit (same root "
                                   "cause: information disclosure) but expected to land in the "
                                   "0.35-0.6 review band, not auto-merge; a real judgment call "
                                   "this evaluator made, not an obvious case."})

    # --- Tier 2 false-merge trap: documented in finding_dedup.py itself ---
    # (IP-address tokens in the title dominating Jaccard on genuinely
    # different NSE script findings sharing the same host:port).
    ip_trap = [
        ("Nmap NSE 'http-title' flagged 172.20.0.13:80 -- Login Page",
         "Nmap NSE 'http-cookie-flags' flagged 172.20.0.13:80 -- missing flags"),
    ]
    for t1, t2 in ip_trap:
        a = _mk(t1, "172.20.0.13", 80, "LOW")
        b = _mk(t2, "172.20.0.13", 80, "LOW")
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": False, "expected_tier": None,
                      "source": "synthetic_authored",
                      "rationale": "Directly re-creates the false-merge trap finding_dedup.py's "
                                   "own _title_tokens() docstring describes (shared IP-octet "
                                   "tokens dominating Jaccard on genuinely different NSE script "
                                   "findings) -- tests that the numeric-token exclusion fix holds."})

    # --- Tier 3: same host + same MITRE technique, different titles, close time ---
    for i in range(12):
        host = f"10.0.5.{i+1}"
        t0 = "2026-09-02T10:00:00Z"
        t1 = "2026-09-02T14:00:00Z"  # 4h apart, within the 24h window
        a = _mk(f"Nmap found open port {21+i} on host", host, 21 + i, "INFO",
                mitre_technique="T1046", discovered_at=t0)
        b = _mk(f"Nikto found path traversal indicator on host", host, 21 + i, "MEDIUM",
                mitre_technique="T1046", discovered_at=t1)
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": True, "expected_tier": 3,
                      "source": "synthetic_authored",
                      "rationale": "Same host + same MITRE technique (T1046, network service "
                                   "discovery) within the 24h window, titles share no tokens at "
                                   "all -- the exact tier-3 scenario finding_dedup.py's own "
                                   "docstring describes (Nmap open port + Nikto path traversal "
                                   "on the same host), never auto-mergeable, LOW confidence."})

    # --- Tier 3 negative: same MITRE technique but time window exceeded (>24h) ---
    for i in range(8):
        host = f"10.0.6.{i+1}"
        a = _mk("Open port discovered", host, 22, "INFO", mitre_technique="T1046",
                discovered_at="2026-08-30T08:00:00Z")
        b = _mk("Unrelated path traversal indicator", host, 22, "MEDIUM", mitre_technique="T1046",
                discovered_at="2026-09-02T08:00:00Z")
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": False, "expected_tier": None,
                      "source": "synthetic_authored",
                      "rationale": "Same host + same MITRE technique, but >24h apart (3 days) -- "
                                   "outside tier 3's overlapping-time-window requirement, "
                                   "labeled non-duplicate."})

    # --- Plain non-duplicates: different host, different everything ---
    for i in range(20):
        a = _mk(f"Synthetic finding A{i}", f"10.0.7.{i+1}", 80, "LOW")
        b = _mk(f"Synthetic finding B{i}", f"10.0.8.{i+1}", 443, "LOW")
        pairs.append({"finding_a": a, "finding_b": b, "is_duplicate": False, "expected_tier": None,
                      "source": "synthetic_authored",
                      "rationale": "Different hosts entirely -- trivial non-duplicate."})

    return pairs


def evaluate_pair(pair: dict) -> dict:
    a, b = pair["finding_a"], pair["finding_b"]
    findings_map = {a["finding_id"]: (a, Path("/dev/null")), b["finding_id"]: (b, Path("/dev/null"))}
    matches = list(fd._find_pairs(findings_map))
    predicted_duplicate = len(matches) > 0
    predicted_tier = matches[0][2] if matches else None
    predicted_confidence = matches[0][3] if matches else None
    predicted_auto_mergeable = matches[0][4] if matches else None
    predicted_reason = matches[0][5] if matches else None

    truth = pair["is_duplicate"]
    if truth and predicted_duplicate:
        outcome = "true_positive"
    elif (not truth) and (not predicted_duplicate):
        outcome = "true_negative"
    elif (not truth) and predicted_duplicate:
        outcome = "false_positive"
    else:
        outcome = "false_negative"

    return {
        **{k: v for k, v in pair.items() if k not in ("finding_a", "finding_b")},
        "finding_a_id": a["finding_id"], "finding_b_id": b["finding_id"],
        "finding_a_title": a["title"], "finding_b_title": b["title"],
        "finding_a_engagement": a.get("engagement_id"), "finding_b_engagement": b.get("engagement_id"),
        "predicted_duplicate": predicted_duplicate, "predicted_tier": predicted_tier,
        "predicted_confidence": predicted_confidence, "predicted_auto_mergeable": predicted_auto_mergeable,
        "predicted_reason": predicted_reason, "outcome": outcome,
    }


def prf(tp, fp, fn):
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and (precision + recall) > 0 else None)
    return precision, recall, f1


def main():
    real_findings = _load_all_real_findings()
    print(f"Loaded {len(real_findings)} real findings from {FINDINGS_DIR}", file=sys.stderr)

    real_pairs = build_real_pairs(real_findings)
    synthetic_pairs = build_synthetic_pairs()
    all_pairs = real_pairs + synthetic_pairs
    print(f"Built {len(real_pairs)} real-corpus pairs + {len(synthetic_pairs)} synthetic pairs "
          f"= {len(all_pairs)} total", file=sys.stderr)

    evaluated = [evaluate_pair(p) for p in all_pairs]

    overall_tp = sum(1 for e in evaluated if e["outcome"] == "true_positive")
    overall_fp = sum(1 for e in evaluated if e["outcome"] == "false_positive")
    overall_fn = sum(1 for e in evaluated if e["outcome"] == "false_negative")
    overall_tn = sum(1 for e in evaluated if e["outcome"] == "true_negative")
    overall_p, overall_r, overall_f1 = prf(overall_tp, overall_fp, overall_fn)

    per_tier = {}
    for tier in (1, 2, 3):
        subset = [e for e in evaluated if e.get("expected_tier") == tier or e.get("predicted_tier") == tier]
        tp = sum(1 for e in subset if e["outcome"] == "true_positive" and e.get("predicted_tier") == tier)
        fp = sum(1 for e in subset if e["outcome"] == "false_positive" and e.get("predicted_tier") == tier)
        fn = sum(1 for e in subset if e["outcome"] == "false_negative" and e.get("expected_tier") == tier)
        p, r, f1 = prf(tp, fp, fn)
        per_tier[f"tier_{tier}"] = {
            "true_positive": tp, "false_positive": fp, "false_negative": fn,
            "precision": round(p, 4) if p is not None else None,
            "recall": round(r, 4) if r is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
            "n_pairs_labeled_this_tier": sum(1 for e in evaluated if e.get("expected_tier") == tier),
        }

    false_positives_detail = [e for e in evaluated if e["outcome"] == "false_positive"]
    false_negatives_detail = [e for e in evaluated if e["outcome"] == "false_negative"]

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "GROUND_TRUTH_CAVEAT": (
            "Every is_duplicate label in this dataset was assigned by this evaluator's own "
            "reading of the finding content. It has NOT been independently adjudicated by a "
            "second human annotator or an authoritative source. This is a self-authored pilot "
            "label set -- true regardless of how large N is."
        ),
        "total_pairs": len(evaluated),
        "real_corpus_pairs": len(real_pairs),
        "synthetic_authored_pairs": len(synthetic_pairs),
        "real_findings_corpus_size": len(real_findings),
        "overall": {
            "true_positive": overall_tp, "false_positive": overall_fp,
            "false_negative": overall_fn, "true_negative": overall_tn,
            "precision": round(overall_p, 4) if overall_p is not None else None,
            "recall": round(overall_r, 4) if overall_r is not None else None,
            "f1": round(overall_f1, 4) if overall_f1 is not None else None,
        },
        "per_tier": per_tier,
        "false_positive_examples": [
            {k: e[k] for k in ("finding_a_title", "finding_b_title", "rationale", "predicted_reason")}
            for e in false_positives_detail[:15]
        ],
        "false_negative_examples": [
            {k: e[k] for k in ("finding_a_title", "finding_b_title", "rationale", "expected_tier")}
            for e in false_negatives_detail[:15]
        ],
        "methodology": (
            "finding_dedup.py's _find_pairs() (bash_scripts_for_pentest/lib/finding_dedup.py, "
            "~line 176) is imported and called DIRECTLY in-memory against a 2-item findings map "
            "built for each labeled pair, exactly the function's real signature -- not shelled "
            "out, and not run once over the whole corpus (which would test grouping/union-find "
            "behavior, not per-pair precision/recall against a ground-truth label)."
        ),
        "limitations": [
            "Self-authored ground truth (see GROUND_TRUTH_CAVEAT) -- not independently adjudicated.",
            "Real-corpus 'duplicate' pairs are same title/host/port findings rediscovered across "
            "repeated scans of the same live target under different engagement runs; they are "
            "genuinely the same real observation, but the corpus-generation process (this "
            "evaluator's own grow_findings_corpus.py) and the labeling judgment are both this "
            "evaluator's, not independent of each other.",
            "Tier 3 (MITRE technique + time window) cannot be exercised on real data at all: "
            "no real finding in this corpus carries a mitre_attack field (add_finding()/"
            "import_engine.py never populate one) -- every tier-3 pair here is synthetic_authored.",
            "Per-tier precision/recall pools together pairs where expected_tier OR predicted_tier "
            "equals that tier, so a pair the algorithm predicts at the wrong tier shows up in "
            "both tiers' denominators -- see the raw per-pair 'requests' list to recompute a "
            "stricter per-tier partition if needed.",
        ],
        "pairs": evaluated,
    }

    out_path = RESULTS_DIR / "phase1_dedup_benchmark.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Wrote {out_path}", file=sys.stderr)
    print(f"overall P={overall_p} R={overall_r} F1={overall_f1}", file=sys.stderr)
    for k, v in per_tier.items():
        print(f"{k}: {v}", file=sys.stderr)


if __name__ == "__main__":
    main()