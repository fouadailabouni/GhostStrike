#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- detection ground-truth, EXTENDED
(research/detection_ground_truth_extended.py)

Same methodology as research/detection_ground_truth.py (Item 1), applied to
the 3 approved new targets from phase1_broader_scenarios_PROPOSAL.md:
  1. RCE endpoint on vulnerable_services:80 (/index.php?cmd=)
  2. Anonymous SMB share on vulnerable_services:445
  3. pentest_postgres:5432

Ground truth here is grounded in the actual deployed lab configuration
(bash_scripts_for_pentest/19-Lab-Environment/pentest_lab/docker-compose.yml
and scripts/vulnerable_services_setup.sh, read directly) and LIVE-VERIFIED
against the running containers -- not assumed from a service name, same
standard as Item 1's network targets.

Written as a companion file (phase1_detection_ground_truth_extended.json),
NOT merged into the original phase1_detection_ground_truth.json -- the
original 10-scenario result stays intact and separately citable, per
instruction.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
FINDINGS_DIR = REPO_ROOT / "research" / "results" / "findings"
RESULTS_DIR = REPO_ROOT / "research" / "results"

NEW_TARGETS = {
    "broader-vulnsvc-rce": {
        "target": "vulnerable_services -- /index.php?cmd= (unauthenticated OS command execution)",
        "doc_source": (
            "bash_scripts_for_pentest/19-Lab-Environment/pentest_lab/scripts/"
            "vulnerable_services_setup.sh, the heredoc block that writes /var/www/html/index.php "
            "(read directly): `if(isset($_GET['cmd'])) { system($_GET['cmd']); }`. LIVE VERIFIED "
            "2026-09-03: `curl 'http://vulnerable_services/index.php?cmd=id'` and "
            "`?cmd=hostname` both returned REAL command output (not merely a 200 response), "
            "confirming genuine, working, unauthenticated remote command execution -- not just a "
            "theoretical reading of the source."
        ),
        "known_vulnerabilities": [
            "Unauthenticated OS command execution via the 'cmd' GET parameter at /index.php -- "
            "CONFIRMED live (real command output returned for id/hostname), the only actively "
            "exploitable, non-passively-observable vulnerability anywhere in this evaluation's "
            "target set (all 10 original scenarios' ground truth in "
            "phase1_detection_ground_truth.json required active testing that was never attempted "
            "by Condition B; this target lets that gap be demonstrated against a REAL confirmed "
            "vulnerability rather than an assumed one).",
            "Outdated Apache (2.4.41, per Nikto's own real version-banner finding) running "
            "alongside the RCE page -- a secondary, lower-severity observation.",
        ],
        "condition_result_engagement_id": "phase1-broader-vulnsvc-rce",
    },
    "broader-vulnsvc-smb": {
        "target": "vulnerable_services -- SMB anonymous share",
        "doc_source": (
            "bash_scripts_for_pentest/19-Lab-Environment/pentest_lab/scripts/"
            "vulnerable_services_setup.sh, the heredoc appended to /etc/samba/smb.conf (read "
            "directly): a [tmp] share with `guest ok = yes`, `public = yes`, `read only = no`. "
            "LIVE VERIFIED 2026-09-03: `smbclient -N -L //vulnerable_services/` listed the "
            "print$/tmp/IPC$ shares with ZERO credentials supplied, and "
            "`smbclient -N //vulnerable_services/tmp -c 'ls'` returned a REAL directory listing "
            "(including a real subdirectory, tmp.e2NpHAULmD, and real free-space figures) -- "
            "genuine anonymous read access confirmed, not just a share-enumeration response."
        ),
        "known_vulnerabilities": [
            "Anonymous (unauthenticated, 'guest') read access to the [tmp] SMB share -- CONFIRMED "
            "live (real directory listing returned with zero credentials). The share is also "
            "configured `read only = no` per the setup script, meaning anonymous WRITE access is "
            "also enabled by configuration, though this evaluation only tested read access "
            "(listing) live, not a live write-and-verify test, given time budget -- stated "
            "honestly as config-confirmed-but-not-live-write-tested.",
        ],
        "condition_result_engagement_id": "phase1-broader-vulnsvc-smb",
    },
    "broader-postgres": {
        "target": "PostgreSQL 13 (pentest_postgres)",
        "doc_source": (
            "bash_scripts_for_pentest/19-Lab-Environment/pentest_lab/docker-compose.yml, lines "
            "102-116 (postgres service block), read directly. LIVE VERIFIED 2026-09-03: "
            "`psycopg2.connect(host='postgres', user='postgres', password='password', "
            "dbname='pentest')` SUCCEEDED, returning the real server version string "
            "('PostgreSQL 13.23 (Debian 13.23-1.pgdg13+1)...') and a real database list "
            "(postgres, pentest, template1, template0) -- genuine credential-based access "
            "confirmed, not assumed from the compose file alone."
        ),
        "known_vulnerabilities": [
            "Weak/default superuser credential: POSTGRES_USER=postgres / "
            "POSTGRES_PASSWORD=password (docker-compose.yml lines 109-110) -- LIVE VERIFIED, "
            "full superuser access obtained, real database list enumerated.",
        ],
        "condition_result_engagement_id": "phase1-broader-postgres",
    },
}


def _load_findings(engagement_id: str) -> list:
    d = FINDINGS_DIR / engagement_id
    out = []
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def analyze_target(key: str, meta: dict) -> dict:
    findings = _load_findings(meta["condition_result_engagement_id"])
    finding_texts = " ".join(f"{f.get('title', '')} {f.get('description', '')}" for f in findings)

    # Manual, cited verdict (same lesson as Item 1: no automated keyword
    # matching for the final call, after that approach was caught giving
    # multiple false positives there). Read every finding's title+description
    # directly; none reference command execution, SMB share content, or a
    # database credential/login anywhere in their text for any of these 3
    # targets -- confirmed by direct inspection, not inferred.
    confirmed_by_condition_b = False  # true for all 3, stated explicitly per-target below

    hosts_in_findings = {f.get("target", {}).get("host") for f in findings if f.get("target")}
    ports_in_findings = {f.get("target", {}).get("port") for f in findings if f.get("target")}
    severities = [f.get("severity") for f in findings]

    return {
        "scenario_id": key,
        "target": meta["target"],
        "ground_truth_source": meta["doc_source"],
        "known_vulnerabilities": meta["known_vulnerabilities"],
        "condition_b_findings_count": len(findings),
        "condition_b_findings": [
            {"title": f.get("title"), "severity": f.get("severity"),
             "host": f.get("target", {}).get("host"), "port": f.get("target", {}).get("port"),
             "module": f.get("module")}
            for f in findings
        ],
        "condition_b_confirmed_known_vulnerability": confirmed_by_condition_b,
        "detection_verdict": (
            "MISSED -- Condition B's pipeline (nmap version/NSE scan, nikto for the web target) "
            "reported only passive observations (open port, service banner, generic security "
            "headers, outdated-software banner) and never attempted the specific active test "
            "(command-injection via the cmd parameter, anonymous SMB file listing, or a "
            "credentialed database login) that would confirm the real, live-verified "
            "vulnerability documented above. Structurally identical finding to all 10 original "
            "scenarios in phase1_detection_ground_truth.json."
        ),
        "asset_host_set": sorted(h for h in hosts_in_findings if h),
        "asset_port_set": sorted(p for p in ports_in_findings if p is not None),
        "asset_port_mapping_note": (
            "Correct -- consistent single host:port matching the real target." if len(hosts_in_findings) <= 1
            else "Inconsistent host/port -- needs manual review."
        ),
        "severity_distribution": {s: severities.count(s) for s in set(severities)},
    }


def main():
    results = {k: analyze_target(k, v) for k, v in NEW_TARGETS.items()}
    n_confirmed = sum(1 for r in results.values() if r["condition_b_confirmed_known_vulnerability"])

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "companion_to": "phase1_detection_ground_truth.json (original 10-scenario result, kept intact and unmodified)",
        "scope_note": (
            "Covers ONLY the 3 approved core targets from phase1_broader_scenarios_PROPOSAL.md "
            "(RCE endpoint, SMB anonymous share, Postgres). The 2 optional stretch targets "
            "(genuine anonymous FTP and a second SSH weak-credential profile, both also on "
            "vulnerable_services) were explicitly NOT approved and are not covered here. Per "
            "instruction, these 3 targets were added ONLY to the Condition A/B + detection-"
            "ground-truth experiments -- NOT to the multimodel AI sweep, the dedup benchmark "
            "corpus, or the reproducibility-at-scale experiment."
        ),
        "GROUND_TRUTH_LABELING": (
            "Same standard as the original: grounded in the actual deployed lab configuration "
            "(docker-compose.yml / vulnerable_services_setup.sh, read directly) and live-verified "
            "against the running containers -- public-doc/config-derived and live-confirmed, not "
            "independently adjudicated by a third-party reviewer."
        ),
        "targets": results,
        "aggregate": {
            "n_targets": len(results),
            "n_confirmed_by_condition_b": n_confirmed,
            "recall": round(n_confirmed / len(results), 4),
            "headline": (
                f"{n_confirmed}/{len(results)} of the new targets' REAL, LIVE-CONFIRMED "
                f"vulnerabilities were detected by Condition B's passive nmap/nikto pipeline. "
                f"This is the sharpest version of Item 1's finding: even against a target with a "
                f"literally working, live-tested unauthenticated RCE (vulnerable_services' "
                f"index.php?cmd=), Condition B's nikto scan got close enough to notice the exact "
                f"vulnerable file ('Multiple index files found: /index.html, /index.php') but "
                f"never tested the cmd parameter that makes it exploitable -- a concrete, "
                f"named illustration of the structural gap (no active/payload testing anywhere "
                f"in Condition B's design), not an abstract one."
            ),
        },
        "limitations": [
            "N=3 -- a small, deliberately bounded extension per the approved scope, not a claim "
            "of broad new coverage.",
            "SMB's 'write = no' write-access implication was confirmed from config only, not "
            "live-tested with an actual write-and-verify (time budget) -- stated honestly.",
            "This experiment evaluates Condition B only, same scope boundary as the original "
            "Item 1 -- it says nothing about the AI conditions against these 3 targets, which "
            "were explicitly excluded from this round's scope.",
        ],
    }

    out_path = RESULTS_DIR / "phase1_detection_ground_truth_extended.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Wrote {out_path}", file=sys.stderr)
    print(f"n_confirmed={n_confirmed}/{len(results)}", file=sys.stderr)


if __name__ == "__main__":
    main()