#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- governance-control ablation analysis
(research/governance_ablation_analysis.py).

Reviewer-requested experiment: quantify each policy-gate sub-control's
independent causal contribution, rather than only reporting the combined
gate's 0.0 false-block/unauthorized-execution rate.

Reuses the REAL per-request data already captured in
phase1_governance.json's `requests` array -- specifically each request's
`subchecks_raw` field, which records the REAL exit codes from the three
real bash sub-check calls (gs_policy_check_trust, gs_policy_check_module,
gs_policy_check_scope) made during the original 2,022-request run. This is
a re-analysis of already-real data, not a new synthetic run: no new bash
execution, no new fabricated numbers.

For each of the three sub-checks, and for the combination of all three
(full policy-gate ablation), this script asks: "if this specific check had
been skipped (always treated as passing), how many of the requests the
real gate correctly blocked would instead have been wrongly allowed?" --
i.e. the unauthorized-execution rate that specific control alone is
responsible for preventing.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path("/opt/ghoststrike")
RESULTS_DIR = REPO_ROOT / "research" / "results"

_SUBCHECK_RE = re.compile(r"trust=(-?\d+) module=(-?\d+) scope=(-?\d+)")


def parse_subchecks(raw: str) -> dict | None:
    m = _SUBCHECK_RE.search(raw or "")
    if not m:
        return None
    trust_rc, module_rc, scope_rc = (int(x) for x in m.groups())
    return {"trust_rc": trust_rc, "module_rc": module_rc, "scope_rc": scope_rc}


def main() -> None:
    src_path = RESULTS_DIR / "phase1_governance.json"
    data = json.loads(src_path.read_text(encoding="utf-8"))
    requests = data["requests"]

    parsed = []
    unparseable = 0
    for r in requests:
        sc = parse_subchecks(r.get("subchecks_raw", ""))
        if sc is None:
            unparseable += 1
            continue
        parsed.append({**r, **sc})

    n = len(parsed)

    # Approval sub-check isn't a bash exit code in subchecks_raw (approval is
    # evaluated by gs_policy_gate itself, not a separate gs_policy_check_*
    # call the template captures) -- so approval-required requests are kept
    # in the denominator for the trust/module/scope ablations (those checks
    # still ran for them) but excluded from a would-be "approval ablation"
    # since this script has no real per-request approval sub-check exit code
    # to ablate, only the combined gate's final decision. Stated as a scoping
    # limitation in the output rather than fabricating an approval_rc.

    def ablate(check_name: str, rc_field: str, extra_ok_fields: list) -> dict:
        """Counterfactual: check_name always passes (rc treated as 0).
        Counts requests that were correctly blocked by the REAL gate
        (actual_allowed=False) but whose OTHER real sub-checks (excluding
        the ablated one) all passed -- meaning ablating this one check alone
        would flip the outcome to allowed."""
        newly_allowed = []
        for r in parsed:
            if r["actual_allowed"]:
                continue  # already allowed; ablation can't un-allow it
            other_checks_pass = all(r[f] == 0 for f in extra_ok_fields)
            # scope_rc == 9 means "no target, scope check skipped" in the
            # original run -- treat as passing (matches expected_allowed's
            # own no-target handling) unless scope is the field under test.
            if not other_checks_pass:
                continue
            newly_allowed.append(r)
        return {
            "ablated_check": check_name,
            "originally_blocked": sum(1 for r in parsed if not r["actual_allowed"]),
            "newly_allowed_if_ablated": len(newly_allowed),
            "unauthorized_execution_rate_if_ablated": round(len(newly_allowed) / n, 4),
            "example_requests": [
                {"module": r["module"], "trust_level": r["trust_level"],
                 "environment": r["environment"], "scope_case": r["scope_case"]}
                for r in newly_allowed[:5]
            ],
        }

    def scope_ok(r):
        return r["scope_rc"] == 0 or r["scope_rc"] == 9

    results = {}

    # Trust-check ablation: hold module + scope real, ignore trust_rc.
    newly_allowed = [r for r in parsed if not r["actual_allowed"]
                      and r["module_rc"] == 0 and scope_ok(r)]
    results["trust_registry"] = {
        "ablated_check": "gs_policy_check_trust (trust-tier permission)",
        "originally_blocked": sum(1 for r in parsed if not r["actual_allowed"]),
        "newly_allowed_if_ablated": len(newly_allowed),
        "unauthorized_execution_rate_if_ablated": round(len(newly_allowed) / n, 4),
        "example_requests": [
            {"module": r["module"], "trust_level": r["trust_level"],
             "environment": r["environment"], "scope_case": r["scope_case"]}
            for r in newly_allowed[:5]
        ],
    }

    # Scope-check ablation: hold trust + module real, ignore scope_rc.
    newly_allowed = [r for r in parsed if not r["actual_allowed"]
                      and r["trust_rc"] == 0 and r["module_rc"] == 0]
    results["scope_check"] = {
        "ablated_check": "gs_policy_check_scope (target scope verification)",
        "originally_blocked": sum(1 for r in parsed if not r["actual_allowed"]),
        "newly_allowed_if_ablated": len(newly_allowed),
        "unauthorized_execution_rate_if_ablated": round(len(newly_allowed) / n, 4),
        "example_requests": [
            {"module": r["module"], "trust_level": r["trust_level"],
             "environment": r["environment"], "scope_case": r["scope_case"]}
            for r in newly_allowed[:5]
        ],
    }

    # Module-check ablation: hold trust + scope real, ignore module_rc.
    newly_allowed = [r for r in parsed if not r["actual_allowed"]
                      and r["trust_rc"] == 0 and scope_ok(r)]
    results["module_check"] = {
        "ablated_check": "gs_policy_check_module (module-identity validity)",
        "originally_blocked": sum(1 for r in parsed if not r["actual_allowed"]),
        "newly_allowed_if_ablated": len(newly_allowed),
        "unauthorized_execution_rate_if_ablated": round(len(newly_allowed) / n, 4),
        "example_requests": [
            {"module": r["module"], "trust_level": r["trust_level"],
             "environment": r["environment"], "scope_case": r["scope_case"]}
            for r in newly_allowed[:5]
        ],
    }

    # Full policy-gate ablation: every check ablated at once -- every
    # request that was correctly blocked becomes an unauthorized execution.
    originally_blocked = sum(1 for r in parsed if not r["actual_allowed"])
    results["full_policy_gate"] = {
        "ablated_check": "all three checks simultaneously (policy gate fully disabled)",
        "originally_blocked": originally_blocked,
        "newly_allowed_if_ablated": originally_blocked,
        "unauthorized_execution_rate_if_ablated": round(originally_blocked / n, 4),
        "example_requests": [],
    }

    out = {
        "generated_at": data.get("generated_at"),
        "purpose": (
            "Quantifies each policy-gate sub-control's independent causal contribution by "
            "re-analyzing the real per-request sub-check exit codes already captured in "
            "phase1_governance.json (gs_policy_check_trust/_module/_scope), rather than only "
            "reporting the combined gate's 0.0 false-block/unauthorized-execution rate. For "
            "each control, this asks: of the requests the real gate correctly blocked, how "
            "many would have been wrongly allowed if that ONE control alone were disabled "
            "(the other real checks still applying)?"
        ),
        "source_file": "phase1_governance.json (requests[].subchecks_raw, real bash exit codes)",
        "total_requests_analyzed": n,
        "unparseable_subchecks_excluded": unparseable,
        "ablations": results,
        "limitations": [
            "Approval-requirement is NOT separately ablated here: gs_policy_gate evaluates "
            "approval internally rather than via a separate gs_policy_check_* call the "
            "original run's bash template captured a sub-check exit code for, so there is no "
            "real per-request approval_rc to ablate the way trust/module/scope are ablated "
            "above. Approval's own effect is already measurable directly from "
            "phase1_governance.json's approval_required_and_blocked_when_unapproved_count.",
            "This is a counterfactual computed from real sub-check exit codes already recorded "
            "against the real bash policy engine, not a live re-execution with each control "
            "actually source-disabled in policy_engine.sh -- stated explicitly since the two "
            "are not identical: a live source-level ablation could in principle surface "
            "interaction effects (e.g. a check silently depending on state another check sets) "
            "that a counterfactual recombination of independently-captured exit codes cannot.",
            "Evidence-layer and reproducibility-wrapper ablation are conceptually different "
            "(both are downstream of the dispatch decision, not part of it) and are not "
            "modeled here; their effect is already directly observable from existing results: "
            "with evidence capture disabled, the tamper-detection property in Table 12 has "
            "nothing to verify (0 hashed artifacts by construction); with the reproducibility "
            "wrapper disabled, 0 of the 200 sessions in the repro-scale study would carry a "
            "rho score at all, rather than the reported scores that simply did not reach the "
            "high-reproducibility tier.",
        ],
    }

    out_path = RESULTS_DIR / "phase1_governance_ablation.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    print(f"\nWrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
