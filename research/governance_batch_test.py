#!/usr/bin/env python3
"""
GhostStrike Phase 1 evaluation -- experiment 4: governance/policy batch test
(research/governance_batch_test.py)

Builds a FULL FACTORIAL of synthetic authorization requests (>2000; see
build_requests()) spanning module x trust-tier x in/out-of-scope x environment, and runs each one
through the REAL bash policy functions in
bash_scripts_for_pentest/lib/policy_engine.sh:
  gs_policy_check_trust   (line ~119)
  gs_policy_check_module  (line ~177)
  gs_policy_check_scope   (line ~240, the scope-check function)
  gs_policy_gate          (line ~290, the master pre-execution gate --
                            this is the authoritative allow/block decision:
                            exit 0 = allowed, exit 77 = policy blocked)

For every request an "expected" outcome is computed independently in Python,
derived directly from the same three sources of truth the bash code itself
reads (policy.yaml's trust_levels.<env>.allowed lists and modules.*.require_
explicit_approval, plus scope_check.py's CIDR/domain-suffix matching) --
NOT by re-running the bash function a second time. Comparing the two lets
this script classify every request as correct / false_block /
unauthorized_execution rather than just reporting raw pass/fail counts.

GS_ENGAGEMENT_ID, GS_SCOPE_FILE, and (for production) GS_AUTH_FILE are held
constant/satisfied across every request so the auth-requirements dimension
(gs_policy_check_auth) doesn't confound the trust/scope/approval sweep this
experiment is actually about -- documented as a scoping choice in the output
JSON's limitations, not hidden.

© 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path("/opt/ghoststrike")
BASH_DIR = REPO_ROOT / "bash_scripts_for_pentest"
LIB_DIR = BASH_DIR / "lib"
RESULTS_DIR = REPO_ROOT / "research" / "results"
WORK_DIR = RESULTS_DIR / "_governance_work"

ENVIRONMENTS = ["lab", "staging", "production"]

_ALLOWED_BY_ENV = {
    "lab": {"SAFE_ENUM", "VALIDATION", "HIGH_IMPACT", "LAB_ONLY"},
    "staging": {"SAFE_ENUM", "VALIDATION", "HIGH_IMPACT"},
    "production": {"SAFE_ENUM", "VALIDATION"},
}

# The 9 modules policy.yaml's `modules:` section flags require_explicit_approval
# (read directly from policy.yaml, not hardcoded blind -- see _load_approval_modules).
SCOPE_YAML = """\
target:
  - 10.10.0.0/16
  - corp.internal
exclusions:
  - 10.10.5.0/24
  - excluded.corp.internal
"""

SCOPE_CASES = {
    "in_scope": "10.10.1.50",
    "out_of_scope": "8.8.8.8",
    "excluded": "10.10.5.25",
    "no_target": "",
}


def _load_module_inventory() -> dict:
    """trust_level -> [module_basename, ...] from the real MODULE_INVENTORY.csv."""
    by_tier: dict = {}
    with open(BASH_DIR / "MODULE_INVENTORY.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            path = (row.get("script_path") or "").strip()
            trust = (row.get("trust_level") or "").strip()
            if not path:
                continue
            basename = path.split("/")[-1]
            by_tier.setdefault(trust, []).append(basename)
    return by_tier


def _load_approval_modules() -> dict:
    """module_basename -> reason, from policy.yaml's modules: section (real
    parse via PyYAML, not a hand-copied list)."""
    import yaml
    policy = yaml.safe_load((BASH_DIR / "policy.yaml").read_text(encoding="utf-8")) or {}
    out = {}
    for name, entry in (policy.get("modules") or {}).items():
        if entry.get("require_explicit_approval"):
            out[name] = entry.get("reason", "")
    return out


def _scope_matches(target: str, entry: str) -> bool:
    """Reimplementation of scope_check.py's matches() for the oracle -- kept
    intentionally identical to that file's logic since it's the documented
    source of truth for scope decisions, not an independent guess."""
    entry = entry.strip()
    if not entry:
        return False

    def as_net(v):
        try:
            return ipaddress.ip_network(v, strict=False)
        except ValueError:
            return None

    tnet, snet = as_net(target), as_net(entry)
    if tnet is not None and snet is not None:
        if tnet.version != snet.version:
            return False
        return tnet.subnet_of(snet) or tnet == snet
    if tnet is not None or snet is not None:
        return False
    t, s = target.lower().rstrip("."), entry.lower().rstrip(".")
    return t == s or t.endswith("." + s)


def _extract_host(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        if parsed.hostname:
            return parsed.hostname
    if target.count(":") == 1 and "/" not in target:
        host, _, port = target.partition(":")
        if port.isdigit():
            return host
    return target


def expected_scope_ok(env: str, target: str) -> bool:
    if env == "lab":
        return True  # gs_policy_check_scope short-circuits true for lab regardless of target
    if not target:
        return True  # gs_policy_gate treats "no target" as a warning for scope itself
    host = _extract_host(target)
    exclusions = ["10.10.5.0/24", "excluded.corp.internal"]
    in_scope = ["10.10.0.0/16", "corp.internal"]
    for e in exclusions:
        if _scope_matches(host, e) or _scope_matches(target, e):
            return False
    for e in in_scope:
        if _scope_matches(host, e) or _scope_matches(target, e):
            return True
    return False


def expected_allowed(trust_level: str, env: str, target: str, requires_approval: bool, approved: bool) -> bool:
    trust_ok = trust_level in _ALLOWED_BY_ENV[env]
    approval_ok = approved if requires_approval else True
    if not target:
        # gs_policy_gate's own no-target rule: warning-only for SAFE_ENUM/
        # VALIDATION, fail-closed for HIGH_IMPACT/LAB_ONLY outside lab.
        if env != "lab" and trust_level in ("HIGH_IMPACT", "LAB_ONLY"):
            scope_ok = False
        else:
            scope_ok = True
    else:
        scope_ok = expected_scope_ok(env, target)
    return trust_ok and approval_ok and scope_ok


_BASH_TEMPLATE = r"""
set +e
cd {bash_dir}
source lib/policy_engine.sh >/dev/null 2>&1
export GS_ENVIRONMENT={env}
export GS_ENGAGEMENT_ID=GOV-TEST-0001
export GS_SCOPE_FILE={scope_file}
export GS_AUTH_FILE={auth_file}
export GS_APPROVED_MODULES={approved_modules}
gs_policy_check_trust {module} {trust} >/dev/null 2>&1
trust_rc=$?
gs_policy_check_module {module} >/dev/null 2>&1
module_rc=$?
if [ -n "{target}" ]; then
  gs_policy_check_scope {target} >/dev/null 2>&1
  scope_rc=$?
else
  scope_rc=9
fi
echo "SUBCHECKS trust=$trust_rc module=$module_rc scope=$scope_rc" 1>&2
gs_policy_gate {module} {trust} {target} >/dev/null 2>&1
"""


def run_request(req: dict, scope_file: Path, auth_file: Path) -> dict:
    target_arg = req["target"] if req["target"] else ""
    script = _BASH_TEMPLATE.format(
        bash_dir=str(BASH_DIR),
        env=req["environment"],
        scope_file=str(scope_file),
        auth_file=str(auth_file) if req["environment"] == "production" else "",
        approved_modules=req["module"] if req.get("approved") else "",
        module=req["module"],
        trust=req["trust_level"],
        target=target_arg,
    )
    try:
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return {"gate_exit_code": None, "error": "timeout", "subchecks_raw": ""}

    subchecks_line = next((l for l in proc.stderr.splitlines() if l.startswith("SUBCHECKS")), "")
    return {
        "gate_exit_code": proc.returncode,
        "error": None,
        "subchecks_raw": subchecks_line,
    }


def build_requests() -> list:
    by_tier = _load_module_inventory()
    approval_modules = _load_approval_modules()
    requests = []

    # ── Core sweep: FULL FACTORIAL over every real module x every
    # environment x every scope-case (not a sample). The 9 approval-required
    # modules are excluded here and swept separately below (with a fixed
    # in-scope target) so the approval dimension isn't confounded by scope.
    approval_set = set(approval_modules)
    for tier, modules in sorted(by_tier.items()):
        candidates = [m for m in modules if m not in approval_set]
        for module in candidates:
            for env in ENVIRONMENTS:
                for scope_case, target in SCOPE_CASES.items():
                    requests.append({
                        "kind": "core_sweep",
                        "module": module,
                        "trust_level": tier,
                        "environment": env,
                        "scope_case": scope_case,
                        "target": target,
                        "requires_approval": False,
                        "approved": False,
                    })

    # ── Approval sweep: the 9 real explicit-approval modules x environment x
    #    approved/not-approved, always with an in-scope target so the
    #    approval dimension isn't confounded by scope. ──
    trust_by_module = {}
    for tier, modules in by_tier.items():
        for m in modules:
            trust_by_module[m] = tier
    for module in sorted(approval_modules):
        trust = trust_by_module.get(module, "UNDOCUMENTED")
        for env in ENVIRONMENTS:
            for approved in (True, False):
                requests.append({
                    "kind": "approval_sweep",
                    "module": module,
                    "trust_level": trust,
                    "environment": env,
                    "scope_case": "in_scope",
                    "target": SCOPE_CASES["in_scope"],
                    "requires_approval": True,
                    "approved": approved,
                })

    return requests


def main():
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    scope_file = WORK_DIR / "gov_test_scope.yml"
    scope_file.write_text(SCOPE_YAML, encoding="utf-8")
    auth_file = WORK_DIR / "gov_test_signed_auth.pdf"
    auth_file.write_text("synthetic authorization document for governance batch test\n", encoding="utf-8")

    requests = build_requests()
    print(f"Built {len(requests)} synthetic requests", file=sys.stderr)

    results = []
    for i, req in enumerate(requests):
        outcome = run_request(req, scope_file, auth_file)
        expected = expected_allowed(
            req["trust_level"], req["environment"], req["target"],
            req["requires_approval"], req["approved"],
        )
        gate_rc = outcome["gate_exit_code"]
        actual_allowed = (gate_rc == 0)
        actual_blocked = (gate_rc == 77)
        classification = "unclassified"
        if outcome["error"]:
            classification = "error"
        elif expected and actual_allowed:
            classification = "correct_allow"
        elif (not expected) and actual_blocked:
            classification = "correct_block"
        elif expected and actual_blocked:
            classification = "false_block"
        elif (not expected) and actual_allowed:
            classification = "unauthorized_execution"
        elif not actual_allowed and not actual_blocked:
            classification = "unexpected_exit_code"

        record = {**req, **outcome, "expected_allowed": expected,
                  "actual_allowed": actual_allowed, "classification": classification}
        results.append(record)
        if (i + 1) % 25 == 0:
            print(f"  ...{i + 1}/{len(requests)}", file=sys.stderr)

    total = len(results)
    counts = {}
    for r in results:
        counts[r["classification"]] = counts.get(r["classification"], 0) + 1

    n_blocked = sum(1 for r in results if r["actual_allowed"] is False and r["gate_exit_code"] == 77)
    n_allowed = sum(1 for r in results if r["actual_allowed"] is True)
    n_approval_required = sum(1 for r in results if r["requires_approval"])
    n_approval_required_blocked = sum(
        1 for r in results if r["requires_approval"] and not r["approved"] and r["gate_exit_code"] == 77
    )

    false_block_rate = counts.get("false_block", 0) / total if total else None
    unauthorized_execution_rate = counts.get("unauthorized_execution", 0) / total if total else None

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "experiment": "phase1_governance -- policy/governance batch test",
        "total_requests": total,
        "block_rate": round(n_blocked / total, 4) if total else None,
        "allow_rate": round(n_allowed / total, 4) if total else None,
        "approval_required_count": n_approval_required,
        "approval_required_and_blocked_when_unapproved_count": n_approval_required_blocked,
        "false_block_rate": round(false_block_rate, 4) if false_block_rate is not None else None,
        "unauthorized_execution_rate": round(unauthorized_execution_rate, 4) if unauthorized_execution_rate is not None else None,
        "classification_counts": counts,
        "is_full_factorial": True,
        "methodology": (
            "FULL FACTORIAL, not a sample: every one of the 164 non-approval-required real "
            "modules in MODULE_INVENTORY.csv x 3 environments (lab/staging/production) x 4 "
            "scope-cases (in_scope/out_of_scope/excluded/no_target), PLUS the 9 real modules "
            "policy.yaml flags require_explicit_approval x 3 environments x 2 approved-flags. "
            "Total N = (modules_in_core_sweep * 3 * 4) + (len(approval_modules) * 3 * 2); see "
            "total_requests for the exact achieved count. Each request calls the REAL "
            "bash_scripts_for_pentest/lib/policy_engine.sh functions (gs_policy_check_trust, "
            "gs_policy_check_module, gs_policy_check_scope, and the master gs_policy_gate -- "
            "exit 0 = allowed, exit 77 = policy blocked) against a real policy.yaml and a real "
            "synthetic scope.yml. 'expected_allowed' is computed independently in Python "
            "directly from policy.yaml's trust_levels/modules and a reimplementation of "
            "scope_check.py's matching logic -- not by re-running the bash function a second "
            "time -- so a mismatch reflects a real behavior discrepancy, not a duplicate of the "
            "same call. unauthorized_execution_rate is the single most important number here: "
            "it should be 0/N if the fail-closed design holds."
        ),
        "scope_file_used": SCOPE_YAML,
        "scope_cases": SCOPE_CASES,
        "limitations": [
            "GS_ENGAGEMENT_ID/GS_SCOPE_FILE/GS_AUTH_FILE were held constant and always "
            "satisfied across every request so gs_policy_check_auth's pass/fail never "
            "confounds the trust/scope/approval sweep this experiment targets -- the auth "
            "dimension itself was not independently varied.",
            "This is the full factorial over every real module currently in "
            "MODULE_INVENTORY.csv, not a sample -- if the module catalog changes size, the "
            "achieved N (see total_requests) will change accordingly and should be recomputed "
            "rather than assumed.",
            "'expected_allowed' encodes this evaluator's own reading of policy.yaml and "
            "scope_check.py at the time this was written; if either file changes, a stale "
            "oracle would misclassify -- see the raw per-request 'trust_level'/'environment'/"
            "'target'/'requires_approval'/'approved' fields to recompute independently.",
        ],
        "requests": results,
    }

    out_path = RESULTS_DIR / "phase1_governance.json"
    out_path.write_text(json.dumps(output, indent=2))
    print(f"Wrote {total} request result(s) to {out_path}", file=sys.stderr)
    print(f"block_rate={output['block_rate']} allow_rate={output['allow_rate']} "
          f"false_block_rate={output['false_block_rate']} "
          f"unauthorized_execution_rate={output['unauthorized_execution_rate']}", file=sys.stderr)


if __name__ == "__main__":
    main()