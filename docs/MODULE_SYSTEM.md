# Module System

## Categories

165 modules across 22 categories under `bash_scripts_for_pentest/`:

| Category | Scripts | | Category | Scripts |
|---|---|---|---|---|
| 00-Framework-Core | 7 | | 11-Cloud-Security | 10 |
| 01-Network-Security | 20 | | 12-Exploitation | 2 |
| 02-Web-Application-Security | 22 | | 13-Post-Exploitation | 8 |
| 03-Wireless-Security | 4 | | 14-Reporting-Tools | 1 |
| 04-Database-Security | 4 | | 15-Automation-Tools | 2 |
| 05-Active-Directory | 16 | | 16-Specialized-Testing | 3 |
| 06-Password-Attacks | 4 | | 17-Monitoring-Detection | 6 |
| 07-Social-Engineering | 3 | | 18-Application-Security | 2 |
| 08-System-Security | 11 | | 19-Lab-Environment | 1 |
| 09-Container-Security | 1 | | 20-IoT-Security | 16 |
| 10-Mobile-Security | 2 | | 21-Bypass-Techniques | 20 |

45 of these were ported from a sibling project (PhantomOps) and individually
re-wired for `gs_policy_gate`; see `SCRIPT_INVENTORY.md` for the full
per-module trust-level and quality breakdown.

## Trust levels

See [SAFETY_MODEL.md](SAFETY_MODEL.md#trust-levels) — `SAFE_ENUM`,
`VALIDATION`, `HIGH_IMPACT`, `LAB_ONLY`.

## Anatomy of a module

Every module follows the same shape:

```bash
#!/bin/bash
set -euo pipefail

# AUTHORIZATION DISCLAIMER: ... (required — CI checks for this)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/common.sh"   # auto-sources policy/evidence/finding/repro

# ── argument parsing ──
while [ $# -gt 0 ]; do case "$1" in
    -t|--target) TARGET="$2"; shift 2;;
    --dry-run)   GS_DRY_RUN="true"; shift;;
    -h|--help)   usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 1;;
esac; done

# ── the policy gate, right after argument parsing completes ──
gs_policy_gate "$(basename "$0")" "<TRUST_LEVEL>" "$TARGET"

# ── the actual module logic ──
```

Key conventions, all enforced (in part) by `tests/module_smoke_test.sh`:

- Runs with **no arguments** must not crash with an unbound-variable error,
  and must exit non-zero — unless the module is a local-audit/no-target tool
  by design (see the harness's `NO_TARGET_REQUIRED` list).
- `--help`/`-h` must exit cleanly with usage text, and must not fall through
  into doing real work.
- `--dry-run` (where supported) must actually skip expensive/real work —
  checking `GS_DRY_RUN` directly, not a separate local flag variable that
  never gets wired to it.
- Findings go through `gs_add_finding` (or a local `finding()` wrapper that
  falls back safely if it isn't defined), never a bespoke ad hoc format.

## Adding a new module

1. Pick the right category directory (or propose a new one if it genuinely
   doesn't fit any existing 22 — see `CONTRIBUTING.md`).
2. Copy the shape above from a similar existing module in that category.
3. Pick a trust level honestly — `LAB_ONLY` and `HIGH_IMPACT` aren't
   optional extras, they're what keeps the policy gate meaningful.
4. Run `bash tests/module_smoke_test.sh` before opening a PR — it's exactly
   what CI runs, so a clean local run means CI will pass too.
5. Regenerate `bash_scripts_for_pentest/MODULE_INVENTORY.csv` via
   `tests/generate_module_inventory.sh` so the GUI picks up the new module.

## Finding format

All findings are validated against `bash_scripts_for_pentest/schemas/finding.schema.json`
and can be exported to SARIF 2.1.0 or structured JSON via
`lib/finding_ontology.sh`. Cross-run duplicates are handled by
`lib/finding_dedup.sh`/`.py` — see [ARCHITECTURE.md](ARCHITECTURE.md).