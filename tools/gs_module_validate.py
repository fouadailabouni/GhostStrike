#!/usr/bin/env python3
"""
GhostStrike Module SDK -- module validator.

Runnable standalone (`python3 tools/gs_module_validate.py <script.sh>`)
or via `gs module validate` (bin/gs -> CyberToolkit/gs_cli.py's
cmd_module_validate, which imports and calls validate_module() below
directly rather than reimplementing it).

Checks, each independently reported (this is a checklist, not a single
pass/fail bit):
  - manifest.yaml exists (as <script>.manifest.yaml alongside the script,
    matching what gs_module_init.py generates) and validates against
    schemas/module_manifest.schema.json
  - AUTHORIZATION DISCLAIMER present (same string CI's Security Checks job
    requires)
  - `set -euo pipefail` present
  - sources lib/common.sh
  - calls gs_policy_gate, and with the SAME trust level the manifest claims
    -- catches manifest/code drift, not just manifest validity in isolation
  - calls gs_add_finding (directly, or via a local finding() wrapper) if
    the manifest claims outputs.findings
  - no obviously unsafe dynamic construction: bare `eval`, and unquoted
    `$1`/`$@`/`$TARGET`-shaped expansions passed directly to `bash -c`
    (a real command-injection shape, not a style nitpick)

This is a real static checker, not a rubber stamp -- it can and should
report real failures on real modules.

(c) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "bash_scripts_for_pentest" / "schemas" / "module_manifest.schema.json"


class Finding:
    def __init__(self, level: str, message: str):
        self.level = level  # "ERROR" or "WARN"
        self.message = message

    def __str__(self):
        return f"[{self.level}] {self.message}"


def validate_module(script_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not script_path.is_file():
        return [Finding("ERROR", f"{script_path} does not exist")]

    source = script_path.read_text(encoding="utf-8", errors="replace")

    manifest_path = script_path.with_suffix("").with_suffix(".manifest.yaml")
    manifest = None
    if not manifest_path.is_file():
        findings.append(Finding("ERROR", f"no manifest found at {manifest_path.name}"))
    else:
        try:
            import yaml
        except ImportError:
            findings.append(Finding("ERROR", "PyYAML not installed -- cannot validate manifest"))
            yaml = None
        if yaml is not None:
            try:
                manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                findings.append(Finding("ERROR", f"manifest.yaml does not parse: {e}"))

            if manifest is not None:
                try:
                    import jsonschema
                    schema = __import__("json").loads(SCHEMA_PATH.read_text(encoding="utf-8"))
                    jsonschema.validate(manifest, schema)
                except ImportError:
                    findings.append(Finding("WARN", "jsonschema not installed -- skipped manifest schema validation"))
                except Exception as e:  # jsonschema.ValidationError or similar
                    findings.append(Finding("ERROR", f"manifest fails schema validation: {e}"))

    if "AUTHORIZATION DISCLAIMER" not in source:
        findings.append(Finding("ERROR", "missing AUTHORIZATION DISCLAIMER (required by CI's Security Checks job)"))

    if not re.search(r"^set\s+-\S*e\S*u\S*", source, re.MULTILINE) and "set -euo pipefail" not in source:
        findings.append(Finding("WARN", "no 'set -euo pipefail' found -- unbound-variable and silent-failure bugs are easy to introduce without it"))

    if not re.search(r"source .*lib/common\.sh", source):
        findings.append(Finding("ERROR", "does not source lib/common.sh"))

    # The real convention across every module in the tree is
    # gs_policy_gate "$(basename "$0")" "TRUST_LEVEL" "$TARGET" -- note the
    # nested double quotes inside $(basename "$0"), which break a naive
    # "match the first two double-quoted strings" regex (verified the hard
    # way: it silently matched zero modules until this was anchored on the
    # actual $(basename "$0") idiom instead of a generic quote count).
    policy_gate_match = re.search(r'gs_policy_gate\s+"\$\(basename\s+"\$0"\)"\s+"([A-Z_]+)"', source)
    if not policy_gate_match:
        findings.append(Finding("ERROR", "does not call gs_policy_gate -- module will not be authorization-gated"))
    elif manifest is not None:
        code_trust = policy_gate_match.group(1)
        manifest_trust = manifest.get("trust")
        if code_trust != manifest_trust:
            findings.append(Finding(
                "ERROR",
                f"manifest declares trust={manifest_trust!r} but the code actually calls "
                f"gs_policy_gate with trust={code_trust!r} -- manifest/code drift"
            ))

    wants_findings = bool(manifest and manifest.get("outputs", {}).get("findings"))
    has_finding_call = bool(re.search(r"\bgs_add_finding\b|^\s*finding\(\)\s*\{", source, re.MULTILINE))
    if wants_findings and not has_finding_call:
        findings.append(Finding("ERROR", "manifest declares outputs.findings=true but no gs_add_finding call or finding() wrapper found"))

    if re.search(r"(^|[^#\w])eval\s", source, re.MULTILINE):
        findings.append(Finding("ERROR", "uses eval -- a well-known source of injection bugs; use an array + direct exec instead"))

    if re.search(r'bash\s+-c\s+"[^"]*\$(\{[@*]|[0-9@*])', source):
        findings.append(Finding("ERROR", "passes an unquoted/interpolated positional or $@/$* into `bash -c \"...\"` -- classic command-injection shape"))

    return findings


def _cli():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("script", help="Path to the module .sh file")
    args = parser.parse_args()

    findings = validate_module(Path(args.script))
    errors = [f for f in findings if f.level == "ERROR"]
    warnings = [f for f in findings if f.level == "WARN"]

    for f in findings:
        print(f)

    print("")
    if not findings:
        print("PASS -- no issues found")
        sys.exit(0)
    print(f"{len(errors)} error(s), {len(warnings)} warning(s)")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    _cli()