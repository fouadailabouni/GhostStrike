#!/usr/bin/env python3
"""
GhostStrike Module SDK -- scaffolding generator.

Runnable standalone (`python3 tools/gs_module_init.py ...`) or via
`gs module init` (bin/gs -> CyberToolkit/gs_cli.py's cmd_module_init,
which imports and calls create_module() below directly rather than
reimplementing it -- one implementation either way).

Usage:
    python3 tools/gs_module_init.py <category>/<module-slug> --name "Human Name" \\
        --trust VALIDATION [--status EXPERIMENTAL] [--mitre T1190,T1110] \\
        [--network] [--root] [--credentials] [--filesystem limited]

Produces bash_scripts_for_pentest/<category>/<module_slug>.sh plus a
manifest.yaml alongside it, following the same argument-parsing +
gs_policy_gate shape every other module in the tree uses -- see
docs/MODULE_SYSTEM.md.

(c) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "bash_scripts_for_pentest"

VALID_STATUS = ("PRODUCTION", "BETA", "EXPERIMENTAL", "LAB_ONLY", "DEPRECATED")
VALID_TRUST = ("SAFE_ENUM", "VALIDATION", "HIGH_IMPACT", "LAB_ONLY")

DISCLAIMER = """\
# AUTHORIZATION DISCLAIMER:
# This tool is provided only to assist authorized penetration tests, security
# assessments, and other lawful security activities. The operator must obtain
# explicit written authorization from the owner(s) of any systems, networks,
# or data to be tested. Testing without authorization may be illegal. The
# authors disclaim all liability for damages resulting from use or misuse.
# If you do not have explicit authorization to test a target, do not use this tool.
"""

MODULE_TEMPLATE = """\
#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
if [ -f "$SCRIPT_DIR/../lib/common.sh" ]; then source "$SCRIPT_DIR/../lib/common.sh"
elif [ -f "$SCRIPT_DIR/../../lib/common.sh" ]; then source "$SCRIPT_DIR/../../lib/common.sh"; fi

# {name}
# For authorized security testing only
# Copyright (C) {year} Fouad Ailabouni. All rights reserved.

{disclaimer}
GS_SCRIPT_NAME="{slug}"
TARGET=""
OUTPUT_DIR=""

usage() {{
    echo "Usage: $0 -t TARGET [-o DIR] [--dry-run]"
}}

finding() {{ command -v gs_add_finding >/dev/null && gs_add_finding "$@" || true; }}

while [ $# -gt 0 ]; do
    case "$1" in
        -t|--target)  TARGET="$2"; shift 2 ;;
        -o|--output)  OUTPUT_DIR="$2"; shift 2 ;;
        --dry-run)    GS_DRY_RUN="true"; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "Error: -t/--target is required" >&2
    usage
    exit 1
fi

declare -f gs_policy_gate &>/dev/null && gs_policy_gate "$(basename "$0")" "{trust}" "$TARGET"

if [ "${{GS_DRY_RUN:-false}}" = "true" ]; then
    echo "[DRY-RUN] Would run against: $TARGET"
    exit 0
fi

GS_OUTPUT_DIR="${{OUTPUT_DIR:-{slug}_$(date +%Y%m%d_%H%M%S)}}"
gs_setup_output "$GS_SCRIPT_NAME" 2>/dev/null || mkdir -p "$GS_OUTPUT_DIR"
gs_repro_start "{slug}" 2>/dev/null || true

# TODO: the actual module logic goes here.
echo "TODO: implement {name}"

gs_repro_end 2>/dev/null || true
echo "Complete: $GS_OUTPUT_DIR"
"""

MANIFEST_TEMPLATE = """\
id: {module_id}
name: {name}
version: 0.1.0
category: {category}
status: {status}
trust: {trust}
mitre: [{mitre}]
permissions:
  network: {network}
  root: {root}
  filesystem: {filesystem}
  credentials: {credentials}
  raw_socket: false
  external_internet: false
  system_package: false
outputs:
  findings: true
  evidence: true
author: ""
description: ""
"""

README_TEMPLATE = """\
# {name}

Status: {status} | Trust: {trust} | Category: {category}

## What this does

TODO.

## Usage

```bash
bash {relpath} -t <target>
```

## MITRE ATT&CK

{mitre_display}
"""


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def create_module(
    module_id: str,
    name: str,
    trust: str,
    status: str = "EXPERIMENTAL",
    mitre: list[str] | None = None,
    network: bool = False,
    root: bool = False,
    credentials: bool = False,
    filesystem: str = "none",
    force: bool = False,
) -> Path:
    if "/" not in module_id:
        raise ValueError(f"module id must be <category-slug>/<module-slug>, got {module_id!r}")
    if trust not in VALID_TRUST:
        raise ValueError(f"trust must be one of {VALID_TRUST}, got {trust!r}")
    if status not in VALID_STATUS:
        raise ValueError(f"status must be one of {VALID_STATUS}, got {status!r}")

    category_slug, module_slug = module_id.split("/", 1)
    module_slug = slugify(module_slug)

    matches = [d for d in SCRIPTS_DIR.iterdir() if d.is_dir() and category_slug.lower() in d.name.lower()]
    if len(matches) == 1:
        category_dir = matches[0]
    else:
        raise ValueError(
            f"could not find a unique existing category directory matching {category_slug!r} "
            f"under {SCRIPTS_DIR} -- pass the full directory name (e.g. 02-Web-Application-Security)"
        )

    script_path = category_dir / f"{module_slug}.sh"
    manifest_path = category_dir / f"{module_slug}.manifest.yaml"
    if script_path.exists() and not force:
        raise FileExistsError(f"{script_path} already exists -- pass force=True to overwrite")

    mitre = mitre or []
    mitre_yaml = ", ".join(f'"{t}"' for t in mitre)
    mitre_display = ", ".join(mitre) if mitre else "(none mapped yet)"

    script_path.write_text(
        MODULE_TEMPLATE.format(
            name=name, year=date.today().year, slug=module_slug,
            disclaimer=DISCLAIMER, trust=trust,
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)

    manifest_path.write_text(
        MANIFEST_TEMPLATE.format(
            module_id=f"{category_slug}/{module_slug}", name=name,
            category=category_dir.name, status=status, trust=trust,
            mitre=mitre_yaml, network=str(network).lower(), root=str(root).lower(),
            filesystem=filesystem, credentials=str(credentials).lower(),
        ),
        encoding="utf-8",
    )

    readme_path = category_dir / f"{module_slug}.README.md"
    readme_path.write_text(
        README_TEMPLATE.format(
            name=name, status=status, trust=trust, category=category_dir.name,
            relpath=script_path.relative_to(REPO_ROOT).as_posix(),
            mitre_display=mitre_display,
        ),
        encoding="utf-8",
    )

    return script_path


def _cli():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("module_id", help="<category-slug>/<module-slug>, e.g. web/example-scanner")
    parser.add_argument("--name", required=True, help="Human-readable module name")
    parser.add_argument("--trust", required=True, choices=VALID_TRUST)
    parser.add_argument("--status", default="EXPERIMENTAL", choices=VALID_STATUS)
    parser.add_argument("--mitre", default="", help="Comma-separated technique IDs, e.g. T1190,T1110")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--root", action="store_true")
    parser.add_argument("--credentials", action="store_true")
    parser.add_argument("--filesystem", default="none", choices=["none", "limited", "full"])
    parser.add_argument("--force", action="store_true", help="Overwrite if the module already exists")
    args = parser.parse_args()

    mitre_list = [t.strip() for t in args.mitre.split(",") if t.strip()]

    try:
        path = create_module(
            args.module_id, args.name, args.trust, args.status, mitre_list,
            args.network, args.root, args.credentials, args.filesystem, args.force,
        )
    except (ValueError, FileExistsError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Created: {path.relative_to(REPO_ROOT)}")
    print(f"Created: {path.with_suffix('').as_posix()}.manifest.yaml".replace(str(REPO_ROOT) + "/", ""))
    print("")
    print("Next: validate it with:")
    print(f"  python3 tools/gs_module_validate.py {path.relative_to(REPO_ROOT).as_posix()}")


if __name__ == "__main__":
    _cli()