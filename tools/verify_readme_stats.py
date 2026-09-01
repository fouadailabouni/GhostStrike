#!/usr/bin/env python3
"""
GhostStrike -- README stats drift check.

The exact "GitHub About says 119 modules, README says 165" problem this
guards against: module/category counts get hand-written in prose and
silently go stale the next time a module is added or removed. This reads
the real numbers from bash_scripts_for_pentest/registry.json (the
canonical, generated source of truth -- see
tools/generate_module_registry.py) and checks them against the machine-
readable markers README.md embeds right next to its human-readable count:

    <!-- STATS:MODULE_COUNT --> 172 modules <!-- /STATS -->

Run standalone: python3 tools/verify_readme_stats.py
Exits 1 (and prints exactly what's stale) if README's numbers don't match
the registry -- intended to run in CI so a module addition that isn't
reflected in README fails the build instead of drifting silently.

(c) 2026 Fouad Ailabouni. All rights reserved.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "bash_scripts_for_pentest" / "registry.json"
README_PATH = REPO_ROOT / "README.md"

MARKER_RE = re.compile(r"<!--\s*STATS:(\w+)\s*-->\s*(\d+)\s*<!--\s*/STATS\s*-->")


def real_stats() -> dict:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    modules = registry.get("modules", [])
    categories = {
        m.get("category") for m in modules
        if m.get("category") and m.get("category") != "uncategorized"
    }
    return {
        "MODULE_COUNT": len(modules),
        "CATEGORY_COUNT": len(categories),
    }


def readme_claims() -> dict:
    text = README_PATH.read_text(encoding="utf-8")
    return {name: int(value) for name, value in MARKER_RE.findall(text)}


def main() -> int:
    real = real_stats()
    claimed = readme_claims()

    missing_markers = set(real) - set(claimed)
    if missing_markers:
        print(f"README.md is missing STATS markers for: {sorted(missing_markers)}")
        print("Add e.g. <!-- STATS:MODULE_COUNT --> 172 modules <!-- /STATS --> near the count.")
        return 1

    mismatches = []
    for key, real_value in real.items():
        claimed_value = claimed.get(key)
        if claimed_value != real_value:
            mismatches.append((key, claimed_value, real_value))

    if mismatches:
        print("README.md stats are stale:")
        for key, claimed_value, real_value in mismatches:
            print(f"  {key}: README says {claimed_value}, registry.json says {real_value}")
        return 1

    print(f"README.md stats match registry.json: {real}")
    return 0


if __name__ == "__main__":
    sys.exit(main())