#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# GhostStrike Release Packager
#
# Produces a versioned, checksummed release tarball:
#   ghoststrike-vX.Y.Z.tar.gz
#   SHA256SUMS
#   SBOM.json          (lightweight package inventory, not full SPDX)
#
# Does NOT create a git tag or push anything -- this only builds local
# release artifacts from the current working tree. Tagging/pushing a
# real release is a separate, deliberate action for whoever's cutting it.
#
# Usage: ./tools/make_release.sh <version>   e.g. ./tools/make_release.sh 3.0.0
#
# Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version>   e.g. $0 3.0.0" >&2
    exit 1
fi
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: version must be MAJOR.MINOR.PATCH (semantic versioning), got: $VERSION" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_NAME="ghoststrike-v${VERSION}"
DIST_DIR="${REPO_ROOT}/dist"
STAGE_DIR="${DIST_DIR}/${RELEASE_NAME}"

echo "Building release: ${RELEASE_NAME}"

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# Export the current working tree via git, so untracked/gitignored local
# clutter (evidence/, findings/, runs/, scan-output dirs, the vault) never
# ends up in a release artifact -- matches the CI Security Checks job's
# assumption that only tracked, disclaimer-carrying files are shipped.
if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree &>/dev/null; then
    git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$STAGE_DIR"
else
    echo "Warning: not a git repository -- falling back to a plain file copy" \
         "(this may include local-only files that shouldn't ship)." >&2
    rsync -a --exclude='.git' "$REPO_ROOT/" "$STAGE_DIR/"
fi

# ── Lightweight SBOM: not full SPDX/CycloneDX, just an honest inventory of
# what's actually installed in the environment doing the build. Good enough
# to answer "what version of X shipped in this release" without pulling in
# SBOM tooling this project doesn't have a real consumer for yet. ─────────
SBOM_FILE="${STAGE_DIR}/SBOM.json"
python3 - "$VERSION" "$SBOM_FILE" <<'PYEOF'
import json
import subprocess
import sys
from datetime import datetime, timezone

version, out_path = sys.argv[1], sys.argv[2]

try:
    freeze = subprocess.run(
        [sys.executable, "-m", "pip", "freeze"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
except Exception:
    freeze = []

packages = []
for line in freeze:
    line = line.strip()
    if not line or line.startswith("#") or "==" not in line:
        continue
    name, _, ver = line.partition("==")
    packages.append({"name": name, "version": ver})

sbom = {
    "bom_format": "GhostStrike-lightweight-sbom-v1",
    "note": "Not full SPDX/CycloneDX -- a plain package inventory from the "
            "build environment's `pip freeze`. Good enough to answer "
            "'what version of X shipped', not a compliance artifact.",
    "component": "GhostStrike",
    "version": version,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "python_packages": packages,
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(sbom, f, indent=2)
    f.write("\n")
print(f"SBOM: {len(packages)} Python packages recorded")
PYEOF

# ── Tarball + checksums ─────────────────────────────────────────
cd "$DIST_DIR"
tar -czf "${RELEASE_NAME}.tar.gz" "$RELEASE_NAME"
sha256sum "${RELEASE_NAME}.tar.gz" > SHA256SUMS
cp "${STAGE_DIR}/SBOM.json" "${DIST_DIR}/SBOM.json"

rm -rf "$STAGE_DIR"

echo ""
echo "Release artifacts in ${DIST_DIR}:"
ls -la "$DIST_DIR"
echo ""
echo "Verify: sha256sum -c ${DIST_DIR}/SHA256SUMS"