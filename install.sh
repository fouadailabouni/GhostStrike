#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# GhostStrike Installer
#
# Detects what's already present, classifies what's missing into
# CORE / RECOMMENDED / OPTIONAL / SPECIALIZED, and offers to install
# each tier -- it does not silently pull in a 20GB toolchain by
# default. Safe to re-run any time; every step is idempotent.
#
# Usage: ./install.sh [--yes] [--core-only]
#   --yes         Don't prompt; install CORE + RECOMMENDED automatically.
#   --core-only   Only install CORE, regardless of --yes.
#
# Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASSUME_YES=false
CORE_ONLY=false

while [ $# -gt 0 ]; do
    case "$1" in
        --yes) ASSUME_YES=true; shift ;;
        --core-only) CORE_ONLY=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--yes] [--core-only]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'

# These write to stderr, not stdout: check_tools() below returns its actual
# result (the list of missing tools) via stdout for the caller to capture
# with mapfile/process substitution, so the human-readable display lines
# must never share that stream -- mixing them corrupts the captured list
# with checkmark/tool-name display text instead of just tool names.
ok()   { echo -e "  ${GREEN}✓${NC} $1" >&2; }
miss() { echo -e "  ${RED}✗${NC} $1" >&2; }
info() { echo -e "${BLUE}[*]${NC} $1" >&2; }
warn() { echo -e "${YELLOW}[!]${NC} $1" >&2; }

have() { command -v "$1" &>/dev/null; }

echo "GhostStrike Installer"
echo "======================"
echo ""

# ── Environment check ──────────────────────────────────────────
info "Checking environment..."
DISTRO="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="${ID:-unknown}"
fi
IS_WSL=false
grep -qi microsoft /proc/version 2>/dev/null && IS_WSL=true

if [[ "$DISTRO" =~ ^(kali|ubuntu|debian)$ ]]; then
    ok "Linux distro: $DISTRO $([ "$IS_WSL" = "true" ] && echo "(WSL2)")"
else
    warn "Distro '$DISTRO' not one of kali/ubuntu/debian -- apt-based install commands below may not apply. GhostStrike itself doesn't require any specific distro, just bash + the tools below."
fi

have bash && ok "Bash: $(bash --version | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)" || miss "Bash not found (should be impossible -- this script is running under bash)"
have python3 && ok "Python: $(python3 --version 2>&1 | awk '{print $2}')" || miss "Python 3 not found"
have git && ok "Git" || miss "Git not found"

echo ""

# ── Dependency tiers ────────────────────────────────────────────
# CORE: nothing in GhostStrike works without these.
# RECOMMENDED: most modules assume these; skipping them just means
#   the modules that need them will report "tool not found" at run
#   time instead of failing to even start.
# OPTIONAL: needed for specific features (AI Co-Pilot, PDF reports),
#   not for the framework generally.
# SPECIALIZED: heavy, niche tools -- installed only if explicitly asked.
CORE_TOOLS=(python3 git jq)
RECOMMENDED_TOOLS=(nmap sqlmap nikto)
OPTIONAL_PY=(customtkinter pillow jsonschema pyyaml)
OPTIONAL_AI_PY=(anthropic openai)
SPECIALIZED_TOOLS=(metasploit-framework hydra john hashcat)

check_tools() {
    local -n arr=$1
    local missing=()
    for t in "${arr[@]}"; do
        if have "$t"; then ok "$t"; else miss "$t"; missing+=("$t"); fi
    done
    printf '%s\n' "${missing[@]}"
}

info "CORE (required):"
mapfile -t MISSING_CORE < <(check_tools CORE_TOOLS)

echo ""
info "RECOMMENDED (most modules assume these):"
mapfile -t MISSING_RECOMMENDED < <(check_tools RECOMMENDED_TOOLS)

echo ""
info "SPECIALIZED (heavy, only if you need them):"
mapfile -t MISSING_SPECIALIZED < <(check_tools SPECIALIZED_TOOLS)

echo ""

if [ "${#MISSING_CORE[@]}" -gt 0 ]; then
    warn "Missing CORE tools: ${MISSING_CORE[*]}"
    if have apt-get; then
        echo "  sudo apt-get update && sudo apt-get install -y ${MISSING_CORE[*]}"
    fi
    echo ""
fi

install_apt() {
    local -a pkgs=("$@")
    [ "${#pkgs[@]}" -eq 0 ] && return 0
    if ! have apt-get; then
        warn "apt-get not found -- install manually: ${pkgs[*]}"
        return 1
    fi
    sudo apt-get update -qq
    sudo apt-get install -y "${pkgs[@]}"
}

prompt_yn() {
    [ "$ASSUME_YES" = "true" ] && return 0
    local reply
    read -r -p "$1 [Y/n] " reply
    [[ -z "$reply" || "$reply" =~ ^[Yy] ]]
}

# pip_install_with_fallback <pip args...>
# PEP 668 "externally-managed-environment" (default on current Debian/
# Ubuntu) blocks a bare `pip install` entirely. GhostStrike runs directly
# (python3 ghoststrike.py), not through an activated venv, so retrying
# with --break-system-packages is the pragmatic fix -- the same approach
# most CLI security tools take for this exact case.
pip_install_with_fallback() {
    local errfile="/tmp/gs_pip_err.$$"
    if pip install "$@" 2>"$errfile"; then
        rm -f "$errfile"
        return 0
    fi
    if grep -qi "externally-managed-environment" "$errfile" 2>/dev/null; then
        warn "System Python is externally-managed (PEP 668) -- retrying with --break-system-packages"
        rm -f "$errfile"
        pip install --break-system-packages "$@"
        return $?
    fi
    cat "$errfile" >&2
    rm -f "$errfile"
    return 1
}

if [ "${#MISSING_RECOMMENDED[@]}" -gt 0 ]; then
    if prompt_yn "Install recommended tools (${MISSING_RECOMMENDED[*]})?"; then
        install_apt "${MISSING_RECOMMENDED[@]}"
    fi
fi

if [ "$CORE_ONLY" != "true" ] && [ "${#MISSING_SPECIALIZED[@]}" -gt 0 ]; then
    if prompt_yn "Install specialized tools (${MISSING_SPECIALIZED[*]})? These are large."; then
        install_apt "${MISSING_SPECIALIZED[@]}"
    fi
fi

# -- Python dependencies --
echo ""
info "Python dependencies (make install)..."
if have pip3 || have pip; then
    (cd "$SCRIPT_DIR" && pip_install_with_fallback -r CyberToolkit/requirements.txt) ||         warn "pip install failed -- see CyberToolkit/requirements.txt and install manually."
else
    miss "pip not found -- install python3-pip first."
fi

echo ""
if [ "$CORE_ONLY" != "true" ]; then
    if prompt_yn "Install optional AI Co-Pilot dependencies (anthropic, openai)?"; then
        pip_install_with_fallback anthropic openai || warn "AI Co-Pilot dependency install failed."
    fi
fi

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo "GhostStrike ready."
echo ""
echo "Run:"
echo "  make gui"
echo ""
echo "Verify everything works:"
echo "  make syntax && make lint && make test && bash tests/module_smoke_test.sh"
echo ""
echo "See docs/QUICKSTART.md for what to do next."