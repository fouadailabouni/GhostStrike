#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# GhostStrike — Module Smoke Test Harness
# tests/module_smoke_test.sh
#
# Phase 0.5 of the production-readiness plan: a narrow, purpose-built
# regression net for the module-wiring work in later phases. This does
# NOT execute attack logic against any target — it only checks that
# each module's argument parsing and exit behavior are sane:
#
#   1. bash -n <script>        -- syntax check
#   2. run with NO arguments   -- must NOT crash with "unbound variable"
#                                  (set -u firing before the script's own
#                                  validation runs), and MUST exit non-zero
#   3. run with --help/-h      -- must exit cleanly (0) if the flag is
#                                  supported; scripts that don't support
#                                  it are recorded as SKIP, not FAIL
#
# Every invocation is wrapped in `timeout` with stdin from /dev/null, so
# nothing can hang waiting on input or run longer than the bound.
#
# Usage: ./module_smoke_test.sh [--dir <bash_scripts_for_pentest path>]
# Output: a PASS/FAIL/SKIP table + summary, and a machine-readable
#         tests/module_smoke_test_results.tsv
#
# Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASH_SCRIPTS_DIR="${1:-${SCRIPT_DIR}/../bash_scripts_for_pentest}"
TIMEOUT_SECS=5
RESULTS_TSV="${SCRIPT_DIR}/module_smoke_test_results.tsv"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

total=0
syntax_fail=0
noargs_fail=0
help_fail=0
help_skip=0

echo -e "script\tsyntax\tnoargs\thelp" > "${RESULTS_TSV}"

echo "GhostStrike Module Smoke Test"
echo "Scanning: ${BASH_SCRIPTS_DIR}"
echo ""

mapfile -t scripts < <(find "${BASH_SCRIPTS_DIR}" -name "*.sh" \
    -not -path "*/lib/*" -not -path "*/benchmarks/*" -not -path "*/metrics/*" \
    | sort)

echo "Found ${#scripts[@]} module scripts"
echo ""

for script in "${scripts[@]}"; do
    total=$((total + 1))
    rel="${script#"${BASH_SCRIPTS_DIR}"/}"

    # ── 1. Syntax ──
    syntax_result="PASS"
    if ! bash -n "${script}" 2>/dev/null; then
        syntax_result="FAIL"
        syntax_fail=$((syntax_fail + 1))
        echo -e "${RED}[SYNTAX FAIL]${NC} ${rel}"
    fi

    # ── 2. No-args invocation ──
    noargs_out=""
    noargs_rc=0
    noargs_out=$(timeout "${TIMEOUT_SECS}" bash "${script}" </dev/null 2>&1)
    noargs_rc=$?

    noargs_result="PASS"
    if echo "${noargs_out}" | grep -qi "unbound variable"; then
        noargs_result="FAIL (unbound variable — set -u fired before validation)"
        noargs_fail=$((noargs_fail + 1))
        echo -e "${RED}[NOARGS FAIL]${NC} ${rel} -- unbound variable crash"
    elif [ "${noargs_rc}" -eq 0 ]; then
        noargs_result="FAIL (exited 0 with no target — should require one)"
        noargs_fail=$((noargs_fail + 1))
        echo -e "${YELLOW}[NOARGS FAIL]${NC} ${rel} -- exited 0 with no arguments"
    elif [ "${noargs_rc}" -eq 124 ]; then
        noargs_result="FAIL (timed out after ${TIMEOUT_SECS}s — did it start real work with no target?)"
        noargs_fail=$((noargs_fail + 1))
        echo -e "${RED}[NOARGS FAIL]${NC} ${rel} -- timed out (${TIMEOUT_SECS}s)"
    fi

    # ── 3. --help / -h invocation ──
    help_out=""
    help_rc=0
    help_out=$(timeout "${TIMEOUT_SECS}" bash "${script}" --help </dev/null 2>&1)
    help_rc=$?
    if [ "${help_rc}" -eq 124 ]; then
        help_result="FAIL (timed out)"
        help_fail=$((help_fail + 1))
        echo -e "${RED}[HELP FAIL]${NC} ${rel} -- --help timed out"
    elif echo "${help_out}" | grep -qi "unbound variable"; then
        help_result="FAIL (unbound variable on --help)"
        help_fail=$((help_fail + 1))
        echo -e "${RED}[HELP FAIL]${NC} ${rel} -- unbound variable on --help"
    elif [ "${help_rc}" -eq 0 ]; then
        help_result="PASS"
    else
        # Many scripts don't implement --help at all; that's a gap worth
        # tracking but not a hard failure the way a crash is.
        help_result="SKIP (no --help support, exit ${help_rc})"
        help_skip=$((help_skip + 1))
    fi

    echo -e "${rel}\t${syntax_result}\t${noargs_result}\t${help_result}" >> "${RESULTS_TSV}"
done

echo ""
echo "════════════════════════════════════════════════════"
echo " Total scripts:       ${total}"
echo " Syntax failures:     ${syntax_fail}"
echo " No-args failures:    ${noargs_fail}"
echo " --help failures:     ${help_fail}"
echo " --help unsupported:  ${help_skip}"
echo "════════════════════════════════════════════════════"
echo " Full results: ${RESULTS_TSV}"

if [ "${syntax_fail}" -gt 0 ] || [ "${noargs_fail}" -gt 0 ] || [ "${help_fail}" -gt 0 ]; then
    exit 1
fi
exit 0
