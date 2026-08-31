#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# GhostStrike — Module Inventory Generator
# tests/generate_module_inventory.sh
#
# Phase 1 of the production-readiness plan: a mechanical, grep-driven
# pass over every module script producing a per-script data row so the
# Phase 3 policy-gate wiring pass is "go to line N" instead of
# "re-read this whole script." This makes no code changes.
#
# Output: bash_scripts_for_pentest/MODULE_INVENTORY.csv
#
# Copyright (C) 2026 Fouad Ailabouni. All rights reserved.
# ═══════════════════════════════════════════════════════════════

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASH_SCRIPTS_DIR="${1:-${SCRIPT_DIR}/../bash_scripts_for_pentest}"
INVENTORY_MD="${SCRIPT_DIR}/../SCRIPT_INVENTORY.md"
OUT_CSV="${BASH_SCRIPTS_DIR}/MODULE_INVENTORY.csv"

echo "script_path,trust_level,target_var,target_line,sources_policy_engine,sources_trust_registry,add_finding_pattern,documented,partial_flag" > "${OUT_CSV}"

mapfile -t scripts < <(find "${BASH_SCRIPTS_DIR}" -name "*.sh" \
    -not -path "*/lib/*" -not -path "*/benchmarks/*" -not -path "*/metrics/*" \
    | sort)

for script in "${scripts[@]}"; do
    rel="${script#"${BASH_SCRIPTS_DIR}"/}"
    base="$(basename "${script}")"

    # ── Target variable + approximate line where it's last assigned ──
    # This list is deliberately not exhaustive -- e.g. wireless modules use
    # TARGET_BSSID/TARGET_SSID/INTERFACE instead of a network target at all.
    # UNKNOWN rows are an expected, honest signal to go read that script by
    # hand in Phase 3, not a bug in this generator.
    target_var="UNKNOWN"
    target_line="0"
    for varname in TARGET_URL TARGET URL FIRMWARE_FILE APP_PATH \
                   TARGET_BSSID TARGET_SSID DOMAIN TARGET_HOST TARGET_IP; do
        line=$(grep -n "^\s*${varname}=" "${script}" | tail -1 | cut -d: -f1)
        if [ -n "${line}" ]; then
            target_var="${varname}"
            target_line="${line}"
            break
        fi
    done

    # ── Trust level: prefer SCRIPT_INVENTORY.md's table, else UNDOCUMENTED ──
    # system_config_audit.sh exists as two different files sharing a
    # basename (01-Network-Security=VALIDATION, 08-System-Security=SAFE_ENUM)
    # -- a plain basename grep can't tell them apart, so special-case it
    # exactly like lib/trust_registry.sh's gs_trust_get() does.
    trust_level="UNDOCUMENTED"
    case "${rel}" in
        01-Network-Security/system_config_audit.sh) trust_level="VALIDATION" ;;
        08-System-Security/system_config_audit.sh)  trust_level="SAFE_ENUM" ;;
        *)
            if [ -f "${INVENTORY_MD}" ]; then
                row=$(grep -F "| ${base} |" "${INVENTORY_MD}" | head -1)
                if [ -n "${row}" ]; then
                    trust_level=$(echo "${row}" | awk -F'|' '{gsub(/ /,"",$5); print $5}')
                    [ -z "${trust_level}" ] && trust_level="UNKNOWN"
                fi
            fi
            # SCRIPT_INVENTORY.md is hand-maintained and lags newly-ported/newly-wired
            # modules (that's Phase 6's job to fix, not this generator's). Rather than
            # report UNDOCUMENTED -- which downstream consumers like the GUI's live
            # trust lookup treat as "unknown" and fall back to a default -- fall back to
            # reading the trust level the module actually enforces at runtime: the
            # second quoted argument to its own gs_policy_gate call. This is strictly
            # more trustworthy than docs anyway, since it can't drift from what's
            # actually enforced.
            if [ "${trust_level}" = "UNDOCUMENTED" ]; then
                gate_line=$(grep -m1 'gs_policy_gate "' "${script}" 2>/dev/null)
                if [ -n "${gate_line}" ]; then
                    # Match one of the four known trust tokens in quotes on the gate
                    # line, rather than positionally parsing "the 2nd argument" -- the
                    # first argument is often $(basename "$0"), whose embedded quotes
                    # would break a naive [^"]*-style positional match.
                    parsed=$(echo "${gate_line}" \
                        | grep -oE '"(SAFE_ENUM|VALIDATION|HIGH_IMPACT|LAB_ONLY)"' \
                        | tr -d '"' | head -1)
                    [ -n "${parsed}" ] && trust_level="${parsed}"
                fi
            fi
            ;;
    esac

    # ── Documented / partial flags from SCRIPT_INVENTORY.md ──
    documented="NO"
    partial_flag="NO"
    if [ -f "${INVENTORY_MD}" ] && grep -qF "| ${base} |" "${INVENTORY_MD}"; then
        documented="YES"
        if grep -F "| ${base} |" "${INVENTORY_MD}" | grep -q "PARTIAL"; then
            partial_flag="YES"
        fi
    fi

    # ── Library sourcing ──
    # common.sh now auto-sources policy_engine.sh (evidence.sh,
    # reproducibility.sh too) internally, guarded against double-sourcing --
    # added after finding 48 modules that called gs_policy_gate but never
    # actually got it defined, because they only sourced common.sh and
    # (at the time) common.sh didn't chain-load policy_engine.sh despite
    # lib/README.md documenting that it did. A module sourcing common.sh is
    # therefore sufficient, not just an explicit policy_engine.sh source line.
    sources_policy="NO"
    if grep -q "policy_engine\.sh" "${script}" || grep -q "common\.sh" "${script}"; then
        sources_policy="YES"
    fi
    sources_trust="NO"
    grep -q "trust_registry\.sh" "${script}" && sources_trust="YES"

    # ── add_finding pattern ──
    finding_pattern="NONE"
    if grep -q "gs_add_finding" "${script}"; then
        finding_pattern="GS_ADD_FINDING_DIRECT"
    elif grep -qE "^\s*add_finding\s*\(\)" "${script}"; then
        finding_pattern="LOCAL_WRAPPER"
    elif grep -qE "(^|[^_a-zA-Z])add_finding[[:space:]]" "${script}"; then
        finding_pattern="BARE_ADD_FINDING_NO_WRAPPER"
    fi

    echo "${rel},${trust_level},${target_var},${target_line},${sources_policy},${sources_trust},${finding_pattern},${documented},${partial_flag}" >> "${OUT_CSV}"
done

echo "Inventory written: ${OUT_CSV}"
echo "Rows: $(($(wc -l < "${OUT_CSV}") - 1))"
