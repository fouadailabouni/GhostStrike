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
# 60s wasn't enough for a couple of full-filesystem local audits when timed
# on this dev machine (WSL2 on Windows, where a `find /` that crosses into
# an NTFS-mounted drive is far slower than the same scan on a native Linux
# filesystem -- which is what the actual GitHub Actions runner uses). Set
# generously rather than risk flaking CI on environment-specific slowness
# that these scripts don't exhibit on real Linux.
SLOW_TIMEOUT_SECS=120
RESULTS_TSV="${SCRIPT_DIR}/module_smoke_test_results.tsv"

# ── Modules that legitimately don't require a target ──────────────────────
# "Exited 0 with no arguments" is only a real bug for a module that's
# supposed to attack/scan an external target. These fall into two honest
# categories instead, found by actually reading what each one does (not by
# relaxing the check blindly):
#   (a) command-dispatch framework tools (Framework-Core) where "no args ->
#       show help, exit 0" is standard, correct CLI behavior (same
#       convention as git/docker/kubectl with no subcommand) -- not
#       something that should be forced to fail.
#   (b) local-system/local-environment audit tools that correctly operate
#       on the current machine, the local Docker lab, or an ambient
#       cloud-CLI session (az/gcloud) rather than an external target.
NO_TARGET_REQUIRED=(
    "00-Framework-Core/authorization_framework.sh"
    "00-Framework-Core/ci_linting_framework.sh"
    "00-Framework-Core/framework_tester.sh"
    "00-Framework-Core/json_output_framework.sh"
    "00-Framework-Core/mitre_attack_framework.sh"
    "00-Framework-Core/pentest_roadmap.sh"
    "00-Framework-Core/system_doctor.sh"
    "00-Framework-Core/tool_verification.sh"
    "01-Network-Security/netdiscover_automation.sh"
    "01-Network-Security/system_config_audit.sh"
    "03-Wireless-Security/bluetooth_scanner.sh"
    "04-Database-Security/database_hardening_checker.sh"
    "06-Password-Attacks/password_attack_suite.sh"
    "08-System-Security/bootloader_protection_checker.sh"
    "08-System-Security/cis_linux_manual_checks.sh"
    "08-System-Security/cis_windows_checks.sh"
    "08-System-Security/file_integrity_monitor.sh"
    "08-System-Security/mandatory_access_control_checker.sh"
    "08-System-Security/ntp_chrony_checker.sh"
    "08-System-Security/system_config_audit.sh"
    "09-Container-Security/container_security_scanner.sh"
    "11-Cloud-Security/aws_security_scanner.sh"
    "11-Cloud-Security/azure_security_audit.sh"
    "11-Cloud-Security/gcp_security_audit.sh"
    "13-Post-Exploitation/file_transfer.sh"
    "13-Post-Exploitation/privilege_escalation_checker.sh"
    "13-Post-Exploitation/privilege_escalation_linux.sh"
    "13-Post-Exploitation/privilege_escalation_windows.sh"
    "14-Reporting-Tools/pentest_report_generator.sh"
    "17-Monitoring-Detection/purple_mode_validator.sh"
    "19-Lab-Environment/pentest_lab/scripts/backup_lab.sh"
    "19-Lab-Environment/pentest_lab/scripts/lab_status.sh"
    "policy_validator.sh"
)

# ── Modules that legitimately do real, slow local work with no target ─────
# These aren't hangs -- confirmed by manual runs producing real, incremental
# output (SUID/SGID filesystem scans, full local service audits, etc.) that
# just takes longer than the default 5s budget. They still get a hard bound
# (SLOW_TIMEOUT_SECS) so a genuine infinite hang is still caught.
SLOW_LOCAL_AUDIT=(
    "00-Framework-Core/framework_tester.sh"
    "01-Network-Security/netdiscover_automation.sh"
    "01-Network-Security/system_config_audit.sh"
    "08-System-Security/cis_linux_manual_checks.sh"
    "08-System-Security/system_config_audit.sh"
    "09-Container-Security/container_security_scanner.sh"
    "13-Post-Exploitation/privilege_escalation_checker.sh"
    "13-Post-Exploitation/privilege_escalation_linux.sh"
    "13-Post-Exploitation/privilege_escalation_windows.sh"
    "policy_validator.sh"
)

# ── Modules whose real (non-dry-run) no-args work is either network-
# dependent (a LinPEAS-style download) or a full-filesystem/full-host scan
# whose duration scales with the size of whatever machine happens to be
# running it (GitHub Actions runner images ship a huge amount of
# preinstalled toolchain on a single filesystem -- a real find / or
# getcap -r / there can legitimately take far longer than on a small dev
# box, and no fixed SLOW_TIMEOUT_SECS budget can be trusted not to flake
# again on some future runner image). That's fundamentally different from
# "slow local work" bounded by a generous timeout -- it depends on
# environment scale/network reachability this harness has no business
# requiring, and it's exactly the kind of real attack/enumeration logic
# the smoke test's own header says it does NOT execute. Every script
# below already supports GS_DRY_RUN as a first-class fast-path that exits
# before doing any of that real work, so the no-args check exercises that
# instead -- a fix that holds regardless of what machine CI happens to
# run on next.
DRY_RUN_FOR_NOARGS=(
    "00-Framework-Core/tool_verification.sh"
    "01-Network-Security/system_config_audit.sh"
    "08-System-Security/cis_linux_manual_checks.sh"
    "08-System-Security/cis_windows_checks.sh"
    "08-System-Security/system_config_audit.sh"
    "09-Container-Security/container_security_scanner.sh"
    "11-Cloud-Security/aws_security_scanner.sh"
    "11-Cloud-Security/azure_security_audit.sh"
    "11-Cloud-Security/gcp_security_audit.sh"
    "13-Post-Exploitation/privilege_escalation_checker.sh"
    "13-Post-Exploitation/privilege_escalation_linux.sh"
    "13-Post-Exploitation/privilege_escalation_windows.sh"
)

_gs_in_list() {
    local needle="$1"; shift
    local item
    for item in "$@"; do
        [ "${item}" = "${needle}" ] && return 0
    done
    return 1
}

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
    -not -name "vulnerable_services_setup.sh" \
    | sort)
# vulnerable_services_setup.sh is bind-mounted as a Docker container's own
# entrypoint (see docker-compose.yml) -- it's provisioning infrastructure
# with no argument interface at all, not a standalone interactive module.
# Running it here would mean actually performing apt-get installs and
# service reconfiguration during every CI run.

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
    this_timeout="${TIMEOUT_SECS}"
    _gs_in_list "${rel}" "${SLOW_LOCAL_AUDIT[@]}" && this_timeout="${SLOW_TIMEOUT_SECS}"

    noargs_out=""
    noargs_rc=0
    if _gs_in_list "${rel}" "${DRY_RUN_FOR_NOARGS[@]}"; then
        noargs_out=$(GS_DRY_RUN=true timeout "${this_timeout}" bash "${script}" </dev/null 2>&1)
    else
        noargs_out=$(timeout "${this_timeout}" bash "${script}" </dev/null 2>&1)
    fi
    noargs_rc=$?

    noargs_result="PASS"
    if echo "${noargs_out}" | grep -qi "unbound variable"; then
        noargs_result="FAIL (unbound variable — set -u fired before validation)"
        noargs_fail=$((noargs_fail + 1))
        echo -e "${RED}[NOARGS FAIL]${NC} ${rel} -- unbound variable crash"
    elif [ "${noargs_rc}" -eq 0 ]; then
        if _gs_in_list "${rel}" "${NO_TARGET_REQUIRED[@]}"; then
            noargs_result="PASS (no target required by design)"
        else
            noargs_result="FAIL (exited 0 with no target — should require one)"
            noargs_fail=$((noargs_fail + 1))
            echo -e "${YELLOW}[NOARGS FAIL]${NC} ${rel} -- exited 0 with no arguments"
        fi
    elif [ "${noargs_rc}" -eq 124 ]; then
        noargs_result="FAIL (timed out after ${this_timeout}s — did it start real work with no target?)"
        noargs_fail=$((noargs_fail + 1))
        echo -e "${RED}[NOARGS FAIL]${NC} ${rel} -- timed out (${this_timeout}s)"
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
