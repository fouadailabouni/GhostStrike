#!/bin/bash
# © 2026 Fouad Ailabouni. All Rights Reserved.
# GhostStrike — Framework Test Suite
# Tests the bash framework libraries (common.sh, evidence.sh,
# finding_ontology.sh, trust_registry.sh, policy, reproducibility).
#
# Usage:
#   bash tests/test_framework.sh
#   make test

set -euo pipefail
IFS=$'\n\t'

FRAMEWORK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/bash_scripts_for_pentest"
PASS=0
FAIL=0
ERRORS=()
TEST_TMP_DIR=""

# ── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ── Test runner helpers ───────────────────────────────────────

_pass() { echo -e "${GREEN}  PASS${NC}  $1"; (( PASS++ )); }
_fail() { echo -e "${RED}  FAIL${NC}  $1: $2"; (( FAIL++ )); ERRORS+=("$1: $2"); }
_skip() { echo -e "${YELLOW}  SKIP${NC}  $1: $2"; }

_run_test() {
    local name="$1"
    shift
    if "$@" 2>/dev/null; then
        _pass "${name}"
    else
        _fail "${name}" "returned non-zero"
    fi
}

setup() {
    TEST_TMP_DIR=$(mktemp -d)
    export GS_OUTPUT_DIR="${TEST_TMP_DIR}"
    export GS_DRY_RUN="false"
}

teardown() {
    [[ -n "${TEST_TMP_DIR:-}" ]] && rm -rf "${TEST_TMP_DIR}"
    # Clean up any test evidence/findings created
    rm -rf "${FRAMEWORK_DIR}/evidence" 2>/dev/null || true
    rm -rf "${FRAMEWORK_DIR}/findings" 2>/dev/null || true
    rm -rf "${FRAMEWORK_DIR}/metrics/repro_sessions/test_module_"* 2>/dev/null || true
}

# ── Tests ─────────────────────────────────────────────────────

test_common_sh_loads() {
    local name="common.sh loads and exposes gs_info"
    if source "${FRAMEWORK_DIR}/lib/common.sh" 2>/dev/null && \
       declare -f gs_info &>/dev/null; then
        _pass "${name}"
    else
        _fail "${name}" "gs_info function not found after sourcing"
    fi
}

test_evidence_init() {
    local name="gs_evidence_init creates evidence directory and manifest"
    source "${FRAMEWORK_DIR}/lib/common.sh" 2>/dev/null || true
    source "${FRAMEWORK_DIR}/lib/evidence.sh" 2>/dev/null || {
        _fail "${name}" "evidence.sh failed to source"; return
    }
    cd "${FRAMEWORK_DIR}"
    gs_evidence_init "TEST-001" 2>/dev/null || { _fail "${name}" "gs_evidence_init returned error"; return; }
    if [[ -d "${FRAMEWORK_DIR}/evidence" ]] && [[ -f "${FRAMEWORK_DIR}/evidence/manifest.json" ]]; then
        _pass "${name}"
    else
        _fail "${name}" "evidence/ or manifest.json not created"
    fi
}

test_finding_new() {
    local name="gs_finding_new creates UUID-keyed finding JSON"
    source "${FRAMEWORK_DIR}/lib/common.sh" 2>/dev/null || true
    source "${FRAMEWORK_DIR}/lib/evidence.sh" 2>/dev/null || true
    source "${FRAMEWORK_DIR}/lib/finding_ontology.sh" 2>/dev/null || {
        _fail "${name}" "finding_ontology.sh failed to source"; return
    }
    cd "${FRAMEWORK_DIR}"
    local fid
    fid=$(gs_finding_new "Test SQL Injection Finding" "HIGH" "Test description for framework test" 2>/dev/null) || {
        _fail "${name}" "gs_finding_new returned error"; return
    }
    if [[ -n "${fid}" ]] && [[ -f "${FRAMEWORK_DIR}/findings/${fid}.json" ]]; then
        _pass "${name}"
    else
        _fail "${name}" "finding file not created at findings/${fid}.json"
    fi
}

test_finding_validates_schema() {
    local name="created finding validates against JSON schema"
    if ! command -v python3 &>/dev/null; then
        _skip "${name}" "python3 not available"; return
    fi
    if ! python3 -c "import jsonschema" 2>/dev/null; then
        _skip "${name}" "jsonschema not installed (pip install jsonschema)"; return
    fi
    local schema="${FRAMEWORK_DIR}/schemas/finding.schema.json"
    local findings_dir="${FRAMEWORK_DIR}/findings"
    if [[ ! -d "${findings_dir}" ]]; then
        _skip "${name}" "no findings directory (run test_finding_new first)"; return
    fi
    local f
    f=$(find "${findings_dir}" -name "*.json" -not -name "findings.json" | head -1)
    if [[ -z "${f}" ]]; then
        _skip "${name}" "no finding files to validate"; return
    fi
    if python3 -c "
import json, jsonschema
schema = json.load(open('${schema}'))
finding = json.load(open('${f}'))
try:
    jsonschema.validate(finding, schema)
    print('valid')
except jsonschema.ValidationError as e:
    print('invalid:', e.message)
    exit(1)
" 2>/dev/null; then
        _pass "${name}"
    else
        _fail "${name}" "finding JSON failed schema validation"
    fi
}

test_trust_get() {
    local name="gs_trust_get returns VALIDATION for nmap_automation.sh"
    source "${FRAMEWORK_DIR}/lib/trust_registry.sh" 2>/dev/null || {
        _fail "${name}" "trust_registry.sh failed to source"; return
    }
    local level
    level=$(gs_trust_get "nmap_automation.sh" 2>/dev/null) || {
        _fail "${name}" "gs_trust_get returned error"; return
    }
    if [[ "${level}" == "VALIDATION" ]]; then
        _pass "${name}"
    else
        _fail "${name}" "expected VALIDATION, got '${level}'"
    fi
}

test_trust_lab_only() {
    local name="gs_trust_get returns LAB_ONLY for metasploit_automation.sh"
    source "${FRAMEWORK_DIR}/lib/trust_registry.sh" 2>/dev/null || true
    local level
    level=$(gs_trust_get "metasploit_automation.sh" 2>/dev/null) || {
        _fail "${name}" "gs_trust_get returned error"; return
    }
    if [[ "${level}" == "LAB_ONLY" ]]; then
        _pass "${name}"
    else
        _fail "${name}" "expected LAB_ONLY, got '${level}'"
    fi
}

test_policy_yaml_parseable() {
    local name="policy.yaml is valid YAML"
    if ! command -v python3 &>/dev/null; then
        _skip "${name}" "python3 not available"; return
    fi
    if python3 -c "
import yaml, sys
try:
    yaml.safe_load(open('${FRAMEWORK_DIR}/policy.yaml'))
    print('ok')
except Exception as e:
    print('error:', e); sys.exit(1)
" 2>/dev/null; then
        _pass "${name}"
    else
        _fail "${name}" "policy.yaml failed YAML parse"
    fi
}

test_scope_template_parseable() {
    local name="scope.yml.template is valid YAML"
    if ! command -v python3 &>/dev/null; then
        _skip "${name}" "python3 not available"; return
    fi
    if python3 -c "
import yaml, sys
try:
    yaml.safe_load(open('${FRAMEWORK_DIR}/scope.yml.template'))
    print('ok')
except Exception as e:
    print('error:', e); sys.exit(1)
" 2>/dev/null; then
        _pass "${name}"
    else
        _fail "${name}" "scope.yml.template failed YAML parse"
    fi
}

test_repro_start_end() {
    local name="gs_repro_start + gs_repro_end creates session JSON"
    source "${FRAMEWORK_DIR}/lib/common.sh" 2>/dev/null || true
    source "${FRAMEWORK_DIR}/lib/reproducibility.sh" 2>/dev/null || {
        _fail "${name}" "reproducibility.sh failed to source"; return
    }
    cd "${FRAMEWORK_DIR}"
    gs_repro_start "test_module" 2>/dev/null || { _fail "${name}" "gs_repro_start failed"; return; }
    gs_repro_end 0 2>/dev/null || { _fail "${name}" "gs_repro_end failed"; return; }
    local session_files
    session_files=$(find "${FRAMEWORK_DIR}/metrics/repro_sessions" -name "test_module_*.json" 2>/dev/null | wc -l)
    if [[ "${session_files}" -ge 1 ]]; then
        _pass "${name}"
    else
        _fail "${name}" "no session JSON found in metrics/repro_sessions/"
    fi
}

test_all_scripts_bash_n() {
    local name="All scripts pass bash -n (0 syntax errors)"
    local failed=0 passed=0
    while IFS= read -r -d '' f; do
        if bash -n "$f" 2>/dev/null; then
            (( passed++ ))
        else
            echo -e "${RED}    SYNTAX ERROR${NC}: $f" >&2
            (( failed++ ))
        fi
    done < <(find "${FRAMEWORK_DIR}" -name "*.sh" -print0)
    local total=$(( passed + failed ))
    if [[ "${failed}" -eq 0 ]]; then
        _pass "${name} (${passed}/${total})"
    else
        _fail "${name}" "${failed}/${total} scripts have syntax errors"
    fi
}

test_shellcheckrc_exists() {
    local name=".shellcheckrc exists and is non-empty"
    local rcfile="${FRAMEWORK_DIR}/.shellcheckrc"
    if [[ -f "${rcfile}" ]] && [[ -s "${rcfile}" ]]; then
        _pass "${name}"
    else
        _fail "${name}" ".shellcheckrc not found or empty at ${rcfile}"
    fi
}

# ── Main ──────────────────────────────────────────────────────

main() {
    echo -e "\n${PURPLE}  ╔══════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}  ║  GhostStrike Framework Test Suite    ║${NC}"
    echo -e "${PURPLE}  ╚══════════════════════════════════════╝${NC}\n"

    setup

    test_common_sh_loads
    test_evidence_init
    test_finding_new
    test_finding_validates_schema
    test_trust_get
    test_trust_lab_only
    test_policy_yaml_parseable
    test_scope_template_parseable
    test_repro_start_end
    test_all_scripts_bash_n
    test_shellcheckrc_exists

    teardown

    local total=$(( PASS + FAIL ))
    echo ""
    echo -e "  ${CYAN}─────────────────────────────────────────${NC}"
    if [[ "${FAIL}" -eq 0 ]]; then
        echo -e "  ${GREEN}✓ ${PASS}/${total} tests passed${NC}"
    else
        echo -e "  ${RED}✗ ${FAIL}/${total} tests failed${NC}  (${PASS} passed)"
        echo ""
        echo -e "  ${RED}Failures:${NC}"
        for err in "${ERRORS[@]}"; do
            echo -e "    ${RED}•${NC} ${err}"
        done
        echo ""
        exit 1
    fi
    echo -e "  ${CYAN}─────────────────────────────────────────${NC}\n"
}

main "$@"
