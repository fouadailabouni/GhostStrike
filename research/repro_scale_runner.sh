#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# GhostStrike research/ -- Phase 1 experiment 2 driver
# Reproducibility at scale: 5 repeated runs of each of the 10
# scenarios in research/scenarios.json (50 real sessions total)
# against the live lab containers, via the real
# bash_scripts_for_pentest/repro_runner.sh wrapper (real
# gs_repro_start/_end scoring, real gs_policy_gate).
#
# Writes session JSON to research/results/repro_scale_sessions/
# (a dedicated directory, NOT the shared
# bash_scripts_for_pentest/metrics/repro_sessions/ used by other,
# unrelated testing) so parsing this experiment's 50 sessions is
# unambiguous.
#
# Module choice per scenario category:
#   web     -> 02-Web-Application-Security/http_security_headers.sh -t <url>
#   network -> 01-Network-Security/nmap_automation.sh -t <host> -p <port>
#              --scan connect -sV --timing 4
# Both call gs_policy_gate internally (confirmed by grep before writing
# this script). GS_ENVIRONMENT=lab relaxes auth/scope per policy_engine.sh
# (this is the existing lab evaluation network, not a real engagement).
#
# © 2026 Fouad Ailabouni. All rights reserved.
# ═══════════════════════════════════════════════════════════════
set -uo pipefail

BASE="/opt/ghoststrike/bash_scripts_for_pentest"
RESEARCH_DIR="/opt/ghoststrike/research"
SESSIONS_DIR="${RESEARCH_DIR}/results/repro_scale_sessions"
SCENARIOS_JSON="${RESEARCH_DIR}/scenarios.json"
# REP_START/REP_END let this be re-invoked to ADD more repetitions without
# redoing earlier ones (session files are uniquely named by timestamp+random
# hex, not by rep number, so there is no overwrite risk either way -- this
# is purely to avoid wasting time re-running reps already collected).
REP_START="${REP_START:-1}"
REP_END="${REP_END:-5}"
CATEGORY_FILTER="${CATEGORY_FILTER:-}"

mkdir -p "${SESSIONS_DIR}"
export GS_ENVIRONMENT=lab

TSV="$(mktemp)"
python3 - "${SCENARIOS_JSON}" > "${TSV}" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for s in d["scenarios"]:
    print(f'{s["id"]}\t{s["category"]}\t{s["target"]}\t{s["port"]}')
PY

total=0
while IFS=$'\t' read -r id category target port; do
    [[ -z "${id}" ]] && continue
    if [[ -n "${CATEGORY_FILTER}" && "${category}" != "${CATEGORY_FILTER}" ]]; then
        continue
    fi
    for rep in $(seq "${REP_START}" "${REP_END}"); do
        eng_id="phase1-repro-${id}-rep${rep}"
        export GS_ENGAGEMENT_ID="${eng_id}"
        export TARGET="${target}"
        export PORT="${port}"

        if [[ "${category}" == "web" ]]; then
            module="${BASE}/02-Web-Application-Security/http_security_headers.sh"
            args=(-t "http://${target}:${port}")
        else
            module="${BASE}/01-Network-Security/nmap_automation.sh"
            args=(-t "${target}" -p "${port}" --scan connect -sV --timing 4)
        fi

        total=$((total + 1))
        echo ""
        echo "### [$(date -u +%H:%M:%S)] run ${total} (reps ${REP_START}-${REP_END}) -- ${eng_id} :: ${module##*/} ${args[*]}"
        "${BASE}/repro_runner.sh" --sessions-dir "${SESSIONS_DIR}" "${module}" "${args[@]}" \
            > "${SESSIONS_DIR}/${eng_id}_runner_stdout.log" 2>&1
        rc=$?
        echo "### exit_code=${rc}"
    done
done < "${TSV}"

rm -f "${TSV}"
echo ""
echo "DONE: ${total} sessions attempted -> ${SESSIONS_DIR}"