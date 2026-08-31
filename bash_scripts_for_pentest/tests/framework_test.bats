#!/usr/bin/env bats

load test_helper

@test "authorization framework loads without errors" {
    run source "${FRAMEWORK_DIR}/authorization_framework.sh"
    [ "$status" -eq 0 ]
}

@test "json output framework loads without errors" {
    run source "${FRAMEWORK_DIR}/json_output_framework.sh"
    [ "$status" -eq 0 ]
}

@test "mitre attack framework loads without errors" {
    run source "${FRAMEWORK_DIR}/mitre_attack_framework.sh"
    [ "$status" -eq 0 ]
}

@test "all framework scripts have proper syntax" {
    for script in "${FRAMEWORK_DIR}"/*.sh; do
        run check_script_syntax "${script}"
        [ "$status" -eq 0 ]
    done
}

@test "all scripts contain authorization disclaimer" {
    for script in "${FRAMEWORK_DIR}"/*.sh; do
        run grep -q "AUTHORIZATION DISCLAIMER" "${script}"
        [ "$status" -eq 0 ]
    done
}
