#!/bin/bash

# Test helper functions for penetration testing scripts

# Setup function called before each test
setup() {
    # Create temporary directory for test files
    export TEST_TEMP_DIR="$(mktemp -d)"
    export BATS_TEST_DIRNAME="$(dirname "${BATS_TEST_FILENAME}")"
    export FRAMEWORK_DIR="${BATS_TEST_DIRNAME}/../00-Framework-Core"
}

# Teardown function called after each test
teardown() {
    # Clean up temporary files
    if [[ -n "${TEST_TEMP_DIR:-}" && -d "${TEST_TEMP_DIR}" ]]; then
        rm -rf "${TEST_TEMP_DIR}"
    fi
}

# Helper function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Helper function to check script syntax
check_script_syntax() {
    local script="$1"
    bash -n "${script}"
}

# Helper function to run script with timeout
run_with_timeout() {
    local timeout="$1"
    local script="$2"
    shift 2
    timeout "${timeout}" "${script}" "$@"
}

# Helper function to create mock target
create_mock_target() {
    local target_file="${TEST_TEMP_DIR}/mock_target"
    echo "127.0.0.1" > "${target_file}"
    echo "${target_file}"
}

# Helper function to validate JSON output
validate_json() {
    local json_file="$1"
    jq . "${json_file}" >/dev/null 2>&1
}

# Helper function to check for sensitive data leaks
check_for_secrets() {
    local file="$1"
    local patterns=(
        "password"
        "passwd"
        "secret"
        "key"
        "token"
        "api_key"
        "private"
    )

    for pattern in "${patterns[@]}"; do
        if grep -qi "${pattern}" "${file}"; then
            echo "Potential secret found: ${pattern}"
            return 1
        fi
    done
    return 0
}
