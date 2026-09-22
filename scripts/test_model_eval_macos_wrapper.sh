#!/usr/bin/env bash
# Exercises the macOS Keychain wrapper with command fixtures; no provider,
# Keychain item, Cargo build, or evaluator implementation is invoked.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
wrapper="$repo_root/scripts/run-model-eval-macos.sh"
fixture_dir="$repo_root/scripts/test-fixtures/model-eval-macos-wrapper"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-model-eval-wrapper.XXXXXX")

cleanup() {
    rm -rf -- "$test_dir"
}
trap cleanup EXIT INT TERM

test_repo="$test_dir/repo"
mkdir -p "$test_repo/scripts"
test_repo=$(CDPATH= cd -- "$test_repo" && pwd)
ln -s "$wrapper" "$test_repo/scripts/run-model-eval-macos.sh"
target_dir="$test_repo/target"
mkdir -p "$target_dir/debug"
ln -s "$fixture_dir/xshield-model-eval" "$target_dir/debug/xshield-model-eval"
input="$test_dir/approved-input.json"
printf '%s\n' '{}' >"$input"

run_wrapper() {
    env -i \
        PATH="$fixture_dir:/usr/bin:/bin" \
        HOME="${HOME:-/tmp}" \
        XSHIELD_WRAPPER_EXPECTED_REPO="$test_repo" \
        "$@" \
        "$test_repo/scripts/run-model-eval-macos.sh" --approved-input "$input"
}

success=$(run_wrapper)
[[ "$success" == '{"fixture":"model-eval-wrapper"}' ]]

assert_failure() {
    local expected=$1
    shift
    local output
    if output=$(run_wrapper "$@" 2>&1); then
        printf '%s\n' 'wrapper unexpectedly succeeded' >&2
        exit 1
    fi
    [[ "$output" == "$expected" ]]
}

assert_failure 'MODEL_WRAPPER_ROUTE_INVALID' XSHIELD_JEV_ROUTE=direct
assert_failure 'MODEL_WRAPPER_ROUTE_INVALID' XSHIELD_JEV_ROUTE=''
assert_failure 'MODEL_WRAPPER_GATEWAY_KEY_PRESET' AI_GATEWAY_API_KEY='synthetic-preset-key'
assert_failure 'MODEL_WRAPPER_DIRECT_KEY_PRESET' XSHIELD_JEV_API_KEY='synthetic-direct-key'
assert_failure 'MODEL_WRAPPER_TARGET_PRESET' CARGO_TARGET_DIR="$test_dir/other-target"
assert_failure 'MODEL_WRAPPER_BUILD_FAILED' XSHIELD_WRAPPER_CARGO_CASE=unavailable
assert_failure 'MODEL_WRAPPER_KEYCHAIN_EMPTY' XSHIELD_WRAPPER_KEYCHAIN_CASE=empty
assert_failure 'MODEL_WRAPPER_KEYCHAIN_KEY_INVALID' XSHIELD_WRAPPER_KEYCHAIN_CASE=invalid
assert_failure 'MODEL_WRAPPER_KEYCHAIN_UNAVAILABLE' XSHIELD_WRAPPER_KEYCHAIN_CASE=unavailable

if output=$(env -i PATH="$fixture_dir:/usr/bin:/bin" HOME="${HOME:-/tmp}" \
    "$test_repo/scripts/run-model-eval-macos.sh" unexpected 2>&1); then
    printf '%s\n' 'wrapper accepted invalid arguments' >&2
    exit 1
fi
[[ "$output" == 'MODEL_WRAPPER_ARGUMENTS_INVALID' ]]

printf '%s\n' 'model evaluation macOS wrapper tests passed'
