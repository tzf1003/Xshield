#!/usr/bin/env bash
# Run one approved model evaluation with the local macOS Gateway credential.
#
# The build completes before this script reads Keychain. This keeps the Gateway
# key out of Cargo, compiler, and build-script environments; after retrieval it
# is exported only to the fixed evaluator process which immediately replaces
# this shell. The evaluator remains responsible for all approval, evidence,
# admission, and provider controls.
set -euo pipefail

readonly gateway_service='Xshield.Jev.VercelAIGateway'
readonly gateway_account='Xshield'
readonly evaluator_bin='xshield-model-eval'

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

if [[ "$#" -ne 2 || "$1" != '--approved-input' || -z "$2" ]]; then
    fail 'MODEL_WRAPPER_ARGUMENTS_INVALID'
fi

# An explicitly selected non-Gateway route must use its own approved launch
# path. This wrapper never combines direct-route configuration with the
# Gateway credential it obtains below.
if [[ ${XSHIELD_JEV_ROUTE+x} == x && "$XSHIELD_JEV_ROUTE" != 'gateway' ]]; then
    fail 'MODEL_WRAPPER_ROUTE_INVALID'
fi
if [[ ${AI_GATEWAY_API_KEY+x} == x ]]; then
    fail 'MODEL_WRAPPER_GATEWAY_KEY_PRESET'
fi
if [[ ${XSHIELD_JEV_API_KEY+x} == x ]]; then
    fail 'MODEL_WRAPPER_DIRECT_KEY_PRESET'
fi
if [[ ${CARGO_TARGET_DIR+x} == x ]]; then
    fail 'MODEL_WRAPPER_TARGET_PRESET'
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_dir="$repo_root/target"
cd "$repo_root"

# Do not inject the Gateway key until Cargo has finished. Cargo therefore
# cannot expose the credential through a compiler, build script, or diagnostic.
if ! CARGO_TARGET_DIR="$target_dir" cargo build --locked -p xshield-worker --bin "$evaluator_bin"; then
    fail 'MODEL_WRAPPER_BUILD_FAILED'
fi

binary="$target_dir/debug/$evaluator_bin"
if [[ ! -x "$binary" ]]; then
    fail 'MODEL_WRAPPER_BINARY_UNAVAILABLE'
fi

# `-w` writes only to this command substitution. Its diagnostics are discarded
# so a Keychain error cannot carry secret material to the operator's terminal.
if ! gateway_key=$(security find-generic-password \
    -s "$gateway_service" -a "$gateway_account" -w 2>/dev/null); then
    fail 'MODEL_WRAPPER_KEYCHAIN_UNAVAILABLE'
fi
if [[ -z "$gateway_key" ]]; then
    fail 'MODEL_WRAPPER_KEYCHAIN_EMPTY'
fi

# Keep the wrapper's acceptance boundary aligned with JevClient::validate_key.
# Printable ASCII avoids whitespace/control parsing ambiguity in HTTP headers.
if (( ${#gateway_key} < 16 || ${#gateway_key} > 512 )) || [[ ! "$gateway_key" =~ ^[!-~]+$ ]]; then
    unset gateway_key
    fail 'MODEL_WRAPPER_KEYCHAIN_KEY_INVALID'
fi

# Prefix assignment to `env` would put the key in argv. Exporting immediately
# before `exec` gives it only to the evaluator's environment; no Cargo process
# runs after this point. Direct-route credentials remain absent from the child.
export AI_GATEWAY_API_KEY="$gateway_key"
unset gateway_key
export XSHIELD_JEV_ROUTE='gateway'
unset XSHIELD_JEV_API_KEY
if ! exec "$binary" "$@"; then
    unset AI_GATEWAY_API_KEY
    fail 'MODEL_WRAPPER_EXEC_UNAVAILABLE'
fi
