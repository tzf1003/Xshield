#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
console_dir="$repo_root/web/console"
console_port=${XSHIELD_CONSOLE_PORT:-5173}
control_proxy=${XSHIELD_CONTROL_PROXY:-http://127.0.0.1:9443}
start_control=0

usage() {
    cat <<'EOF'
Usage: ./dev.sh [--console-only|--with-control]

Start the local Xshield development environment.

By default only the Vite console is started. It proxies /control/v1 to
http://127.0.0.1:9443, or to XSHIELD_CONTROL_PROXY when set.

Options:
  --console-only  Start only the console (default).
  --with-control  Also start xshield-control. All control-service environment
                  variables and its PostgreSQL, ClickHouse, and OIDC services
                  must already be configured; this script never creates or
                  stores credentials.
  -h, --help      Show this help.

Development-only overrides:
  XSHIELD_CONSOLE_PORT                 Vite port (default: 5173)
  XSHIELD_CONTROL_PROXY                Control origin for the Vite proxy
  XSHIELD_DEV_START_CONTROL=1          Same as --with-control
  XSHIELD_DEV_ROOT                     Runtime directory (default: target/xshield-dev)
  XSHIELD_DEV_JOURNAL_DIRECTORY        Control journal directory
  XSHIELD_DEV_MANIFEST_DIRECTORY       Control manifest directory
  XSHIELD_DEV_CHECKPOINT_DIRECTORY     Control checkpoint directory
  XSHIELD_DEV_CONTROL_AUDIT_DIRECTORY  Control audit directory
EOF
}

die() {
    printf 'dev.sh: %s\n' "$*" >&2
    exit 1
}

case "${XSHIELD_DEV_START_CONTROL:-0}" in
    0) ;;
    1) start_control=1 ;;
    *) die "XSHIELD_DEV_START_CONTROL must be 0 or 1" ;;
esac

while (($# > 0)); do
    case "$1" in
        --console-only)
            start_control=0
            ;;
        --with-control)
            start_control=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option: $1"
            ;;
    esac
    shift
done

command -v node >/dev/null 2>&1 || die "node is required (web/console requires Node.js 22.12+ or 24+)"
command -v npm >/dev/null 2>&1 || die "npm is required"
node_version=$(node -p 'process.versions.node')
IFS=. read -r node_major node_minor _node_patch <<<"$node_version"
if ((node_major < 22 || node_major == 23 || (node_major == 22 && node_minor < 12))); then
    die "Node.js $node_version is unsupported; use 22.12+ or 24+"
fi
[[ -x "$console_dir/node_modules/.bin/vite" ]] ||
    die "web/console dependencies are missing; run: (cd web/console && npm ci)"
[[ "$console_port" =~ ^[0-9]+$ ]] && ((console_port >= 1 && console_port <= 65535)) ||
    die "XSHIELD_CONSOLE_PORT must be an integer from 1 to 65535"

dev_root=${XSHIELD_DEV_ROOT:-"$repo_root/target/xshield-dev"}
journal_directory=${XSHIELD_DEV_JOURNAL_DIRECTORY:-"$dev_root/journal"}
manifest_directory=${XSHIELD_DEV_MANIFEST_DIRECTORY:-"$dev_root/manifests"}
checkpoint_directory=${XSHIELD_DEV_CHECKPOINT_DIRECTORY:-"$dev_root/checkpoints"}
control_audit_directory=${XSHIELD_DEV_CONTROL_AUDIT_DIRECTORY:-"$dev_root/control-audit"}

if ((start_control)); then
    command -v cargo >/dev/null 2>&1 || die "cargo is required for --with-control"

    required_control_env=(
        XSHIELD_TENANT_ID XSHIELD_SITE_ID XSHIELD_CONTROL_SUBJECT XSHIELD_CONTROL_ROLES
        XSHIELD_CONTROL_OIDC_ISSUER XSHIELD_CONTROL_OIDC_CLIENT_ID
        XSHIELD_CONTROL_OIDC_CLIENT_SECRET XSHIELD_CONTROL_CONSOLE_ORIGIN
        XSHIELD_CONTROL_OIDC_REQUIRED_ACR XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON
        XSHIELD_CONTROL_TOKEN XSHIELD_CONTROL_CURSOR_KEY_HEX
        XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX XSHIELD_JOURNAL_KEY_ID
        XSHIELD_JOURNAL_KEY_HEX XSHIELD_SEAL_KEY_ID XSHIELD_SEAL_PUBLIC_KEY_HEX
        XSHIELD_CONTROL_AUDIT_KEY_ID XSHIELD_CONTROL_AUDIT_KEY_HEX
        XSHIELD_INDEX_TARGET_ID XSHIELD_CLICKHOUSE_URL XSHIELD_CLICKHOUSE_DATABASE
        XSHIELD_CLICKHOUSE_USER XSHIELD_CLICKHOUSE_PASSWORD XSHIELD_DATABASE_URL
        XSHIELD_CONTROL_DATABASE_MAX_CONNECTIONS XSHIELD_CONTROL_DATABASE_ACQUIRE_TIMEOUT_MS
        XSHIELD_AUDIT_METADATA_RETENTION_DAYS XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES
        XSHIELD_CONTROL_TOKEN_ISSUED_AT XSHIELD_CONTROL_TOKEN_EXPIRES_AT
        XSHIELD_CONTROL_REQUESTS_PER_MINUTE XSHIELD_CONTROL_MAX_QUERY_EVENTS
        XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS XSHIELD_CONTROL_MAX_OPEN_CASES
        XSHIELD_CONTROL_MAX_PENDING_EVIDENCE_ACCESS_REQUESTS
        XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS XSHIELD_EVIDENCE_ROOT
        XSHIELD_EVIDENCE_KEY_ID XSHIELD_EVIDENCE_KEY_HEX
        XSHIELD_EVIDENCE_MAX_ARTIFACT_BYTES XSHIELD_EVIDENCE_MAX_RETENTION_DAYS
        XSHIELD_CONTROL_AUDIT_MAX_BYTES XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES
        XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES
    )
    missing_control_env=()
    for variable in "${required_control_env[@]}"; do
        [[ -n "${!variable:-}" ]] || missing_control_env+=("$variable")
    done
    if ((${#missing_control_env[@]} > 0)); then
        printf 'dev.sh: --with-control requires these environment variables:\n' >&2
        printf '  %s\n' "${missing_control_env[@]}" >&2
        exit 1
    fi

    install -d -m 0700 \
        "$journal_directory" \
        "$manifest_directory" \
        "$checkpoint_directory" \
        "$control_audit_directory"
fi

pids=()
cleanup() {
    local status=$?
    trap - EXIT INT TERM
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ((start_control)); then
    printf 'Starting xshield-control (proxy target: %s)\n' "$control_proxy"
    (
        cd "$repo_root"
        exec cargo run -p xshield-control -- \
            "$journal_directory" \
            "$manifest_directory" \
            "$checkpoint_directory" \
            "$control_audit_directory"
    ) &
    pids+=("$!")
fi

printf 'Starting console at http://127.0.0.1:%s (proxy: %s)\n' "$console_port" "$control_proxy"
(
    cd "$console_dir"
    export XSHIELD_CONTROL_PROXY="$control_proxy"
    exec npm run dev -- --host 127.0.0.1 --port "$console_port"
) &
pids+=("$!")

wait_for_any_child() {
    local pid
    while :; do
        for pid in "${pids[@]}"; do
            if ! kill -0 "$pid" 2>/dev/null; then
                if wait "$pid"; then
                    return 0
                else
                    return $?
                fi
            fi
        done
        sleep 0.2
    done
}

if wait_for_any_child; then
    status=0
else
    status=$?
fi
exit "$status"
