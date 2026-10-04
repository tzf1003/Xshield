#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
console_dir="$repo_root/web/console"
compose_file="$repo_root/docker-compose.dev.yml"
compose_project=${XSHIELD_DEV_COMPOSE_PROJECT:-xshield-dev}
console_port=${XSHIELD_CONSOLE_PORT:-55173}
tls_port=${XSHIELD_DEV_TLS_PORT:-5443}
idor_tls_port=${XSHIELD_DEV_IDOR_TLS_PORT:-5444}
control_proxy=${XSHIELD_CONTROL_PROXY:-http://127.0.0.1:9443}
dev_root=${XSHIELD_DEV_ROOT:-"$repo_root/target/xshield-dev"}
console_only=0
reset_stack=0

usage() {
    cat <<'EOF'
Usage: ./dev.sh [--all|--console-only] [--reset]

Start the local development stack. The default starts:
  - PostgreSQL with every migration under migrations/
  - ClickHouse with sql/clickhouse.sql
  - a local Keycloak OIDC realm
  - xshield-control on 127.0.0.1:9443
  - xshield-gateway with an empty bootstrap snapshot and loopback apply API
  - a local HTTPS terminator at https://juice.local:5443 (self-signed development certificate)
  - the Vite console on http://127.0.0.1:55173

Docker Desktop (or a compatible Docker daemon) is required for the managed
dependencies. The stack uses development-only credentials and data volumes;
they are never used by production configuration.

Options:
  --all            Start the complete local stack (default).
  --console-only  Start only the Vite console.
  --reset          Remove this stack's development volumes before starting.
  -h, --help      Show this help.

Development overrides:
  XSHIELD_CONSOLE_PORT                 Vite port (full stack uses 55173)
  XSHIELD_CONTROL_PROXY                Control origin for the Vite proxy
  XSHIELD_DEV_ROOT                     Runtime directory (default: target/xshield-dev)
  XSHIELD_DEV_COMPOSE_PROJECT         Docker Compose project name
  XSHIELD_DEV_TLS_PORT                Local HTTPS port (default: 5443)
  XSHIELD_DEV_IDOR_TLS_PORT           IDOR lab HTTPS port (default: 5444)
  XSHIELD_DEV_KEEP_DEPS=1              Keep Docker containers after Ctrl-C
  XSHIELD_DEV_AUTO_START_DOCKER=0      Do not open Docker Desktop on macOS
EOF
}

die() {
    printf 'dev.sh: %s\n' "$*" >&2
    exit 1
}

[[ "$compose_project" =~ ^[a-z0-9][a-z0-9_-]*$ ]] ||
    die "XSHIELD_DEV_COMPOSE_PROJECT must contain lowercase letters, digits, _ or -"

while (($# > 0)); do
    case "$1" in
        --all|--with-control)
            console_only=0
            ;;
        --console-only)
            console_only=1
            ;;
        --reset)
            reset_stack=1
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
[[ "$tls_port" =~ ^[0-9]+$ ]] && ((tls_port >= 1 && tls_port <= 65535)) ||
    die "XSHIELD_DEV_TLS_PORT must be an integer from 1 to 65535"
[[ "$idor_tls_port" =~ ^[0-9]+$ ]] && ((idor_tls_port >= 1 && idor_tls_port <= 65535)) ||
    die "XSHIELD_DEV_IDOR_TLS_PORT must be an integer from 1 to 65535"

if ((console_only)); then
    [[ "$reset_stack" == 0 ]] || die "--reset requires the complete local stack"
else
    [[ "$console_port" == 55173 ]] ||
        die "the managed OIDC realm is registered for console port 55173"
    command -v cargo >/dev/null 2>&1 || die "cargo is required for the complete local stack"
    command -v curl >/dev/null 2>&1 || die "curl is required for the local OIDC readiness check"
    command -v openssl >/dev/null 2>&1 || die "openssl is required to create local development keys"
    command -v stunnel >/dev/null 2>&1 || die "stunnel is required for the local HTTPS development entry"
    [[ -f "$compose_file" ]] || die "missing docker-compose.dev.yml"
fi

# Probe before touching managed dependencies. The owner of an occupied port
# remains running; a second dev invocation reports the conflicting endpoint.
check_local_port() {
    node - "$1" <<'NODE'
const net = require('node:net');
const port = Number(process.argv[2]);
const server = net.createServer();
server.once('error', (error) => {
    console.error('dev.sh: cannot listen on 127.0.0.1:' + port + ' (' + error.code + '). Stop the owning development process or choose another console-only port.');
    process.exitCode = 1;
});
server.listen(port, '127.0.0.1', () => server.close());
NODE
}
check_local_port "$console_port"
if (( ! console_only )); then check_local_port 9443; fi
if (( ! console_only )); then check_local_port "$tls_port"; fi
if (( ! console_only )); then check_local_port "$idor_tls_port"; fi

compose_cmd=()
if (( ! console_only )); then
    if docker compose version >/dev/null 2>&1; then
        compose_cmd=(docker compose)
    elif command -v docker-compose >/dev/null 2>&1; then
        compose_cmd=(docker-compose)
    else
        die "Docker Compose is required for the complete local stack"
    fi
fi

compose() {
    (cd "$repo_root" && "${compose_cmd[@]}" -p "$compose_project" -f "$compose_file" "$@")
}

generate_hex() {
    openssl rand -hex 32 | tr -d '\n'
}

write_dev_env() {
    local env_file="$dev_root/control.env"
    local dev_roles='observer,investigator,audit_administrator,sensitive_evidence_reader,sensitive_evidence_approver,policy_author,policy_approver,release_operator,system_admin'
    local dev_oidc_roles='[{"subject":"00000000-0000-7000-8000-000000000001","roles":["observer","investigator","audit_administrator","sensitive_evidence_reader","sensitive_evidence_approver","policy_author","policy_approver","release_operator","system_admin"]}]'
    install -d -m 0700 "$dev_root"
    if [[ ! -f "$env_file" ]]; then
        local journal_key control_audit_key cursor_key idempotency_key seal_key evidence_key token api_key_hash_key edge_apply_key
        journal_key=$(generate_hex)
        control_audit_key=$(generate_hex)
        cursor_key=$(generate_hex)
        idempotency_key=$(generate_hex)
        seal_key=$(generate_hex)
        evidence_key=$(generate_hex)
        token=$(generate_hex)
        api_key_hash_key=$(generate_hex)
        edge_apply_key=$(generate_hex)
        umask 077
        {
            printf 'XSHIELD_DEV_POSTGRES_DB=%q\n' 'xshield'
            printf 'XSHIELD_DEV_POSTGRES_USER=%q\n' 'xshield_dev'
            printf 'XSHIELD_DEV_POSTGRES_PASSWORD=%q\n' 'xshield_dev'
            printf 'XSHIELD_DEV_POSTGRES_PORT=%q\n' '55432'
            printf 'XSHIELD_DEV_CLICKHOUSE_HTTP_PORT=%q\n' '58123'
            printf 'XSHIELD_DEV_CLICKHOUSE_NATIVE_PORT=%q\n' '59000'
            printf 'XSHIELD_CONTROL_OIDC_ISSUER=%q\n' 'http://127.0.0.1:58080/realms/xshield-dev'
            printf 'XSHIELD_CONTROL_OIDC_CLIENT_ID=%q\n' 'xshield-console-dev'
            printf 'XSHIELD_CONTROL_OIDC_CLIENT_SECRET=%q\n' 'xshield-dev-client-secret'
            printf 'XSHIELD_CONTROL_OIDC_REQUIRED_ACR=%q\n' '1'
            printf 'XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON=%q\n' \
                '[{"subject":"00000000-0000-7000-8000-000000000001","roles":["observer","investigator","audit_administrator","sensitive_evidence_reader","sensitive_evidence_approver","system_admin"]}]'
            printf 'XSHIELD_TENANT_ID=%q\n' 'tenant_dev'
            printf 'XSHIELD_SITE_ID=%q\n' 'site_dev'
            printf 'XSHIELD_CONTROL_SUBJECT=%q\n' 'dev-operator'
            printf 'XSHIELD_CONTROL_ROLES=%q\n' 'observer,investigator,audit_administrator,sensitive_evidence_reader,sensitive_evidence_approver,system_admin'
            printf 'XSHIELD_CONTROL_TOKEN=%q\n' "$token"
            printf 'XSHIELD_CONTROL_CURSOR_KEY_HEX=%q\n' "$cursor_key"
            printf 'XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX=%q\n' "$idempotency_key"
            printf 'XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX=%q\n' "$api_key_hash_key"
            printf 'XSHIELD_EDGE_APPLY_KEY_HEX=%q\n' "$edge_apply_key"
            printf 'XSHIELD_EDGE_APPLY_URL=%q\n' 'http://127.0.0.1:9553/internal/v1/apply'
            printf 'XSHIELD_EDGE_SNAPSHOT_PATH=%q\n' "$dev_root/edge-snapshot.json"
            printf 'XSHIELD_JOURNAL_KEY_ID=%q\n' 'dev-journal-key'
            printf 'XSHIELD_JOURNAL_KEY_HEX=%q\n' "$journal_key"
            printf 'XSHIELD_SEAL_KEY_ID=%q\n' 'dev-seal-key'
            printf 'XSHIELD_SEAL_PUBLIC_KEY_HEX=%q\n' "$seal_key"
            printf 'XSHIELD_CONTROL_AUDIT_KEY_ID=%q\n' 'dev-control-audit-key'
            printf 'XSHIELD_CONTROL_AUDIT_KEY_HEX=%q\n' "$control_audit_key"
            printf 'XSHIELD_INDEX_TARGET_ID=%q\n' 'clickhouse-dev'
            printf 'XSHIELD_CLICKHOUSE_URL=%q\n' 'http://127.0.0.1:58123'
            printf 'XSHIELD_CLICKHOUSE_DATABASE=%q\n' 'xshield'
            printf 'XSHIELD_CLICKHOUSE_USER=%q\n' 'xshield'
            printf 'XSHIELD_CLICKHOUSE_PASSWORD=%q\n' 'xshield_dev'
            printf 'XSHIELD_DATABASE_URL=%q\n' 'postgresql://xshield_dev:xshield_dev@127.0.0.1:55432/xshield'
            printf 'XSHIELD_CONTROL_DATABASE_MAX_CONNECTIONS=%q\n' '8'
            printf 'XSHIELD_CONTROL_DATABASE_ACQUIRE_TIMEOUT_MS=%q\n' '2000'
            printf 'XSHIELD_AUDIT_METADATA_RETENTION_DAYS=%q\n' '30'
            printf 'XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES=%q\n' '16777216'
            printf 'XSHIELD_CONTROL_REQUESTS_PER_MINUTE=%q\n' '120'
            printf 'XSHIELD_CONTROL_MAX_QUERY_EVENTS=%q\n' '1000'
            printf 'XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS=%q\n' '128'
            printf 'XSHIELD_CONTROL_MAX_OPEN_CASES=%q\n' '32'
            printf 'XSHIELD_CONTROL_MAX_PENDING_EVIDENCE_ACCESS_REQUESTS=%q\n' '32'
            printf 'XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS=%q\n' '120'
            printf 'XSHIELD_EVIDENCE_ROOT=%q\n' "$dev_root/evidence"
            printf 'XSHIELD_EVIDENCE_KEY_ID=%q\n' 'dev-evidence-key'
            printf 'XSHIELD_EVIDENCE_KEY_HEX=%q\n' "$evidence_key"
            printf 'XSHIELD_EVIDENCE_MAX_ARTIFACT_BYTES=%q\n' '67108864'
            printf 'XSHIELD_EVIDENCE_MAX_RETENTION_DAYS=%q\n' '30'
            printf 'XSHIELD_CONTROL_AUDIT_MAX_BYTES=%q\n' '16777216'
            printf 'XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES=%q\n' '12582912'
            printf 'XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES=%q\n' '4194304'
        } >"$env_file"
    fi
    # Upgrade fixed local role defaults without rotating any generated secret.
    local env_tmp="$env_file.tmp.$$"
    local roles_seen=0
    local oidc_roles_seen=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            XSHIELD_CONTROL_ROLES=*)
                printf 'XSHIELD_CONTROL_ROLES=%q\n' "$dev_roles" >>"$env_tmp"
                roles_seen=1
                ;;
            XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON=*)
                printf 'XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON=%q\n' "$dev_oidc_roles" >>"$env_tmp"
                oidc_roles_seen=1
                ;;
            *) printf '%s\n' "$line" >>"$env_tmp" ;;
        esac
    done <"$env_file"
    ((roles_seen)) || printf 'XSHIELD_CONTROL_ROLES=%q\n' "$dev_roles" >>"$env_tmp"
    ((oidc_roles_seen)) || printf 'XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON=%q\n' "$dev_oidc_roles" >>"$env_tmp"
    chmod 600 "$env_tmp"
    mv "$env_tmp" "$env_file"
    set -a
    # This file is generated with mode 0600 under target/ and contains only
    # local development values; it is not a production configuration source.
    . "$env_file"
    set +a
    if [[ -z "${XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX:-}" ]]; then
        export XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX="$(generate_hex)"
        printf 'XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX=%q\n' "$XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX" >>"$env_file"
    fi
    if [[ -z "${XSHIELD_EDGE_APPLY_KEY_HEX:-}" ]]; then
        export XSHIELD_EDGE_APPLY_KEY_HEX="$(generate_hex)"
        printf 'XSHIELD_EDGE_APPLY_KEY_HEX=%q\n' "$XSHIELD_EDGE_APPLY_KEY_HEX" >>"$env_file"
    fi
    export XSHIELD_EDGE_APPLY_URL="${XSHIELD_EDGE_APPLY_URL:-http://127.0.0.1:9553/internal/v1/apply}"
    export XSHIELD_EDGE_SNAPSHOT_PATH="${XSHIELD_EDGE_SNAPSHOT_PATH:-$dev_root/edge-snapshot.json}"
    export XSHIELD_EDGE_APPLY_LISTEN="${XSHIELD_EDGE_APPLY_LISTEN:-127.0.0.1:9553}"
    export XSHIELD_EDGE_LISTEN_PORTS="${XSHIELD_EDGE_LISTEN_PORTS:-127.0.0.1:6188,127.0.0.1:56188,127.0.0.1:56189}"
    export XSHIELD_EDGE_BOOTSTRAP_ONLY=1
    export XSHIELD_ALLOW_LOOPBACK_UPSTREAM=1
    local bootstrap_config="$dev_root/gateway-bootstrap.json"
    if [[ ! -f "$bootstrap_config" ]]; then
        sed -e "s#target/xshield-dev#${dev_root}#g" "$repo_root/examples/gateway-bootstrap-config.json" >"$bootstrap_config"
        chmod 600 "$bootstrap_config"
    else
        # Gateway audit recovery is event-contract strict. Keep development
        # journals versioned so an older local event schema cannot prevent a
        # newly checked-out gateway from booting. The old directory remains
        # intact for manual inspection and is never used as current state.
        # Gateway audit events are contract-versioned. A development checkout
        # must never reuse an older journal after the event schema changes;
        # retain the old directory for inspection and start from a fresh one.
        local versioned_audit_dir="${dev_root}/gateway-audit-v4-$(date +%s)"
        install -d -m 0700 "$versioned_audit_dir"
        BOOTSTRAP_CONFIG="$bootstrap_config" VERSIONED_AUDIT_DIR="$versioned_audit_dir" \
            python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["BOOTSTRAP_CONFIG"])
document = json.loads(path.read_text())
document["audit"]["directory"] = os.environ["VERSIONED_AUDIT_DIR"]
path.write_text(json.dumps(document, indent=2) + "\n")
PY
    fi
    export XSHIELD_CONFIG="${XSHIELD_CONFIG:-$bootstrap_config}"
    chmod 600 "$env_file"
    export XSHIELD_CONTROL_OIDC_ISSUER='http://127.0.0.1:58080/realms/xshield-dev'
    export XSHIELD_CONTROL_OIDC_CLIENT_ID='xshield-console-dev'
    export XSHIELD_CONTROL_OIDC_CLIENT_SECRET='xshield-dev-client-secret'
    export XSHIELD_CONTROL_OIDC_REQUIRED_ACR='1'
    export XSHIELD_CONTROL_ROLES="$dev_roles"
    export XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON="$dev_oidc_roles"
    export XSHIELD_CONTROL_CONSOLE_ORIGIN="http://127.0.0.1:${console_port}"
    export XSHIELD_CONTROL_LISTEN="127.0.0.1:9443"
    now=$(date +%s)
    export XSHIELD_CONTROL_TOKEN_ISSUED_AT=$((now - 60))
    export XSHIELD_CONTROL_TOKEN_EXPIRES_AT=$((now + 86340))
    export XSHIELD_EVIDENCE_ROOT
    install -d -m 0700 "$XSHIELD_EVIDENCE_ROOT" "$dev_root/journal" "$dev_root/manifests" \
        "$dev_root/checkpoints" "$dev_root/control-audit"
}

ensure_docker() {
    if docker info >/dev/null 2>&1; then
        return
    fi
    if [[ "${XSHIELD_DEV_AUTO_START_DOCKER:-1}" == 0 ]]; then
        die 'Docker daemon is unavailable; start Docker Desktop and retry'
    fi
    if [[ "${XSHIELD_DEV_AUTO_START_DOCKER:-1}" == 1 ]] &&
        [[ "$(uname -s)" == Darwin ]] && command -v open >/dev/null 2>&1 &&
        [[ -d /Applications/Docker.app ]]; then
        printf '%s\n' 'Docker daemon is stopped; opening Docker Desktop...'
        open -a Docker >/dev/null 2>&1 || true
    fi
    for _ in $(seq 1 120); do
        if docker info >/dev/null 2>&1; then
            return
        fi
        sleep 1
    done
    die 'Docker daemon is unavailable; start Docker Desktop and retry'
}

wait_for() {
    local label="$1"
    local service="$2"
    shift 2
    for _ in $(seq 1 120); do
        if "$@"; then
            printf '%s\n' "$label is ready"
            return
        fi
        sleep 1
    done
    compose logs --tail=80 "$service" >&2 || true
    die "$label did not become ready"
}

postgres_ready() {
    compose exec -T postgres pg_isready -U "$XSHIELD_DEV_POSTGRES_USER" \
        -d "$XSHIELD_DEV_POSTGRES_DB" >/dev/null 2>&1
}

clickhouse_ready() {
    compose exec -T clickhouse clickhouse-client --user default \
        --query 'SELECT 1' >/dev/null 2>&1
}

oidc_ready() {
    curl --fail --silent --show-error \
        'http://127.0.0.1:58080/realms/xshield-dev/.well-known/openid-configuration' \
        >/dev/null 2>&1
}

control_ready() {
    local status
    status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --max-time 2 http://127.0.0.1:9443/control/v1/session) || return 1
    [[ "$status" == 401 || "$status" == 403 ]]
}

wait_for_control() {
    for _ in $(seq 1 120); do
        if control_ready; then
            printf '%s\n' 'xshield-control is ready'
            return
        fi
        if [[ -n "${control_pid:-}" ]] && ! kill -0 "$control_pid" 2>/dev/null; then
            die 'xshield-control exited before becoming ready; inspect its output'
        fi
        sleep 1
    done
    die 'xshield-control did not become ready'
}

check_schemas() {
    compose exec -T postgres psql -U "$XSHIELD_DEV_POSTGRES_USER" \
        -d "$XSHIELD_DEV_POSTGRES_DB" -Atqc \
        "SELECT to_regclass('xshield.management_browser_sessions')" | grep -qx 'xshield.management_browser_sessions' ||
        die 'PostgreSQL baseline migrations are incomplete; inspect the migration output before using --reset'
    local required_site_tables=(
        protected_site_configs site_port_leases site_apply_intents protected_sites
        site_origins site_routes site_policy_revisions site_health_snapshots
        site_secret_refs site_snapshot_sequences
    )
    local table
    for table in "${required_site_tables[@]}"; do
        compose exec -T postgres psql -U "$XSHIELD_DEV_POSTGRES_USER" \
            -d "$XSHIELD_DEV_POSTGRES_DB" -Atqc \
            "SELECT to_regclass('xshield.$table')" | grep -qx "xshield.$table" ||
            die "PostgreSQL site schema is incomplete: xshield.$table"
    done
    compose exec -T postgres psql -U "$XSHIELD_DEV_POSTGRES_USER" \
        -d "$XSHIELD_DEV_POSTGRES_DB" -Atqc \
        "SELECT 1 FROM information_schema.columns WHERE table_schema='xshield' AND table_name='protected_site_configs' AND column_name='policy_json'" |
        grep -qx '1' || die 'PostgreSQL site schema is incomplete: protected_site_configs.policy_json'
    compose exec -T postgres psql -U "$XSHIELD_DEV_POSTGRES_USER" \
        -d "$XSHIELD_DEV_POSTGRES_DB" -Atqc \
        "SELECT 1 FROM information_schema.columns WHERE table_schema='xshield' AND table_name='site_apply_intents' AND column_name='approval_id'" |
        grep -qx '1' || die 'PostgreSQL site schema is incomplete: site_apply_intents.approval_id'
    compose exec -T postgres psql -U "$XSHIELD_DEV_POSTGRES_USER" \
        -d "$XSHIELD_DEV_POSTGRES_DB" -Atqc \
        "SELECT 1 FROM information_schema.columns WHERE table_schema='xshield' AND table_name='site_routes' AND column_name='response_config'" |
        grep -qx '1' || die 'PostgreSQL site schema is incomplete: site_routes.response_config'
    compose exec -T postgres psql -U "$XSHIELD_DEV_POSTGRES_USER" \
        -d "$XSHIELD_DEV_POSTGRES_DB" -Atqc \
        "SELECT 1 FROM pg_constraint WHERE conname='site_apply_intents_approval_id_shape'" |
        grep -qx '1' || die 'PostgreSQL site schema is incomplete: approval constraint'
    compose exec -T clickhouse clickhouse-client --user "$XSHIELD_CLICKHOUSE_USER" \
        --password "$XSHIELD_CLICKHOUSE_PASSWORD" \
        --query "SELECT 1 FROM system.tables WHERE database='xshield' AND name='audit_events'" |
        grep -qx '1' || die 'ClickHouse schema is incomplete; retry with --reset'
}

pids=()
control_pid=''
tls_pid=''
stack_started=0

start_dev_tls() {
    local tls_dir="$dev_root/tls"
    local cert="$tls_dir/juice.local.crt"
    local key="$tls_dir/juice.local.key"
    local config="$tls_dir/stunnel.conf"
    "$repo_root/scripts/generate_dev_tls_cert.sh" "$tls_dir" >/dev/null
    cat >"$config" <<EOF
foreground = yes
debug = 0
output = $tls_dir/stunnel.log
pid = $tls_dir/stunnel.pid

[juice-local]
accept = 127.0.0.1:$tls_port
connect = 127.0.0.1:56188
cert = $cert
key = $key
options = NO_SSLv2
options = NO_SSLv3
EOF
    printf 'Starting local HTTPS entry at https://juice.local:%s\n' "$tls_port"
    (exec stunnel "$config") &
    tls_pid=$!
    pids+=("$tls_pid")
    sleep 1
    kill -0 "$tls_pid" 2>/dev/null || die 'local HTTPS terminator exited during startup; inspect target/xshield-dev/tls/stunnel.log'

    local idor_config="$tls_dir/stunnel-idor.conf"
    cat >"$idor_config" <<EOF
foreground = yes
debug = 0
output = $tls_dir/stunnel-idor.log
pid = $tls_dir/stunnel-idor.pid

[idor-local]
accept = 127.0.0.1:$idor_tls_port
connect = 127.0.0.1:56189
cert = $cert
key = $key
options = NO_SSLv2
options = NO_SSLv3
EOF
    printf 'Starting IDOR HTTPS entry at https://idor.local:%s\n' "$idor_tls_port"
    (exec stunnel "$idor_config") &
    local idor_pid=$!
    pids+=("$idor_pid")
    sleep 1
    kill -0 "$idor_pid" 2>/dev/null || die 'IDOR HTTPS terminator exited during startup; inspect target/xshield-dev/tls/stunnel-idor.log'
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if ((${#pids[@]} > 0)); then
        for pid in "${pids[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        for pid in "${pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi
    if ((stack_started)) && [[ "${XSHIELD_DEV_KEEP_DEPS:-0}" != 1 ]]; then
        compose down --remove-orphans >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ((console_only)); then
    :
else
    write_dev_env
    ensure_docker
    if ((reset_stack)); then
        compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    stack_started=1
    compose up -d
    wait_for 'PostgreSQL' postgres postgres_ready
    wait_for 'ClickHouse' clickhouse clickhouse_ready
    wait_for 'local OIDC' oidc oidc_ready
    "$repo_root/scripts/migrate_dev_postgres.sh" "$compose_project" "$compose_file" \
        "$XSHIELD_DEV_POSTGRES_USER" "$XSHIELD_DEV_POSTGRES_DB"
    check_schemas
    printf '%s\n' 'Starting xshield-control on http://127.0.0.1:9443'
    (
        cd "$repo_root"
        exec cargo run -p xshield-control -- \
            "$dev_root/journal" \
            "$dev_root/manifests" \
            "$dev_root/checkpoints" \
            "$dev_root/control-audit"
    ) &
    control_pid=$!
    pids+=("$control_pid")
    wait_for_control
    printf '%s\n' 'Starting xshield-gateway in bootstrap-only mode on the configured loopback listener'
    (
        cd "$repo_root"
        exec cargo run -p xshield-gateway
    ) &
    gateway_pid=$!
    pids+=("$gateway_pid")
    sleep 1
    kill -0 "$gateway_pid" 2>/dev/null || die 'xshield-gateway exited during startup; inspect its output'
    start_dev_tls
fi

printf 'Starting console at http://127.0.0.1:%s (proxy: %s)\n' "$console_port" "$control_proxy"
if (( ! console_only )); then
    printf '%s\n' 'Local OIDC account: developer / xshield-dev-password'
fi
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
