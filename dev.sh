#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
console_dir="$repo_root/web/console"
compose_file="$repo_root/docker-compose.dev.yml"
compose_project=${XSHIELD_DEV_COMPOSE_PROJECT:-xshield-dev}
console_port=${XSHIELD_CONSOLE_PORT:-55173}
tls_port=${XSHIELD_DEV_TLS_PORT:-5443}
idor_tls_port=${XSHIELD_DEV_IDOR_TLS_PORT:-5444}
control_port=9443
control_proxy=${XSHIELD_CONTROL_PROXY:-http://127.0.0.1:$control_port}
dev_root=${XSHIELD_DEV_ROOT:-"$repo_root/target/xshield-dev"}
dev_admin_password='xshield-dev-password'
console_only=0
reset_stack=0
control_bin=''
edge_bin=''
control_pid=''
edge_pid=''
console_pid=''
stack_started=0
pids=()

usage() {
    cat <<'EOF'
Usage: ./dev.sh [--all|--console-only] [--reset]

Start the local development stack. The default starts:
  - PostgreSQL in Docker Compose (docker-compose.dev.yml)
  - xshield-control on http://127.0.0.1:9443; it applies migrations/ before it serves
  - xshield-edge on https://juice.local:5443 and https://idor.local:5444
    (self-signed development certificate; both names must resolve to 127.0.0.1)
  - the Vite console on http://127.0.0.1:55173

Create sites in the console; xshield-edge reads them from PostgreSQL.
Docker Desktop (or a compatible Docker daemon) is required for PostgreSQL.
Jev needs a key: set AI_GATEWAY_API_KEY (or XSHIELD_JEV_ROUTE=direct and
XSHIELD_JEV_API_KEY), or save one on the console's model page after the stack is
up. Until then judgements report JEV_NOT_CONFIGURED. The development administrator
password is xshield-dev-password. The stack uses development-only credentials
and data volumes; they are never used by production configuration.

Options:
  --all            Start the complete local stack (default).
  --console-only   Start only the Vite console.
  --reset          Remove this stack's development volumes before starting.
                   Needed once for a database created by the v3 stack.
  -h, --help       Show this help.

Development overrides:
  XSHIELD_CONSOLE_PORT                 Vite port (default: 55173)
  XSHIELD_CONTROL_PROXY                Control origin for the Vite proxy
  XSHIELD_DEV_ROOT                     Runtime directory (default: target/xshield-dev)
  XSHIELD_DEV_COMPOSE_PROJECT          Docker Compose project name
  XSHIELD_DEV_TLS_PORT                 Edge HTTPS port for juice.local (default: 5443)
  XSHIELD_DEV_IDOR_TLS_PORT            Edge HTTPS port for idor.local (default: 5444)
  XSHIELD_JEV_ROUTE, XSHIELD_JEV_API_KEY, XSHIELD_JEV_ENDPOINT, XSHIELD_JEV_MODEL,
  XSHIELD_JEV_TIMEOUT_MS               Jev settings passed to xshield-edge (docs/02)
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
[[ "$tls_port" != "$idor_tls_port" ]] ||
    die "XSHIELD_DEV_TLS_PORT and XSHIELD_DEV_IDOR_TLS_PORT must differ"

if ((console_only)); then
    [[ "$reset_stack" == 0 ]] || die "--reset requires the complete local stack"
else
    command -v cargo >/dev/null 2>&1 || die "cargo is required for the complete local stack"
    command -v curl >/dev/null 2>&1 || die "curl is required for the local readiness checks"
    command -v openssl >/dev/null 2>&1 || die "openssl is required to create local development keys"
    [[ -f "$compose_file" ]] || die "missing docker-compose.dev.yml"
    case "${XSHIELD_JEV_ROUTE:-gateway}" in
        gateway)
            [[ -n "${AI_GATEWAY_API_KEY:-}" ]] ||
                printf '%s\n' 'dev.sh: no AI_GATEWAY_API_KEY is set; judgements report JEV_NOT_CONFIGURED until a Jev key is saved on the console model page' >&2
            ;;
        direct)
            [[ -n "${XSHIELD_JEV_API_KEY:-}" ]] ||
                printf '%s\n' 'dev.sh: XSHIELD_JEV_ROUTE=direct without XSHIELD_JEV_API_KEY; judgements report JEV_NOT_CONFIGURED until a Jev key is saved on the console model page' >&2
            ;;
        *)
            die "XSHIELD_JEV_ROUTE must be gateway or direct"
            ;;
    esac
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
if (( ! console_only )); then
    check_local_port "$control_port"
    check_local_port "$tls_port"
    check_local_port "$idor_tls_port"
fi

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

# Prints one value from a control.env written by write_dev_env.
env_value() {
    (set -a && . "$1" && printf '%s' "${!2:-}")
}

build_services() {
    printf '%s\n' 'Building xshield-control and xshield-edge'
    (cd "$repo_root" && cargo build -p xshield-control -p xshield-edge)
    # Run the built binaries directly: a readiness wait must not include a compile,
    # and the process that is signalled on exit is the service itself.
    local target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
    [[ "$target_dir" == /* ]] || target_dir="$repo_root/$target_dir"
    control_bin="$target_dir/debug/xshield-control"
    edge_bin="$target_dir/debug/xshield-edge"
    [[ -x "$control_bin" && -x "$edge_bin" ]] ||
        die "cargo did not produce xshield-control and xshield-edge under $target_dir/debug"
}

write_dev_env() {
    local env_file="$dev_root/control.env"
    local context_key='' admin_password_hash=''
    install -d -m 0700 "$dev_root"
    if [[ -f "$env_file" ]]; then
        # Keep the secrets of an existing stack: the context key produces the context
        # hashes that stored decisions refer to, and the password hash signs sessions.
        context_key=$(env_value "$env_file" XSHIELD_CONTEXT_KEY_HEX)
        admin_password_hash=$(env_value "$env_file" XSHIELD_ADMIN_PASSWORD_HASH)
    fi
    [[ -n "$context_key" ]] || context_key=$(generate_hex)
    if [[ -z "$admin_password_hash" ]]; then
        admin_password_hash=$(printf '%s\n' "$dev_admin_password" | "$control_bin" hash-password) ||
            die 'could not hash the development administrator password'
    fi
    local env_tmp="$env_file.tmp.$$"
    umask 077
    {
        printf 'XSHIELD_DEV_POSTGRES_DB=%q\n' 'xshield'
        printf 'XSHIELD_DEV_POSTGRES_USER=%q\n' 'xshield_dev'
        printf 'XSHIELD_DEV_POSTGRES_PASSWORD=%q\n' 'xshield_dev'
        printf 'XSHIELD_DEV_POSTGRES_PORT=%q\n' '55432'
        printf 'XSHIELD_DATABASE_URL=%q\n' 'postgresql://xshield_dev:xshield_dev@127.0.0.1:55432/xshield'
        printf 'XSHIELD_CONTROL_LISTEN=%q\n' "127.0.0.1:$control_port"
        printf 'XSHIELD_CONTROL_CONSOLE_ORIGIN=%q\n' "http://127.0.0.1:$console_port"
        # The console is opened over plain http://127.0.0.1, where Chromium does not keep
        # Secure cookies. Both control and console listen on loopback only.
        printf 'XSHIELD_CONTROL_PLAIN_HTTP=%q\n' 'true'
        printf 'XSHIELD_ADMIN_PASSWORD_HASH=%q\n' "$admin_password_hash"
        printf 'XSHIELD_CONTEXT_KEY_HEX=%q\n' "$context_key"
    } >"$env_tmp"
    mv "$env_tmp" "$env_file"
    set -a
    # This file is generated with mode 0600 under target/ and contains only
    # local development values; it is not a production configuration source.
    . "$env_file"
    set +a
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

control_ready() {
    curl --fail --silent --max-time 2 "http://127.0.0.1:$control_port/health" >/dev/null 2>&1
}

wait_for_control() {
    for _ in $(seq 1 120); do
        if control_ready; then
            printf '%s\n' 'xshield-control is ready'
            return
        fi
        if ! kill -0 "$control_pid" 2>/dev/null; then
            die 'xshield-control exited before becoming ready; its output above says why. A database created by the v3 stack needs ./dev.sh --reset'
        fi
        sleep 1
    done
    die 'xshield-control did not become ready'
}

start_control() {
    printf 'Starting xshield-control on http://127.0.0.1:%s\n' "$control_port"
    "$control_bin" &
    control_pid=$!
    pids+=("$control_pid")
    wait_for_control
}

edge_ready() {
    (exec 3<>"/dev/tcp/127.0.0.1/$tls_port") 2>/dev/null
}

wait_for_edge() {
    for _ in $(seq 1 60); do
        if edge_ready; then
            printf '%s\n' 'xshield-edge is ready'
            return
        fi
        if ! kill -0 "$edge_pid" 2>/dev/null; then
            die 'xshield-edge exited before becoming ready; inspect its output above'
        fi
        sleep 1
    done
    die 'xshield-edge did not become ready'
}

start_edge() {
    local tls_dir="$dev_root/tls"
    "$repo_root/scripts/generate_dev_tls_cert.sh" "$tls_dir" >/dev/null
    printf 'Starting xshield-edge on https://juice.local:%s and https://idor.local:%s\n' \
        "$tls_port" "$idor_tls_port"
    XSHIELD_EDGE_LISTEN_PORTS="$tls_port,$idor_tls_port" \
        XSHIELD_EDGE_TLS_CERT_PATH="$tls_dir/juice.local.crt" \
        XSHIELD_EDGE_TLS_KEY_PATH="$tls_dir/juice.local.key" \
        "$edge_bin" &
    edge_pid=$!
    pids+=("$edge_pid")
    wait_for_edge
}

# Background jobs start with SIGINT ignored, so control and the console take SIGTERM.
# The edge is the exception: pingora reads SIGTERM as a graceful shutdown that does not
# finish while the stack is torn down, and SIGINT as its fast shutdown.
stop_child() {
    local pid="$1" signal="$2"
    if [[ -n "$pid" ]]; then
        kill "-$signal" "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_child "$control_pid" TERM
    stop_child "$edge_pid" INT
    stop_child "$console_pid" TERM
    if ((${#pids[@]} > 0)); then
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
    build_services
    write_dev_env
    ensure_docker
    if ((reset_stack)); then
        compose down --volumes --remove-orphans >/dev/null 2>&1 || true
    fi
    stack_started=1
    compose up -d --remove-orphans
    wait_for 'PostgreSQL' postgres postgres_ready
    start_control
    start_edge
fi

printf 'Starting console at http://127.0.0.1:%s (proxy: %s)\n' "$console_port" "$control_proxy"
if (( ! console_only )); then
    printf '%s\n' 'Development administrator password: xshield-dev-password'
fi
# The package's dev script is `vite --host 127.0.0.1`. Running vite directly leaves one
# process to stop: npm and its shell would leave vite running after the stack exits.
(
    cd "$console_dir"
    export XSHIELD_CONTROL_PROXY="$control_proxy"
    exec node_modules/.bin/vite --host 127.0.0.1 --port "$console_port"
) &
console_pid=$!
pids+=("$console_pid")

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
