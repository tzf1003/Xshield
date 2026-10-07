# Shared setup of the real OIDC stack for scripts/test_oidc_login.sh (no browser)
# and scripts/test_oidc_browser.sh (real Chromium): a native Keycloak with the dev
# realm, the real `xshield-control` binary and a throwaway PostgreSQL database.
#
# This file is sourced, never executed. The caller must already have enforced
# bash >= 4.1 and `set -euo pipefail`, and must define before calling anything:
#   repo_root   the repository root
#   work        a private scratch directory (removed by the caller's cleanup)
# and it owns the cleanup: these helpers record what they started in
#   control_pid keycloak_pid test_database database_created
# and the caller's EXIT trap must call oidc_stop_process on both pids and drop the
# database when `database_created` is 1. Nothing here deletes anything by itself.

control_pid=""
keycloak_pid=""
test_database=""
database_created=0

oidc_stop_process() {
    local pid=$1
    [[ -n "$pid" ]] || return 0
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
    done
    pkill -KILL -P "$pid" 2>/dev/null || true
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

oidc_free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

oidc_wait_for() {
    local label=$1 pid=$2 url=$3
    for _ in $(seq 1 120); do
        if curl -sS -o /dev/null --max-time 2 "$url" 2>/dev/null; then
            return 0
        fi
        kill -0 "$pid" 2>/dev/null || { echo "error: $label exited during startup" >&2; return 1; }
        sleep 0.5
    done
    echo "error: $label did not become ready" >&2
    return 1
}

# oidc_check_tools [extra tool...]: Keycloak, JDK and the command line tools.
oidc_check_tools() {
    keycloak_source=${XSHIELD_KEYCLOAK_HOME:-}
    [[ -n "$keycloak_source" && -x "$keycloak_source/bin/kc.sh" ]] || {
        echo "error: set XSHIELD_KEYCLOAK_HOME to an unpacked Keycloak distribution (the directory containing bin/kc.sh)" >&2
        exit 2
    }
    if [[ -n "${JAVA_HOME:-}" ]]; then
        [[ -x "$JAVA_HOME/bin/java" ]] || { echo "error: JAVA_HOME has no bin/java" >&2; exit 2; }
    else
        command -v java >/dev/null 2>&1 || { echo "error: a JDK 21+ is required (set JAVA_HOME)" >&2; exit 2; }
    fi
    local tool
    for tool in openssl curl python3 psql createdb dropdb "$@"; do
        command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 2; }
    done
}

# oidc_locate_binaries: builds unless XSHIELD_OIDC_SKIP_BUILD=1; sets control_bin, dump_bin.
oidc_locate_binaries() {
    target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
    control_bin="$target_dir/debug/xshield-control"
    dump_bin="$target_dir/debug/examples/dump_access_audit"
    if [[ "${XSHIELD_OIDC_SKIP_BUILD:-0}" != "1" ]]; then
        (cd "$repo_root" && cargo build -p xshield-control --bin xshield-control --example dump_access_audit --locked)
    fi
    [[ -x "$control_bin" && -x "$dump_bin" ]] || { echo "error: control binaries are not built under $target_dir" >&2; exit 2; }
}

# oidc_create_database: a throwaway database with every migration applied; sets
# test_database, database_created and database_url.
oidc_create_database() {
    test_database="xshield_oidc_${PPID}_${RANDOM}"
    createdb "$test_database"
    database_created=1
    local migration
    for migration in "$repo_root"/migrations/*.sql; do
        psql -X -q -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration" >/dev/null
    done
    database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
    database_url="$database_base_url/$test_database"
}

# oidc_start_keycloak <console_origin>: a private copy of Keycloak, in-memory database,
# the dev realm imported; sets keycloak_port, keycloak_pid and issuer.
oidc_start_keycloak() {
    local console_origin=$1
    keycloak_port=$(oidc_free_port)
    cp -R "$keycloak_source" "$work/keycloak"
    mkdir -p "$work/keycloak/data/import"
    # The dev realm, with two test-only changes. (1) Keycloak's authorization code lives 60 s
    # by default, exactly the control plane's auth_time freshness bound, so a callback
    # delayed past that bound would be rejected by the IdP ("token rejected") before the
    # control plane's own check could be exercised. (2) The registered redirect URI and web
    # origin follow `console_origin` (the realm names http://127.0.0.1:55173, and that is
    # what the no-browser script uses, so for it the file is unchanged), because the
    # browser run starts its console on a free port. The repo's realm file is not changed.
    python3 -I - "$repo_root/dev/keycloak/xshield-dev-realm.json" "$work/keycloak/data/import/xshield-dev-realm.json" "$console_origin" <<'PY'
import json
import sys

realm = json.load(open(sys.argv[1], encoding="utf-8"))
realm["accessCodeLifespan"] = 180
origin = sys.argv[3]
for client in realm["clients"]:
    if client["clientId"] == "xshield-console-dev":
        client["redirectUris"] = [origin + "/control/v1/auth/oidc/callback"]
        client["webOrigins"] = [origin]
json.dump(realm, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
    KC_BOOTSTRAP_ADMIN_USERNAME=dev-admin \
    KC_BOOTSTRAP_ADMIN_PASSWORD=dev-admin-password \
    KC_HOSTNAME="http://127.0.0.1:$keycloak_port" \
    KC_HOSTNAME_STRICT=false \
    KC_HTTP_ENABLED=true \
    KC_HTTP_HOST=127.0.0.1 \
    KC_HTTP_PORT="$keycloak_port" \
        "$work/keycloak/bin/kc.sh" start-dev --db=dev-mem --import-realm >"$work/keycloak.log" 2>&1 &
    keycloak_pid=$!
    issuer="http://127.0.0.1:$keycloak_port/realms/xshield-dev"
    oidc_wait_for keycloak "$keycloak_pid" "$issuer/.well-known/openid-configuration"
}

# oidc_start_control <console_origin>: the real control process against `issuer` and
# `database_url`; sets control_port, control_pid and audit_key_hex. The console origin
# is where the control plane sends the browser after login and the only origin it
# accepts on writes.
oidc_start_control() {
    local console_origin=$1
    control_port=$(oidc_free_port)
    install -d -m 0700 "$work/journal" "$work/manifests" "$work/checkpoints" "$work/control-audit" "$work/evidence"
    hex() { openssl rand -hex 32 | tr -d '\n'; }
    audit_key_hex=$(hex)
    local now
    now=$(date +%s)
    local roles_json='[{"subject":"00000000-0000-7000-8000-000000000001","roles":["observer","investigator","audit_administrator","sensitive_evidence_reader","sensitive_evidence_approver","policy_author","policy_approver","release_operator","system_admin"]},{"subject":"00000000-0000-7000-8000-000000000002","roles":["observer"]}]'
    (
        export XSHIELD_TENANT_ID=tenant_oidc XSHIELD_SITE_ID=site_oidc
        export XSHIELD_CONTROL_SUBJECT=oidc-test-machine XSHIELD_CONTROL_ROLES=observer
        export XSHIELD_CONTROL_OIDC_ISSUER="$issuer"
        export XSHIELD_CONTROL_OIDC_CLIENT_ID=xshield-console-dev
        export XSHIELD_CONTROL_OIDC_CLIENT_SECRET=xshield-dev-client-secret
        export XSHIELD_CONTROL_OIDC_REQUIRED_ACR=1
        export XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON="$roles_json"
        export XSHIELD_CONTROL_CONSOLE_ORIGIN="$console_origin"
        export XSHIELD_CONTROL_TOKEN="$(hex)"
        export XSHIELD_CONTROL_TOKEN_ISSUED_AT=$((now - 60)) XSHIELD_CONTROL_TOKEN_EXPIRES_AT=$((now + 86340))
        export XSHIELD_CONTROL_CURSOR_KEY_HEX="$(hex)" XSHIELD_CONTROL_IDEMPOTENCY_KEY_HEX="$(hex)"
        export XSHIELD_CONTROL_API_KEY_HASH_KEY_HEX="$(hex)"
        export XSHIELD_JOURNAL_KEY_ID=oidc-test-journal XSHIELD_JOURNAL_KEY_HEX="$(hex)"
        # RFC 8032 test vector 1 public key: a valid verifying key, no secret behind it here.
        export XSHIELD_SEAL_KEY_ID=oidc-test-seal
        export XSHIELD_SEAL_PUBLIC_KEY_HEX=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        export XSHIELD_CONTROL_AUDIT_KEY_ID=oidc-test-control-audit XSHIELD_CONTROL_AUDIT_KEY_HEX="$audit_key_hex"
        export XSHIELD_INDEX_TARGET_ID=clickhouse-oidc-test
        # The index is not used by the login flow; the client connects lazily.
        export XSHIELD_CLICKHOUSE_URL=http://127.0.0.1:9 XSHIELD_CLICKHOUSE_DATABASE=xshield
        export XSHIELD_CLICKHOUSE_USER=xshield XSHIELD_CLICKHOUSE_PASSWORD=unused
        export XSHIELD_DATABASE_URL="$database_url"
        export XSHIELD_CONTROL_DATABASE_MAX_CONNECTIONS=8 XSHIELD_CONTROL_DATABASE_ACQUIRE_TIMEOUT_MS=2000
        export XSHIELD_AUDIT_METADATA_RETENTION_DAYS=30 XSHIELD_AUDIT_MAX_SEGMENT_READ_BYTES=16777216
        export XSHIELD_CONTROL_REQUESTS_PER_MINUTE=1200 XSHIELD_CONTROL_MAX_QUERY_EVENTS=1000
        export XSHIELD_CONTROL_MAX_QUERY_ARTIFACTS=128 XSHIELD_CONTROL_MAX_OPEN_CASES=32
        export XSHIELD_CONTROL_MAX_PENDING_EVIDENCE_ACCESS_REQUESTS=32 XSHIELD_CONTROL_MAX_EVIDENCE_ACCESS_TTL_SECONDS=120
        export XSHIELD_EVIDENCE_ROOT="$work/evidence" XSHIELD_EVIDENCE_KEY_ID=oidc-test-evidence XSHIELD_EVIDENCE_KEY_HEX="$(hex)"
        export XSHIELD_EVIDENCE_MAX_ARTIFACT_BYTES=1048576 XSHIELD_EVIDENCE_MAX_RETENTION_DAYS=30
        export XSHIELD_CONTROL_AUDIT_MAX_BYTES=16777216 XSHIELD_CONTROL_AUDIT_HIGH_WATERMARK_BYTES=12582912
        export XSHIELD_CONTROL_AUDIT_SEGMENT_MAX_BYTES=4194304
        export XSHIELD_CONTROL_LISTEN="127.0.0.1:$control_port"
        exec "$control_bin" "$work/journal" "$work/manifests" "$work/checkpoints" "$work/control-audit"
    ) >"$work/control.log" 2>&1 &
    control_pid=$!
    oidc_wait_for control "$control_pid" "http://127.0.0.1:$control_port/control/v1/session"
}
