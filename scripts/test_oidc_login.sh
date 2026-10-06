#!/usr/bin/env bash
# Real OIDC login regression: a native Keycloak (the dev realm), the real
# `xshield-control` binary and a throwaway PostgreSQL database, driven by
# scripts/test_oidc_login.py without a browser.
#
# Needs: PostgreSQL client tools and a reachable server (PGHOST/PGUSER/... as for
# scripts/test_postgres.sh), a JDK 21+ (JAVA_HOME or `java` on PATH), an unpacked
# Keycloak distribution in XSHIELD_KEYCLOAK_HOME (the directory that contains
# bin/kc.sh; Keycloak 26.7.4 is what docker-compose.dev.yml and CI use), openssl,
# curl and python3.
# Optional: XSHIELD_OIDC_SKIP_BUILD=1 (use already built binaries),
# XSHIELD_OIDC_SKIP_STALE=1 (skip the two-minute step-up lapse checks),
# XSHIELD_OIDC_KEEP=1 (keep the work directory and logs for inspection).
# Set TMPDIR if the default temporary directory must not receive the Keycloak
# copy (about 200 MB).
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
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
for tool in openssl curl python3 psql createdb dropdb; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is required" >&2; exit 2; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/xshield-oidc.XXXXXX")
test_database="xshield_oidc_${PPID}_${RANDOM}"
database_created=0
control_pid=""
keycloak_pid=""

stop_process() {
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

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        echo "---- control log (tail)" >&2
        tail -n 60 "$work/control.log" 2>/dev/null >&2 || true
        echo "---- keycloak log (tail)" >&2
        tail -n 40 "$work/keycloak.log" 2>/dev/null >&2 || true
    fi
    stop_process "$control_pid"
    stop_process "$keycloak_pid"
    if ((database_created)); then
        dropdb --if-exists "$test_database" >/dev/null 2>&1 || true
    fi
    if [[ "${XSHIELD_OIDC_KEEP:-0}" == "1" ]]; then
        echo "work directory kept: $work" >&2
    else
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT INT TERM

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

wait_for() {
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

target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
control_bin="$target_dir/debug/xshield-control"
dump_bin="$target_dir/debug/examples/dump_access_audit"
if [[ "${XSHIELD_OIDC_SKIP_BUILD:-0}" != "1" ]]; then
    (cd "$repo_root" && cargo build -p xshield-control --bin xshield-control --example dump_access_audit --locked)
fi
[[ -x "$control_bin" && -x "$dump_bin" ]] || { echo "error: control binaries are not built under $target_dir" >&2; exit 2; }

# ---- throwaway database with every migration applied -----------------------
createdb "$test_database"
database_created=1
for migration in "$repo_root"/migrations/*.sql; do
    psql -X -q -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration" >/dev/null
done
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
database_url="$database_base_url/$test_database"

# ---- Keycloak: a private copy, in-memory database, the dev realm imported ---
keycloak_port=$(free_port)
control_port=$(free_port)
cp -R "$keycloak_source" "$work/keycloak"
mkdir -p "$work/keycloak/data/import"
# The dev realm, with one test-only change: Keycloak's authorization code lives 60 s
# by default, exactly the control plane's auth_time freshness bound, so a callback
# delayed past that bound would be rejected by the IdP ("token rejected") before the
# control plane's own check could be exercised. The repo's realm file is not changed.
python3 -I - "$repo_root/dev/keycloak/xshield-dev-realm.json" "$work/keycloak/data/import/xshield-dev-realm.json" <<'PY'
import json
import sys

realm = json.load(open(sys.argv[1], encoding="utf-8"))
realm["accessCodeLifespan"] = 180
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
wait_for keycloak "$keycloak_pid" "$issuer/.well-known/openid-configuration"

# ---- the real control process ----------------------------------------------
install -d -m 0700 "$work/journal" "$work/manifests" "$work/checkpoints" "$work/control-audit" "$work/evidence"
hex() { openssl rand -hex 32 | tr -d '\n'; }
audit_key_hex=$(hex)
now=$(date +%s)
roles_json='[{"subject":"00000000-0000-7000-8000-000000000001","roles":["observer","investigator","audit_administrator","sensitive_evidence_reader","sensitive_evidence_approver","policy_author","policy_approver","release_operator","system_admin"]},{"subject":"00000000-0000-7000-8000-000000000002","roles":["observer"]}]'
(
    export XSHIELD_TENANT_ID=tenant_oidc XSHIELD_SITE_ID=site_oidc
    export XSHIELD_CONTROL_SUBJECT=oidc-test-machine XSHIELD_CONTROL_ROLES=observer
    export XSHIELD_CONTROL_OIDC_ISSUER="$issuer"
    export XSHIELD_CONTROL_OIDC_CLIENT_ID=xshield-console-dev
    export XSHIELD_CONTROL_OIDC_CLIENT_SECRET=xshield-dev-client-secret
    export XSHIELD_CONTROL_OIDC_REQUIRED_ACR=1
    export XSHIELD_CONTROL_OIDC_SUBJECT_ROLES_JSON="$roles_json"
    # The console origin is the redirect URI registered in the dev realm; nothing
    # listens there, the test script rewrites redirects to the control listener.
    export XSHIELD_CONTROL_CONSOLE_ORIGIN=http://127.0.0.1:55173
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
wait_for control "$control_pid" "http://127.0.0.1:$control_port/control/v1/session"

stale_flag=()
if [[ "${XSHIELD_OIDC_SKIP_STALE:-0}" == "1" ]]; then
    stale_flag=(--skip-stale-wait)
fi
XSHIELD_CONTROL_AUDIT_KEY_ID=oidc-test-control-audit \
XSHIELD_CONTROL_AUDIT_KEY_HEX="$audit_key_hex" \
    python3 -I "$repo_root/scripts/test_oidc_login.py" \
    --control-url "http://127.0.0.1:$control_port" \
    --keycloak-url "http://127.0.0.1:$keycloak_port" \
    --console-origin http://127.0.0.1:55173 \
    --database-url "$database_url" \
    --audit-dir "$work/control-audit" \
    --dump-bin "$dump_bin" \
    --realm-file "$repo_root/dev/keycloak/xshield-dev-realm.json" \
    ${stale_flag[@]+"${stale_flag[@]}"}
