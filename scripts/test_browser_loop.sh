#!/usr/bin/env bash
# Real-browser provenance loop (docs/20): a real Chromium drives a small orders
# app (tests/browser-loop) through the real edge binary over its native TLS,
# backed by an isolated PostgreSQL database. The page's own script, which
# knows nothing about Xshield, logs in, lists orders (a page-issued first-hop
# action) and opens one (a response-derived, resource-bound action) with its
# own Authorization header; sensor 1.1.0 attaches the server-issued
# references. Requests that did not follow the flow, references from another
# object, another browser context or an expired lease, calls after logout and
# calls from unhooked contexts (Worker, iframe, a saved fetch reference) must
# all be denied before the origin sees them. Afterwards the encrypted journal
# is read back to prove every decision was audited with its reason code, and
# the ui_action.issued outbox rows are run through the worker's parser. The
# edge must also refuse to start without its database and when a changed
# configuration would redefine descriptors under the same policy revision.
#
# Needs: cargo, python3, openssl, curl, psql/createdb/dropdb for a reachable
# PostgreSQL (PG* variables; XSHIELD_TEST_DATABASE_BASE_URL overrides the
# connection URL), node 22 and @playwright/test with its Chromium. By default
# the Playwright install of web/console is used (run `npm ci` and
# `npx playwright install chromium` there); XSHIELD_PLAYWRIGHT_PACKAGE may
# point at another package.json that depends on @playwright/test.
# Build output honours CARGO_TARGET_DIR; scratch files go under TMPDIR and
# are removed on exit. XSHIELD_BROWSER_LOOP_TRANSCRIPT=path keeps the JSON
# transcript of the run.
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
gateway_bin="$target_dir/debug/xshield-gateway"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-browser-loop.XXXXXX")
test_database="xshield_browser_loop_${PPID}_${RANDOM}"
journal_key=8888888888888888888888888888888888888888888888888888888888888888
fingerprint_key=7777777777777777777777777777777777777777777777777777777777777777
origin_pid=""
gateway_pid=""
database_created=0

stop_gateway() {
    if [[ -n "$gateway_pid" ]]; then
        kill -TERM "$gateway_pid" 2>/dev/null || true
        for _ in {1..50}; do
            kill -0 "$gateway_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$gateway_pid" 2>/dev/null || true
        wait "$gateway_pid" 2>/dev/null || true
        gateway_pid=""
    fi
}

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        printf '%s\n' '--- gateway.log (head)'
        sed -n '1,80p' "$test_dir/gateway.log" 2>/dev/null || true
        printf '%s\n' '--- origin.log (head)'
        sed -n '1,40p' "$test_dir/origin.log" 2>/dev/null || true
    fi
    stop_gateway
    if [[ -n "$origin_pid" ]]; then
        kill "$origin_pid" 2>/dev/null || true
        wait "$origin_pid" 2>/dev/null || true
    fi
    if ((database_created)); then
        dropdb --if-exists "$test_database" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$test_dir"
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

cargo build --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway --bin xshield-gateway

createdb "$test_database"
database_created=1
for migration in "$repo_root"/migrations/*.sql; do
    psql -X -q -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration" >/dev/null 2>&1
done
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
database_url="$database_base_url/$test_database"

# A throwaway self-signed edge certificate; the browser context ignores the
# trust error, everything else about the TLS listener is real.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$test_dir/edge.key" -out "$test_dir/edge.pem" -days 2 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 600 "$test_dir/edge.key"

origin_port=$(free_port)
edge_port=$(free_port)
python3 "$repo_root/tests/browser-loop/app_origin.py" "$origin_port" >"$test_dir/origin.log" 2>&1 &
origin_pid=$!
for _ in {1..100}; do
    curl -sf "http://127.0.0.1:$origin_port/__lab/metrics" >/dev/null 2>&1 && break
    sleep 0.1
done

# The approved page is pinned by its exact digest and </head> offset.
read -r app_sha256 app_offset < <(python3 - "$repo_root/tests/browser-loop/app.html" <<'PY'
import hashlib
import sys
body = open(sys.argv[1], "rb").read()
print(hashlib.sha256(body).hexdigest(), body.index(b"</head>"))
PY
)

cat >"$test_dir/gateway.json" <<JSON
{
  "listen": "127.0.0.1:$edge_port",
  "origin": {"address": "127.0.0.1:$origin_port", "server_name": "orders.local", "tls": false},
  "tenant_id": "tenant_loop",
  "site_id": "site_loop",
  "policy_revision": "loop-r1",
  "audit": {"directory": "$test_dir/audit", "key_id": "journal-loop-r1",
            "producer_id": "edge-browser-loop", "max_bytes": 16777216,
            "high_watermark_bytes": 12582912, "segment_max_bytes": 1048576},
  "identity_store": {"max_connections": 4, "acquire_timeout_ms": 2000},
  "sensor": {"origin": "https://localhost:$edge_port", "build_ref": "$app_sha256",
             "heartbeat_seconds": 15},
  "operations": [
    {"operation_id": "login.page", "method": "GET", "path": "/", "admission": "PUBLIC"},
    {"operation_id": "auth.login", "method": "POST", "path": "/api/login",
     "admission": "AUTH_ENTRY",
     "response": {"mode": "BUFFERED_JSON", "max_bytes": 1024,
                  "auth_binding": {"success_status": 200, "principal_pointer": "/identity/id",
                                   "authorization_context_pointer": "/identity/authorization_context",
                                   "bearer_pointer": "/access_token",
                                   "credential_ttl_seconds": 1800, "session_ttl_seconds": 3600}}},
    {"operation_id": "app.page", "method": "GET", "path": "/app",
     "admission": "AUTHENTICATED_ROOT",
     "response": {"mode": "SENSOR_HTML", "max_bytes": 16384, "adapter_revision": "app-r1",
                  "origin_sha256": "$app_sha256", "injection_offset": $app_offset,
                  "page_actions": {"mapping_revision": "app-map-r1", "max_active_pages": 32}}},
    {"operation_id": "orders.list", "method": "GET", "path": "/orders",
     "admission": "UI_ACTION_REQUIRED", "source_action": "app.orders.list",
     "issued_by": {"page_operation_id": "app.page", "ttl_seconds": 600},
     "response": {"mode": "BUFFERED_JSON", "max_bytes": 4096,
                  "resource_grant": {"success_status": 200, "items_pointer": "/orders",
                                     "resource_pointer": "/id",
                                     "action_ref_field": "_xshield_action_ref",
                                     "target_operation_id": "orders.read",
                                     "target_mapping_revision": "orders-map-r1",
                                     "ttl_seconds": 600, "max_items": 10,
                                     "max_active_grants": 200}}},
    {"operation_id": "orders.read", "method": "GET", "path": "/orders/{order_id}",
     "admission": "UI_ACTION_REQUIRED", "source_action": "orders.open",
     "resource_type": "order", "view_profile": "customer_detail",
     "resource_path_parameter": "order_id"},
    {"operation_id": "auth.logout", "method": "POST", "path": "/api/logout",
     "admission": "AUTHENTICATED_ROOT",
     "response": {"mode": "BUFFERED_JSON", "max_bytes": 256,
                  "auth_revoke": {"success_status": 200}}}
  ]
}
JSON

start_gateway() { # config database-url log
    env -u XSHIELD_EDGE_APPLY_KEY_HEX -u XSHIELD_EDGE_SNAPSHOT_PATH \
        -u XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED \
        XSHIELD_CONFIG="$1" \
        XSHIELD_PUBLIC_HOSTS=localhost \
        XSHIELD_EDGE_LISTEN_PORTS="127.0.0.1:$edge_port" \
        XSHIELD_EDGE_TLS_CERT_PATH="$test_dir/edge.pem" \
        XSHIELD_EDGE_TLS_KEY_PATH="$test_dir/edge.key" \
        XSHIELD_JOURNAL_KEY_HEX="$journal_key" \
        XSHIELD_FINGERPRINT_KEY_HEX="$fingerprint_key" \
        XSHIELD_DATABASE_URL="$2" \
        "$gateway_bin" >"$3" 2>&1 &
    gateway_pid=$!
}

# Expects a refused startup: the process exits non-zero before it listens and
# names the stable reason. $1 = log, $2 = reason code.
expect_refused_start() {
    local exited=0
    for _ in {1..100}; do
        if ! kill -0 "$gateway_pid" 2>/dev/null; then
            exited=1
            break
        fi
        sleep 0.1
    done
    ((exited)) || { echo "edge started although it must refuse ($2)" >&2; exit 1; }
    if wait "$gateway_pid"; then
        echo "edge exited successfully although it must refuse ($2)" >&2
        exit 1
    fi
    gateway_pid=""
    grep -q "$2" "$1" || { cat "$1" >&2; exit 1; }
    if curl -sk -o /dev/null "https://localhost:$edge_port/" 2>/dev/null; then
        echo "a refused edge still accepted a connection ($2)" >&2
        exit 1
    fi
}

# Without its database the edge cannot provision descriptors and must not
# start. Refused starts use their own journal directory.
sed "s#\"$test_dir/audit\"#\"$test_dir/audit-refused\"#" "$test_dir/gateway.json" \
    >"$test_dir/gateway-refused.json"
start_gateway "$test_dir/gateway-refused.json" "${database_url}_missing" "$test_dir/gateway-no-db.log"
expect_refused_start "$test_dir/gateway-no-db.log" IDENTITY_STORE_UNAVAILABLE

start_gateway "$test_dir/gateway.json" "$database_url" "$test_dir/gateway.log"
ready=0
for _ in {1..150}; do
    kill -0 "$gateway_pid" 2>/dev/null || break
    if curl -sk -o /dev/null "https://localhost:$edge_port/" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
((ready)) || { echo "edge did not become ready" >&2; exit 1; }

# The edge provisioned its digest-bound descriptors before it listened.
descriptors=$(psql -X -At -d "$test_database" -c \
    "SELECT string_agg(action_id || '@' || mapping_revision, ',' ORDER BY action_id)
     FROM xshield.action_descriptors WHERE tenant_id = 'tenant_loop' AND site_id = 'site_loop'")
[[ "$descriptors" == "app.orders.list@app-map-r1,orders.open@orders-map-r1" ]]

EDGE_URL="https://localhost:$edge_port" \
ORIGIN_URL="http://127.0.0.1:$origin_port" \
LOOP_DATABASE="$test_database" \
LOOP_EXPECTATIONS="$test_dir/expectations.json" \
    node "$repo_root/scripts/test_browser_loop.mjs" | tee "$test_dir/transcript.json"

# Flush and close the journal, then prove every decision above was audited.
stop_gateway

# The same policy revision may never be redefined: a configuration that moves
# the page-issued list action refuses to start and leaves the rows unchanged.
sed 's#"path": "/orders",#"path": "/orders-v2",#' "$test_dir/gateway-refused.json" \
    >"$test_dir/gateway-drift.json"
if cmp -s "$test_dir/gateway-refused.json" "$test_dir/gateway-drift.json"; then
    echo "the drift configuration did not change the list route" >&2
    exit 1
fi
start_gateway "$test_dir/gateway-drift.json" "$database_url" "$test_dir/gateway-drift.log"
expect_refused_start "$test_dir/gateway-drift.log" UI_DESCRIPTOR_CONFLICT
[[ "$(psql -X -At -d "$test_database" -c \
    "SELECT route_template FROM xshield.action_descriptors
     WHERE tenant_id = 'tenant_loop' AND action_id = 'app.orders.list'")" == "/orders" ]]
XSHIELD_BROWSER_LOOP_AUDIT="$test_dir/expectations.json" \
XSHIELD_BROWSER_LOOP_JOURNAL="$test_dir/audit" \
XSHIELD_BROWSER_LOOP_JOURNAL_KEY_HEX="$journal_key" \
    cargo test --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway \
    --test browser_loop_audit -- --ignored >"$test_dir/audit-check.log" 2>&1 || {
        cat "$test_dir/audit-check.log"
        exit 1
    }

# Every ui_action.issued row the run committed must parse under the worker's
# strict family contract, or its publication would stall.
psql -X -At -d "$test_database" -c \
    "SELECT json_agg(json_build_object('event_id', event_id, 'aggregate_ref', aggregate_ref,
                                       'envelope', envelope) ORDER BY event_id)
     FROM xshield.audit_outbox
     WHERE tenant_id = 'tenant_loop' AND event_type = 'ui_action.issued'" >"$test_dir/outbox.json"
XSHIELD_BROWSER_LOOP_OUTBOX="$test_dir/outbox.json" \
    cargo test --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-worker --lib \
    browser_loop_outbox -- --ignored >"$test_dir/outbox-check.log" 2>&1 || {
        cat "$test_dir/outbox-check.log"
        exit 1
    }

if [[ -n "${XSHIELD_BROWSER_LOOP_TRANSCRIPT:-}" ]]; then
    cp "$test_dir/transcript.json" "$XSHIELD_BROWSER_LOOP_TRANSCRIPT"
fi
echo "browser provenance loop passed"
