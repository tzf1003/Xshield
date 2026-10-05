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
# the ui_action.issued outbox rows are run through the worker's parser.
#
# The edge starts from a minimal, bootstrap-only configuration that routes
# nothing. The whole orders topology (login, the SENSOR_HTML page root with
# page_actions, the list with issued_by and resource_grant, the detail and
# logout) arrives through the signed /internal/v1/apply channel, exactly as a
# control plane delivers it, and the edge supplies the derived descriptors to
# PostgreSQL before the snapshot becomes active. The script also proves the
# fail-closed paths around that supply: an apply without the database is
# refused (503 EDGE_APPLY_DESCRIPTOR_UNAVAILABLE) and nothing is persisted; a
# snapshot that redefines descriptors under the same policy revision is
# refused (409 EDGE_APPLY_DESCRIPTOR_CONFLICT) and the serving snapshot and
# the rows stay as they were; a restart re-supplies the persisted snapshot
# before it listens, and refuses to start without its database
# (IDENTITY_STORE_UNAVAILABLE) or when the persisted snapshot redefines the
# descriptors (UI_DESCRIPTOR_CONFLICT).
#
# Needs: cargo, python3, openssl, curl, psql/createdb/dropdb for a reachable
# PostgreSQL (PG* variables; XSHIELD_TEST_DATABASE_BASE_URL overrides the
# connection URL), node 22 and @playwright/test with its Chromium. By default
# the Playwright install of web/console is used (run `npm ci` and
# `npx playwright install chromium` there); XSHIELD_PLAYWRIGHT_PACKAGE may
# point at another package.json that depends on @playwright/test.
# Build output honours CARGO_TARGET_DIR; scratch files go under TMPDIR and
# are removed on exit, as are the two throwaway databases.
# XSHIELD_BROWSER_LOOP_TRANSCRIPT=path keeps the JSON transcript of the run.
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
# A second database on which a drifted snapshot is new, so a real edge can
# persist it; restoring that snapshot against the first database must fail.
drift_database="${test_database}_drift"
journal_key=8888888888888888888888888888888888888888888888888888888888888888
fingerprint_key=7777777777777777777777777777777777777777777777777777777777777777
apply_key=6666666666666666666666666666666666666666666666666666666666666666
origin_pid=""
gateway_pid=""
databases_created=()

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
        for log in "$test_dir"/gateway*.log; do
            [[ -e "$log" ]] || continue
            printf -- '--- %s (head)\n' "$(basename "$log")"
            sed -n '1,60p' "$log" 2>/dev/null || true
        done
        printf '%s\n' '--- origin.log (head)'
        sed -n '1,40p' "$test_dir/origin.log" 2>/dev/null || true
    fi
    stop_gateway
    if [[ -n "$origin_pid" ]]; then
        kill "$origin_pid" 2>/dev/null || true
        wait "$origin_pid" 2>/dev/null || true
    fi
    for database in ${databases_created[@]+"${databases_created[@]}"}; do
        dropdb --if-exists "$database" >/dev/null 2>&1 || true
    done
    rm -rf -- "$test_dir"
}
trap cleanup EXIT INT TERM

step() {
    printf '== %s\n' "$*" >&2
}

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

create_database() { # name
    createdb "$1"
    databases_created+=("$1")
    for migration in "$repo_root"/migrations/*.sql; do
        psql -X -q -v ON_ERROR_STOP=1 -d "$1" -f "$migration" >/dev/null 2>&1
    done
}

cargo build --quiet --locked --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway --bin xshield-gateway

create_database "$test_database"
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
apply_port=$(free_port)
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

# The bootstrap configuration routes nothing (XSHIELD_EDGE_BOOTSTRAP_ONLY=1):
# it carries only what belongs to the process, namely the journal and the
# identity store. The edge builds its identity runtime from it, so it also
# declares one protected placeholder route, which is never served.
write_bootstrap() { # path audit-directory
    cat >"$1" <<JSON
{
  "listen": "127.0.0.1:$edge_port",
  "origin": {"address": "127.0.0.1:1", "server_name": "bootstrap.invalid", "tls": false},
  "tenant_id": "tenant_loop",
  "site_id": "site_bootstrap",
  "policy_revision": "bootstrap-r1",
  "audit": {"directory": "$2", "key_id": "journal-loop-r1",
            "producer_id": "edge-browser-loop", "max_bytes": 16777216,
            "high_watermark_bytes": 12582912, "segment_max_bytes": 1048576},
  "identity_store": {"max_connections": 4, "acquire_timeout_ms": 2000},
  "operations": [
    {"operation_id": "bootstrap.placeholder", "method": "GET", "path": "/__bootstrap__",
     "admission": "AUTHENTICATED_ROOT"}
  ]
}
JSON
}
# Every edge run that is expected to fail, and every extra start, gets its
# own journal so the browser run's journal holds only that run.
write_bootstrap "$test_dir/bootstrap.json" "$test_dir/audit"
write_bootstrap "$test_dir/bootstrap-no-db.json" "$test_dir/audit-no-db"
write_bootstrap "$test_dir/bootstrap-restart.json" "$test_dir/audit-restart"
write_bootstrap "$test_dir/bootstrap-drift.json" "$test_dir/audit-drift"
write_bootstrap "$test_dir/bootstrap-refused.json" "$test_dir/audit-refused"

# The site the control plane would deliver, in its complete apply envelope.
cat >"$test_dir/site.json" <<JSON
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

# Wraps the site into a complete tenant snapshot. $3 moves the page-issued
# list action: a different descriptor set under the same policy revision.
write_apply() { # path snapshot-revision list-path
    python3 - "$test_dir/site.json" "$1" "$2" "$3" "$edge_port" <<'PY'
import json
import sys

site_path, out_path, revision, list_path, port = sys.argv[1:]
site = json.load(open(site_path, encoding="utf-8"))
for operation in site["operations"]:
    if operation["operation_id"] == "orders.list":
        operation["path"] = list_path
request = {
    "protocol_version": 1,
    "tenant_id": "tenant_loop",
    "apply_id": "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01",
    "snapshot_revision": int(revision),
    "sites": [{
        "site_id": "site_loop",
        "listen_port": int(port),
        "public_origin": f"https://localhost:{port}",
        "gateway_config": site,
        "revision": int(revision),
    }],
}
with open(out_path, "w", encoding="utf-8") as output:
    json.dump(request, output, separators=(",", ":"))
PY
}
write_apply "$test_dir/apply.json" 1 /orders
write_apply "$test_dir/apply-drift.json" 2 /orders-v2

start_gateway() { # bootstrap-config database-url log snapshot-path
    env -u XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED -u XSHIELD_PUBLIC_HOSTS \
        XSHIELD_CONFIG="$1" \
        XSHIELD_EDGE_BOOTSTRAP_ONLY=1 \
        XSHIELD_EDGE_LISTEN_PORTS="127.0.0.1:$edge_port" \
        XSHIELD_EDGE_APPLY_KEY_HEX="$apply_key" \
        XSHIELD_EDGE_APPLY_LISTEN="127.0.0.1:$apply_port" \
        XSHIELD_EDGE_SNAPSHOT_PATH="$4" \
        XSHIELD_EDGE_TLS_CERT_PATH="$test_dir/edge.pem" \
        XSHIELD_EDGE_TLS_KEY_PATH="$test_dir/edge.key" \
        XSHIELD_JOURNAL_KEY_HEX="$journal_key" \
        XSHIELD_FINGERPRINT_KEY_HEX="$fingerprint_key" \
        XSHIELD_DATABASE_URL="$2" \
        "$gateway_bin" >"$3" 2>&1 &
    gateway_pid=$!
}

# Waits until the edge answers on its apply channel, which it binds after
# every data-plane listener: an unsigned health request is refused with 401.
wait_for_apply() {
    for _ in {1..150}; do
        kill -0 "$gateway_pid" 2>/dev/null || break
        if [[ "$(curl -s -o /dev/null -w '%{http_code}' \
            "http://127.0.0.1:$apply_port/internal/v1/health" 2>/dev/null)" == "401" ]]; then
            return 0
        fi
        sleep 0.1
    done
    echo "edge did not become ready" >&2
    exit 1
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

# The data plane has no route for the app: 503 SITE_CONFIG_UNAVAILABLE.
expect_no_route() {
    local status
    status=$(curl -sk -o "$test_dir/no-route.body" -w '%{http_code}' "https://localhost:$edge_port/")
    [[ "$status" == "503" ]] || { echo "expected no route, got $status" >&2; exit 1; }
    grep -q SITE_CONFIG_UNAVAILABLE "$test_dir/no-route.body"
}

# Posts one signed apply request. Leaves the request signature in $signature,
# the status in $apply_status, the response headers in apply.headers and the
# body in apply.response.
post_apply() {
    signature=$(python3 - "$1" "$apply_key" <<'PY'
import hashlib
import hmac
import sys
with open(sys.argv[1], "rb") as body:
    print(hmac.new(bytes.fromhex(sys.argv[2]), body.read(), hashlib.sha256).hexdigest())
PY
)
    apply_status=$(curl -sS -D "$test_dir/apply.headers" -o "$test_dir/apply.response" \
        -w '%{http_code}' \
        -H "x-xshield-apply-signature: $signature" \
        --data-binary "@$1" \
        "http://127.0.0.1:$apply_port/internal/v1/apply")
}

# A refusal names its reason and, for a descriptor refusal, the site.
expect_refused_apply() { # status reason-code
    [[ "$apply_status" == "$1" ]] || { cat "$test_dir/apply.response" >&2; exit 1; }
    python3 - "$test_dir/apply.response" "$2" <<'PY'
import json
import sys
body = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {"error": "edge_apply_failed", "reason_code": sys.argv[2], "site_id": "site_loop"}
assert body == expected, body
PY
}

# The edge signs its acknowledgement over the signature of the request it
# answers; recompute that independently of the Rust implementation.
expect_confirmed_apply() { # active-revision
    [[ "$apply_status" == "200" ]] || { cat "$test_dir/apply.response" >&2; exit 1; }
    python3 - "$test_dir/apply.headers" "$test_dir/apply.response" "$apply_key" "$signature" "$1" <<'PY'
import hashlib
import hmac
import json
import sys

headers_path, body_path, key_hex, request_signature, revision = sys.argv[1:]
with open(headers_path, encoding="ascii") as handle:
    values = [
        line.split(":", 1)[1].strip()
        for line in handle
        if line.lower().startswith("x-xshield-apply-ack-signature:")
    ]
assert len(values) == 1, values
with open(body_path, "rb") as handle:
    body = handle.read()
message = b"xshield-edge-apply-ack-v1\n" + request_signature.encode() + b"\n" + body
expected = hmac.new(bytes.fromhex(key_hex), message, hashlib.sha256).hexdigest()
assert hmac.compare_digest(values[0], expected), (values[0], expected)
ack = json.loads(body)
assert ack["active_revision"] == int(revision) and ack["apply_state"] == "active", ack
PY
}

descriptors() { # database
    psql -X -At -d "$1" -c \
        "SELECT string_agg(action_id || '@' || mapping_revision || '@' || route_template, ','
                           ORDER BY action_id)
         FROM xshield.action_descriptors WHERE tenant_id = 'tenant_loop' AND site_id = 'site_loop'"
}

# 1. Without its database the edge cannot supply the descriptors: the apply
#    is refused, nothing is persisted and the app stays unrouted.
mkdir -p "$test_dir/snapshot-no-db"
start_gateway "$test_dir/bootstrap-no-db.json" "${database_url}_missing" \
    "$test_dir/gateway-no-db.log" "$test_dir/snapshot-no-db/edge.json"
wait_for_apply
expect_no_route
post_apply "$test_dir/apply.json"
expect_refused_apply 503 EDGE_APPLY_DESCRIPTOR_UNAVAILABLE
[[ -z "$(ls -A "$test_dir/snapshot-no-db")" ]] || { ls -la "$test_dir/snapshot-no-db" >&2; exit 1; }
expect_no_route
stop_gateway
step "apply without a database: 503 EDGE_APPLY_DESCRIPTOR_UNAVAILABLE, nothing persisted"

# 2. With its database: the signed apply supplies the digest-bound
#    descriptors, then activates the topology.
mkdir -p "$test_dir/snapshot"
start_gateway "$test_dir/bootstrap.json" "$database_url" "$test_dir/gateway.log" \
    "$test_dir/snapshot/edge.json"
wait_for_apply
expect_no_route
[[ -z "$(descriptors "$test_database")" ]]
post_apply "$test_dir/apply.json"
expect_confirmed_apply 1
expected_descriptors="app.orders.list@app-map-r1@/orders,orders.open@orders-map-r1@/orders/{order_id}"
[[ "$(descriptors "$test_database")" == "$expected_descriptors" ]]
# The revision's digest is the canonical encoding of exactly these
# descriptors (xshield_core::edge_descriptors), computed here independently.
expected_digest=$(python3 - <<'PY'
import hashlib
fields = [b"xshield-edge-descriptors-v1", b"2",
          b"app.orders.list", b"app-map-r1", b"app.page", b"orders.list", b"GET", b"/orders",
          b"none", b"0", b"none",
          b"orders.open", b"orders-map-r1", b"orders.read", b"orders.read", b"GET",
          b"/orders/{order_id}", b"resource", b"order", b"1", b"order_id", b"customer_detail"]
print(hashlib.sha256(b"".join(field + b"\0" for field in fields)).hexdigest())
PY
)
[[ "$(psql -X -At -d "$test_database" -c \
    "SELECT status || ' ' || content_digest FROM xshield.policy_revisions
     WHERE tenant_id = 'tenant_loop' AND site_id = 'site_loop' AND revision = 'loop-r1'")" \
    == "active $expected_digest" ]]
# An identical retry is idempotent.
post_apply "$test_dir/apply.json"
expect_confirmed_apply 1
step "signed apply supplied the descriptors (digest $expected_digest) and activated revision 1"

EDGE_URL="https://localhost:$edge_port" \
ORIGIN_URL="http://127.0.0.1:$origin_port" \
LOOP_DATABASE="$test_database" \
LOOP_EXPECTATIONS="$test_dir/expectations.json" \
    node "$repo_root/scripts/test_browser_loop.mjs" | tee "$test_dir/transcript.json"

# 3. The same policy revision may never be redefined: a newer snapshot that
#    moves the page-issued list action is refused as a whole, the rows stay,
#    and the edge keeps serving (and persisting) revision 1.
post_apply "$test_dir/apply-drift.json"
expect_refused_apply 409 EDGE_APPLY_DESCRIPTOR_CONFLICT
[[ "$(descriptors "$test_database")" == "$expected_descriptors" ]]
[[ "$(ls -A "$test_dir/snapshot")" == "edge.json" ]]
python3 - "$test_dir/snapshot/edge.json" <<'PY'
import json
import sys
snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
assert snapshot["request"]["snapshot_revision"] == 1, snapshot["request"]["snapshot_revision"]
PY
[[ "$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:$edge_port/")" == "200" ]]
step "redefining apply: 409 EDGE_APPLY_DESCRIPTOR_CONFLICT, revision 1 still serving"

# Flush and close the journal, then prove every decision above was audited.
stop_gateway

# 4. A restart re-supplies the persisted snapshot before it listens: without
#    the database it refuses to start; with it, it serves again.
start_gateway "$test_dir/bootstrap-refused.json" "${database_url}_missing" \
    "$test_dir/gateway-restart-no-db.log" "$test_dir/snapshot/edge.json"
expect_refused_start "$test_dir/gateway-restart-no-db.log" \
    "IDENTITY_STORE_UNAVAILABLE: persisted snapshot site site_loop"
start_gateway "$test_dir/bootstrap-restart.json" "$database_url" \
    "$test_dir/gateway-restart.log" "$test_dir/snapshot/edge.json"
wait_for_apply
[[ "$(curl -sk -o /dev/null -w '%{http_code}' "https://localhost:$edge_port/")" == "200" ]]
stop_gateway
step "restart: refused without a database, re-supplied and serving with it"

# 5. A persisted snapshot that redefines the descriptors refuses to start and
#    leaves the rows unchanged. A real edge persists that snapshot first, on a
#    second database where its descriptor set is new.
create_database "$drift_database"
mkdir -p "$test_dir/snapshot-drift"
start_gateway "$test_dir/bootstrap-drift.json" "$database_base_url/$drift_database" \
    "$test_dir/gateway-drift-apply.log" "$test_dir/snapshot-drift/edge.json"
wait_for_apply
post_apply "$test_dir/apply-drift.json"
expect_confirmed_apply 2
stop_gateway
start_gateway "$test_dir/bootstrap-refused.json" "$database_url" \
    "$test_dir/gateway-drift.log" "$test_dir/snapshot-drift/edge.json"
expect_refused_start "$test_dir/gateway-drift.log" \
    "UI_DESCRIPTOR_CONFLICT: persisted snapshot site site_loop policy revision loop-r1"
[[ "$(descriptors "$test_database")" == "$expected_descriptors" ]]
step "restart from a redefining persisted snapshot: refused, rows unchanged"

XSHIELD_BROWSER_LOOP_AUDIT="$test_dir/expectations.json" \
XSHIELD_BROWSER_LOOP_JOURNAL="$test_dir/audit" \
XSHIELD_BROWSER_LOOP_JOURNAL_KEY_HEX="$journal_key" \
    cargo test --quiet --locked --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway \
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
    cargo test --quiet --locked --manifest-path "$repo_root/Cargo.toml" -p xshield-worker --lib \
    browser_loop_outbox -- --ignored >"$test_dir/outbox-check.log" 2>&1 || {
        cat "$test_dir/outbox-check.log"
        exit 1
    }

if [[ -n "${XSHIELD_BROWSER_LOOP_TRANSCRIPT:-}" ]]; then
    cp "$test_dir/transcript.json" "$XSHIELD_BROWSER_LOOP_TRANSCRIPT"
fi
echo "browser provenance loop passed"
