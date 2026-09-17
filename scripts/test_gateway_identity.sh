#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_database="xshield_gateway_${PPID}_${RANDOM}"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-gateway-identity.XXXXXX")
origin_pid=""
gateway_pid=""

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        sed -n '1,120p' "$test_dir/gateway.log" 2>/dev/null || true
        sed -n '1,120p' "$test_dir/origin.log" 2>/dev/null || true
    fi
    if [[ -n "$gateway_pid" ]]; then kill -KILL "$gateway_pid" 2>/dev/null || true; fi
    if [[ -n "$origin_pid" ]]; then kill "$origin_pid" 2>/dev/null || true; fi
    wait "$gateway_pid" 2>/dev/null || true
    wait "$origin_pid" 2>/dev/null || true
    dropdb --if-exists "$test_database" >/dev/null
    rm -r -- "$test_dir"
}
trap cleanup EXIT INT TERM

createdb "$test_database"
for migration in "$repo_root"/migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration" >/dev/null
done

fingerprint_key="7777777777777777777777777777777777777777777777777777777777777777"
session_id="ses_018f2a3b-4c5d-7000-8000-000000000902"
bearer="verified-business-token"
session_fingerprint=$(printf '%s' "$session_id" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary | od -An -tx1 | tr -d ' \n')
bearer_fingerprint=$(printf '%s' "$bearer" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary | od -An -tx1 | tr -d ' \n')

psql -X -v ON_ERROR_STOP=1 -d "$test_database" \
    -v session_fingerprint="$session_fingerprint" \
    -v bearer_fingerprint="$bearer_fingerprint" <<'SQL' >/dev/null
INSERT INTO xshield.auth_bindings (
    tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
    auth_epoch, credential_generation, status, absolute_expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'auth_018f2a3b-4c5d-7000-8000-000000000901',
    decode(:'session_fingerprint', 'hex'), 'principal_gateway',
    1, 1, 'active', now() + interval '1 hour'
);
INSERT INTO xshield.credential_bindings (
    tenant_id, site_id, binding_id, generation, credential_kind,
    fingerprint, expires_at, status
) VALUES (
    'tenant_gateway', 'site_gateway',
    'auth_018f2a3b-4c5d-7000-8000-000000000901',
    1, 'bearer', decode(:'bearer_fingerprint', 'hex'),
    now() + interval '1 hour', 'active'
);
SQL

cat >"$test_dir/config.json" <<JSON
{
  "listen":"127.0.0.1:6288",
  "origin":{"address":"127.0.0.1:8180","server_name":"origin.example","tls":false},
  "tenant_id":"tenant_gateway",
  "site_id":"site_gateway",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/journal","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432},
  "identity_store":{"max_connections":2,"acquire_timeout_ms":2000},
  "operations":[
    {"operation_id":"account.root","method":"GET","path":"/account","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null}
  ]
}
JSON

cargo build -p xshield-gateway >/dev/null
cat >"$test_dir/origin.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(sys.argv[1], "a", encoding="utf-8") as output:
            output.write(f"{self.command} {self.path}\n")
            output.write(f"Cookie={self.headers.get('Cookie', '')}\n")
            output.write(f"Authorization={self.headers.get('Authorization', '')}\n")
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return

HTTPServer(("127.0.0.1", 8180), Handler).serve_forever()
PY
python3 "$test_dir/origin.py" "$test_dir/origin.log" &
origin_pid=$!
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
XSHIELD_CONFIG="$test_dir/config.json" \
XSHIELD_JOURNAL_KEY_HEX="8888888888888888888888888888888888888888888888888888888888888888" \
XSHIELD_DATABASE_URL="$database_base_url/$test_database" \
XSHIELD_FINGERPRINT_KEY_HEX="$fingerprint_key" \
    "$repo_root/target/debug/xshield-gateway" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!

for _ in {1..50}; do
    if curl -sS -o "$test_dir/missing.json" -w '%{http_code}' \
        -H "Cookie: __Host-xshield_sid=$session_id" \
        http://127.0.0.1:6288/account >"$test_dir/missing.status" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
[[ $(<"$test_dir/missing.status") == "403" ]]
grep -q '"reason_code":"AUTH_REQUIRED"' "$test_dir/missing.json"

valid_status=$(curl -sS -o "$test_dir/valid.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    http://127.0.0.1:6288/account)
[[ "$valid_status" == "404" ]]

invalid_status=$(curl -sS -o "$test_dir/invalid.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer substituted-token" \
    http://127.0.0.1:6288/account)
[[ "$invalid_status" == "403" ]]
grep -q '"reason_code":"AUTH_BINDING_MISMATCH"' "$test_dir/invalid.json"

kill -KILL "$gateway_pid"
wait "$gateway_pid" 2>/dev/null || true
gateway_pid=""
kill "$origin_pid"
wait "$origin_pid" 2>/dev/null || true
origin_pid=""
[[ $(grep -c 'GET /account' "$test_dir/origin.log") == "1" ]]
! grep -q '__Host-xshield_sid' "$test_dir/origin.log"
grep -q 'Authorization=Bearer verified-business-token' "$test_dir/origin.log"
[[ -n $(find "$test_dir/journal" -name 'segment-*.xaj' -type f -print -quit) ]]

echo "gateway identity integration passed"
