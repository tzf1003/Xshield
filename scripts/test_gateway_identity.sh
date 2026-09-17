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
service_credential="verified-service-token"
share_token="verified-share-token"
session_fingerprint=$(printf '%s' "$session_id" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary | od -An -tx1 | tr -d ' \n')
bearer_fingerprint=$(printf '%s' "$bearer" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary | od -An -tx1 | tr -d ' \n')
resource_fingerprint=$(printf '%s\0%s\0%s\0%s\0%s\0' \
    'xshield-resource-v1' 'tenant_gateway' 'site_gateway' 'order' 'order-123' \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
service_fingerprint=$(printf '%s\0%s\0%s\0%s\0' \
    'xshield-service-credential-v1' 'tenant_gateway' 'site_gateway' "$service_credential" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
share_fingerprint=$(printf '%s\0%s\0%s\0%s\0' \
    'xshield-share-token-v1' 'tenant_gateway' 'site_gateway' "$share_token" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
share_resource_fingerprint=$(printf '%s\0%s\0%s\0%s\0%s\0' \
    'xshield-resource-v1' 'tenant_gateway' 'site_gateway' 'record' 'record-123' \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')

psql -X -v ON_ERROR_STOP=1 -d "$test_database" \
    -v session_fingerprint="$session_fingerprint" \
    -v bearer_fingerprint="$bearer_fingerprint" \
    -v resource_fingerprint="$resource_fingerprint" \
    -v service_fingerprint="$service_fingerprint" \
    -v share_fingerprint="$share_fingerprint" \
    -v share_resource_fingerprint="$share_resource_fingerprint" <<'SQL' >/dev/null
INSERT INTO xshield.policy_revisions (
    tenant_id, site_id, revision, status, content_digest, artifact_ref
) VALUES (
    'tenant_gateway', 'site_gateway', 'policy-r1', 'active',
    repeat('a', 64), 'artifact_gateway_policy_r1'
);
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
INSERT INTO xshield.action_descriptors (
    tenant_id, site_id, action_id, page_template, operation_id, method,
    route_template, target_rule, allowed_fields, field_profile,
    policy_revision, mapping_revision, status
) VALUES (
    'tenant_gateway', 'site_gateway', 'settings.open', 'settings_page',
    'settings.open', 'GET', '/settings', '{"kind":"none"}', '[]',
    'no_fields', 'policy-r1', 'mapping-r1', 'approved'
);
INSERT INTO xshield.action_descriptors (
    tenant_id, site_id, action_id, page_template, operation_id, method,
    route_template, target_rule, allowed_fields, field_profile,
    policy_revision, mapping_revision, status
) VALUES (
    'tenant_gateway', 'site_gateway', 'orders.open', 'settings_page',
    'orders.read', 'GET', '/orders',
    '{"kind":"resource","resource_type":"order"}', '["order_id"]',
    'customer_detail', 'policy-r1', 'mapping-r1', 'approved'
);
INSERT INTO xshield.page_evidence (
    tenant_id, site_id, page_evidence_id, binding_id, auth_epoch,
    source_request_id, response_artifact_ref, page_template, build_fingerprint,
    policy_revision, mapping_revision, status, verified_at, expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'page_018f2a3b-4c5d-7000-8000-000000000903',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1,
    'req_018f2a3b-4c5d-7000-8000-000000000904', 'artifact_settings_page',
    'settings_page', decode(repeat('b', 64), 'hex'), 'policy-r1',
    'mapping-r1', 'verified', now() - interval '1 minute', now() + interval '30 minutes'
);
INSERT INTO xshield.ui_actions (
    tenant_id, site_id, action_ref, binding_id, auth_epoch,
    source_request_id, page_evidence_id, source_action_ref, operation_id,
    target_constraints, field_profile, source_rule, policy_revision,
    status, issued_at, expires_at, mapping_revision, method, route_template,
    allowed_fields
) VALUES (
    'tenant_gateway', 'site_gateway', 'action_settings_primary',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1,
    'req_018f2a3b-4c5d-7000-8000-000000000904',
    'page_018f2a3b-4c5d-7000-8000-000000000903', 'settings.open',
    'settings.open', '{"kind":"none"}', 'no_fields', 'mapping-r1',
    'policy-r1', 'active', now() - interval '30 seconds', now() + interval '15 minutes',
    'mapping-r1', 'GET', '/settings', '[]'
);
INSERT INTO xshield.ui_actions (
    tenant_id, site_id, action_ref, binding_id, auth_epoch,
    source_request_id, page_evidence_id, source_action_ref, operation_id,
    target_constraints, field_profile, source_rule, policy_revision,
    status, issued_at, expires_at, mapping_revision, method, route_template,
    allowed_fields
) VALUES (
    'tenant_gateway', 'site_gateway', 'action_order_primary',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1,
    'req_018f2a3b-4c5d-7000-8000-000000000904',
    'page_018f2a3b-4c5d-7000-8000-000000000903', 'orders.open',
    'orders.read', jsonb_build_object(
        'kind', 'resource', 'resource_type', 'order',
        'resource_key_hmac', :'resource_fingerprint'
    ), 'customer_detail', 'mapping-r1', 'policy-r1', 'active',
    now() - interval '30 seconds', now() + interval '15 minutes',
    'mapping-r1', 'GET', '/orders', '["order_id"]'
);
INSERT INTO xshield.resource_grants (
    tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
    resource_type, resource_key_hmac, operation_id, view_id, constraints,
    source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'grant_018f2a3b-4c5d-7000-8000-000000000905',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1, 'action_order_primary',
    'order', decode(:'resource_fingerprint', 'hex'), 'orders.read',
    'customer_detail', '{}', 'ev_018f2a3b-4c5d-7000-8000-000000000906',
    'orders-primary-r1', 'policy-r1', 'active',
    now() - interval '20 seconds', now() + interval '10 minutes'
);
INSERT INTO xshield.service_identities (
    tenant_id, site_id, service_id, credential_fingerprint,
    operation_ids, status, issued_at, expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'svc_018f2a3b-4c5d-7000-8000-000000000907',
    decode(:'service_fingerprint', 'hex'), ARRAY['reports.ingest'],
    'active', now() - interval '1 minute', now() + interval '30 minutes'
);
INSERT INTO xshield.share_grants (
    tenant_id, site_id, share_id, issuer_binding_id, token_fingerprint,
    resource_type, resource_key_hmac, operation_id, view_id, use_policy,
    source_event_id, policy_revision, status, issued_at, expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'share_018f2a3b-4c5d-7000-8000-000000000908',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', decode(:'share_fingerprint', 'hex'),
    'record', decode(:'share_resource_fingerprint', 'hex'), 'records.share.read',
    'shared_summary', 'reusable_read', 'ev_018f2a3b-4c5d-7000-8000-000000000909',
    'policy-r1', 'active', now() - interval '1 minute', now() + interval '30 minutes'
);
SQL

cat >"$test_dir/config.json" <<JSON
{
  "listen":"127.0.0.1:6288",
  "origin":{"address":"127.0.0.1:8180","server_name":"origin.example","tls":false},
  "tenant_id":"tenant_gateway",
  "site_id":"site_gateway",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/journal","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
  "identity_store":{"max_connections":2,"acquire_timeout_ms":2000},
  "operations":[
    {"operation_id":"account.root","method":"GET","path":"/account","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null},
    {"operation_id":"settings.open","method":"GET","path":"/settings","admission":"UI_ACTION_REQUIRED","source_action":"settings.open","resource_type":null,"view_profile":null},
    {"operation_id":"orders.read","method":"GET","path":"/orders","admission":"UI_ACTION_REQUIRED","source_action":"orders.open","resource_type":"order","view_profile":"customer_detail","resource_query_parameter":"order_id"},
    {"operation_id":"reports.ingest","method":"POST","path":"/service/report","admission":"SERVICE_IDENTITY","source_action":null,"resource_type":null,"view_profile":null,"resource_query_parameter":null},
    {"operation_id":"records.share.read","method":"GET","path":"/shared-record","admission":"SHARE_ENTRY","source_action":null,"resource_type":"record","view_profile":"shared_summary","resource_query_parameter":"record_id"}
  ]
}
JSON

cargo build -p xshield-gateway >/dev/null
cat >"$test_dir/origin.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.record()
    def do_POST(self):
        self.record()
    def record(self):
        with open(sys.argv[1], "a", encoding="utf-8") as output:
            output.write(f"{self.command} {self.path}\n")
            output.write(f"Cookie={self.headers.get('Cookie', '')}\n")
            output.write(f"Authorization={self.headers.get('Authorization', '')}\n")
            output.write(f"ActionRef={self.headers.get('X-Xshield-Action-Ref', '')}\n")
            output.write(f"ServiceCredential={self.headers.get('X-Xshield-Service-Credential', '')}\n")
            output.write(f"ShareToken={self.headers.get('X-Xshield-Share-Token', '')}\n")
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

missing_action_status=$(curl -sS -o "$test_dir/missing-action.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    http://127.0.0.1:6288/settings)
[[ "$missing_action_status" == "403" ]]
grep -q '"reason_code":"UI_ACTION_NOT_AVAILABLE"' "$test_dir/missing-action.json"

invalid_action_status=$(curl -sS -o "$test_dir/invalid-action.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_settings_substituted" \
    http://127.0.0.1:6288/settings)
[[ "$invalid_action_status" == "403" ]]

valid_action_status=$(curl -sS -o "$test_dir/valid-action.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_settings_primary" \
    http://127.0.0.1:6288/settings)
[[ "$valid_action_status" == "404" ]]

psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.action_descriptors SET status = 'retired' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND action_id = 'settings.open'" >/dev/null
retired_action_status=$(curl -sS -o "$test_dir/retired-action.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_settings_primary" \
    http://127.0.0.1:6288/settings)
[[ "$retired_action_status" == "403" ]]
grep -q '"reason_code":"UI_ACTION_NOT_AVAILABLE"' "$test_dir/retired-action.json"

valid_resource_status=$(curl -sS -o "$test_dir/valid-resource.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_primary" \
    'http://127.0.0.1:6288/orders?order_id=order-123')
[[ "$valid_resource_status" == "404" ]]

unknown_resource_status=$(curl -sS -o "$test_dir/unknown-resource.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_primary" \
    'http://127.0.0.1:6288/orders?order_id=order-999')
[[ "$unknown_resource_status" == "403" ]]
grep -q '"reason_code":"CAPABILITY_MISSING"' "$test_dir/unknown-resource.json"

expanded_fields_status=$(curl -sS -o "$test_dir/expanded-fields.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_primary" \
    'http://127.0.0.1:6288/orders?order_id=order-123&expand=admin')
[[ "$expanded_fields_status" == "403" ]]
grep -q '"reason_code":"FIELD_NOT_ALLOWED"' "$test_dir/expanded-fields.json"

ambiguous_resource_status=$(curl -sS -o "$test_dir/ambiguous-resource.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_primary" \
    'http://127.0.0.1:6288/orders?order_id=order-123&order%5fid=order-999')
[[ "$ambiguous_resource_status" == "403" ]]

psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.resource_grants SET status = 'revoked' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND grant_id = 'grant_018f2a3b-4c5d-7000-8000-000000000905'" >/dev/null
revoked_resource_status=$(curl -sS -o "$test_dir/revoked-resource.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_primary" \
    'http://127.0.0.1:6288/orders?order_id=order-123')
[[ "$revoked_resource_status" == "403" ]]
grep -q '"reason_code":"CAPABILITY_MISSING"' "$test_dir/revoked-resource.json"

missing_service_status=$(curl -sS -o "$test_dir/missing-service.json" -w '%{http_code}' \
    -X POST http://127.0.0.1:6288/service/report)
[[ "$missing_service_status" == "403" ]]
grep -q '"reason_code":"SERVICE_IDENTITY_MISMATCH"' "$test_dir/missing-service.json"

invalid_service_status=$(curl -sS -o "$test_dir/invalid-service.json" -w '%{http_code}' \
    -X POST -H 'X-Xshield-Service-Credential: substituted-service-token' \
    http://127.0.0.1:6288/service/report)
[[ "$invalid_service_status" == "403" ]]
grep -q '"reason_code":"SERVICE_IDENTITY_MISMATCH"' "$test_dir/invalid-service.json"

valid_service_status=$(curl -sS -o "$test_dir/valid-service.body" -w '%{http_code}' \
    -X POST -H "X-Xshield-Service-Credential: $service_credential" \
    http://127.0.0.1:6288/service/report)
[[ "$valid_service_status" == "404" ]]

psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.service_identities SET status = 'revoked' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND service_id = 'svc_018f2a3b-4c5d-7000-8000-000000000907'" >/dev/null
revoked_service_status=$(curl -sS -o "$test_dir/revoked-service.json" -w '%{http_code}' \
    -X POST -H "X-Xshield-Service-Credential: $service_credential" \
    http://127.0.0.1:6288/service/report)
[[ "$revoked_service_status" == "403" ]]
grep -q '"reason_code":"SERVICE_IDENTITY_MISMATCH"' "$test_dir/revoked-service.json"

missing_share_status=$(curl -sS -o "$test_dir/missing-share.json" -w '%{http_code}' \
    'http://127.0.0.1:6288/shared-record?record_id=record-123')
[[ "$missing_share_status" == "403" ]]
grep -q '"reason_code":"SHARE_SCOPE_MISMATCH"' "$test_dir/missing-share.json"

invalid_share_status=$(curl -sS -o "$test_dir/invalid-share.json" -w '%{http_code}' \
    -H 'X-Xshield-Share-Token: substituted-share-token' \
    'http://127.0.0.1:6288/shared-record?record_id=record-123')
[[ "$invalid_share_status" == "403" ]]

wrong_share_resource_status=$(curl -sS -o "$test_dir/wrong-share-resource.json" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-999')
[[ "$wrong_share_resource_status" == "403" ]]

expanded_share_status=$(curl -sS -o "$test_dir/expanded-share.json" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-123&expand=full')
[[ "$expanded_share_status" == "403" ]]

valid_share_status=$(curl -sS -o "$test_dir/valid-share.body" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-123')
[[ "$valid_share_status" == "404" ]]

psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.share_grants SET status = 'revoked' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND share_id = 'share_018f2a3b-4c5d-7000-8000-000000000908'" >/dev/null
revoked_share_status=$(curl -sS -o "$test_dir/revoked-share.json" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-123')
[[ "$revoked_share_status" == "403" ]]
grep -q '"reason_code":"SHARE_SCOPE_MISMATCH"' "$test_dir/revoked-share.json"

kill -KILL "$gateway_pid"
wait "$gateway_pid" 2>/dev/null || true
gateway_pid=""
kill "$origin_pid"
wait "$origin_pid" 2>/dev/null || true
origin_pid=""
[[ $(grep -c 'GET /account' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /settings' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /orders?order_id=order-123' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'POST /service/report' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /shared-record?record_id=record-123' "$test_dir/origin.log") == "1" ]]
! grep -q '__Host-xshield_sid' "$test_dir/origin.log"
! grep -q 'ActionRef=action_' "$test_dir/origin.log"
! grep -q 'ServiceCredential=verified-' "$test_dir/origin.log"
! grep -q 'ShareToken=verified-' "$test_dir/origin.log"
grep -q 'Authorization=Bearer verified-business-token' "$test_dir/origin.log"
[[ -n $(find "$test_dir/journal" -name 'segment-*.xaj' -type f -print -quit) ]]

echo "gateway identity integration passed"
