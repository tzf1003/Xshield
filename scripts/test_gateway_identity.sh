#!/usr/bin/env bash
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

# `! cmd` never trips `set -e` (in any bash), so an "absent" assertion written
# that way cannot fail the script; `refute` can. It names the line, never the
# pattern, because the pattern is often a token.
refute() {
    if "$@"; then
        echo "assertion failed at line ${BASH_LINENO[0]}: a pattern that must be absent was found" >&2
        return 1
    fi
}

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_database="xshield_gateway_${PPID}_${RANDOM}"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-gateway-identity.XXXXXX")
origin_pid=""
gateway_pid=""
share_request_pid=""

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        sed -n '1,120p' "$test_dir/gateway.log" 2>/dev/null || true
        sed -n '1,120p' "$test_dir/origin.log" 2>/dev/null || true
    fi
    if [[ -n "$gateway_pid" ]]; then kill -KILL "$gateway_pid" 2>/dev/null || true; fi
    if [[ -n "$origin_pid" ]]; then kill "$origin_pid" 2>/dev/null || true; fi
    if [[ -n "$share_request_pid" ]]; then kill "$share_request_pid" 2>/dev/null || true; fi
    wait "$gateway_pid" 2>/dev/null || true
    wait "$origin_pid" 2>/dev/null || true
    wait "$share_request_pid" 2>/dev/null || true
    dropdb --if-exists "$test_database" >/dev/null
    rm -r -- "$test_dir"
}
trap cleanup EXIT INT TERM

createdb "$test_database"
for migration in "$repo_root"/migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration" >/dev/null
done

fingerprint_key="7777777777777777777777777777777777777777777777777777777777777777"
share_token_key="9999999999999999999999999999999999999999999999999999999999999999"
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
response_resource_fingerprint=$(printf '%s\0%s\0%s\0%s\0%s\0' \
    'xshield-resource-v1' 'tenant_gateway' 'site_gateway' 'order' 'order-456' \
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
    authorization_context_ref, auth_epoch, credential_generation, status,
    absolute_expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'auth_018f2a3b-4c5d-7000-8000-000000000901',
    decode(:'session_fingerprint', 'hex'), 'principal_gateway', 'tenant_gateway:user',
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
    'tenant_gateway', 'site_gateway', 'settings.legacy.submit', 'settings_page',
    'settings.legacy.submit', 'POST', '/settings-legacy', '{"kind":"none"}', '[]',
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
INSERT INTO xshield.action_descriptors (
    tenant_id, site_id, action_id, page_template, operation_id, method,
    route_template, target_rule, allowed_fields, field_profile,
    policy_revision, mapping_revision, status
) VALUES (
    'tenant_gateway', 'site_gateway', 'orders.path.open', 'settings_page',
    'orders.path.read', 'GET', '/path-orders/{order_id}',
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
    'tenant_gateway', 'site_gateway', 'action_settings_legacy',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1,
    'req_018f2a3b-4c5d-7000-8000-000000000904',
    'page_018f2a3b-4c5d-7000-8000-000000000903', 'settings.legacy.submit',
    'settings.legacy.submit', '{"kind":"none"}', 'no_fields', 'mapping-r1',
    'policy-r1', 'active', now() - interval '30 seconds', now() + interval '15 minutes',
    'mapping-r1', 'POST', '/settings-legacy', '[]'
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
INSERT INTO xshield.ui_actions (
    tenant_id, site_id, action_ref, binding_id, auth_epoch,
    source_request_id, page_evidence_id, source_action_ref, operation_id,
    target_constraints, field_profile, source_rule, policy_revision,
    status, issued_at, expires_at, mapping_revision, method, route_template,
    allowed_fields
) VALUES (
    'tenant_gateway', 'site_gateway', 'action_order_path_primary',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1,
    'req_018f2a3b-4c5d-7000-8000-000000000904',
    'page_018f2a3b-4c5d-7000-8000-000000000903', 'orders.path.open',
    'orders.path.read', jsonb_build_object(
        'kind', 'resource', 'resource_type', 'order',
        'resource_key_hmac', :'resource_fingerprint'
    ), 'customer_detail', 'mapping-r1', 'policy-r1', 'active',
    now() - interval '30 seconds', now() + interval '15 minutes',
    'mapping-r1', 'GET', '/path-orders/{order_id}', '["order_id"]'
);
INSERT INTO xshield.resource_grants (
    tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
    resource_type, resource_key_hmac, operation_id, view_id, constraints,
    source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'grant_018f2a3b-4c5d-7000-8000-000000000915',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1, 'action_order_path_primary',
    'order', decode(:'resource_fingerprint', 'hex'), 'orders.path.read',
    'customer_detail', '{}', 'ev_018f2a3b-4c5d-7000-8000-000000000916',
    'orders-path-primary-r1', 'policy-r1', 'active',
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
INSERT INTO xshield.action_descriptors (
    tenant_id, site_id, action_id, page_template, operation_id, method,
    route_template, target_rule, allowed_fields, field_profile,
    policy_revision, mapping_revision, status
) VALUES (
    'tenant_gateway', 'site_gateway', 'records.share', 'settings_page',
    'records.share.issue', 'GET', '/share-issue',
    '{"kind":"resource","resource_type":"record"}', '["record_id"]',
    'share_controls', 'policy-r1', 'mapping-r1', 'approved'
);
INSERT INTO xshield.ui_actions (
    tenant_id, site_id, action_ref, binding_id, auth_epoch,
    source_request_id, page_evidence_id, source_action_ref, operation_id,
    target_constraints, field_profile, source_rule, policy_revision,
    status, issued_at, expires_at, mapping_revision, method, route_template,
    allowed_fields
) VALUES (
    'tenant_gateway', 'site_gateway', 'action_share_issue_primary',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1,
    'req_018f2a3b-4c5d-7000-8000-000000000904',
    'page_018f2a3b-4c5d-7000-8000-000000000903', 'records.share',
    'records.share.issue', jsonb_build_object(
        'kind', 'resource', 'resource_type', 'record',
        'resource_key_hmac', :'share_resource_fingerprint'
    ), 'share_controls', 'mapping-r1', 'policy-r1', 'active',
    now() - interval '30 seconds', now() + interval '15 minutes',
    'mapping-r1', 'GET', '/share-issue', '["record_id"]'
);
INSERT INTO xshield.resource_grants (
    tenant_id, site_id, grant_id, binding_id, auth_epoch, action_ref,
    resource_type, resource_key_hmac, operation_id, view_id, constraints,
    source_event_id, issuance_key, policy_revision, status, issued_at, expires_at
) VALUES (
    'tenant_gateway', 'site_gateway',
    'grant_018f2a3b-4c5d-7000-8000-000000000925',
    'auth_018f2a3b-4c5d-7000-8000-000000000901', 1, 'action_share_issue_primary',
    'record', decode(:'share_resource_fingerprint', 'hex'), 'records.share.issue',
    'share_controls', '{}', 'ev_018f2a3b-4c5d-7000-8000-000000000926',
    'share-issue-source-r1', 'policy-r1', 'active',
    now() - interval '20 seconds', now() + interval '10 minutes'
);
INSERT INTO xshield.share_issuance_rules (
    tenant_id, site_id, policy_revision, rule_id, issuer_operation_id,
    issuer_view_id, share_operation_id, share_view_id, max_ttl_seconds, status
) VALUES (
    'tenant_gateway', 'site_gateway', 'policy-r1', 'record-share-r1',
    'records.share.issue', 'share_controls', 'records.share.read',
    'shared_summary', 300, 'active'
);
SQL

compatibility_expires_at=$(($(date +%s) + 600))
cat >"$test_dir/config.json" <<JSON
{
  "listen":"127.0.0.1:6288",
  "origin":{"address":"127.0.0.1:8180","server_name":"origin.example","tls":false},
  "tenant_id":"tenant_gateway",
  "site_id":"site_gateway",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/journal","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
  "identity_store":{"max_connections":2,"acquire_timeout_ms":2000,"anonymous_session_ttl_seconds":300,"max_active_anonymous_sessions":10,"anonymous_session_rate_window_seconds":60,"max_anonymous_session_creations_per_source":1,"max_anonymous_session_creations_per_site":1},
  "sensor":{"origin":"http://127.0.0.1:6288","build_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","heartbeat_seconds":15},
  "operations":[
    {"operation_id":"auth.login","method":"POST","path":"/login","admission":"AUTH_ENTRY","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"auth_binding":{"success_status":200,"principal_pointer":"/identity/id","authorization_context_pointer":"/identity/authorization_context","bearer_pointer":"/access_token","credential_ttl_seconds":1800,"session_ttl_seconds":3600}}},
    {"operation_id":"auth.login.invalid","method":"POST","path":"/login-invalid","admission":"AUTH_ENTRY","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"auth_binding":{"success_status":200,"principal_pointer":"/identity/id","authorization_context_pointer":"/identity/authorization_context","bearer_pointer":"/access_token","credential_ttl_seconds":1800,"session_ttl_seconds":3600}}},
    {"operation_id":"auth.refresh","method":"POST","path":"/refresh","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"auth_refresh":{"success_status":200,"principal_pointer":"/identity/id","authorization_context_pointer":"/identity/authorization_context","bearer_pointer":"/access_token","credential_ttl_seconds":1800}}},
    {"operation_id":"auth.refresh.switch","method":"POST","path":"/refresh-switch","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"auth_refresh":{"success_status":200,"principal_pointer":"/identity/id","authorization_context_pointer":"/identity/authorization_context","bearer_pointer":"/access_token","credential_ttl_seconds":1800}}},
    {"operation_id":"auth.context.switch","method":"POST","path":"/account-switch","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"auth_context_switch":{"success_status":200,"principal_pointer":"/identity/id","authorization_context_pointer":"/identity/authorization_context","bearer_pointer":"/access_token","credential_ttl_seconds":1800}}},
    {"operation_id":"auth.context.switch.same","method":"POST","path":"/account-switch-same","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"auth_context_switch":{"success_status":200,"principal_pointer":"/identity/id","authorization_context_pointer":"/identity/authorization_context","bearer_pointer":"/access_token","credential_ttl_seconds":1800}}},
    {"operation_id":"auth.logout","method":"POST","path":"/logout","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":256,"auth_revoke":{"success_status":200}}},
    {"operation_id":"account.new","method":"GET","path":"/new-account","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"resource_grant":{"success_status":200,"items_pointer":"/orders","resource_pointer":"/id","action_ref_field":"_xshield_action_ref","target_operation_id":"orders.read","target_mapping_revision":"mapping-r1","ttl_seconds":900,"max_items":10,"max_active_grants":100}}},
    {"operation_id":"account.paged","method":"GET","path":"/paged-account","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"query_pagination":{"parameters":[{"name":"page","kind":"page"},{"name":"page_size","kind":"page_size","max_value":50}]},"response":{"mode":"BUFFERED_JSON","max_bytes":512,"resource_grant":{"success_status":200,"items_pointer":"/orders","resource_pointer":"/id","action_ref_field":"_xshield_action_ref","target_operation_id":"orders.read","target_mapping_revision":"mapping-r1","ttl_seconds":900,"max_items":10,"max_active_grants":100}}},
    {"operation_id":"account.slow","method":"GET","path":"/slow-account","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":512,"resource_grant":{"success_status":200,"items_pointer":"/orders","resource_pointer":"/id","action_ref_field":"_xshield_action_ref","target_operation_id":"orders.read","target_mapping_revision":"mapping-r1","ttl_seconds":900,"max_items":10,"max_active_grants":100}}},
    {"operation_id":"account.current","method":"GET","path":"/whoami","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null},
    {"operation_id":"account.root","method":"GET","path":"/account","admission":"AUTHENTICATED_ROOT","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":256,"resource_grant":{"success_status":200,"items_pointer":"/orders","resource_pointer":"/id","action_ref_field":"_xshield_action_ref","target_operation_id":"orders.read","target_mapping_revision":"mapping-r1","ttl_seconds":900,"max_items":10,"max_active_grants":100}}},
    {"operation_id":"settings.open","method":"GET","path":"/settings","admission":"UI_ACTION_REQUIRED","source_action":"settings.open","resource_type":null,"view_profile":null,"query_pagination":{"parameters":[{"name":"page","kind":"page"},{"name":"page_size","kind":"page_size","max_value":50}]}},
    {"operation_id":"settings.legacy.submit","method":"POST","path":"/settings-legacy","admission":"UI_ACTION_REQUIRED","source_action":"settings.legacy.submit","resource_type":null,"view_profile":null,"request_crypto":{"mode":"COMPATIBILITY","adapter_revision":"settings-legacy-r1","approval_ref":"approval-42","expires_at":$compatibility_expires_at,"build_fingerprints":["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}},
    {"operation_id":"orders.read","method":"GET","path":"/orders","admission":"UI_ACTION_REQUIRED","source_action":"orders.open","resource_type":"order","view_profile":"customer_detail","resource_query_parameter":"order_id"},
    {"operation_id":"orders.path.read","method":"GET","path":"/path-orders/{order_id}","admission":"UI_ACTION_REQUIRED","source_action":"orders.path.open","resource_type":"order","view_profile":"customer_detail","resource_path_parameter":"order_id"},
    {"operation_id":"reports.ingest","method":"POST","path":"/service/report","admission":"SERVICE_IDENTITY","source_action":null,"resource_type":null,"view_profile":null,"resource_query_parameter":null},
    {"operation_id":"records.share.read","method":"GET","path":"/shared-record","admission":"SHARE_ENTRY","source_action":null,"resource_type":"record","view_profile":"shared_summary","resource_query_parameter":"record_id"},
    {"operation_id":"records.share.issue","method":"GET","path":"/share-issue","admission":"UI_ACTION_REQUIRED","source_action":"records.share","resource_type":"record","view_profile":"share_controls","resource_query_parameter":"record_id","response":{"mode":"BUFFERED_JSON","max_bytes":512,"share_issue":{"success_status":200,"token_field":"share_token","target_operation_id":"records.share.read","issuance_rule_id":"record-share-r1","ttl_seconds":300,"max_active_shares":1}}},
    {"operation_id":"buffered.valid","method":"GET","path":"/buffered-valid","admission":"PUBLIC","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":64}},
    {"operation_id":"buffered.invalid","method":"GET","path":"/buffered-invalid","admission":"PUBLIC","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":64}},
    {"operation_id":"buffered.oversize","method":"GET","path":"/buffered-oversize","admission":"PUBLIC","source_action":null,"resource_type":null,"view_profile":null,"response":{"mode":"BUFFERED_JSON","max_bytes":8}}
  ]
}
JSON

cargo build -p xshield-gateway >/dev/null
cat >"$test_dir/origin.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import time

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.record()
    def do_POST(self):
        self.record()
    def record(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length) if length else b""
        with open(sys.argv[1], "a", encoding="utf-8") as output:
            output.write(f"{self.command} {self.path}\n")
            output.write(f"Cookie={self.headers.get('Cookie', '')}\n")
            output.write(f"Authorization={self.headers.get('Authorization', '')}\n")
            output.write(f"ActionRef={self.headers.get('X-Xshield-Action-Ref', '')}\n")
            output.write(f"ServiceCredential={self.headers.get('X-Xshield-Service-Credential', '')}\n")
            output.write(f"ShareToken={self.headers.get('X-Xshield-Share-Token', '')}\n")
            output.write(f"Body={request_body.decode('utf-8', errors='replace')}\n")
        responses = {
            "/login": b'{"identity":{"id":"principal_login","authorization_context":"tenant_gateway:user"},"access_token":"login-business-token"}',
            "/login-invalid": b'{"identity":{"id":"principal_invalid","authorization_context":"tenant_gateway:user"}}',
            "/refresh": b'{"identity":{"id":"principal_login","authorization_context":"tenant_gateway:user"},"access_token":"refreshed-business-token"}',
            "/refresh-switch": b'{"identity":{"id":"principal_login","authorization_context":"tenant_gateway:admin"},"access_token":"other-business-token"}',
            "/account-switch": b'{"identity":{"id":"principal_login","authorization_context":"tenant_gateway:admin"},"access_token":"context-admin-business-token"}',
            "/account-switch-same": b'{"identity":{"id":"principal_login","authorization_context":"tenant_gateway:user"},"access_token":"other-business-token"}',
            "/logout": b'{"logged_out":true}',
            "/new-account": b'{"orders":[{"id":"order-refresh"}]}',
            "/paged-account?page=2&page_size=20": b'{"orders":[{"id":"order-refresh"}]}',
            "/paged-account": b'{"orders":[{"id":"order-refresh"}]}',
            "/slow-account": b'{"orders":[{"id":"order-late"}]}',
            "/account": b'{"orders":[{"id":"order-456"},{"id":"order-457"}]}',
            "/settings-legacy": b'{"ok":true}',
            "/buffered-valid": b'{"ok":true}',
            "/buffered-invalid": b'private-invalid-json',
            "/buffered-oversize": b'{"private":"must-not-release"}',
            "/shared-record?record_id=record-123": b'{"record_id":"record-123","summary":"shared"}',
        }
        body = responses.get(self.path)
        status = 200
        truncated = False
        share_mode = "valid"
        if self.path == "/share-issue?record_id=record-123":
            control = Path(sys.argv[3])
            mode_path = control / "share.mode"
            share_mode = mode_path.read_text().strip() if mode_path.exists() else "valid"
            body = {
                "collision": b'{"ok":true,"share_token":null}',
                "duplicate": b'{"ok":true,"ok":false}',
                "nonobject": b'[{"ok":true}]',
                "truncated": b'{"ok":true',
                "oversize": b'{"padding":"' + b'x' * 440 + b'"}',
                "unsuccessful": b'{"error":"share_declined"}',
            }.get(share_mode, b'{"ok":true}')
            status = 422 if share_mode == "unsuccessful" else 200
            truncated = share_mode == "truncated"
            if share_mode in ("grant-revoked", "epoch-changed"):
                (control / f"share-{share_mode}.started").touch()
                for _ in range(250):
                    if (control / f"share-{share_mode}.release").exists():
                        (control / f"share-{share_mode}.released").touch()
                        break
                    time.sleep(0.02)
                else:
                    self.send_error(504)
                    return
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/slow-account":
            open(sys.argv[2], "w", encoding="utf-8").close()
            time.sleep(1)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body) + (16 if truncated else 0)))
        if self.path == "/share-issue?record_id=record-123":
            self.send_header("Cache-Control", "public, max-age=600")
            self.send_header("ETag", '"origin-share-response"')
            if share_mode == "content-range":
                self.send_header("Content-Range", "bytes 0-10/100")
            if share_mode == "attachment":
                self.send_header("Content-Disposition", 'attachment; filename="record.json"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

ThreadingHTTPServer(("127.0.0.1", 8180), Handler).serve_forever()
PY
python3 "$test_dir/origin.py" "$test_dir/origin.log" "$test_dir/slow.started" "$test_dir" &
origin_pid=$!
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
XSHIELD_CONFIG="$test_dir/config.json" \
XSHIELD_JOURNAL_KEY_HEX="8888888888888888888888888888888888888888888888888888888888888888" \
XSHIELD_DATABASE_URL="$database_base_url/$test_database" \
XSHIELD_FINGERPRINT_KEY_HEX="$fingerprint_key" \
XSHIELD_SHARE_TOKEN_KEY_HEX="$share_token_key" \
    "${CARGO_TARGET_DIR:-$repo_root/target}/debug/xshield-gateway" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!

for _ in {1..50}; do
    if curl -sS -o "$test_dir/missing.json" -w '%{http_code}' \
        -H "Cookie: __Host-xshield_sid=$session_id" \
        http://127.0.0.1:6288/account >"$test_dir/missing.status" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
[[ $(<"$test_dir/missing.status") == "401" ]]
grep -q '"reason_code":"AUTH_REQUIRED"' "$test_dir/missing.json"

anonymous_status=$(curl -sS -D "$test_dir/anonymous.headers" \
    -o "$test_dir/anonymous.json" -w '%{http_code}' \
    http://127.0.0.1:6288/account)
[[ "$anonymous_status" == "401" ]]
grep -q '"reason_code":"AUTH_REQUIRED"' "$test_dir/anonymous.json"
grep -qi '^set-cookie: __Host-xshield_sid=.*; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300' \
    "$test_dir/anonymous.headers"
anonymous_session_id=$(sed -n \
    's/^[Ss]et-[Cc]ookie: __Host-xshield_sid=\([^;]*\).*/\1/p' \
    "$test_dir/anonymous.headers")
[[ "$anonymous_session_id" == ses_* ]]
anonymous_session_fingerprint=$(printf '%s' "$anonymous_session_id" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
anonymous_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" \
    -v session_fingerprint="$anonymous_session_fingerprint" <<'SQL'
SELECT binding.status, binding.principal_ref IS NULL,
       binding.authorization_context_ref IS NULL,
       binding.auth_epoch, binding.credential_generation,
       (SELECT count(*) FROM xshield.credential_bindings credential
        WHERE credential.tenant_id = binding.tenant_id
          AND credential.site_id = binding.site_id
          AND credential.binding_id = binding.binding_id),
       (SELECT count(*) FROM xshield.audit_outbox outbox
        WHERE outbox.tenant_id = binding.tenant_id
          AND outbox.site_id = binding.site_id
          AND outbox.aggregate_ref = binding.binding_id
          AND outbox.event_type = 'session.created'
          AND outbox.envelope->'payload' @> '{"status":"anonymous","auth_epoch":0,"credential_generation":0,"reason_code":"SESSION_CREATED"}')
FROM xshield.auth_bindings binding
WHERE binding.tenant_id = 'tenant_gateway'
  AND binding.site_id = 'site_gateway'
  AND binding.waf_sid_fingerprint = decode(:'session_fingerprint', 'hex');
SQL
)
[[ "$anonymous_state" == "anonymous|t|t|0|0|0|1" ]]

anonymous_rate_status=$(curl -sS -D "$test_dir/anonymous-rate.headers" \
    -o "$test_dir/anonymous-rate.json" -w '%{http_code}' \
    http://127.0.0.1:6288/account)
[[ "$anonymous_rate_status" == "429" ]]
grep -q '"reason_code":"ANONYMOUS_SESSION_RATE_EXCEEDED"' \
    "$test_dir/anonymous-rate.json"
refute grep -qi '^set-cookie: __Host-xshield_sid=' "$test_dir/anonymous-rate.headers"
anonymous_rate_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT count(*), min(used), max(used)
FROM xshield.anonymous_session_rate_limits
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway';
SQL
)
[[ "$anonymous_rate_state" == "2|1|1" ]]

anonymous_repeat_status=$(curl -sS -D "$test_dir/anonymous-repeat.headers" \
    -o "$test_dir/anonymous-repeat.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$anonymous_session_id" \
    http://127.0.0.1:6288/account)
[[ "$anonymous_repeat_status" == "401" ]]
refute grep -qi '^set-cookie: __Host-xshield_sid=' "$test_dir/anonymous-repeat.headers"
anonymous_substitution_status=$(curl -sS -o "$test_dir/anonymous-substitution.json" \
    -w '%{http_code}' -H "Cookie: __Host-xshield_sid=$anonymous_session_id" \
    -H 'Authorization: Bearer unbound-business-token' \
    http://127.0.0.1:6288/account)
[[ "$anonymous_substitution_status" == "403" ]]
grep -q '"reason_code":"AUTH_BINDING_MISMATCH"' \
    "$test_dir/anonymous-substitution.json"

login_status=$(curl -sS -D "$test_dir/login.headers" -o "$test_dir/login.body" -w '%{http_code}' \
    -X POST http://127.0.0.1:6288/login)
[[ "$login_status" == "200" ]]
grep -qi '^cache-control: private, no-store' "$test_dir/login.headers"
grep -qi '^pragma: no-cache' "$test_dir/login.headers"
grep -qi '^set-cookie: __Host-xshield_sid=.*; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600' \
    "$test_dir/login.headers"
login_session_id=$(sed -n \
    's/^[Ss]et-[Cc]ookie: __Host-xshield_sid=\([^;]*\).*/\1/p' \
    "$test_dir/login.headers")
login_bearer=$(python3 -c \
    'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["access_token"])' \
    "$test_dir/login.body")
[[ "$login_session_id" == ses_* ]]
[[ "$login_bearer" == "login-business-token" ]]
login_session_fingerprint=$(printf '%s' "$login_session_id" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
login_bearer_fingerprint=$(printf '%s' "$login_bearer" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
login_binding_count=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" \
    -v session_fingerprint="$login_session_fingerprint" \
    -v bearer_fingerprint="$login_bearer_fingerprint" <<'SQL'
SELECT count(*)
FROM xshield.auth_bindings binding
JOIN xshield.credential_bindings credential
  USING (tenant_id, site_id, binding_id)
JOIN xshield.audit_outbox outbox
  ON outbox.aggregate_ref = binding.binding_id
WHERE binding.tenant_id = 'tenant_gateway'
  AND binding.site_id = 'site_gateway'
  AND binding.principal_ref = 'principal_login'
  AND binding.authorization_context_ref = 'tenant_gateway:user'
  AND binding.auth_epoch = 1
  AND binding.credential_generation = 1
  AND binding.waf_sid_fingerprint = decode(:'session_fingerprint', 'hex')
  AND credential.credential_kind = 'bearer'
  AND credential.fingerprint = decode(:'bearer_fingerprint', 'hex')
  AND outbox.event_type = 'binding.created'
  AND outbox.envelope->'payload' @> '{"principal_ref":"principal_login","authorization_context_ref":"tenant_gateway:user","auth_epoch":1,"credential_generation":1,"reason_code":"BINDING_CREATED"}';
SQL
)
[[ "$login_binding_count" == "1" ]]

curl -sS -o "$test_dir/sensor-bootstrap.json" \
    http://127.0.0.1:6288/__xshield/v1/bootstrap
python3 - "$test_dir/sensor-bootstrap.json" "$test_dir/sensor-event.json" <<'PY'
import json
import pathlib
import sys

bootstrap = json.loads(pathlib.Path(sys.argv[1]).read_text())
event = {
    "events": [{
        "sensor_version": bootstrap["sensor_version"],
        "build_ref": bootstrap["build_ref"],
        "page_handle": bootstrap["page_handle"],
        "navigation_id": bootstrap["navigation_id"],
        "action_hint": None,
        "client_request_id": None,
        "client_event_seq": 1,
        "visibility": "visible",
        "event_type": "PAGE_READY",
        "callsite_fingerprint": None,
    }]
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(event, separators=(",", ":")))
PY
sensor_prepare_status=$(curl -sS -D "$test_dir/sensor-prepare.headers" \
    -o "$test_dir/sensor-prepare.json" -w '%{http_code}' \
    -H 'Origin: http://127.0.0.1:6288' \
    -H 'Content-Type: application/json' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    --data-binary @"$test_dir/sensor-event.json" \
    http://127.0.0.1:6288/__xshield/v1/events/prepare)
[[ "$sensor_prepare_status" == "202" ]]
grep -q '"status":"accepted"' "$test_dir/sensor-prepare.json"
grep -qi '^cache-control: private, no-store' "$test_dir/sensor-prepare.headers"
sensor_wrong_origin_status=$(curl -sS -o "$test_dir/sensor-wrong-origin.json" \
    -w '%{http_code}' -H 'Origin: https://attacker.example' \
    -H 'Content-Type: application/json' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    --data-binary @"$test_dir/sensor-event.json" \
    http://127.0.0.1:6288/__xshield/v1/events/prepare)
[[ "$sensor_wrong_origin_status" == "400" ]]
grep -q 'SENSOR_OBSERVATION_INVALID' "$test_dir/sensor-wrong-origin.json"
sensor_missing_session_status=$(curl -sS -o "$test_dir/sensor-missing-session.json" \
    -w '%{http_code}' -H 'Origin: http://127.0.0.1:6288' \
    -H 'Content-Type: application/json' \
    --data-binary @"$test_dir/sensor-event.json" \
    http://127.0.0.1:6288/__xshield/v1/events/prepare)
[[ "$sensor_missing_session_status" == "401" ]]
grep -q 'AUTH_REQUIRED' "$test_dir/sensor-missing-session.json"
refute grep -q '/__xshield/v1/events/prepare' "$test_dir/origin.log"

new_account_status=$(curl -sS -o "$test_dir/new-account.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    http://127.0.0.1:6288/new-account)
[[ "$new_account_status" == "200" ]]
login_action_ref=$(python3 -c \
    'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["orders"][0]["_xshield_action_ref"])' \
    "$test_dir/new-account.body")
[[ "$login_action_ref" == action.* ]]

# A grant-issuing root list admits no query string: the caller must not choose
# whose objects it lists, because every item it returns becomes a grant.
new_account_query_status=$(curl -sS -o "$test_dir/new-account-query.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    'http://127.0.0.1:6288/new-account?customer=other')
[[ "$new_account_query_status" == "403" ]]
grep -q '"reason_code":"FIELD_NOT_ALLOWED"' "$test_dir/new-account-query.json"
refute grep -q 'customer=other' "$test_dir/origin.log"

# A route that declares pagination parameters takes exactly those, digits only,
# and the origin receives a query the edge rebuilt (declared order), never the
# raw one. Anything else is the same FIELD_NOT_ALLOWED denial and never
# reaches the origin.
paged_status=$(curl -sS -o "$test_dir/paged.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    'http://127.0.0.1:6288/paged-account?page=2&page_size=20')
[[ "$paged_status" == "200" ]]
grep -q '"_xshield_action_ref"' "$test_dir/paged.body"
paged_reordered_status=$(curl -sS -o "$test_dir/paged-reordered.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    'http://127.0.0.1:6288/paged-account?page_size=20&page=2')
[[ "$paged_reordered_status" == "200" ]]
paged_bare_status=$(curl -sS -o "$test_dir/paged-bare.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    http://127.0.0.1:6288/paged-account)
[[ "$paged_bare_status" == "200" ]]
while IFS= read -r denied_query; do
    denied_status=$(curl -sS -g -o "$test_dir/paged-denied.json" -w '%{http_code}' \
        -H "Cookie: __Host-xshield_sid=$login_session_id" \
        -H "Authorization: Bearer $login_bearer" \
        "http://127.0.0.1:6288/paged-account?$denied_query")
    [[ "$denied_status" == "403" ]]
    grep -q '"reason_code":"FIELD_NOT_ALLOWED"' "$test_dir/paged-denied.json"
done <<'QUERIES'
customerId=B
page=2&customerId=B
page=02
page=0
page=10001
page_size=51
page=1&page=1
page=%31
pag%65=1
page=1;page_size=2
page=1&&page_size=2
page[]=1
page=+1
page=
page
QUERIES
refute grep -q 'customerId' "$test_dir/origin.log"
refute grep -q 'page=02' "$test_dir/origin.log"
refute grep -q 'page_size=51' "$test_dir/origin.log"
[[ $(grep -c '^GET /paged-account?page=2&page_size=20$' "$test_dir/origin.log") == "2" ]]
[[ $(grep -c '^GET /paged-account$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^GET /paged-account' "$test_dir/origin.log") == "3" ]]

refresh_status=$(curl -sS -D "$test_dir/refresh.headers" -o "$test_dir/refresh.body" \
    -w '%{http_code}' -X POST \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    http://127.0.0.1:6288/refresh)
[[ "$refresh_status" == "200" ]]
grep -qi '^cache-control: private, no-store' "$test_dir/refresh.headers"
refute grep -qi '^set-cookie: __Host-xshield_sid=' "$test_dir/refresh.headers"
refreshed_bearer=$(python3 -c \
    'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["access_token"])' \
    "$test_dir/refresh.body")
[[ "$refreshed_bearer" == "refreshed-business-token" ]]
refreshed_bearer_fingerprint=$(printf '%s' "$refreshed_bearer" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
refresh_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" \
    -v old_fingerprint="$login_bearer_fingerprint" \
    -v new_fingerprint="$refreshed_bearer_fingerprint" <<'SQL'
SELECT binding.credential_generation,
       (SELECT count(*) FROM xshield.credential_bindings credential
        WHERE credential.tenant_id = binding.tenant_id
          AND credential.site_id = binding.site_id
          AND credential.binding_id = binding.binding_id
          AND credential.generation = 1 AND credential.status = 'revoked'
          AND credential.fingerprint = decode(:'old_fingerprint', 'hex')),
       (SELECT count(*) FROM xshield.credential_bindings credential
        WHERE credential.tenant_id = binding.tenant_id
          AND credential.site_id = binding.site_id
          AND credential.binding_id = binding.binding_id
          AND credential.generation = 2 AND credential.status = 'active'
          AND credential.fingerprint = decode(:'new_fingerprint', 'hex')),
       (SELECT count(*) FROM xshield.audit_outbox outbox
        WHERE outbox.aggregate_ref = binding.binding_id
          AND outbox.tenant_id = binding.tenant_id
          AND outbox.site_id = binding.site_id
          AND outbox.event_type = 'identity.refreshed'
          AND outbox.envelope->'payload' @> '{"principal_ref":"principal_login","authorization_context_ref":"tenant_gateway:user","auth_epoch":1,"previous_credential_generation":1,"credential_generation":2,"rotation_reason":"same_context_refresh","reason_code":"IDENTITY_REFRESHED"}'
          AND outbox.envelope->'payload'->'previous_credentials' @>
            jsonb_build_array(jsonb_build_object(
              'kind', 'bearer', 'fingerprint', :'old_fingerprint'))
          AND outbox.envelope->'payload'->'credentials' @>
            jsonb_build_array(jsonb_build_object(
              'kind', 'bearer', 'fingerprint', :'new_fingerprint')))
FROM xshield.auth_bindings binding
WHERE binding.tenant_id = 'tenant_gateway'
  AND binding.site_id = 'site_gateway'
  AND binding.principal_ref = 'principal_login';
SQL
)
[[ "$refresh_state" == "2|1|1|1" ]]

old_bearer_status=$(curl -sS -o "$test_dir/old-bearer.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $login_bearer" \
    http://127.0.0.1:6288/new-account)
[[ "$old_bearer_status" == "403" ]]
grep -q '"reason_code":"AUTH_BINDING_MISMATCH"' "$test_dir/old-bearer.json"

refreshed_grant_status=$(curl -sS -o "$test_dir/refreshed-grant.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $refreshed_bearer" \
    -H "X-Xshield-Action-Ref: $login_action_ref" \
    'http://127.0.0.1:6288/orders?order_id=order-refresh')
[[ "$refreshed_grant_status" == "404" ]]

# The origin answers this refresh with a different principal, which a refresh
# must never do. The edge refuses to deliver that reply: the client gets a bare
# 502 and none of the origin's body, and (checked below) the generation stays.
refresh_switch_status=$(curl -sS -o "$test_dir/refresh-switch.body" -w '%{http_code}' -X POST \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $refreshed_bearer" \
    http://127.0.0.1:6288/refresh-switch)
[[ "$refresh_switch_status" == "502" ]]
[[ ! -s "$test_dir/refresh-switch.body" ]]
refresh_generation=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT credential_generation FROM xshield.auth_bindings
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND principal_ref = 'principal_login';
SQL
)
[[ "$refresh_generation" == "2" ]]

curl -sS -o "$test_dir/account-switch-same.body" -X POST \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $refreshed_bearer" \
    http://127.0.0.1:6288/account-switch-same >/dev/null 2>&1 || true
[[ ! -s "$test_dir/account-switch-same.body" ]]
refresh_generation_after_same=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT credential_generation FROM xshield.auth_bindings
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND principal_ref = 'principal_login';
SQL
)
[[ "$refresh_generation_after_same" == "2" ]]

(
    curl -sS -o "$test_dir/slow-account.body" \
        -H "Cookie: __Host-xshield_sid=$login_session_id" \
        -H "Authorization: Bearer $refreshed_bearer" \
        http://127.0.0.1:6288/slow-account >/dev/null 2>&1 || true
) &
slow_request_pid=$!
for _ in {1..50}; do
    [[ -f "$test_dir/slow.started" ]] && break
    sleep 0.02
done
[[ -f "$test_dir/slow.started" ]]

account_switch_status=$(curl -sS -D "$test_dir/account-switch.headers" \
    -o "$test_dir/account-switch.body" -w '%{http_code}' -X POST \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $refreshed_bearer" \
    http://127.0.0.1:6288/account-switch)
[[ "$account_switch_status" == "200" ]]
grep -qi '^cache-control: private, no-store' "$test_dir/account-switch.headers"
refute grep -qi '^set-cookie: __Host-xshield_sid=' "$test_dir/account-switch.headers"
context_admin_bearer=$(python3 -c \
    'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["access_token"])' \
    "$test_dir/account-switch.body")
[[ "$context_admin_bearer" == "context-admin-business-token" ]]
context_admin_fingerprint=$(printf '%s' "$context_admin_bearer" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
switch_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" \
    -v old_fingerprint="$refreshed_bearer_fingerprint" \
    -v new_fingerprint="$context_admin_fingerprint" <<'SQL'
SELECT binding.principal_ref, binding.authorization_context_ref,
       binding.auth_epoch, binding.credential_generation,
       (SELECT count(*) FROM xshield.credential_bindings credential
        WHERE credential.tenant_id = binding.tenant_id
          AND credential.site_id = binding.site_id
          AND credential.binding_id = binding.binding_id
          AND credential.generation = 2 AND credential.status = 'revoked'
          AND credential.fingerprint = decode(:'old_fingerprint', 'hex')),
       (SELECT count(*) FROM xshield.credential_bindings credential
        WHERE credential.tenant_id = binding.tenant_id
          AND credential.site_id = binding.site_id
          AND credential.binding_id = binding.binding_id
          AND credential.generation = 3 AND credential.status = 'active'
          AND credential.fingerprint = decode(:'new_fingerprint', 'hex')),
       (SELECT count(*) FROM xshield.audit_outbox outbox
        WHERE outbox.aggregate_ref = binding.binding_id
          AND outbox.event_type = 'epoch.changed'
          AND outbox.tenant_id = binding.tenant_id
          AND outbox.site_id = binding.site_id
          AND outbox.envelope->'payload' @> '{"previous_principal_ref":"principal_login","principal_ref":"principal_login","previous_authorization_context_ref":"tenant_gateway:user","authorization_context_ref":"tenant_gateway:admin","previous_auth_epoch":1,"auth_epoch":2,"previous_credential_generation":2,"credential_generation":3,"rotation_reason":"account_context_changed","reason_code":"IDENTITY_CONTEXT_CHANGED"}'
          AND outbox.envelope->'payload'->'previous_credentials' @>
            jsonb_build_array(jsonb_build_object(
              'kind', 'bearer', 'fingerprint', :'old_fingerprint'))
          AND outbox.envelope->'payload'->'credentials' @>
            jsonb_build_array(jsonb_build_object(
              'kind', 'bearer', 'fingerprint', :'new_fingerprint')))
FROM xshield.auth_bindings binding
WHERE binding.tenant_id = 'tenant_gateway'
  AND binding.site_id = 'site_gateway'
  AND binding.principal_ref = 'principal_login';
SQL
)
[[ "$switch_state" == "principal_login|tenant_gateway:admin|2|3|1|1|1" ]]

wait "$slow_request_pid"
[[ ! -s "$test_dir/slow-account.body" ]]
late_grant_count=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT count(*) FROM xshield.response_evidence
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND source_operation_id = 'account.slow';
SQL
)
[[ "$late_grant_count" == "0" ]]

account_a_after_switch=$(curl -sS -o "$test_dir/account-a-after-switch.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $refreshed_bearer" \
    http://127.0.0.1:6288/whoami)
[[ "$account_a_after_switch" == "403" ]]
context_admin_status=$(curl -sS -o "$test_dir/context-admin.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $context_admin_bearer" \
    http://127.0.0.1:6288/whoami)
[[ "$context_admin_status" == "404" ]]
old_epoch_grant_status=$(curl -sS -o "$test_dir/old-epoch-grant.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $context_admin_bearer" \
    -H "X-Xshield-Action-Ref: $login_action_ref" \
    'http://127.0.0.1:6288/orders?order_id=order-refresh')
[[ "$old_epoch_grant_status" == "403" ]]
grep -q '"reason_code":"UI_ACTION_NOT_AVAILABLE"' "$test_dir/old-epoch-grant.json"

# The origin's login reply names an identity the route does not accept. The edge
# must not deliver it: a bare 502 (or, if the connection is cut first, a failed
# transfer), never the origin's bytes, and no binding for that principal below.
set +e
invalid_login_status=$(curl -sS -o "$test_dir/login-invalid.body" -w '%{http_code}' \
    -X POST http://127.0.0.1:6288/login-invalid 2>/dev/null)
invalid_login_exit=$?
set -e
[[ "$invalid_login_exit" != "0" || "$invalid_login_status" == "502" ]]
[[ ! -s "$test_dir/login-invalid.body" ]]
refute grep -q 'principal_invalid' "$test_dir/login-invalid.body"
invalid_login_binding_count=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT count(*) FROM xshield.auth_bindings
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND principal_ref = 'principal_invalid';
SQL
)
[[ "$invalid_login_binding_count" == "0" ]]

buffered_status=$(curl -sS -o "$test_dir/buffered-valid.json" -w '%{http_code}' \
    http://127.0.0.1:6288/buffered-valid)
[[ "$buffered_status" == "200" ]]
[[ $(<"$test_dir/buffered-valid.json") == '{"ok":true}' ]]

# A body that is not the JSON the route promises is never released: the client
# gets a bare 502 and none of the origin's bytes (same as the oversize case below).
invalid_buffer_status=$(curl -sS -o "$test_dir/buffered-invalid.body" -w '%{http_code}' \
    http://127.0.0.1:6288/buffered-invalid)
[[ "$invalid_buffer_status" == "502" ]]
[[ ! -s "$test_dir/buffered-invalid.body" ]]
refute grep -q 'private-invalid-json' "$test_dir/buffered-invalid.body"

oversize_status=$(curl -sS -o "$test_dir/buffered-oversize.body" -w '%{http_code}' \
    http://127.0.0.1:6288/buffered-oversize)
[[ "$oversize_status" == "502" ]]
refute grep -q 'must-not-release' "$test_dir/buffered-oversize.body"

valid_status=$(curl -sS -D "$test_dir/valid.headers" -o "$test_dir/valid.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    http://127.0.0.1:6288/account)
[[ "$valid_status" == "200" ]]
grep -qi '^cache-control: private, no-store' "$test_dir/valid.headers"
grep -qi '^transfer-encoding: chunked' "$test_dir/valid.headers"
refute grep -qi '^content-length:' "$test_dir/valid.headers"
response_action_ref=$(python3 -c \
    'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["orders"][0]["_xshield_action_ref"])' \
    "$test_dir/valid.body")
[[ "$response_action_ref" == action.* ]]

committed_response_grants=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" \
    -v resource_fingerprint="$response_resource_fingerprint" <<'SQL'
SELECT count(*)
FROM xshield.response_evidence evidence
JOIN xshield.ui_actions action
  USING (tenant_id, site_id, response_evidence_id)
JOIN xshield.resource_grants resource_grant
  ON resource_grant.tenant_id = action.tenant_id
 AND resource_grant.site_id = action.site_id
 AND resource_grant.action_ref = action.action_ref
JOIN xshield.audit_outbox outbox
  ON outbox.event_id = resource_grant.source_event_id
WHERE evidence.tenant_id = 'tenant_gateway'
  AND evidence.site_id = 'site_gateway'
  AND evidence.source_operation_id = 'account.root'
  AND evidence.target_operation_id = 'orders.read'
  AND evidence.candidate_count = 2
  AND action.page_evidence_id IS NULL
  AND resource_grant.resource_key_hmac = decode(:'resource_fingerprint', 'hex')
  AND outbox.event_type = 'response_grant.issued'
  AND outbox.envelope->'payload'->>'resource_key_hmac' = :'resource_fingerprint';
SQL
)
[[ "$committed_response_grants" == "1" ]]

response_grant_status=$(curl -sS -o "$test_dir/response-grant.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: $response_action_ref" \
    'http://127.0.0.1:6288/orders?order_id=order-456')
[[ "$response_grant_status" == "404" ]]

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

# A UI-action route that is not a resource route takes only its declared
# pagination parameters, and forwards the rebuilt query.
for allowed_query in 'page=2&page_size=20' 'page_size=20&page=2'; do
    paged_action_status=$(curl -sS -o "$test_dir/paged-action.body" -w '%{http_code}' \
        -H "Cookie: __Host-xshield_sid=$session_id" \
        -H "Authorization: Bearer $bearer" \
        -H "X-Xshield-Action-Ref: action_settings_primary" \
        "http://127.0.0.1:6288/settings?$allowed_query")
    [[ "$paged_action_status" == "404" ]]
done
while IFS= read -r denied_query; do
    denied_action_status=$(curl -sS -g -o "$test_dir/paged-action-denied.json" -w '%{http_code}' \
        -H "Cookie: __Host-xshield_sid=$session_id" \
        -H "Authorization: Bearer $bearer" \
        -H "X-Xshield-Action-Ref: action_settings_primary" \
        "http://127.0.0.1:6288/settings?$denied_query")
    [[ "$denied_action_status" == "403" ]]
    grep -q '"reason_code":"FIELD_NOT_ALLOWED"' "$test_dir/paged-action-denied.json"
done <<'QUERIES'
customerId=B
page=2&customerId=B
page=02
page=1&page=2
page_size=0
QUERIES
refute grep -q 'customerId' "$test_dir/origin.log"
[[ $(grep -c '^GET /settings?page=2&page_size=20$' "$test_dir/origin.log") == "2" ]]

compatibility_status=$(curl -sS -o "$test_dir/compatibility.body" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/octet-stream' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_settings_legacy" \
    --data-binary 'legacy=on&value=1' \
    http://127.0.0.1:6288/settings-legacy)
[[ "$compatibility_status" == "200" ]]
[[ "$(<"$test_dir/compatibility.body")" == '{"ok":true}' ]]

encrypted_fallback_status=$(curl -sS -o "$test_dir/encrypted-fallback.json" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/vnd.xshield.encrypted+json; charset=utf-8' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_settings_legacy" \
    --data-binary '{"invalid":"envelope"}' \
    http://127.0.0.1:6288/settings-legacy)
[[ "$encrypted_fallback_status" == "400" ]]
grep -q '"reason_code":"REQUEST_ENVELOPE_INVALID"' "$test_dir/encrypted-fallback.json"

psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.page_evidence SET build_fingerprint = decode(repeat('c', 64), 'hex') WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND page_evidence_id = 'page_018f2a3b-4c5d-7000-8000-000000000903'" >/dev/null
unapproved_build_status=$(curl -sS -o "$test_dir/unapproved-build.json" -w '%{http_code}' \
    -X POST -H 'Content-Type: application/octet-stream' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_settings_legacy" \
    --data-binary 'legacy=changed' \
    http://127.0.0.1:6288/settings-legacy)
[[ "$unapproved_build_status" == "403" ]]
grep -q '"reason_code":"REQUEST_CRYPTO_BUILD_NOT_APPROVED"' "$test_dir/unapproved-build.json"

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

valid_path_resource_status=$(curl -sS -o "$test_dir/valid-path-resource.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_path_primary" \
    'http://127.0.0.1:6288/path-orders/order%2D123')
[[ "$valid_path_resource_status" == "404" ]]

unknown_path_resource_status=$(curl -sS -o "$test_dir/unknown-path-resource.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_path_primary" \
    'http://127.0.0.1:6288/path-orders/order-999')
[[ "$unknown_path_resource_status" == "403" ]]
grep -q '"reason_code":"CAPABILITY_MISSING"' "$test_dir/unknown-path-resource.json"

encoded_slash_status=$(curl --path-as-is -sS -o "$test_dir/encoded-slash.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H "X-Xshield-Action-Ref: action_order_path_primary" \
    'http://127.0.0.1:6288/path-orders/order%2F123')
[[ "$encoded_slash_status" == "403" ]]
grep -q '"reason_code":"CAPABILITY_MISSING"' "$test_dir/encoded-slash.json"

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
[[ "$valid_share_status" == "200" ]]

psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.share_grants SET status = 'revoked' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND share_id = 'share_018f2a3b-4c5d-7000-8000-000000000908'" >/dev/null
revoked_share_status=$(curl -sS -o "$test_dir/revoked-share.json" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-123')
[[ "$revoked_share_status" == "403" ]]
grep -q '"reason_code":"SHARE_SCOPE_MISMATCH"' "$test_dir/revoked-share.json"

share_issue_rows() {
    psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT (SELECT count(*) FROM xshield.share_grants
        WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
          AND issuance_rule_id = 'record-share-r1'),
       (SELECT count(*) FROM xshield.audit_outbox
        WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
          AND event_type = 'share.issued');
SQL
}

assert_share_issue_blocked() {
    local label=$1 before status result=0
    before=$(share_issue_rows)
    status=$(curl -sS --max-time 10 -o "$test_dir/share-$label.body" -w '%{http_code}' \
        -H "Cookie: __Host-xshield_sid=$session_id" \
        -H "Authorization: Bearer $bearer" \
        -H 'X-Xshield-Action-Ref: action_share_issue_primary' \
        'http://127.0.0.1:6288/share-issue?record_id=record-123' 2>/dev/null) || result=$?
    [[ "$status" != "200" || "$result" != "0" ]]
    refute grep -Eq '"(share_token|ok|padding)"' "$test_dir/share-$label.body" 2>/dev/null
    [[ "$(share_issue_rows)" == "$before" ]]
}

missing_issue_action=$(curl -sS -o "$test_dir/share-missing-action.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    'http://127.0.0.1:6288/share-issue?record_id=record-123')
[[ "$missing_issue_action" == "403" ]]
grep -q '"reason_code":"UI_ACTION_NOT_AVAILABLE"' "$test_dir/share-missing-action.json"
wrong_issue_resource=$(curl -sS -o "$test_dir/share-wrong-resource.json" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H 'X-Xshield-Action-Ref: action_share_issue_primary' \
    'http://127.0.0.1:6288/share-issue?record_id=record-999')
[[ "$wrong_issue_resource" == "403" ]]
grep -q '"reason_code":"CAPABILITY_MISSING"' "$test_dir/share-wrong-resource.json"
refute grep -q '^GET /share-issue' "$test_dir/origin.log"
[[ "$(share_issue_rows)" == "0|0" ]]

for share_mode in collision duplicate nonobject truncated oversize content-range attachment; do
    printf '%s' "$share_mode" >"$test_dir/share.mode"
    assert_share_issue_blocked "$share_mode"
done
printf '%s' unsuccessful >"$test_dir/share.mode"
unsuccessful_share_status=$(curl -sS -o "$test_dir/share-unsuccessful.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H 'X-Xshield-Action-Ref: action_share_issue_primary' \
    'http://127.0.0.1:6288/share-issue?record_id=record-123')
[[ "$unsuccessful_share_status" == "422" ]]
[[ "$(<"$test_dir/share-unsuccessful.body")" == '{"error":"share_declined"}' ]]
[[ "$(share_issue_rows)" == "0|0" ]]

printf '%s' valid >"$test_dir/share.mode"
issued_share_status=$(curl -sS -D "$test_dir/share-issued.headers" \
    -o "$test_dir/share-issued.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$session_id" \
    -H "Authorization: Bearer $bearer" \
    -H 'X-Xshield-Action-Ref: action_share_issue_primary' \
    'http://127.0.0.1:6288/share-issue?record_id=record-123')
[[ "$issued_share_status" == "200" ]]
grep -qi '^cache-control: private, no-store' "$test_dir/share-issued.headers"
refute grep -Eqi '^(content-length|etag):' "$test_dir/share-issued.headers"
issued_share_token=$(python3 - "$test_dir/share-issued.body" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as response:
    body = json.load(response)
assert set(body) == {"ok", "share_token"} and body["ok"] is True
assert re.fullmatch(r"[0-9a-f]{64}", body["share_token"])
print(body["share_token"])
PY
)
issued_share_fingerprint=$(printf '%s\0%s\0%s\0%s\0' \
    'xshield-share-token-v1' 'tenant_gateway' 'site_gateway' "$issued_share_token" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$fingerprint_key" -binary \
    | od -An -tx1 | tr -d ' \n')
issued_share_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" \
    -v fingerprint="$issued_share_fingerprint" \
    -v resource_fingerprint="$share_resource_fingerprint" \
    -v request_id="$(awk 'tolower($1) == "x-xshield-request-id:" {gsub("\r", "", $2); print $2}' "$test_dir/share-issued.headers")" <<'SQL'
SELECT count(*), count(*) FILTER (WHERE
    share.status = 'active' AND share.issuer_auth_epoch = 1
    AND share.resource_key_hmac = decode(:'resource_fingerprint', 'hex')
    AND share.operation_id = 'records.share.read' AND share.view_id = 'shared_summary'
    AND share.use_policy = 'reusable_read'
    AND share.expires_at > clock_timestamp()
    AND share.expires_at <= source.expires_at
    AND share.expires_at <= share.issued_at + interval '300 seconds'
    AND outbox.aggregate_ref = share.share_id
    AND outbox.envelope @> '{"schema_version":3,"producer_id":"gateway-share-grant","producer_seq":1,"request_seq":1,"policy_revision":"policy-r1","example_only":false,"payload":{"stage":"share_grant","outcome":"PASS","reason_code":"SHARE_ISSUED","issuer_auth_epoch":1,"issuer_grant_id":"grant_018f2a3b-4c5d-7000-8000-000000000925","issuance_rule_id":"record-share-r1","issuer_operation_id":"records.share.issue","issuer_view_profile":"share_controls","resource_type":"record","operation_id":"records.share.read","view_profile":"shared_summary","method":"GET","use_policy":"reusable_read"}}'
    AND outbox.envelope->>'request_id' = :'request_id'
    AND outbox.envelope->>'event_id' = outbox.event_id
    AND outbox.envelope->>'producer_boot_id' = outbox.event_id
    AND outbox.envelope->'payload'->>'share_id' = share.share_id
    AND outbox.envelope->'payload'->>'resource_key_hmac' = :'resource_fingerprint'
    AND NOT (outbox.envelope->'payload' ?| ARRAY['token', 'share_token', 'token_fingerprint', 'issuance_key'])
)
FROM xshield.share_grants share
JOIN xshield.resource_grants source
  ON (source.tenant_id, source.site_id, source.grant_id) =
     (share.tenant_id, share.site_id, share.issuer_grant_id)
JOIN xshield.audit_outbox outbox
  ON (outbox.tenant_id, outbox.site_id, outbox.event_id) =
     (share.tenant_id, share.site_id, share.source_event_id)
WHERE share.tenant_id = 'tenant_gateway' AND share.site_id = 'site_gateway'
  AND share.token_fingerprint = decode(:'fingerprint', 'hex')
  AND outbox.event_type = 'share.issued';
SQL
)
[[ "$issued_share_state" == "1|1" ]]
[[ "$(share_issue_rows)" == "1|1" ]]

issued_share_read_status=$(curl -sS -o "$test_dir/share-issued-read.body" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $issued_share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-123')
[[ "$issued_share_read_status" == "200" ]]
[[ "$(<"$test_dir/share-issued-read.body")" == '{"record_id":"record-123","summary":"shared"}' ]]
issued_share_wrong_resource=$(curl -sS -o "$test_dir/share-issued-wrong-resource.json" -w '%{http_code}' \
    -H "X-Xshield-Share-Token: $issued_share_token" \
    'http://127.0.0.1:6288/shared-record?record_id=record-999')
[[ "$issued_share_wrong_resource" == "403" ]]
grep -q '"reason_code":"SHARE_SCOPE_MISMATCH"' "$test_dir/share-issued-wrong-resource.json"
assert_share_issue_blocked capacity
psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.share_grants SET status = 'revoked' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND issuance_rule_id = 'record-share-r1'" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.share_issuance_rules SET status = 'retired' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND rule_id = 'record-share-r1'" >/dev/null
assert_share_issue_blocked retired-rule
psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
    "UPDATE xshield.share_issuance_rules SET status = 'active' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND rule_id = 'record-share-r1'" >/dev/null

# The origin barrier ensures each authority change commits after request admission.
for share_mode in grant-revoked epoch-changed; do
    printf '%s' "$share_mode" >"$test_dir/share.mode"
    assert_share_issue_blocked "$share_mode" &
    share_request_pid=$!
    for _ in {1..100}; do
        [[ -f "$test_dir/share-$share_mode.started" ]] && break
        sleep 0.02
    done
    [[ -f "$test_dir/share-$share_mode.started" ]]
    if [[ "$share_mode" == "grant-revoked" ]]; then
        psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
            "UPDATE xshield.resource_grants SET status = 'revoked' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND grant_id = 'grant_018f2a3b-4c5d-7000-8000-000000000925'" >/dev/null
    else
        psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
            "UPDATE xshield.auth_bindings SET auth_epoch = auth_epoch + 1 WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND binding_id = 'auth_018f2a3b-4c5d-7000-8000-000000000901'" >/dev/null
    fi
    touch "$test_dir/share-$share_mode.release"
    wait "$share_request_pid"
    share_request_pid=""
    [[ -f "$test_dir/share-$share_mode.released" ]]
    if [[ "$share_mode" == "grant-revoked" ]]; then
        psql -X -v ON_ERROR_STOP=1 -d "$test_database" -c \
            "UPDATE xshield.resource_grants SET status = 'active' WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway' AND grant_id = 'grant_018f2a3b-4c5d-7000-8000-000000000925'" >/dev/null
    fi
done
[[ "$(share_issue_rows)" == "1|1" ]]
share_secret_events=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" \
    -v token="$issued_share_token" -v token_fingerprint="$issued_share_fingerprint" \
    -v bearer="$bearer" -v session_id="$session_id" <<'SQL'
SELECT count(*) FROM xshield.audit_outbox
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND (position(:'token' IN envelope::text) > 0
       OR position(:'token_fingerprint' IN envelope::text) > 0
       OR position(:'bearer' IN envelope::text) > 0
       OR position(:'session_id' IN envelope::text) > 0);
SQL
)
[[ "$share_secret_events" == "0" ]]

logout_status=$(curl -sS -D "$test_dir/logout.headers" -o "$test_dir/logout.body" -w '%{http_code}' \
    -X POST \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $context_admin_bearer" \
    http://127.0.0.1:6288/logout)
[[ "$logout_status" == "200" ]]
[[ "$(<"$test_dir/logout.body")" == '{"logged_out":true}' ]]
grep -qi '^cache-control: private, no-store' "$test_dir/logout.headers"
# The logout above ends the login session's binding (not the fixed seeded one):
# it is revoked, no credential of it is left usable, and exactly one
# binding.revoked event was queued for it.
logout_binding_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" \
    -v session_fingerprint="$login_session_fingerprint" <<'SQL'
SELECT binding.status,
       count(DISTINCT credential.generation) FILTER (WHERE credential.status <> 'revoked'),
       count(DISTINCT outbox.event_id) FILTER (WHERE outbox.event_type = 'binding.revoked')
FROM xshield.auth_bindings binding
LEFT JOIN xshield.credential_bindings credential
  ON credential.tenant_id = binding.tenant_id
 AND credential.site_id = binding.site_id
 AND credential.binding_id = binding.binding_id
LEFT JOIN xshield.audit_outbox outbox
  ON outbox.tenant_id = binding.tenant_id
 AND outbox.site_id = binding.site_id
 AND outbox.aggregate_ref = binding.binding_id
WHERE binding.tenant_id = 'tenant_gateway'
  AND binding.site_id = 'site_gateway'
  AND binding.waf_sid_fingerprint = decode(:'session_fingerprint', 'hex')
GROUP BY binding.status;
SQL
)
[[ "$logout_binding_state" == "revoked|0|1" ]]
logout_secret_events=$(psql -X -At -v ON_ERROR_STOP=1 -d "$test_database" \
    -v bearer="$context_admin_bearer" -v session_id="$login_session_id" <<'SQL'
SELECT count(*) FROM xshield.audit_outbox
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND event_type = 'binding.revoked'
  AND (position(:'bearer' IN envelope::text) > 0
       OR position(:'session_id' IN envelope::text) > 0);
SQL
)
[[ "$logout_secret_events" == "0" ]]
set +e
curl -sS -o "$test_dir/post-logout.body" -w '%{http_code}' \
    -H "Cookie: __Host-xshield_sid=$login_session_id" \
    -H "Authorization: Bearer $context_admin_bearer" \
    http://127.0.0.1:6288/whoami >"$test_dir/post-logout.status"
set -e
[[ "$(<"$test_dir/post-logout.status")" == "403" ]]
grep -q 'AUTH_BINDING_MISMATCH' "$test_dir/post-logout.body"

kill -KILL "$gateway_pid"
wait "$gateway_pid" 2>/dev/null || true
gateway_pid=""
kill "$origin_pid"
wait "$origin_pid" 2>/dev/null || true
origin_pid=""
[[ $(grep -c 'GET /account' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /login$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /login-invalid$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^GET /new-account$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /refresh$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /refresh-switch$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /account-switch$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /account-switch-same$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^POST /logout$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^GET /slow-account$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c '^GET /whoami$' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /settings' "$test_dir/origin.log") == "3" ]]
[[ $(grep -c '^POST /settings-legacy$' "$test_dir/origin.log") == "1" ]]
grep -q '^Body=legacy=on&value=1$' "$test_dir/origin.log"
[[ $(grep -c 'GET /orders?order_id=order-123' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /orders?order_id=order-456' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /orders?order_id=order-refresh' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /path-orders/order%2D123' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'POST /service/report' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /shared-record?record_id=record-123' "$test_dir/origin.log") == "2" ]]
[[ $(grep -c '^GET /share-issue?record_id=record-123$' "$test_dir/origin.log") == "13" ]]
[[ $(grep -c 'GET /buffered-valid' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /buffered-invalid' "$test_dir/origin.log") == "1" ]]
[[ $(grep -c 'GET /buffered-oversize' "$test_dir/origin.log") == "1" ]]
refute grep -q '__Host-xshield_sid' "$test_dir/origin.log"
refute grep -q 'ActionRef=action_' "$test_dir/origin.log"
refute grep -q 'ServiceCredential=verified-' "$test_dir/origin.log"
refute grep -q 'ShareToken=verified-' "$test_dir/origin.log"
refute grep -q '^ShareToken=.' "$test_dir/origin.log"
refute grep -Fq "$issued_share_token" "$test_dir/origin.log" "$test_dir/gateway.log"
grep -q 'Authorization=Bearer verified-business-token' "$test_dir/origin.log"
[[ -n $(find "$test_dir/journal" -name 'segment-*.xja' -type f -print -quit) ]]

identity_envelope_state=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" \
    -v anonymous_request_id="$(awk 'tolower($1) == "x-xshield-request-id:" {gsub("\r", "", $2); print $2}' "$test_dir/anonymous.headers")" \
    -v login_request_id="$(awk 'tolower($1) == "x-xshield-request-id:" {gsub("\r", "", $2); print $2}' "$test_dir/login.headers")" \
    -v refresh_request_id="$(awk 'tolower($1) == "x-xshield-request-id:" {gsub("\r", "", $2); print $2}' "$test_dir/refresh.headers")" \
    -v switch_request_id="$(awk 'tolower($1) == "x-xshield-request-id:" {gsub("\r", "", $2); print $2}' "$test_dir/account-switch.headers")" <<'SQL'
SELECT count(*), count(*) FILTER (WHERE
    envelope @> '{"schema_version":3,"producer_id":"gateway-identity","producer_seq":1,"request_seq":1,"policy_revision":"policy-r1","example_only":false,"sensitivity":"SENSITIVE","integrity":{"state":"pending","previous_hash":null,"event_hash":null},"payload":{"stage":"identity_lifecycle","outcome":"PASS"}}'
    AND envelope->>'event_id' = event_id
    AND envelope->>'event_type' = event_type
    AND envelope->>'tenant_id' = tenant_id
    AND envelope->>'site_id' = site_id
    AND envelope->'payload'->>'binding_id' = aggregate_ref
    AND envelope->>'request_id' = CASE event_type
        WHEN 'session.created' THEN :'anonymous_request_id'
        WHEN 'binding.created' THEN :'login_request_id'
        WHEN 'identity.refreshed' THEN :'refresh_request_id'
        WHEN 'epoch.changed' THEN :'switch_request_id' END
    AND envelope->>'producer_boot_id' = envelope->>'request_id'
    AND envelope->>'request_id' ~ '^req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND envelope->>'trace_id' ~ '^[0-9a-f]{32}$'
    AND envelope->>'span_id' = left(envelope->>'trace_id', 16)
    AND envelope->'cause_event_ids' = '[]'::jsonb
    AND envelope->'evidence_refs' = '[]'::jsonb
    AND envelope->>'observed_at' = envelope->>'occurred_at'
    AND envelope->>'occurred_at' ~ 'Z$'
    AND (envelope->>'occurred_at')::timestamptz BETWEEN
        created_at - interval '1 minute' AND created_at + interval '1 minute'
)
FROM xshield.audit_outbox
WHERE tenant_id = 'tenant_gateway' AND site_id = 'site_gateway'
  AND event_type IN ('session.created', 'binding.created', 'identity.refreshed', 'epoch.changed');
SQL
)
[[ "$identity_envelope_state" == "4|4" ]]

XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-worker --lib postgres_gateway_identity_outbox_publishing -- --ignored

if [[ -n "${XSHIELD_TEST_CLICKHOUSE_URL:-}" ]]; then
    XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
        cargo test -p xshield-worker --lib real_gateway_response_grant_outbox_delivery -- --ignored
else
    echo "real gateway response-grant ClickHouse delivery skipped: set XSHIELD_TEST_CLICKHOUSE_URL"
fi

echo "gateway identity integration passed"
