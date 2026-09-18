#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_database="xshield_test_${PPID}_${RANDOM}"

cleanup() {
    dropdb --if-exists "$test_database" >/dev/null
}
trap cleanup EXIT INT TERM

createdb "$test_database"
for migration in "$repo_root"/migrations/*.sql; do
    if [[ $(basename "$migration") == "0007_m1_authorization_context.sql" ]]; then
        psql -X -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
INSERT INTO xshield.auth_bindings (
    tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
    auth_epoch, credential_generation, status, absolute_expires_at
) VALUES (
    'tenant_migration', 'site_migration',
    'auth_018f2a3b-4c5d-7000-8000-000000000700',
    decode(repeat('70', 32), 'hex'), 'principal_legacy',
    1, 1, 'active', now() + interval '1 hour'
);
INSERT INTO xshield.credential_bindings (
    tenant_id, site_id, binding_id, generation, credential_kind,
    fingerprint, expires_at, status
) VALUES (
    'tenant_migration', 'site_migration',
    'auth_018f2a3b-4c5d-7000-8000-000000000700',
    1, 'bearer', decode(repeat('71', 32), 'hex'),
    now() + interval '1 hour', 'active'
);
SQL
    fi
    psql -X -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration"
    if [[ $(basename "$migration") == "0007_m1_authorization_context.sql" ]]; then
        legacy_status=$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d "$test_database" <<'SQL'
SELECT binding.status,
       (SELECT credential.status FROM xshield.credential_bindings credential
        WHERE credential.tenant_id = binding.tenant_id
          AND credential.site_id = binding.site_id
          AND credential.binding_id = binding.binding_id),
       (SELECT count(*) FROM xshield.audit_outbox outbox
        WHERE outbox.tenant_id = binding.tenant_id
          AND outbox.site_id = binding.site_id
          AND outbox.aggregate_ref = binding.binding_id
          AND outbox.event_type = 'binding.revoked'
          AND outbox.envelope->>'reason_code' = 'AUTH_BINDING_REVOKED')
FROM xshield.auth_bindings binding
WHERE binding.tenant_id = 'tenant_migration' AND binding.site_id = 'site_migration';
SQL
)
        [[ "$legacy_status" == "revoked|revoked|1" ]]
    fi
done
psql -X -v ON_ERROR_STOP=1 -d "$test_database" \
    -f "$repo_root/tests/postgres/m1_identity_grants.sql"

database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --tests -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control evidence_manifests_are_scoped_paginated_and_audited -- --ignored
