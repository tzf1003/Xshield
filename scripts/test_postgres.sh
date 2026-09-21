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
    cargo test -p xshield-postgres --test calibration_report -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --test calibration_report_retention -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --test calibration_lineage_review -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-gateway --test evidence_capture -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-gateway --test share_issue -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-worker --test evidence_retention -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-worker --lib model_eval::tests::postgres_evaluation -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-worker --lib postgres_outbox_publishing -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-worker --test calibration_vault_reader -- --ignored
if [[ -n "${XSHIELD_TEST_CLICKHOUSE_URL:-}" ]]; then
    XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
        cargo test -p xshield-worker --lib real_retention_outbox_clickhouse_delivery -- --ignored
    XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
        cargo test -p xshield-worker --lib real_outbox_clickhouse_delivery -- --ignored
else
    printf '%s\n' 'ClickHouse outbox integration skipped: XSHIELD_TEST_CLICKHOUSE_URL is not configured.'
fi
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control evidence_manifests_are_scoped_paginated_and_audited -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control case_creation_is_idempotent_bounded_and_audited -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control evidence_access_request_is_idempotent_bounded_and_audited -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control evidence_access_decision_is_independent_short_lived_and_audited -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib evidence_lifecycle -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib evidence_access_inspection -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib evidence_access_list -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control case_evidence_is_durable_idempotent_and_disconnect_safe -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control case_collection_success_is_scoped_and_audited -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control case_list_is_scoped_paginated_audited_and_disconnect_safe -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control case_close_is_durable_revokes_new_access_and_survives_disconnect -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control case_holds_are_scoped_idempotent_paginated_and_audited -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control grant_lookup_reads_redacted_history_and_survives_disconnect -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control binding_lookup_reads_redacted_history_and_survives_disconnect -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib console_ledger_client_reads_postgres_http_contract -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib console_case_client_mutates_postgres_http_contract -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib console_access_client_mutates_postgres_and_reads_vault_http_contract -- --ignored
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-control --lib console_hold_client_mutates_postgres_http_contract -- --ignored
