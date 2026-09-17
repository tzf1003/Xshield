#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_database="xshield_test_${PPID}_${RANDOM}"

cleanup() {
    dropdb --if-exists "$test_database" >/dev/null
}
trap cleanup EXIT INT TERM

createdb "$test_database"
psql -X -v ON_ERROR_STOP=1 -d "$test_database" \
    -f "$repo_root/migrations/0001_m1_identity_grants.sql" \
    -f "$repo_root/tests/postgres/m1_identity_grants.sql"

database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --test identity_refresh -- --ignored
