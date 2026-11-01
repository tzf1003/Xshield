#!/usr/bin/env bash
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_database="xshield_test_${PPID}_${RANDOM}"

cleanup() {
    dropdb --if-exists "$test_database" >/dev/null
}
trap cleanup EXIT INT TERM

createdb "$test_database"
for migration in "$repo_root"/migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration"
done

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
    cargo test -p xshield-postgres --test calibration_lineage_review_retention -- --ignored
