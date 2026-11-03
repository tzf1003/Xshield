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
control_database="xshield_control_${PPID}_${RANDOM}"

cleanup() {
    dropdb --if-exists "$test_database" >/dev/null
    dropdb --if-exists "$control_database" >/dev/null
}
trap cleanup EXIT INT TERM

# Each suite gets a migrated database of its own: the control plane's tests fail when the
# PostgreSQL crate's tests have already written to the same database.
migrate() {
    createdb "$1"
    for migration in "$repo_root"/migrations/*.sql; do
        psql -X -v ON_ERROR_STOP=1 -d "$1" -f "$migration"
    done
}
migrate "$test_database"
migrate "$control_database"

# v4 keeps only site_spec_store and decision_log_store (docs/05-v3-removal.md
# section 5.2); both of their database-gated tests live as `#[cfg(test)]`
# modules inside src/, so `--tests` here covers library unit tests, not a
# `tests/` integration suite (that directory is now empty).
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --lib -- --ignored

# The control plane's database-gated tests (the object map and the impact preview) run on their
# own migrated database, through XSHIELD_DATABASE_URL.
XSHIELD_DATABASE_URL="$database_base_url/$control_database" \
    cargo test -p xshield-control --lib -- --ignored
