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
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
database_base_url=${database_base_url%/}

cleanup() {
    if [ -n "${XSHIELD_TEST_DATABASE_BASE_URL:-}" ]; then
        dropdb --if-exists --maintenance-db="$database_base_url/postgres" "$test_database" >/dev/null
        dropdb --if-exists --maintenance-db="$database_base_url/postgres" "$control_database" >/dev/null
    else
        dropdb --if-exists "$test_database" >/dev/null
        dropdb --if-exists "$control_database" >/dev/null
    fi
}
trap cleanup EXIT INT TERM

# Each suite gets a migrated database of its own: the control plane's tests fail when the
# PostgreSQL crate's tests have already written to the same database.
migrate() {
    if [ -n "${XSHIELD_TEST_DATABASE_BASE_URL:-}" ]; then
        createdb --maintenance-db="$database_base_url/postgres" "$1"
        for migration in "$repo_root"/migrations/*.sql; do
            psql -X -v ON_ERROR_STOP=1 -d "$database_base_url/$1" -f "$migration"
        done
    else
        createdb "$1"
        for migration in "$repo_root"/migrations/*.sql; do
            psql -X -v ON_ERROR_STOP=1 -d "$1" -f "$migration"
        done
    fi
}
migrate "$test_database"
migrate "$control_database"

# The PostgreSQL crate's database-gated tests are `#[ignore]`d `#[cfg(test)]`
# modules inside src/, so `--lib -- --ignored` runs exactly them.
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --lib -- --ignored

# The control plane's database-gated tests run on their own migrated database
# (XSHIELD_DATABASE_URL) or create scratch databases on the server
# (XSHIELD_TEST_DATABASE_BASE_URL).
XSHIELD_DATABASE_URL="$database_base_url/$control_database" \
XSHIELD_TEST_DATABASE_BASE_URL="$database_base_url" \
    cargo test -p xshield-control --lib -- --ignored

XSHIELD_TEST_DATABASE_BASE_URL="$database_base_url" \
    cargo test -p xshield-control --test migrations -- --ignored

XSHIELD_TEST_DATABASE_BASE_URL="$database_base_url" \
    cargo test -p xshield-edge --test postgres -- --ignored
