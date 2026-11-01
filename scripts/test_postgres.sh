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

# v4 keeps only site_spec_store and decision_log_store (docs/05-v3-removal.md
# section 5.2); both of their database-gated tests live as `#[cfg(test)]`
# modules inside src/, so `--tests` here covers library unit tests, not a
# `tests/` integration suite (that directory is now empty).
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
XSHIELD_TEST_DATABASE_URL="$database_base_url/$test_database" \
    cargo test -p xshield-postgres --lib -- --ignored
