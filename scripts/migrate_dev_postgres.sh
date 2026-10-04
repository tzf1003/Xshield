#!/usr/bin/env bash
# Local development only. Each DDL change and its ledger row commit together.
set -Eeuo pipefail
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[[ $# -eq 4 ]] || { printf '%s\n' 'usage: migrate_dev_postgres.sh project compose-file user database' >&2; exit 1; }
compose_project=$1
compose_file=$2
postgres_user=$3
postgres_db=$4
if docker compose version >/dev/null 2>&1; then compose='docker compose'
else compose='docker-compose'; fi
run_psql() {
    $compose -p "$compose_project" -f "$compose_file" exec -T postgres \
        psql -X -q -v ON_ERROR_STOP=1 -U "$postgres_user" -d "$postgres_db"
}
emit_migration() {
    local file=$1 migration_id sha256
    migration_id=$(basename "$file" | cut -c1-4)
    if command -v shasum >/dev/null 2>&1; then sha256=$(shasum -a 256 "$file" | awk '{print $1}')
    else sha256=$(sha256sum "$file" | awk '{print $1}'); fi
    cat <<SQL
BEGIN;
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM dev_expected_checksums WHERE phase='$migration_id' AND sha256='$sha256') THEN
    RAISE EXCEPTION 'dev migration $migration_id checksum differs from reviewed schema manifest';
  END IF;
  IF EXISTS (SELECT 1 FROM xshield.dev_schema_migrations WHERE migration_id='$migration_id' AND sha256<>'$sha256') THEN
    RAISE EXCEPTION 'dev migration $migration_id checksum mismatch';
  END IF;
END \$\$;
SELECT EXISTS (SELECT 1 FROM xshield.dev_schema_migrations WHERE migration_id='$migration_id') AS applied \gset
SELECT NOT EXISTS (
  SELECT 1 FROM dev_expected_objects e LEFT JOIN dev_schema_objects a USING(kind,table_name,name)
  WHERE e.phase='$migration_id' AND e.definition IS DISTINCT FROM a.definition
) AS complete \gset
SELECT EXISTS (
  SELECT 1 FROM dev_expected_objects e JOIN dev_schema_objects a USING(kind,table_name,name)
  WHERE e.phase='$migration_id'
) AS partial \gset
\if :applied
SELECT pg_temp.dev_assert_schema('$migration_id');
\elif :complete
INSERT INTO xshield.dev_schema_migrations(migration_id,sha256) VALUES ('$migration_id','$sha256');
\elif :partial
DO \$\$ BEGIN RAISE EXCEPTION 'dev migration $migration_id is partially applied; inspect schema before retrying'; END \$\$;
\else
SQL
    cat "$file"
    cat <<SQL
SELECT pg_temp.dev_assert_schema('$migration_id');
INSERT INTO xshield.dev_schema_migrations(migration_id,sha256) VALUES ('$migration_id','$sha256');
\endif
COMMIT;
SQL
}
{
    # A session lock covers baseline inspection and every migration. PostgreSQL
    # releases it even when the caller exits or ON_ERROR_STOP aborts the stream.
    printf "SELECT pg_advisory_lock(hashtextextended('xshield-dev-migrations',0));\n"
    cat "$repo_root/scripts/dev_postgres_schema.sql"
    printf "SELECT pg_temp.dev_assert_schema('0040');\n"
    cat <<'SQL'
CREATE TABLE IF NOT EXISTS xshield.dev_schema_migrations (
    migration_id text PRIMARY KEY,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
SQL
    for file in "$repo_root"/migrations/004[1-9]_*.sql "$repo_root"/migrations/0050_*.sql; do
        emit_migration "$file"
    done
    printf "SELECT pg_advisory_unlock(hashtextextended('xshield-dev-migrations',0));\n"
} | run_psql
printf '%s\n' 'dev migration: baseline and site schema verified'
