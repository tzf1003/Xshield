#!/usr/bin/env python3
"""Exercise the local migration runner using only owned temporary databases.

Requires the running development PostgreSQL container. Copies migration sources
only for checksum corruption tests; existing developer databases stay untouched.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parent.parent
PROJECT = os.environ.get('XSHIELD_DEV_COMPOSE_PROJECT', 'xshield-dev')
USER = os.environ.get('XSHIELD_DEV_POSTGRES_USER', 'xshield_dev')
COMPOSE = ['docker', 'compose', '-p', PROJECT, '-f', str(ROOT / 'docker-compose.dev.yml'), 'exec', '-T', 'postgres']
owned = []

def command(args, data=None):
    return subprocess.run(args, input=data, text=True, capture_output=True)

def sql(db, statement):
    result = command(COMPOSE + ['psql', '-XqAt', '-v', 'ON_ERROR_STOP=1', '-U', USER, '-d', db], statement)
    if result.returncode: raise RuntimeError(result.stderr)
    return result.stdout.strip()

def database(phase=48):
    db = 'xshield_migration_test_' + uuid.uuid4().hex[:10]
    result = command(COMPOSE + ['createdb', '-U', USER, db])
    if result.returncode: raise RuntimeError(result.stderr)
    owned.append(db)
    for path in sorted((ROOT / 'migrations').glob('*.sql')):
        if int(path.name[:4]) <= phase: sql(db, path.read_text())
    return db

def migrate(db, root=ROOT, error=None):
    result = command(['bash', str(root / 'scripts/migrate_dev_postgres.sh'), PROJECT, str(ROOT / 'docker-compose.dev.yml'), USER, db])
    if error:
        assert result.returncode != 0 and error in result.stderr, result.stdout + result.stderr
    else:
        assert result.returncode == 0, result.stdout + result.stderr
    return result

def main():
    fresh = database()
    migrate(fresh)
    assert sql(fresh, 'SELECT count(*) FROM xshield.dev_schema_migrations') == '8'
    migrate(fresh)
    assert sql(fresh, 'SELECT count(*) FROM xshield.dev_schema_migrations') == '8'
    print('PASS initialized schema adoption and repeated startup', flush=True)
    old = database(40)
    sql(old, 'CREATE TABLE public.migration_sentinel (id int PRIMARY KEY, payload text); INSERT INTO public.migration_sentinel VALUES (1, \'preserve\');')
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(migrate, [old, old]))
    assert sql(old, 'SELECT count(*) FROM xshield.dev_schema_migrations') == '8'
    assert sql(old, 'SELECT payload FROM public.migration_sentinel') == 'preserve'
    print('PASS old baseline upgrade, concurrent startup, preserved rows', flush=True)
    populated = database(41)
    sql(populated, """
INSERT INTO xshield.protected_site_configs (
 tenant_id, site_id, display_name, public_origin, upstream_address, upstream_server_name,
 upstream_tls, listen_port, entry_path, security_entry, sensor_enabled, policy_revision,
 status, revision, config_digest, updated_by, idempotency_digest, request_digest
) VALUES ('tenant_preserve', 'site_preserve', 'Preserved site', 'https://example.test',
 '127.0.0.1:8080', 'example.test', false, 6100, '/', 'ui_action_required', false,
 'policy-v1', 'draft', 7, decode(repeat('a',64),'hex'), 'fixture-author',
 decode(repeat('b',64),'hex'), decode(repeat('c',64),'hex'));
""")
    before = sql(populated, "SELECT display_name || revision::text || encode(config_digest, 'hex') FROM xshield.protected_site_configs")
    migrate(populated)
    assert before == sql(populated, "SELECT display_name || revision::text || encode(config_digest, 'hex') FROM xshield.protected_site_configs")
    assert sql(populated, 'SELECT revision FROM xshield.site_policy_revisions') == '7'
    tables = ['protected_site_configs', 'protected_sites', 'site_policy_revisions']
    def snapshot():
        return {t: sql(populated, "SELECT coalesce(json_agg(t ORDER BY t::text), '[]') FROM xshield." + t + ' t') for t in tables}
    rows = snapshot()
    migrate(populated)
    assert rows == snapshot()
    print('PASS populated site upgrades preserve configuration, version and repeated-start rows', flush=True)
    partial = database(40)
    sql(partial, 'CREATE TABLE xshield.protected_site_configs (tenant_id text);')
    migrate(partial, error='0041 is partially applied')
    assert sql(partial, "SELECT to_regclass('xshield.site_port_leases') IS NULL") == 't'
    print('PASS partial migration blocks later writes', flush=True)
    missing_base = database(0)
    migrate(missing_base, error='0040 schema mismatch')
    print('PASS incomplete baseline fails before site migrations', flush=True)
    sql(fresh, "UPDATE xshield.dev_schema_migrations SET sha256=repeat('0',64) WHERE migration_id='0048'")
    migrate(fresh, error='0048 checksum mismatch')
    print('PASS ledger checksum mismatch', flush=True)
    sql(old, 'ALTER TABLE xshield.site_apply_intents DROP CONSTRAINT site_apply_intents_approval_id_shape')
    migrate(old, error='0048 schema mismatch')
    print('PASS recorded migrations are revalidated', flush=True)
    with tempfile.TemporaryDirectory(prefix='xshield-migration-source-') as temp:
        root = Path(temp)
        (root / 'scripts').mkdir()
        shutil.copytree(ROOT / 'migrations', root / 'migrations')
        for file in ['migrate_dev_postgres.sh', 'dev_postgres_schema.sql']:
            shutil.copy2(ROOT / 'scripts' / file, root / 'scripts' / file)
        migration = next((root / 'migrations').glob('0041_*.sql'))
        with migration.open('a') as f: f.write('\n-- checksum test\n')
        migrate(partial, root, error='0041 checksum differs')
    print('PASS changed migration file blocks startup', flush=True)
    integration = database()
    env = dict(os.environ, XSHIELD_TEST_DATABASE_URL='postgresql://' + USER + ':' + os.environ.get('XSHIELD_DEV_POSTGRES_PASSWORD', 'xshield_dev') + '@127.0.0.1:' + os.environ.get('XSHIELD_DEV_POSTGRES_PORT', '55432') + '/' + integration)
    subprocess.run(['cargo', 'test', '-p', 'xshield-postgres', '--test', 'site_config', '--offline', '--', '--ignored'], cwd=ROOT, env=env, check=True)
    subprocess.run(['cargo', 'test', '-p', 'xshield-control', '--offline', 'site_admin_http_', '--', '--ignored'], cwd=ROOT, env=env, check=True)
    # Both integration suites use only this owned database, dropped in finally.
    print('PASS actual PostgreSQL site configuration contract', flush=True)

try:
    main()
finally:
    for db in reversed(owned):
        result = command(COMPOSE + ['dropdb', '-U', USER, '--if-exists', db])
        if result.returncode: print('Temporary database cleanup failed: ' + db + ': ' + result.stderr)
