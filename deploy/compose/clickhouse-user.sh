#!/bin/bash
# ClickHouse first-start hook (docker-entrypoint-initdb.d): the account the
# publishers and control use, with the password from the mounted secret.
set -euo pipefail
password=$(cat /run/secrets/clickhouse_password)
digest=$(printf '%s' "$password" | sha256sum | cut -d' ' -f1)
clickhouse client --multiquery <<SQL
CREATE USER IF NOT EXISTS xshield IDENTIFIED WITH sha256_hash BY '$digest';
GRANT ALL ON xshield.* TO xshield;
SQL
