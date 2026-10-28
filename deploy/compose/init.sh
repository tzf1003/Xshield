#!/usr/bin/env bash
# Prepares the reference Compose deployment (README.md): generates every key
# the stack needs under ./secrets, renders edge-config.json for the tenant and
# site in .env, and issues the short-lived bootstrap bearer.
#
# Re-running keeps existing keys (rotating one means deleting its file and
# following docs/19 19.3) and always issues a fresh bootstrap bearer.
#
# The OIDC client secret comes from the IdP: write it to secrets/oidc_client_secret
# first, or pass it in XSHIELD_OIDC_CLIENT_SECRET for this run.
set -Eeuo pipefail
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

die() { printf 'init.sh: %s\n' "$1" >&2; exit 1; }
[[ -f .env ]] || die 'copy env.example to .env and edit it first'
command -v openssl >/dev/null || die 'openssl is required'

# Only the values this script needs; .env is not sourced as shell.
env_value() {
    local line
    line=$(grep -E "^$1=" .env | tail -n 1) || die "$1 is not set in .env"
    line=${line#*=}
    line=${line#\'}; line=${line%\'}
    printf '%s' "$line"
}
tenant_id=$(env_value XSHIELD_TENANT_ID)
site_id=$(env_value XSHIELD_SITE_ID)
edge_ip=$(env_value XSHIELD_EDGE_IP)
# Same rule as the services' identifiers (letters, digits, _ - .; 1-128).
[[ "$tenant_id" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || die 'XSHIELD_TENANT_ID is not a valid identifier'
[[ "$site_id" =~ ^[A-Za-z0-9_.-]{1,128}$ ]] || die 'XSHIELD_SITE_ID is not a valid identifier'
[[ "$edge_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die 'XSHIELD_EDGE_IP must be an IPv4 address'

# The directory is the access boundary on the host: compose bind-mounts each
# file into containers whose users differ (postgres, clickhouse, uid 10001),
# so the files themselves stay world-readable inside a private directory.
umask 077
mkdir -p secrets
chmod 700 secrets

hex32() { openssl rand -hex 32; }
write_secret() {
    local name=$1 value=$2
    printf '%s\n' "$value" >"secrets/$name.tmp"
    chmod 444 "secrets/$name.tmp"
    mv -f "secrets/$name.tmp" "secrets/$name"
}
generate() {
    [[ -f "secrets/$1" ]] || write_secret "$1" "$2"
}
# Ed25519 seal pair as raw 32-byte hex (xshield-audit-seal / publisher).
seal_pair() {
    local name=$1 der
    [[ -f "secrets/${name}_key" && -f "secrets/${name}_public_key" ]] && return
    der=$(mktemp)
    openssl genpkey -algorithm ed25519 -outform DER -out "$der"
    write_secret "${name}_key" "$(tail -c 32 "$der" | od -An -v -tx1 | tr -d ' \n')"
    write_secret "${name}_public_key" \
        "$(openssl pkey -inform DER -in "$der" -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')"
    rm -f "$der"
}

generate postgres_password "$(openssl rand -hex 24)"
generate clickhouse_password "$(openssl rand -hex 24)"
write_secret database_url \
    "postgresql://xshield:$(head -n 1 secrets/postgres_password)@postgres:5432/xshield"
for key in control_cursor_key control_idempotency_key control_api_key_hash_key \
    control_journal_key edge_journal_key edge_apply_key fingerprint_key \
    share_token_key evidence_key; do
    generate "$key" "$(hex32)"
done
seal_pair edge_seal
seal_pair control_seal

if [[ -n "${XSHIELD_OIDC_CLIENT_SECRET:-}" ]]; then
    write_secret oidc_client_secret "$XSHIELD_OIDC_CLIENT_SECRET"
fi
[[ -s secrets/oidc_client_secret ]] ||
    die 'write the IdP client secret to secrets/oidc_client_secret (or set XSHIELD_OIDC_CLIENT_SECRET)'
chmod 444 secrets/oidc_client_secret

# Bootstrap bearer: control accepts at most a 24-hour lifetime and the window
# is fixed at start, so restart control after re-running this script.
write_secret control_token "$(openssl rand -hex 32)"
now=$(date +%s)
{
    printf 'XSHIELD_CONTROL_TOKEN_ISSUED_AT=%s\n' "$((now - 60))"
    printf 'XSHIELD_CONTROL_TOKEN_EXPIRES_AT=%s\n' "$((now + 86340))"
} >control-token.env
chmod 644 control-token.env

# Static bootstrap configuration: one placeholder route that never serves, so
# the edge starts with its identity runtime and waits for the first apply.
cat >edge-config.json <<JSON
{
  "listen": "${edge_ip}:6400",
  "origin": {"address": "127.0.0.1:1", "server_name": "bootstrap.invalid", "tls": false},
  "tenant_id": "${tenant_id}",
  "site_id": "${site_id}",
  "policy_revision": "bootstrap-r1",
  "audit": {
    "directory": "/var/lib/xshield/edge-audit",
    "key_id": "edge-journal-r1",
    "producer_id": "edge-1",
    "max_bytes": 268435456,
    "high_watermark_bytes": 201326592,
    "segment_max_bytes": 16777216,
    "reconcile_max_records": 1000000
  },
  "identity_store": {"max_connections": 4, "acquire_timeout_ms": 2000},
  "operations": [{
    "operation_id": "bootstrap.reject",
    "method": "GET",
    "path": "/__bootstrap__",
    "admission": "AUTHENTICATED_ROOT"
  }]
}
JSON
chmod 644 edge-config.json

printf '%s\n' 'init.sh: secrets, edge-config.json and the bootstrap bearer are ready' \
    "init.sh: the bootstrap bearer is in $here/secrets/control_token and expires in 24 hours"
