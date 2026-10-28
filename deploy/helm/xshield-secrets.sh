#!/usr/bin/env bash
# Writes every key the Helm chart's Secret needs into a directory, one file per
# key, for `kubectl create secret generic <name> --from-file=<directory>`
# (deploy/helm/README.md). The keys never touch the chart values.
#
#   deploy/helm/xshield-secrets.sh <directory>
#
# Generated: the journal, apply, cursor, idempotency, API key hash,
# fingerprint, share token and evidence keys, both Ed25519 seal pairs, and the
# bootstrap bearer with its issue and expiry times. Existing key files are
# kept (rotating one means deleting it and following docs/19 19.3); the bearer
# is issued afresh on every run.
#
# Supplied by you, from the environment on the first run or as files already
# in the directory: XSHIELD_DATABASE_URL (database_url), XSHIELD_CLICKHOUSE_PASSWORD
# (clickhouse_password) and XSHIELD_OIDC_CLIENT_SECRET (oidc_client_secret).
set -Eeuo pipefail

die() { printf 'xshield-secrets.sh: %s\n' "$1" >&2; exit 1; }
[[ $# -eq 1 ]] || die 'usage: xshield-secrets.sh <directory>'
command -v openssl >/dev/null || die 'openssl is required'
umask 077
dir=$1
mkdir -p "$dir"
chmod 700 "$dir"

write_secret() {
    printf '%s' "$2" >"$dir/$1.tmp"
    mv -f "$dir/$1.tmp" "$dir/$1"
}
generate() {
    [[ -f "$dir/$1" ]] || write_secret "$1" "$2"
}
supplied() {
    local key=$1 variable=$2
    if [[ -n "${!variable:-}" ]]; then
        write_secret "$key" "${!variable}"
    fi
    [[ -s "$dir/$key" ]] || die "set $variable or write $dir/$key"
}
# Ed25519 seal pair as raw 32-byte hex (xshield-audit-seal / publisher).
seal_pair() {
    local name=$1 der
    [[ -f "$dir/${name}_key" && -f "$dir/${name}_public_key" ]] && return
    der=$(mktemp)
    openssl genpkey -algorithm ed25519 -outform DER -out "$der"
    write_secret "${name}_key" "$(tail -c 32 "$der" | od -An -v -tx1 | tr -d ' \n')"
    write_secret "${name}_public_key" \
        "$(openssl pkey -inform DER -in "$der" -pubout -outform DER | tail -c 32 | od -An -v -tx1 | tr -d ' \n')"
    rm -f "$der"
}

supplied database_url XSHIELD_DATABASE_URL
supplied clickhouse_password XSHIELD_CLICKHOUSE_PASSWORD
supplied oidc_client_secret XSHIELD_OIDC_CLIENT_SECRET
for key in control_cursor_key control_idempotency_key control_api_key_hash_key \
    control_journal_key edge_journal_key edge_apply_key fingerprint_key \
    share_token_key evidence_key; do
    generate "$key" "$(openssl rand -hex 32)"
done
seal_pair edge_seal
seal_pair control_seal

# Bootstrap bearer: control accepts at most a 24-hour lifetime, fixed when it
# starts, so update the Secret and restart the pod after re-running this.
write_secret control_token "$(openssl rand -hex 32)"
now=$(date +%s)
write_secret control_token_issued_at "$((now - 60))"
write_secret control_token_expires_at "$((now + 86340))"

printf 'xshield-secrets.sh: keys are in %s; the bootstrap bearer (control_token) expires in 24 hours\n' "$dir"
