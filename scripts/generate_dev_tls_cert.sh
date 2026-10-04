#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir=${1:-"$repo_root/target/xshield-dev/tls"}
install_cert=0
if [[ "${2:-}" == "--install" ]]; then
    install_cert=1
fi

command -v openssl >/dev/null 2>&1 || {
    printf '%s\n' 'openssl is required' >&2
    exit 1
}
install -d -m 0700 "$output_dir"
cert="$output_dir/juice.local.crt"
key="$output_dir/juice.local.key"
config="$output_dir/openssl.cnf"

if [[ ! -s "$cert" || ! -s "$key" || ! "$(openssl x509 -in "$cert" -noout -text 2>/dev/null || true)" =~ DNS:idor\.local ]]; then
    umask 077
    cat >"$config" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = juice.local

[v3_req]
subjectAltName = @alt_names
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = juice.local
DNS.2 = localhost
DNS.3 = idor.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$key" -out "$cert" -days 30 \
        -config "$config" -extensions v3_req >/dev/null 2>&1
    chmod 600 "$key"
    chmod 644 "$cert"
fi

if ((install_cert)); then
    case "$(uname -s)" in
        Darwin)
            security add-trusted-cert -d -r trustRoot \
                -k "$HOME/Library/Keychains/login.keychain-db" "$cert"
            ;;
        Linux)
            printf '%s\n' "Certificate generated at $cert; install it in the local trust store as needed." >&2
            ;;
        *)
            printf '%s\n' "Certificate generated at $cert; install it in the local trust store as needed." >&2
            ;;
    esac
fi

printf '%s\n' "$cert"
