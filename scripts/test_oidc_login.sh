#!/usr/bin/env bash
# Real OIDC login regression: a native Keycloak (the dev realm), the real
# `xshield-control` binary and a throwaway PostgreSQL database, driven by
# scripts/test_oidc_login.py without a browser.
#
# Needs: PostgreSQL client tools and a reachable server (PGHOST/PGUSER/... as for
# scripts/test_postgres.sh), a JDK 21+ (JAVA_HOME or `java` on PATH), an unpacked
# Keycloak distribution in XSHIELD_KEYCLOAK_HOME (the directory that contains
# bin/kc.sh; Keycloak 26.7.4 is what docker-compose.dev.yml and CI use), openssl,
# curl and python3.
# Optional: XSHIELD_OIDC_SKIP_BUILD=1 (use already built binaries),
# XSHIELD_OIDC_SKIP_STALE=1 (skip the two-minute step-up lapse checks),
# XSHIELD_OIDC_KEEP=1 (keep the work directory and logs for inspection).
# Set TMPDIR if the default temporary directory must not receive the Keycloak
# copy (about 200 MB).
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# The Keycloak/control/PostgreSQL setup is shared with scripts/test_oidc_browser.sh.
# shellcheck source=lib/oidc_stack.sh
source "$repo_root/scripts/lib/oidc_stack.sh"
oidc_check_tools

work=$(mktemp -d "${TMPDIR:-/tmp}/xshield-oidc.XXXXXX")

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        echo "---- control log (tail)" >&2
        tail -n 60 "$work/control.log" 2>/dev/null >&2 || true
        echo "---- keycloak log (tail)" >&2
        tail -n 40 "$work/keycloak.log" 2>/dev/null >&2 || true
    fi
    oidc_stop_process "$control_pid"
    oidc_stop_process "$keycloak_pid"
    if ((database_created)); then
        dropdb --if-exists "$test_database" >/dev/null 2>&1 || true
    fi
    if [[ "${XSHIELD_OIDC_KEEP:-0}" == "1" ]]; then
        echo "work directory kept: $work" >&2
    else
        rm -rf -- "$work"
    fi
}
trap cleanup EXIT INT TERM

oidc_locate_binaries
oidc_create_database

# The console origin is the redirect URI registered in the dev realm; nothing
# listens there, the test script rewrites redirects to the control listener.
console_origin=http://127.0.0.1:55173
oidc_start_keycloak "$console_origin"
oidc_start_control "$console_origin"

stale_flag=()
if [[ "${XSHIELD_OIDC_SKIP_STALE:-0}" == "1" ]]; then
    stale_flag=(--skip-stale-wait)
fi
XSHIELD_CONTROL_AUDIT_KEY_ID=oidc-test-control-audit \
XSHIELD_CONTROL_AUDIT_KEY_HEX="$audit_key_hex" \
    python3 -I "$repo_root/scripts/test_oidc_login.py" \
    --control-url "http://127.0.0.1:$control_port" \
    --keycloak-url "http://127.0.0.1:$keycloak_port" \
    --console-origin http://127.0.0.1:55173 \
    --database-url "$database_url" \
    --audit-dir "$work/control-audit" \
    --dump-bin "$dump_bin" \
    --realm-file "$repo_root/dev/keycloak/xshield-dev-realm.json" \
    ${stale_flag[@]+"${stale_flag[@]}"}
