#!/usr/bin/env bash
# Real-browser OIDC login regression: a real Chromium signs in to the console (Vite dev
# server, VITE_XSHIELD_E2E_MACHINE_LOGIN=0, same-origin proxy to control) against a native
# Keycloak (the dev realm), the real `xshield-control` binary and a throwaway PostgreSQL
# database, driven by scripts/test_oidc_browser.mjs. It complements
# scripts/test_oidc_login.sh (no browser, protocol-level negatives): this one proves
# browser cookie handling, the proxy's Set-Cookie passthrough and the console's own
# sign-in / session / step-up / write / sign-out UI.
#
# Needs what scripts/test_oidc_login.sh needs (bash >= 4.1, PostgreSQL client tools and a
# reachable server, XSHIELD_KEYCLOAK_HOME, a JDK 21+, openssl, curl, python3) plus node 22
# and web/console/node_modules with @playwright/test and its Chromium (`npm ci` and
# `npx playwright install chromium` in web/console).
# Optional: XSHIELD_OIDC_SKIP_BUILD=1 (use already built binaries), XSHIELD_OIDC_KEEP=1
# (keep the work directory and logs). Scratch files go under TMPDIR (Keycloak is copied
# there, about 200 MB) and are removed on exit, as is the throwaway database.
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=lib/oidc_stack.sh
source "$repo_root/scripts/lib/oidc_stack.sh"
oidc_check_tools node
console_dir="$repo_root/web/console"
vite_bin="$console_dir/node_modules/.bin/vite"
[[ -x "$vite_bin" && -d "$console_dir/node_modules/@playwright/test" ]] || {
    echo "error: run 'npm ci' in web/console first (vite and @playwright/test are required)" >&2
    exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/xshield-oidc-browser.XXXXXX")
vite_pid=""

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        for log in control keycloak vite; do
            echo "---- $log log (tail)" >&2
            tail -n 40 "$work/$log.log" 2>/dev/null >&2 || true
        done
    fi
    oidc_stop_process "$vite_pid"
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

# The console really listens here; Keycloak's redirect URI and the control plane's console
# origin both name it (the dev realm's own 55173 is replaced in the test copy only).
console_port=$(oidc_free_port)
console_origin="http://127.0.0.1:$console_port"
oidc_start_keycloak "$console_origin"
oidc_start_control "$console_origin"

(
    cd "$console_dir"
    export VITE_XSHIELD_E2E_MACHINE_LOGIN=0
    export XSHIELD_CONTROL_PROXY="http://127.0.0.1:$control_port"
    exec "$vite_bin" --host 127.0.0.1 --port "$console_port" --strictPort
) >"$work/vite.log" 2>&1 &
vite_pid=$!
oidc_wait_for "console dev server" "$vite_pid" "$console_origin/"

XSHIELD_BROWSER_CONSOLE_ORIGIN="$console_origin" \
XSHIELD_BROWSER_KEYCLOAK_ORIGIN="http://127.0.0.1:$keycloak_port" \
XSHIELD_BROWSER_DATABASE_URL="$database_url" \
    node "$repo_root/scripts/test_oidc_browser.mjs"
