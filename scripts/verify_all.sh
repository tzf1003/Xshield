#!/usr/bin/env bash
# Local verification gates from docs/17 section 17.10, one log file per step.
#
#   scripts/verify_all.sh [rust] [gateway] [console]    (no argument: all three groups)
#
# Groups
#   rust     fmt, audit-event coverage and environment-variable guards, library
#            validation, clippy, tests,
#            doc tests, PostgreSQL integration suite
#   gateway  the browser sensor unit tests, the real-binary gateway scripts
#            (transport, dynamic listeners, request crypto, identity), the
#            Docker-free IDOR lab and the real-browser provenance loop
#   console  npm ci, lint, unit tests, production build, Playwright e2e
#
# Environment
#   CARGO_TARGET_DIR        cargo output. Release and debug builds are tens of GB:
#                           point this at a large volume, not the system disk
#                           (scripts/package_release.sh refuses in-repo targets).
#   XSHIELD_VERIFY_LOG_DIR  where the per-step logs go (default: a fresh directory
#                           under $TMPDIR). Put it on persistent storage if the
#                           logs must survive a reboot.
#   XSHIELD_E2E_PORT        first of the two Playwright ports (default 5175).
#   XSHIELD_PLAYWRIGHT_PACKAGE  package.json whose @playwright/test the browser
#                           loop uses (default web/console after `npm ci`).
#   PGHOST/PGPORT/PGUSER/PGPASSWORD   server for the PostgreSQL steps.
#
# A step whose tool is missing is reported as SKIP, never as success. The exit
# status is non-zero when any step failed. Docker, ClickHouse and Keycloak
# regressions are not part of this script (see docs/20).
set -u

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo_root" || exit 2

groups=("$@")
if [ "${#groups[@]}" -eq 0 ]; then
    groups=(rust gateway console)
fi
for group in "${groups[@]}"; do
    case "$group" in
        rust | gateway | console) ;;
        *)
            printf 'error: unknown group %s (expected rust, gateway or console)\n' "$group" >&2
            exit 2
            ;;
    esac
done

log_dir=${XSHIELD_VERIFY_LOG_DIR:-${TMPDIR:-/tmp}/xshield-verify-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$log_dir" || exit 2
export CARGO_INCREMENTAL=${CARGO_INCREMENTAL:-0}

names=()
results=()
seconds=()

record() { # name result seconds
    names+=("$1")
    results+=("$2")
    seconds+=("$3")
    printf '%-6s %-24s %5ss\n' "$2" "$1" "$3"
}

run_step() { # name command...
    local name=$1
    shift
    local started=$SECONDS
    "$@" >"$log_dir/$name.log" 2>&1
    local code=$?
    local result=PASS
    [ "$code" -eq 0 ] || result=FAIL
    record "$name" "$result" "$((SECONDS - started))"
}

skip_step() { # name reason
    record "$1" SKIP 0
    printf '       (%s)\n' "$2"
}

have() { command -v "$1" >/dev/null 2>&1; }

in_console() { (cd "$repo_root/web/console" && "$@"); }

group_rust() {
    if ! have cargo; then
        skip_step rust-all "cargo not found"
        return
    fi
    run_step fmt cargo fmt --all --check
    run_step audit-coverage python3 scripts/check_audit_event_coverage.py
    run_step env-docs python3 scripts/check_env_docs.py
    run_step library python3 scripts/validate_library.py
    run_step clippy cargo clippy --workspace --all-targets --locked -- -D warnings
    run_step test cargo test --workspace --all-targets --locked --no-fail-fast
    run_step doctest cargo test --workspace --doc --locked
    if have psql && have createdb; then
        run_step postgres scripts/test_postgres.sh
    else
        skip_step postgres "psql/createdb not found"
    fi
}

have_playwright() {
    have node && node -e 'require("node:module").createRequire(process.argv[1]).resolve("@playwright/test")' \
        "${XSHIELD_PLAYWRIGHT_PACKAGE:-$repo_root/web/console/package.json}" >/dev/null 2>&1
}

group_gateway() {
    if ! have cargo; then
        skip_step gateway-all "cargo not found"
        return
    fi
    if have node; then
        run_step sensor-unit node --test sensor/test/sensor.test.mjs sensor/test/sensor-1.1.0.test.mjs
    else
        skip_step sensor-unit "node not found"
    fi
    run_step gw-transport scripts/test_gateway_transport.sh
    run_step gw-dynamic scripts/test_gateway_dynamic_listeners.sh
    if have psql && have createdb; then
        run_step gw-request-crypto scripts/test_gateway_request_crypto.sh
        run_step gw-identity scripts/test_gateway_identity.sh
        run_step idor-lab scripts/test_idor_lab_local.sh
        if have_playwright; then
            run_step browser-loop scripts/test_browser_loop.sh
        else
            skip_step browser-loop "@playwright/test not installed (npm ci in web/console)"
        fi
    else
        skip_step gw-request-crypto "psql/createdb not found"
        skip_step gw-identity "psql/createdb not found"
        skip_step idor-lab "psql/createdb not found"
        skip_step browser-loop "psql/createdb not found"
    fi
}

group_console() {
    if ! have npm; then
        skip_step console-all "npm not found"
        return
    fi
    run_step console-ci in_console npm ci --no-audit --no-fund
    run_step console-lint in_console npm run lint
    run_step console-unit in_console npm test
    run_step console-build in_console npm run build
    run_step console-e2e in_console env "XSHIELD_E2E_PORT=${XSHIELD_E2E_PORT:-5175}" npm run test:e2e
}

printf 'logs: %s\n' "$log_dir"
for group in "${groups[@]}"; do
    "group_$group"
done

failed=0
passed=0
for index in "${!results[@]}"; do
    [ "${results[$index]}" = PASS ] && passed=$((passed + 1))
    if [ "${results[$index]}" = FAIL ]; then
        failed=$((failed + 1))
        printf '\nFAILED: %s (log: %s/%s.log)\n' "${names[$index]}" "$log_dir" "${names[$index]}"
        tail -n 15 "$log_dir/${names[$index]}.log" 2>/dev/null | cut -c1-200
    fi
done
if [ "$failed" -gt 0 ]; then
    printf '\n%s step(s) failed\n' "$failed"
    exit 1
fi
if [ "$passed" -eq 0 ]; then
    printf '\nno step was executed: every step was skipped\n'
    exit 3
fi
printf '\n%s step(s) passed; SKIP means the tool was missing\n' "$passed"
