#!/usr/bin/env bash
# Runs the IDOR lab regression (real edge binary + isolated PostgreSQL) with the
# two lab origins started as local Python processes instead of Docker containers.
#
# Needs: python3, a reachable PostgreSQL (PG* variables), and the gateway binary
# (built here if missing; honours CARGO_TARGET_DIR so the build can live outside
# the repository). The Juice Shop part of the lab still needs Docker and is not
# run here. No model call is made.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}

if [[ ! -x "$target_dir/debug/xshield-gateway" ]]; then
    cargo build --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway --bin xshield-gateway
fi

pids=()
cleanup() {
    for pid in "${pids[@]:-}"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

LAB_ORIGIN_HOST=127.0.0.1 LAB_ORIGIN_PORT=53001 python3 "$repo_root/tests/security-lab/idor_origin.py" &
pids+=($!)
LAB_ORIGIN_HOST=127.0.0.1 LAB_ORIGIN_PORT=53002 python3 "$repo_root/tests/security-lab/invoice_origin.py" &
pids+=($!)

# The test waits for both origins itself; run both scenarios.
CARGO_TARGET_DIR="$target_dir" python3 "$repo_root/scripts/test_idor_lab.py" --scenario all
