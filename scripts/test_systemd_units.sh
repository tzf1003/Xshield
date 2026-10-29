#!/usr/bin/env bash
# Validates the systemd unit files under deploy/systemd without a real
# install: syntax/semantics via `systemd-analyze verify` (catches a missing
# ExecStart=, an unknown directive, a bad specifier, etc.), plus a couple of
# checks specific to this deployment's shape that `verify` does not make on
# its own (every *.env an EnvironmentFile= line names has a matching
# *.env.example next to it, every ExecStart= binary is one of the release
# targets this repo actually builds). `verify` also confirms every
# ExecStart= binary exists and is executable, so this script stages throwaway
# stand-ins at the real /opt/xshield/current/bin path the units reference and
# removes them afterwards; it cannot check a unit against a real root
# filesystem otherwise (ReadWritePaths=, User=, etc. are reviewed by hand).
#
# Usage: scripts/test_systemd_units.sh

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dir=deploy/systemd
fail=0

echo "== stage stand-in binaries at /opt/xshield/current/bin =="
bin=/opt/xshield/current/bin
sudo=""
if [[ ! -w /opt ]] && command -v sudo >/dev/null 2>&1; then
    sudo="sudo"
fi
made_bin_dirs=()
for p in /opt/xshield /opt/xshield/current "$bin"; do
    [[ -d "$p" ]] || { $sudo mkdir -p "$p"; made_bin_dirs+=("$p"); }
done
$sudo chmod a+rx /opt/xshield /opt/xshield/current "$bin" 2>/dev/null || true
known_binaries="xshield-gateway xshield-control xshield-worker xshield-outbox-worker xshield-audit-seal xshield-evidence-retain xshield-model-eval"
made_bins=()
for b in $known_binaries; do
    if [[ ! -e "$bin/$b" ]]; then
        printf '#!/bin/true\n' | $sudo tee "$bin/$b" >/dev/null
        $sudo chmod +x "$bin/$b"
        made_bins+=("$bin/$b")
    fi
done
scratch=$(mktemp -d)
cleanup() {
    for f in "${made_bins[@]:-}"; do [[ -n "$f" ]] && $sudo rm -f "$f"; done
    for ((i = ${#made_bin_dirs[@]} - 1; i >= 0; i--)); do $sudo rmdir "${made_bin_dirs[i]}" 2>/dev/null || true; done
    rm -rf "$scratch"
}
trap cleanup EXIT

echo "== systemd-analyze verify =="
# Instantiate each template unit once (systemd-analyze verify refuses a bare
# `foo@.service`) and copy the rest into one scratch directory so cross-unit
# references (e.g. seal@.timer -> seal@.service) resolve.
for f in "$dir"/*.service "$dir"/*.timer; do
    base=$(basename "$f")
    case "$base" in
    *@.service | *@.timer) cp "$f" "$scratch/${base/@./@demo.}" ;;
    *) cp "$f" "$scratch/$base" ;;
    esac
done
if ! systemd-analyze verify --recursive-errors=yes "$scratch"/*.service "$scratch"/*.timer; then
    fail=1
fi

echo "== every EnvironmentFile= has a matching *.env.example =="
for f in "$dir"/*.service; do
    while IFS= read -r line; do
        path=${line#EnvironmentFile=}
        path=${path#-} # optional-file prefix
        name=$(basename "$path")
        if [[ "$name" == *%i* ]]; then
            glob="$dir/$(sed 's/%i/*/' <<<"$name").example"
            # shellcheck disable=SC2086 # intentional glob
            if ! compgen -G "$glob" >/dev/null; then
                echo "no example matches $name (pattern $glob) referenced by $f" >&2
                fail=1
            fi
        elif [[ ! -f "$dir/$name.example" ]]; then
            echo "missing $dir/$name.example referenced by $f" >&2
            fail=1
        fi
    done < <(grep -E '^EnvironmentFile=' "$f")
done

echo "== every ExecStart= binary is a release target =="
for f in "$dir"/*.service; do
    binary=$(grep -E '^ExecStart=' -A2 "$f" | grep -oP '(?<=bin/)[a-zA-Z0-9_-]+' | head -1)
    [[ -z "$binary" ]] && continue
    if ! grep -qw "$binary" <<<"$known_binaries"; then
        echo "$f references unknown binary '$binary'" >&2
        fail=1
    fi
done

if [[ $fail -eq 0 ]]; then
    echo "ok"
else
    exit 1
fi
