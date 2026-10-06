#!/usr/bin/env bash
# Builds release binaries and the console bundle and assembles one tarball.
#
# Build output is large (a release Rust build is tens of GB), so nothing is
# written to a default location: the caller names both directories and the
# script refuses any that lie inside the repository.
#
#   XSHIELD_DIST_DIR   where the staging tree and the tarball go
#   CARGO_TARGET_DIR   where cargo puts its build output
#
# Example (external disk mounted at /Volumes/XshieldBuild):
#   XSHIELD_DIST_DIR=/Volumes/XshieldBuild/dist \
#   CARGO_TARGET_DIR=/Volumes/XshieldBuild/target-release \
#   scripts/package_release.sh
#
# This packages artifacts; it does not publish, sign or deploy them, and it
# does not run the test suites (see docs/17 section 17.10 for the gates).
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)

require_outside_repo() {
    local name=$1 value=${2:-}
    if [[ -z "$value" ]]; then
        printf 'error: %s must be set to a directory outside the repository\n' "$name" >&2
        exit 2
    fi
    # Decide before creating anything: resolve the nearest existing parent.
    local probe=$value
    while [[ ! -d "$probe" ]]; do probe=$(dirname -- "$probe"); done
    local resolved
    resolved=$(CDPATH= cd -- "$probe" && pwd -P)${value#"$probe"}
    case "$resolved/" in
        "$repo_root"/*)
            printf 'error: %s=%s is inside the repository (%s)\n' "$name" "$resolved" "$repo_root" >&2
            exit 2
            ;;
    esac
    mkdir -p -- "$value"
    printf '%s' "$resolved"
}

dist_dir=$(require_outside_repo XSHIELD_DIST_DIR "${XSHIELD_DIST_DIR:-}")
target_dir=$(require_outside_repo CARGO_TARGET_DIR "${CARGO_TARGET_DIR:-}")
export CARGO_TARGET_DIR="$target_dir"
# Incremental caches are useless for a release build and need hard links that
# some external file systems lack.
export CARGO_INCREMENTAL=0

version=$(git -C "$repo_root" describe --tags --always --dirty 2>/dev/null || printf 'unversioned')
if [[ "$version" == *-dirty ]]; then
    printf 'warning: the working tree has uncommitted changes (%s)\n' "$version" >&2
fi
platform="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
name="xshield-${version}-${platform}"
stage="$dist_dir/stage/$name"

binaries=(
    xshield-gateway
    xshield-control
    xshield-worker
    xshield-outbox-worker
    xshield-evidence-retain
    xshield-model-eval
    xshield-audit-seal
)

rm -rf -- "$stage"
mkdir -p -- "$stage/bin" "$stage/docs"

printf '==> cargo build --release (target: %s)\n' "$target_dir"
(cd "$repo_root" && cargo build --release --locked \
    -p xshield-gateway -p xshield-control -p xshield-worker -p xshield-audit)
for binary in "${binaries[@]}"; do
    install -m 0755 -- "$target_dir/release/$binary" "$stage/bin/$binary"
done

printf '==> console bundle\n'
(
    cd "$repo_root/web/console"
    npm ci --no-audit --no-fund
    # The bundle goes straight to the staging tree, never to web/console/dist.
    npx tsc --noEmit
    npx vite build --outDir "$stage/console" --emptyOutDir
)

printf '==> assemble\n'
cp -R -- "$repo_root/migrations" "$stage/migrations"
mkdir -p -- "$stage/sql" "$stage/examples"
cp -- "$repo_root/sql/clickhouse.sql" "$stage/sql/"
cp -- "$repo_root"/examples/gateway-bootstrap-config.json "$stage/examples/"
cp -- "$repo_root/README.md" "$repo_root/CHANGELOG.md" "$stage/"
for doc in 13-audit-storage-reliability.md 15-console-and-api.md 19-deployment-operations.md 21-performance-capacity.md 26-runbooks.md 29-api-endpoint-catalog.md; do
    cp -- "$repo_root/docs/$doc" "$stage/docs/"
done
printf '%s\n' "$version" >"$stage/VERSION"
(
    cd "$stage"
    # Deterministic order so two builds of the same tree compare equal.
    find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 >MANIFEST.sha256
)

archive="$dist_dir/$name.tar.gz"
tar -C "$dist_dir/stage" -czf "$archive" "$name"
shasum -a 256 "$archive" | tee "$archive.sha256"
printf 'wrote %s\n' "$archive"
