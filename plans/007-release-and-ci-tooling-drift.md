# Plan 007: The release script, the advisory exceptions and the CI filters match the code that exists

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- scripts/package_release.sh deny.toml .github/workflows/ci.yml`
> If any of these changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: dx
- **Planned at**: commit `ebc710b`, 2026-11-13

## Why this matters

Four small pieces of tooling describe a codebase that no longer exists:

1. `scripts/package_release.sh` installs a binary `xshield-build` that no crate produces, so under
   `set -e` the script always aborts: the release tarball cannot be built. It also compiles the
   control binary *before* building the console, although the control binary embeds
   `web/console/dist` at compile time (`crates/xshield-control/build.rs`); with the stale name
   removed it would ship a control plane with an old console or none (HTTP 503 on `/`).
2. `deny.toml` ignores two RustSec advisories "because they enter only through openidconnect".
   OIDC was removed in v4; `Cargo.lock` contains none of `openidconnect`, `rsa`, `crypto-bigint`,
   `p256`, `p384`. If one of them returns through another dependency, its advisory would pass silently.
3. The CI `changes` filter does not select the `container-images` job for changes under
   `web/console/`, although the Dockerfile builds the console and embeds it. The workflow's own
   comment promises that anything that can change what a job builds selects it.
4. CI runs `cargo clippy` and `cargo test` without `--locked`, while `scripts/verify_all.sh`, the
   Dockerfile and the acceptance script use `--locked`. CI may therefore test a re-resolved graph.

## Current state

`scripts/package_release.sh:58-82`:

```bash
binaries=(
    xshield-edge
    xshield-control
    xshield-build
)

rm -rf -- "$stage"
mkdir -p -- "$stage/bin" "$stage/docs"

printf '==> cargo build --release (target: %s)\n' "$target_dir"
(cd "$repo_root" && cargo build --release --locked \
    -p xshield-edge -p xshield-control)
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
```

`web/console/dist/` is git-ignored. The Dockerfile does it in the right order: `npm ci`,
`npm run build` (which is `tsc --noEmit && vite build`, output `web/console/dist`), then
`cargo build --release --locked -p xshield-edge -p xshield-control`.

`deny.toml:17-25` — the `ignore` list has seven entries; the two to remove are the ones with ids
`RUSTSEC-2023-0071` and `RUSTSEC-2026-0387` (both reasons mention `openidconnect`).

`.github/workflows/ci.yml:46`:

```
echo "images=$(match '^(Cargo\.(toml|lock)|rust-toolchain\.toml|Dockerfile|\.dockerignore|crates/|migrations/|tests/site-config/|\.github/)')"
```

`.github/workflows/ci.yml:99-101`:

```yaml
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace --all-targets
      - run: cargo test --workspace --doc
```

The `fuzz-replay` job deliberately runs without `--locked` (its comment explains why). Leave it.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Shell syntax | `bash -n scripts/package_release.sh` | exit 0 |
| Lockfile in sync | `cargo metadata --locked --format-version 1 >/dev/null` | exit 0 |
| Removed crates absent | `grep -c -E '^name = "(openidconnect|rsa|crypto-bigint|p256|p384)"' Cargo.lock` | prints 0 |
| Workflow parses | `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml'))"` | exit 0 (PyYAML is in scripts/requirements.txt; `pip install pyyaml` if missing) |
| Advisory check (optional) | `cargo deny --locked check advisories` | exit 0; skip and say so if `cargo-deny` is not installed |

## Scope

**In scope**:
- `scripts/package_release.sh`
- `deny.toml`
- `.github/workflows/ci.yml`

**Out of scope**:
- `.github/workflows/release*.yml`, `fuzz.yml`, the Dockerfile, `scripts/verify_all.sh`.
- The other five advisory exceptions (they are about pingora's dependencies, which are present).
- Pinning actions by SHA, cargo caching, job timeouts — recorded in plans/README.md, not done here.

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(console): …`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: package_release.sh builds what exists, in the order the embed needs

- Remove `xshield-build` from `binaries`.
- Move the console build before the cargo build: in `web/console` run `npm ci --no-audit --no-fund`
  and `npm run build` (output: `web/console/dist`, the directory `build.rs` embeds).
- After the cargo build, copy the same bundle into the tarball so its layout is unchanged:
  `cp -R -- "$repo_root/web/console/dist" "$stage/console"`.
- Replace the comment "The bundle goes straight to the staging tree, never to web/console/dist."
  with one saying the control binary embeds `web/console/dist` at compile time
  (`crates/xshield-control/build.rs`), so the console is built first, as in the Dockerfile.
- Keep everything else (the outside-the-repository checks, manifest, tarball).

**Verify**: `bash -n scripts/package_release.sh` → exit 0;
`grep -n "xshield-build" scripts/package_release.sh` → no match;
the line number of `npm run build` is smaller than that of `cargo build --release`.

### Step 2: Remove the two dead advisory exceptions

Delete the `RUSTSEC-2023-0071` and `RUSTSEC-2026-0387` entries from `deny.toml`.

**Verify**: `grep -c openidconnect deny.toml` → 0; the "removed crates absent" command prints 0.

### Step 3: CI

- Add `web/console/` to the `images` pattern (`…|crates/|migrations/|web/console/|tests/site-config/|…`).
- Add `--locked` to the three cargo commands of the `validate` job quoted above.

**Verify**: the workflow-parses command exits 0; `cargo metadata --locked --format-version 1 >/dev/null` exits 0.

## Test plan

No unit tests apply. The CI run of the pull request is the test for step 3 (all jobs are selected
because `.github/` changed); `supply-chain` is the test for step 2.

## Done criteria

- [ ] `bash -n scripts/package_release.sh` exits 0 and `grep -c xshield-build scripts/package_release.sh` prints 0
- [ ] `grep -c openidconnect deny.toml` prints 0 and `grep -c 'id = "RUSTSEC' deny.toml` prints 5
- [ ] `grep -c -- "--locked" .github/workflows/ci.yml` is at least 3 higher than before (was: count it first)
- [ ] `grep -n "web/console/" .github/workflows/ci.yml` shows the `images=` line among the matches
- [ ] Only the three in-scope files are modified

## STOP conditions

- Excerpts do not match.
- A crate named `xshield-build` or a `[[bin]]` of that name exists after all (`grep -rn "xshield-build" crates/ Cargo.toml`).
- Any of the five named crates is present in `Cargo.lock`.
- `cargo metadata --locked` fails (the lockfile is out of sync; adding `--locked` to CI would turn main red).

## Maintenance notes

- The full release script was not executed (a release build is tens of GB); the first real run should be watched.
- cargo-deny can warn on exceptions that match nothing; turning that into an error would catch the next stale entry.
