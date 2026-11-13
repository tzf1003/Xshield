# Plan 003: A re-created site does not show the automatic changes of the site it replaced

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- crates/xshield-postgres/src/site_spec_store.rs crates/xshield-control/src/object_map.rs`
> If either file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `ebc710b`, 2026-11-13

## Why this matters

Configuration history is kept by site name and deliberately survives deleting a site. Everything
the learning feature stores is scoped to the current "generation" of a name (rows at or after the
site record's `created_at`). The list of automatic changes (`auto_tighten`, `auto_pause`) is the
exception: it reads history by name only. Delete a site and create one with the same name within
30 days, and the new site's objects page lists the old site's automatic changes, counts them in
the seven-day figures, and lets the administrator "undo" them, which writes the old site's earlier
entry into the new configuration.

## Current state

`crates/xshield-postgres/src/site_spec_store.rs:563-581`:

```rust
pub async fn automatic_history(
    pool: &PgPool,
    name: &str,
    limit: i64,
) -> Result<Vec<HistoryEntry>, SiteSpecStoreError> {
    let limit = limit.clamp(1, 200);
    let rows = sqlx::query(
        "SELECT version, change, rollback_of, note, changed_at, spec
         FROM site_config_history
         WHERE site = $1 AND change IN ('auto_tighten', 'auto_pause')
         ORDER BY version DESC LIMIT $2",
    )
```

`crates/xshield-control/src/object_map.rs:1510-1522` (`automatic_events`):

```rust
    let name = record.spec.name();
    let since = now.saturating_sub(EVENTS_DAYS.saturating_mul(DAY_MILLIS));
    let versions = site_spec_store::automatic_history(&state.pool, name, EVENTS_MAX).await?;
    let handled: BTreeMap<String, store::EventStatus> =
        store::event_statuses(&state.pool, name, record.created_at)
```

`record` is a `SiteRecord` whose `created_at: DateTime<Utc>` (`site_spec_store.rs:29`) is the
start of the current generation; `event_statuses` already takes it. `changed_at` in
`site_config_history` is a `timestamptz`.

Find every caller first: `grep -rn "automatic_history" crates/`.

Database tests in `xshield-postgres` and `xshield-control` are `#[ignore]`d library tests run by
`scripts/test_postgres.sh` against a real PostgreSQL (needs `psql`, `createdb` and a server on
`PGHOST`/`PGPORT`). Look at the existing tests at the bottom of `site_spec_store.rs` for how they
obtain a pool and create a site.

## Commands you will need

Run from the repository root. Toolchain is pinned by `rust-toolchain.toml` (1.99.0).

| Purpose | Command | Expected on success |
|---|---|---|
| Format | `cargo fmt --all --check` | exit 0, no output |
| Lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` | exit 0 (pedantic lints are on; warnings fail) |
| Tests (one crate) | `cargo test -p <crate> --locked <filter>` | all pass |

Set `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only` to keep the build small.
Repository rules (AGENTS.md): no `unwrap`/`expect`/`panic` on production input paths; do not add
dependencies, configuration items or environment variables.
| PostgreSQL suite | `scripts/test_postgres.sh` | exit 0 (only if a server is reachable; otherwise say it was not run) |

## Scope

**In scope**:
- `crates/xshield-postgres/src/site_spec_store.rs`
- `crates/xshield-control/src/object_map.rs` (call sites of `automatic_history` only)
- any other file that calls `automatic_history` (call-site argument only)

**Out of scope**:
- The history table, migrations, and the versions endpoint (history across generations is intended there).
- `find_event` logic beyond passing the new argument.

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(judge): place slug and escaped ids at the declared id`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Bound the query by the generation

Add a parameter `since: DateTime<Utc>` to `automatic_history` (after `name`), add
`AND changed_at >= $2` to the WHERE clause (the limit becomes `$3`), bind it, and document it:
"only changes of the site created at `since`; a deleted site of the same name keeps its history".

### Step 2: Pass `record.created_at` at every call site

In `automatic_events` pass `record.created_at`. Do the same for any other caller found by the grep.

**Verify**: `cargo clippy --workspace --all-targets --locked -- -D warnings` → exit 0

### Step 3: Test

Add an `#[ignore]`d database test next to the existing ones in `site_spec_store.rs`, following
their pattern: create a site, append an `auto_pause` history version (use whatever store function
the existing tests or `object_learning.rs` use to write an automatic change), delete the site,
create it again under the same name, and assert that `automatic_history(pool, name,
new_record.created_at, 20)` is empty while the same call with the old `created_at` is not.

**Verify**: `scripts/test_postgres.sh` → exit 0 when PostgreSQL is available. If it is not, the
test must at least compile: `cargo test -p xshield-postgres --locked --no-run` → exit 0, and your
report must say the database test was not run.

## Test plan

Step 3. Existing object-map tests must pass unchanged: `cargo test -p xshield-control --locked`.

## Done criteria

- [ ] `cargo fmt --all --check` exits 0
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` exits 0
- [ ] `cargo test -p xshield-postgres -p xshield-control --locked` exits 0
- [ ] `grep -n "changed_at >=" crates/xshield-postgres/src/site_spec_store.rs` shows the new bound inside `automatic_history`
- [ ] Only in-scope files are modified

## STOP conditions

- Excerpts do not match.
- Re-creating a site does not produce a new `created_at` (then the generation boundary is something else — report what it is).
- Writing the test needs a new public store function.

## Maintenance notes

- Any future reader of `site_config_history` that feeds the learning or objects pages needs the same bound.
