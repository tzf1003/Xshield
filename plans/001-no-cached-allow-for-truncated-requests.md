# Plan 001: A request with values the judge did not read never reuses or stores a cached allow

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- crates/xshield-judge/src/engine.rs`
> If the file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: security
- **Planned at**: commit `ebc710b`, 2026-11-13

## Why this matters

The gateway extracts at most 200 values from a request (`REQUEST_VALUES_MAX`), 16 levels of JSON
depth, and the first 2048 bytes of a body that is neither JSON nor a form. When anything is left
out, `extracted.truncated` is true. The fast-allow path already refuses to settle such a request
without Jev. The cached-allow path does not: its key is built only from the values that *were*
extracted, so once Jev allows one truncated request, every later request with the same visible
values and a different hidden remainder is allowed for the cache lifetime with no Jev call. The
hidden remainder can carry another user's object id or an attack payload. After this plan a
truncated request always goes to Jev and its allow is never stored.

## Current state

- `crates/xshield-judge/src/engine.rs` — the judge. Relevant places:

`engine.rs:461-476` (inside `plan`):

```rust
        let unknown = turn.resolved.is_unknown();
        if all_known && !attempted && !unplaceable && !turn.extracted.truncated && !unknown {
            return Plan::Done(Verdict::Safe(DecisionPath::FastAllow));
        }
        // An attempt goes to Jev, whatever an earlier allow of the same request said.
        if tuning.cache_ms > 0
            && !unknown
            && !attempted
            && !unplaceable
            && let Some(source) = session.cached_allow(turn.cache_key, request.now_ms)
        {
            trace.cache_source = request_text(source);
            return Plan::Done(Verdict::Safe(DecisionPath::CachedAllow));
        }
```

`engine.rs:692-694` (where an allow from Jev is stored):

```rust
        let verdict = match conclusion {
            Conclusion::Allow => {
                if tuning.cache_ms > 0 && !turn.resolved.is_unknown() {
```

`engine.rs:761-784` `cache_key` hashes method, logical path, the admin flag and the extracted
`values` only — nothing about what was cut.

- Tests live in the `#[cfg(test)] mod tests` at the bottom of the same file. Exemplar for a
  cached-allow test: `a_cached_allow_names_the_request_that_was_allowed` (`engine.rs:3775`), which
  uses the helpers `FakeJev::new()`, `judge(&fake)`, `site(r#","mode":"enforce""#)`, `get(path,
  query, credential, now_ms)` and asserts on `record.decision_path` and `fake.calls()`.
  An existing test that builds a truncated request: `a_truncated_body_with_a_json_escape_teaches_its_echo_nothing` (`engine.rs:2282`).

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

## Scope

**In scope** (the only file you should modify):
- `crates/xshield-judge/src/engine.rs`

**Out of scope** (do NOT touch):
- `crates/xshield-judge/src/values.rs` — the truncation limits themselves stay as they are.
- The Jev instructions in `state.rs`; what Jev is told about `truncated` is a separate decision.
- `cache_key` — do not change the key.

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(judge): place slug and escaped ids at the declared id`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Skip the cached-allow lookup for a truncated request

In the `if tuning.cache_ms > 0 && !unknown && !attempted && !unplaceable && let Some(source) = …`
condition at `engine.rs:468-472`, add `&& !turn.extracted.truncated` before the `let`. Extend the
comment above it with one sentence saying a request with unread values is never settled by an
earlier allow, because the key covers only the values that were read.

**Verify**: `cargo clippy -p xshield-judge --all-targets --locked -- -D warnings` → exit 0

### Step 2: Do not store an allow for a truncated request

At `engine.rs:694` change the condition to
`if tuning.cache_ms > 0 && !turn.resolved.is_unknown() && !turn.extracted.truncated {`.

**Verify**: `cargo clippy -p xshield-judge --all-targets --locked -- -D warnings` → exit 0

### Step 3: Add the regression test

Add `#[tokio::test] async fn a_truncated_request_is_never_allowed_from_the_cache()` next to
`a_cached_allow_names_the_request_that_was_allowed`. Send the same truncated request twice for the
same credential (for example a query string with more than 200 distinct non-empty parameters, or
copy the way the existing truncated test builds its request). Assert that both records have
`decision_path == DecisionPath::JevAllow`, that `record.trace.values_truncated` is true, and that
`fake.calls() == 2`.

**Verify**: `cargo test -p xshield-judge --locked a_truncated_request_is_never_allowed_from_the_cache` → 1 passed

## Test plan

- The new test above (the regression).
- `cargo test -p xshield-judge --locked` → all pass; the existing cached-allow tests still pass unchanged.

## Done criteria

- [ ] `cargo fmt --all --check` exits 0
- [ ] `cargo clippy -p xshield-judge --all-targets --locked -- -D warnings` exits 0
- [ ] `cargo test -p xshield-judge --locked` exits 0 and includes the new test
- [ ] `grep -c "extracted.truncated" crates/xshield-judge/src/engine.rs` prints at least 6
- [ ] `git status --short` lists only `crates/xshield-judge/src/engine.rs` (and `plans/README.md` if you maintain it)

## STOP conditions

- The excerpts above do not match the live code.
- The new test shows the second request was already not served from the cache before your change (the finding would be wrong).
- An existing test fails after the change and the failure is not about truncation.

## Maintenance notes

- If the cache key ever gains a digest of the unread remainder, this restriction can be revisited.
- Deferred on purpose: telling Jev what `truncated: true` means, and counting only non-inert values toward the 200 cap (see plans/README.md backlog).
