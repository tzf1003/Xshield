# Plan 004: `application/…+json` bodies are read as JSON everywhere the gateway reads JSON

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- crates/xshield-judge/src/values.rs crates/xshield-judge/src/engine.rs crates/xshield-edge/src/proxy.rs`
> If any of these changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `ebc710b`, 2026-11-13

## Why this matters

Two places decide "this response is JSON, buffer and observe it" with `contains("json")`. The code
that then extracts values accepts only the exact type `application/json`. For an origin that
answers `application/vnd.api+json`, `application/hal+json` or `application/problem+json`, the
decision log says a JSON response was observed, yet no value is learned: the session context
stays empty, every later request goes to Jev (cost, latency, false refusals), and the log
misleads. Request bodies of those types are likewise treated as opaque text, of which only the
first 2048 bytes are looked at. One shared rule fixes all four places.

## Current state

`crates/xshield-edge/src/proxy.rs:191-194`:

```rust
fn observable_type(content_type: &str) -> bool {
    let lower = content_type.to_ascii_lowercase();
    lower.contains("json") || lower.starts_with("text/html")
}
```

`crates/xshield-judge/src/engine.rs:1267-1277`:

```rust
fn response_kind(content_type: Option<&str>) -> Option<Observed> {
    let lower = content_type?.to_ascii_lowercase();
    if lower.contains("json") {
        Some(Observed::Json)
```

`crates/xshield-judge/src/values.rs` — request bodies (`:330-338`) and response bodies
(`:464-473`) both compute `kind` (the media type before `;`, trimmed, lower-cased) and then match
`"application/json" => …` exactly.

`xshield-edge` depends on `xshield-judge` (check `crates/xshield-edge/Cargo.toml`), so a public
helper in the judge crate can serve both.

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

**In scope**:
- `crates/xshield-judge/src/values.rs`
- `crates/xshield-judge/src/engine.rs` (only `response_kind`)
- `crates/xshield-judge/src/lib.rs` (only if a re-export is needed)
- `crates/xshield-edge/src/proxy.rs` (only `observable_type`)

**Out of scope**:
- HTML handling, body size limits, compressed bodies.
- NDJSON / `application/x-ndjson`, `text/json`: not a single JSON document or not standard; leave unread.
- Duplicate-key handling in JSON (separate finding).

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(judge): place slug and escaped ids at the declared id`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: One rule

In `values.rs` add:

```rust
/// Whether a media type (parameters already removed, lower case) is a JSON document:
/// `application/json` or a structured-syntax suffix type such as `application/vnd.api+json`.
#[must_use]
pub fn is_json_media(kind: &str) -> bool {
    kind == "application/json" || (kind.starts_with("application/") && kind.ends_with("+json"))
}
```

Also add a small helper (or reuse the existing inline code) that reduces a raw `Content-Type`
header value to that `kind` form, so every caller normalises the same way.

### Step 2: Use it in the four places

- `values.rs` request and response matches: replace the `"application/json" =>` arms by a guard
  using `is_json_media` (e.g. `kind if is_json_media(kind) =>`), behaviour otherwise unchanged.
- `engine.rs` `response_kind`: JSON when `is_json_media(normalised)`.
- `proxy.rs` `observable_type`: JSON when `is_json_media(normalised)`, HTML as before.

After this, a type such as `application/x-ndjson` or `text/json` is no longer buffered as
"JSON" by the edge. That is intended: it was never parsed anyway.

**Verify**: `cargo clippy --workspace --all-targets --locked -- -D warnings` → exit 0

### Step 3: Tests

- In `values.rs` tests: `is_json_media` truth table (`application/json`, `application/vnd.api+json`,
  `application/problem+json` true; `text/html`, `application/x-ndjson`, `application/jsonp`,
  `text/json`, empty false); and one test each that a request body and a response body with
  `Content-Type: application/vnd.api+json; charset=utf-8` yield the same values as with `application/json`.
  Model them on the nearest existing request/response extraction tests in that module.
- In `engine.rs` tests: one test that a 200 response with `application/hal+json` teaches a value
  so that the next request naming it is `DecisionPath::FastAllow`. Model it on an existing test that
  observes a JSON list and then fetches an item.

**Verify**: `cargo test -p xshield-judge -p xshield-edge --locked` → all pass

## Test plan

Step 3; all existing tests of both crates pass unchanged.

## Done criteria

- [ ] `cargo fmt --all --check` exits 0
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` exits 0
- [ ] `cargo test -p xshield-judge -p xshield-edge --locked` exits 0
- [ ] `grep -rn 'contains("json")' crates/xshield-judge/src crates/xshield-edge/src` returns no match
- [ ] Only in-scope files are modified

## STOP conditions

- Excerpts do not match.
- An existing test depends on a non-`application/*` JSON type being observed.
- `xshield-edge` cannot reach the helper without a new dependency.

## Maintenance notes

- Any new place that asks "is this JSON?" must call `is_json_media`.
- `scripts/test_idor_lab.py` has no `+json` origin; adding one would be a good later acceptance scenario.
