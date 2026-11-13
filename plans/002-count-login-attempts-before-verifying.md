# Plan 002: Concurrent wrong passwords cannot exceed the sign-in limit

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- crates/xshield-control/src/auth.rs`
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

The console has one administrator password, and the only brute-force control is "ten failures in
ten minutes per client address". The handler asks the limiter whether the address may try, then
runs a slow password check (PBKDF2 on a blocking thread), and only afterwards records the
failure. Requests sent in parallel all pass the first question before any failure is recorded, so
one address can test as many passwords per burst as fit into one password-check latency. After
this plan the attempt is counted in the same locked step that admits it.

## Current state

`crates/xshield-control/src/auth.rs`:

`auth.rs:283-324` — the limiter:

```rust
pub struct LoginLimiter {
    failures: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}
impl LoginLimiter {
    pub fn allows(&self, address: IpAddr, now: Instant) -> bool { … attempts.len() < LOGIN_FAILURES_ALLOWED }
    pub fn record_failure(&self, address: IpAddr, now: Instant) { … attempts.push(now); }
    pub fn clear(&self, address: IpAddr) { self.table().remove(&address); }
}
```

`record_failure` also prunes the table when it holds `LOGIN_TRACKED_MAX` addresses.

`auth.rs:357-378` — the handler:

```rust
    let address = client_address(parts.extensions.get::<ConnectInfo<SocketAddr>>());
    if !state.login_limiter.allows(address, Instant::now()) {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "LOGIN_RATE_LIMITED"));
    }
    let LoginBody { password } = json_body(&parts.headers, &body)?;
    let stored = state.admin_password_hash.clone();
    let accepted = tokio::task::spawn_blocking(move || verify_password(&stored, &password))
        .await
        .unwrap_or(false);
    if !accepted {
        state.login_limiter.record_failure(address, Instant::now());
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "INVALID_PASSWORD"));
    }
    state.login_limiter.clear(address);
```

Existing unit tests (`auth.rs:473-497`): `the_limiter_locks_an_address_after_ten_failures` and
`the_limiter_forgets_failures_after_the_window` call `allows`, `record_failure`, `clear`.
The documented behaviour (doc comment at `auth.rs:354`, and docs/07) stays: 429
`LOGIN_RATE_LIMITED` after ten failures in ten minutes from one address; a success forgets the address.

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
- `crates/xshield-control/src/auth.rs`

**Out of scope**:
- Any other file. If another caller of `allows`/`record_failure` exists outside `auth.rs`
  (`grep -rn "login_limiter" crates/`), that is a STOP condition.
- A global concurrency cap on password checks, IPv6 /64 grouping, and session revocation — separate findings.
- The error codes, status codes and limits.

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(judge): place slug and escaped ids at the declared id`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Give the limiter one admitting-and-counting operation

Add `pub fn try_begin(&self, address: IpAddr, now: Instant) -> bool` to `LoginLimiter`. Under one
lock acquisition it: prunes the table exactly as `record_failure` does today when it is at
`LOGIN_TRACKED_MAX`; drops this address's entries older than `LOGIN_WINDOW`; returns `false` when
`LOGIN_FAILURES_ALLOWED` entries remain; otherwise pushes `now` and returns `true`. An admitted
attempt is thus counted as a failure until it is shown to be something else.

Keep `allows` (read-only question, used by tests) and `clear`. Remove `record_failure` if nothing
uses it after step 2; if the tests still want it, keep it. Update the struct doc comment: it now
counts attempts that have not succeeded.

**Verify**: `cargo clippy -p xshield-control --all-targets --locked -- -D warnings` → exit 0

### Step 2: Use it in the handler

In `login`: parse the body first (`json_body`), so a malformed body costs no attempt, exactly as
today (today a malformed body returns before `record_failure`). Then call
`state.login_limiter.try_begin(address, Instant::now())`; on `false` return the same 429. Run the
password check. On failure return 401 without recording again (the attempt is already counted).
On success call `clear(address)` as today.

Note the order change: today the 429 is returned before the body is parsed. Keep 429 taking
precedence for a locked address: check `allows` first (cheap), then parse, then `try_begin`.

**Verify**: `cargo test -p xshield-control --locked --lib auth` → all pass

### Step 3: Tests

In the test module of `auth.rs`:
- Update the two existing limiter tests to the new API without weakening what they assert.
- Add `the_limiter_admits_only_ten_attempts_at_once`: call `try_begin` 25 times for one address
  with the same `Instant` and no `clear`; assert exactly `LOGIN_FAILURES_ALLOWED` return true.
- Add `a_success_forgets_the_attempts_of_an_address`: nine `try_begin`, `clear`, then ten more succeed.

**Verify**: `cargo test -p xshield-control --locked --lib limiter` → all pass, 2 new tests among them

## Test plan

See step 3. Also run `cargo test -p xshield-control --locked` (HTTP tests for login live in
`crates/xshield-control/tests/`; those needing PostgreSQL skip themselves without a database).

## Done criteria

- [ ] `cargo fmt --all --check` exits 0
- [ ] `cargo clippy -p xshield-control --all-targets --locked -- -D warnings` exits 0
- [ ] `cargo test -p xshield-control --locked` exits 0
- [ ] In `login`, no `.await` lies between the limiter call that admits the attempt and the point where the attempt is counted (they are the same call)
- [ ] `git status --short` lists only `crates/xshield-control/src/auth.rs`

## STOP conditions

- The excerpts do not match the live code.
- `login_limiter` is used outside `auth.rs` other than its construction in `lib.rs`.
- An HTTP test of the login contract fails in a way that needs a status-code or error-code change.

## Maintenance notes

- A correct sign-in that arrives while ten earlier attempts from the same address are still being
  checked is now refused with 429. That is the intended trade.
- Follow-ups not done here: a small global semaphore around `verify_password`, and keying IPv6 clients by /64.
