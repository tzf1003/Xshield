# Plan 005: The live request list never shows rows fetched for a filter the page has left

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- web/console/src/features/requests/live.ts`
> If the file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `ebc710b`, 2026-11-13

## Why this matters

In live mode the requests page polls the list every two seconds. The poll's cleanup only clears
the timer. A request already in flight when the administrator changes the filter (say from
"all" to "blocked") resolves after the page has reset its live rows, and its rows — fetched for
the old filter — are merged into the new list: allowed requests appear under the "blocked" chip
until the next reload. The same in-flight flag also blocks the first poll of the new filter.
Separately, the poll keeps running in a hidden browser tab for up to ten minutes, which is
wasted load on the control plane. Neither behaviour is covered by a unit test, although
docs/07 section 7.10.8 lists live-mode merging among the logic that must be unit-tested.

## Current state

`web/console/src/features/requests/live.ts` (whole file is 112 lines). The pure helpers
`liveSince(query, newestMillis, now)` and `liveQuery(query, since)` are exported. The hook:

```ts
  const busy = useRef(false);
  …
  useEffect(() => {
    if (!enabled || paused) return undefined;
    const timer = window.setInterval(() => {
      if (Date.now() - lastTouch.current > LIVE_IDLE_MS) {
        setPaused(true);
        return;
      }
      if (busy.current) return;
      const since = liveSince(query, newest.current, Date.now());
      busy.current = true;
      api
        .requests(liveQuery(query, since))
        .then((page) => {
          const oldest = page.rows.reduce(
            (min, row) => Math.min(min, row.at_millis),
            Number.POSITIVE_INFINITY,
          );
          handler.current(page.rows, page.rows.length >= LIVE_LIMIT && oldest > since);
        })
        // A failed poll is simply tried again on the next tick.
        .catch(() => undefined)
        .finally(() => {
          busy.current = false;
        });
    }, LIVE_POLL_MS);
    return () => window.clearInterval(timer);
  }, [enabled, paused, query]);
```

The caller is `src/features/requests/RequestsPage.tsx:158`
(`useLivePoll({ enabled: live, query: plan.query, newestMillis, onRows: onLiveRows })`); a second
caller may exist under `src/features/jev/` — check with `grep -rn "useLivePoll" src`.

Unit tests are plain `node:test` files in `tests/*.test.ts` importing from `../src/...` with the
`.ts` suffix; see `tests/sessions-model.test.ts` for the style. They run without a DOM, so only
pure functions can be tested there.

## Commands you will need

Run inside `web/console` (Node 22; `npm ci --no-audit --no-fund` first if `node_modules` is missing).

| Purpose | Command | Expected on success |
|---|---|---|
| Lint + format check | `npm run lint` | exit 0 (Biome; it also checks formatting) |
| Unit tests | `npm test` | all pass (node:test over `tests/*.test.ts`) |
| Typecheck + build | `npm run build` | exit 0 |
| One browser spec | `npx playwright test tests/<file>.spec.ts --trace off` | all pass (Chromium is preinstalled; do NOT run `playwright install`) |

Conventions: TypeScript with explicit `.ts`/`.tsx` import suffixes, double quotes, comments in
English that state what the code guarantees, user-visible text in Chinese. Server state goes
through `@tanstack/react-query` hooks in `src/api/queries.ts`; errors are shown with
`<ErrorBar error={…} />` from `src/ui/Page.tsx`. Do not add dependencies.

## Scope

**In scope**:
- `web/console/src/features/requests/live.ts`
- `web/console/tests/live.test.ts` (create)

**Out of scope**:
- `RequestsPage.tsx`, `JevRequestList.tsx` and the query keys: the 30-second window reset of the
  list is a separate, larger finding (see plans/README.md backlog). Do not change when the page resets.
- `src/api/client.ts`.

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(console): …`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Make each effect run own its in-flight request

Inside the effect, declare `let current = true;` and a per-run `let busy = false;` (remove the
shared `busy` ref). In `.then`, return without calling the handler when `!current`. In the
cleanup, set `current = false` and clear the timer. Add a one-line comment: a poll that answers
after the filter changed belongs to the old list and is dropped.

### Step 2: Do not poll a hidden tab

At the top of the interval callback, after the idle check, `if (document.hidden) return;`. Update
the file's header comment with one sentence saying so.

**Verify**: `npm run lint && npm run build` → both exit 0

### Step 3: Unit-test the pure parts

Move the overflow rule into an exported pure function in `live.ts`:

```ts
/** Whether a poll hit its limit before reaching `since`, so rows inside its window may be missing. */
export function liveOverflow(rows: readonly { at_millis: number }[], since: number): boolean
```

and call it from the hook (behaviour unchanged: `rows.length >= LIVE_LIMIT` and the oldest row is
newer than `since`). Create `tests/live.test.ts` covering:
- `liveSince`: uses newest-minus-lookback; never before the query's `since_millis`; falls back to `now` when there is no row.
- `liveQuery`: sets `since_millis` and `limit`, removes `cursor`, keeps other filters, accepts a query with or without the leading `?`.
- `liveOverflow`: false below the limit; true at the limit when the oldest row is newer than `since`; false at the limit when the oldest row is at or before `since`.

If importing `live.ts` from node:test fails because of its `react` or client imports, do not
restructure the app: STOP and report.

**Verify**: `npm test` → all pass, including the new file

### Step 4: Browser check

**Verify**: `npx playwright test tests/requests.spec.ts --trace off` → all pass

## Test plan

Step 3 (unit) and step 4 (existing browser spec stays green).

## Done criteria

- [ ] `npm run lint` exits 0
- [ ] `npm test` exits 0 and runs `tests/live.test.ts`
- [ ] `npm run build` exits 0
- [ ] `npx playwright test tests/requests.spec.ts --trace off` exits 0
- [ ] `grep -n "useRef(false)" src/features/requests/live.ts` returns no match
- [ ] Only the two in-scope files are modified

## STOP conditions

- Excerpts do not match.
- `live.ts` cannot be imported by a node:test file.
- The requests browser spec fails for a reason related to live mode after two fix attempts.

## Maintenance notes

- If `api.requests` gains an `AbortSignal` parameter, abort in the cleanup instead of ignoring the answer.
- Reviewer: check that no path can leave a run permanently "busy".
