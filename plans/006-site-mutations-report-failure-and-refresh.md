# Plan 006: Deleting a site reports failure, and import and rollback refresh what they changed

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ebc710b..HEAD -- web/console/src/api/queries.ts web/console/src/features/sites/SiteDetailPage.tsx`
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

Three mutations in the console leave the administrator looking at something untrue:

1. **Delete site** has no error path. On a 5xx, a 409 or a network failure the button just becomes
   clickable again; nothing says the site still exists.
2. **Import log** invalidates the query key prefix `["requests"]`, but the requests page reads
   `["requests-pages", …]` and its counts read `["counts", …]`; the overview reads `summary`,
   `timeseries`. After an import these show pre-import data until their stale time passes.
3. **Rollback** writes a new site version just as a save does, but invalidates less than a save:
   the insights and objects tabs keep showing data computed for the version that was rolled back.

## Current state

`web/console/src/features/sites/SiteDetailPage.tsx`:

```tsx
  const remove = useDeleteSite();            // line 130
  …
  const deleteSite = () => {                 // lines 261-269
    remove.mutate(name, {
      onSuccess: () => {
        clearDraft(name);
        leaving.current = true;
        void navigate({ to: "/sites" });
      },
    });
  };
  …
  return (
    <>
      <SiteHeader … onDelete={deleteSite} deleting={remove.isPending} />   // lines 356-363
```

`remove.error` is read nowhere. `ErrorBar` (`src/ui/Page.tsx:68`) renders
`<div className="errbar" role="alert">` with the text for an `ApiError` code.

`web/console/src/api/queries.ts`:

```ts
// useSaveSite, lines 264-272
    onSuccess: (site) => {
      client.setQueryData(keys.site(site.name), site);
      void client.invalidateQueries({ queryKey: keys.sites });
      void client.invalidateQueries({ queryKey: keys.versions(site.name) });
      void client.invalidateQueries({ queryKey: keys.insights(site.name) });
      // A save can undo an automatic change or move a position, so the map and its events are read again.
      void client.invalidateQueries({ queryKey: ["objects", site.name] });
      void client.invalidateQueries({ queryKey: ["object-events", site.name] });
    },
// useRollback, lines 298-302
    onSuccess: (site) => {
      client.setQueryData(keys.site(site.name), site);
      void client.invalidateQueries({ queryKey: keys.versions(site.name) });
      void client.invalidateQueries({ queryKey: keys.sites });
    },
// useImport, lines 310-316
    onSuccess: () => client.invalidateQueries({ queryKey: ["requests"] }),
```

Key roots defined in `keys` (lines 25-50): `["requests", q]`, `["requests-pages", q]`,
`["counts", q]`, `["sessions", q]`, `["summary", q]`, `["timeseries", q]`, `["jev-stats", q]`.

Browser specs use an in-memory mock API (`tests/helpers/mock-api.ts`); a spec can override one
route to make it fail through `MockOptions.overrides` (see the comment at `mock-api.ts:1199` and
its use in `tests/system-models.spec.ts`). `tests/sites-detail.spec.ts` covers the site page.

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
- `web/console/src/api/queries.ts` (only `useSaveSite`, `useRollback`, `useImport`)
- `web/console/src/features/sites/SiteDetailPage.tsx`
- `web/console/tests/sites-detail.spec.ts` (add one spec)

**Out of scope**:
- `SiteHeader.tsx` and the delete confirmation itself.
- Other mutations (`useConfirmJudgement`, the bulk acknowledge loop in `ObjectsBanner.tsx`): separate findings.
- `tests/helpers/mock-api.ts` — use overrides, do not change the mock.

## Git workflow

- Commit on the branch you were given; one commit for this plan.
- Message style is conventional commits, e.g. `fix(console): …`.
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: One function for "a site got a new version"

In `queries.ts`, above `useSaveSite`, add a module-level function
`siteVersionChanged(client: QueryClient, site: <the type onSuccess receives>)` that performs
exactly the six calls `useSaveSite.onSuccess` performs today (keep its comment). Use it from
`useSaveSite` and `useRollback`. Import the `QueryClient` type from `@tanstack/react-query` if it
is not already imported.

**Verify**: `npm run lint && npm run build` → exit 0

### Step 2: Import refreshes every list and figure built from the decision log

Replace the single invalidation in `useImport` with invalidations of the roots `"requests"`,
`"requests-pages"`, `"counts"`, `"sessions"`, `"summary"`, `"timeseries"`, `"jev-stats"`
(a `for` loop over a small constant array is fine; `onSuccess` may return `Promise.all` of them or
fire them with `void`, matching the surrounding style).

**Verify**: `npm run lint && npm run build` → exit 0

### Step 3: Show a failed delete

In `SiteDetailPage.tsx` render `{remove.isError ? <ErrorBar error={remove.error} /> : null}`
directly after `<SiteHeader … />`. Import `ErrorBar` from `../../ui/Page.tsx` if the file does not
already import it (it imports `Loading`/`Notice` from there).

**Verify**: `npm run lint && npm run build` → exit 0

### Step 4: Browser spec

In `tests/sites-detail.spec.ts` add a spec "a failed delete says so and stays on the page":
override `DELETE /api/sites/<name>` to answer 500 with `{ error: "INTERNAL" }` (use the override
mechanism the other specs use), open the site, delete it through the UI the way an existing spec
does (find one with `grep -rn "删除站点\|onDelete\|deleteSite" tests src/features/sites/SiteHeader.tsx`),
and assert that an element with role `alert` is visible and the URL is still the site's page.

**Verify**: `npx playwright test tests/sites-detail.spec.ts tests/sites-history.spec.ts --trace off` → all pass

## Test plan

Step 4, plus the full unit suite (`npm test`). Invalidations are not unit-testable without a DOM;
the reviewer reads them.

## Done criteria

- [ ] `npm run lint`, `npm test`, `npm run build` all exit 0
- [ ] `npx playwright test tests/sites-detail.spec.ts tests/sites-history.spec.ts tests/requests.spec.ts --trace off` exits 0
- [ ] `grep -n "remove.error" src/features/sites/SiteDetailPage.tsx` has a match
- [ ] `grep -n '"requests-pages"' src/api/queries.ts` shows it inside `useImport`'s invalidation list as well as in `keys`
- [ ] Only the three in-scope files are modified

## STOP conditions

- Excerpts do not match.
- No existing spec deletes a site and the delete control cannot be driven without changing `SiteHeader.tsx`.
- The mock cannot be overridden for a DELETE route without editing `mock-api.ts`.

## Maintenance notes

- Any new mutation that produces a site version should call `siteVersionChanged`.
- Any new query built from the decision log needs its root added to the import list.
