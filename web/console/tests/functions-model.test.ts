import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteFunctions, SiteSpec } from "../src/api/types.ts";
import {
  askEstimate,
  changesOf,
  defaultPending,
  emptiesTable,
  isDefaultPick,
  NO_PENDING,
  type Pending,
  place,
  prunePending,
  underBypass,
  withAskUnknown,
} from "../src/features/sites/objects/functions-model.ts";
import { siteFunctions } from "./helpers/fixtures.ts";

const data: SiteFunctions = siteFunctions;

function pendingOf(parts: Partial<Record<keyof Pending, string[]>>): Pending {
  return {
    add: new Set(parts.add ?? []),
    admin: new Set(parts.admin ?? []),
    open: new Set(parts.open ?? []),
    remove: new Set(parts.remove ?? []),
  };
}

test("the default selection takes suggested candidates that are not sensitive", () => {
  const picked = defaultPending(data);
  // The fixture's candidates: metrics (below the threshold, sensitive), admin/reports (suggested, sensitive),
  // reports/{id} (suggested, not sensitive).
  assert.deepEqual([...picked.add], ["GET /api/reports/{id}"]);
  assert.equal(picked.admin.size, 0);
  assert.equal(picked.open.size, 0);
  assert.equal(picked.remove.size, 0);
});

test("the default selection leaves a proposed key to its proposal", () => {
  // A candidate the rules also propose as an administrator's function is not added as an open function.
  const proposed: SiteFunctions = {
    ...data,
    candidates: [
      {
        key: "POST /api/orders/{id}/refund",
        ordinary_units: 0,
        admin_units: 6,
        refused_units: 0,
        last_seen: "2026-11-10T00:00:00.000Z",
        requests_24h: 3,
        suggested: true,
        sensitive: false,
        on_entry: false,
      },
    ],
    proposals: [
      {
        key: "POST /api/orders/{id}/refund",
        tier: "admin",
        reliability: "high",
        admin_units: 6,
        refused_units: null,
        last_seen: "2026-11-10T00:00:00.000Z",
        in_table: false,
      },
    ],
  };
  assert.equal(defaultPending(proposed).add.size, 0);
});

test("pruning drops the keys the list no longer has", () => {
  const before = pendingOf({
    add: ["GET /api/reports/{id}", "GET /gone"],
    admin: ["DELETE /api/users/{id}", "GET /gone"],
    open: ["POST /api/admin/export", "GET /gone"],
    remove: ["GET /api/products/{id}", "GET /gone"],
  });
  const after = prunePending(before, data);
  assert.deepEqual([...after.add], ["GET /api/reports/{id}"]);
  assert.deepEqual([...after.admin], ["DELETE /api/users/{id}"]);
  assert.deepEqual([...after.open], ["POST /api/admin/export"]);
  assert.deepEqual([...after.remove], ["GET /api/products/{id}"]);
});

test("the body carries only the lists that hold something, in the list's order", () => {
  assert.equal(changesOf(NO_PENDING, data), null);
  // Picked out of order, the body follows the candidates' order: admin/reports comes before reports/{id}.
  const two = pendingOf({ add: ["GET /api/reports/{id}", "GET /api/admin/reports"] });
  assert.deepEqual(changesOf(two, data), {
    add: ["GET /api/admin/reports", "GET /api/reports/{id}"],
  });
  // An administrator's proposal carries the reliability the proposal states.
  const confirm = pendingOf({ admin: ["DELETE /api/users/{id}"] });
  assert.deepEqual(changesOf(confirm, data), {
    admin: [{ key: "DELETE /api/users/{id}", reliability: "medium" }],
  });
  assert.deepEqual(changesOf(pendingOf({ remove: ["GET /api/old"] }), data), null);
  assert.deepEqual(changesOf(pendingOf({ open: ["POST /api/admin/export"] }), data), {
    open: ["POST /api/admin/export"],
  });
});

test("the estimate adds the candidates and the unlearned traffic once", () => {
  const estimate = askEstimate(data);
  // 9 + 58 + 340 requests of the three candidates, 55 unlearned requests and 2 unkeyed ones.
  assert.equal(estimate.candidateRequests, 407);
  assert.equal(estimate.candidateCount, 3);
  assert.equal(estimate.unlearned, 55);
  assert.equal(estimate.unkeyed, 2);
  assert.equal(estimate.complete, true);
  assert.equal(estimate.total, 464);
  const quiet: SiteFunctions = {
    ...data,
    candidates: [],
    unlearned: { requests: 0, unkeyed_requests: 0, complete: true, top: [] },
  };
  assert.equal(askEstimate(quiet).total, 0);
});

test("a batch that empties the table is caught while the site asks about unknown functions", () => {
  const all = pendingOf({ remove: ["POST /api/admin/export", "GET /api/products/{id}"] });
  assert.equal(emptiesTable(all, data), true);
  // One entry left is enough to keep the table.
  assert.equal(emptiesTable(pendingOf({ remove: ["POST /api/admin/export"] }), data), false);
  // Removing every entry and adding a candidate keeps a function too.
  assert.equal(
    emptiesTable(
      pendingOf({
        remove: ["POST /api/admin/export", "GET /api/products/{id}"],
        add: ["GET /api/reports/{id}"],
      }),
      data,
    ),
    false,
  );
});

test("a function under a bypass pattern is flagged", () => {
  assert.equal(underBypass("GET /static/app.js", ["/static/*"]), true);
  assert.equal(underBypass("GET /api/x", ["/static/*"]), false);
  assert.equal(underBypass("GET /static/app.js", undefined), false);
  assert.equal(underBypass("GET /static/app.js", []), false);
  // A key without its space has no path to match, and does not throw.
  assert.equal(underBypass("/static/app.js", ["/static/*"]), false);
});

test("a key takes one change at a time, and the switch writes or removes its key", () => {
  const added = place(NO_PENDING, "add", "GET /api/reports/{id}", true);
  const confirmed = place(added, "admin", "GET /api/reports/{id}", true);
  assert.equal(confirmed.add.size, 0);
  assert.equal(confirmed.admin.has("GET /api/reports/{id}"), true);
  const spec: SiteSpec = {
    name: "emr",
    hosts: ["emr.example.com"],
    origin: "http://10.0.0.5:8080",
    session: { cookie: "SESSIONID" },
    entries: ["/login"],
    objects: { functions: [{ key: "POST /api/admin/export", source: "rule" }] },
  };
  const on = withAskUnknown(spec, true);
  assert.equal(on.objects?.ask_unknown_functions, true);
  const off = withAskUnknown(on, false);
  assert.equal("ask_unknown_functions" in (off.objects ?? {}), false);
  assert.deepEqual(off.objects?.functions, spec.objects?.functions);
});

test("a default pick is suggested, not sensitive and not proposed", () => {
  const candidate: SiteFunctions["candidates"][number] = {
    key: "POST /api/orders/{id}/refund",
    ordinary_units: 0,
    admin_units: 6,
    refused_units: 0,
    last_seen: "2026-11-10T00:00:00.000Z",
    requests_24h: 3,
    suggested: true,
    sensitive: false,
    on_entry: false,
  };
  assert.equal(isDefaultPick(candidate, new Set()), true);
  assert.equal(isDefaultPick(candidate, new Set([candidate.key])), false);
  assert.equal(isDefaultPick({ ...candidate, sensitive: true }, new Set()), false);
  assert.equal(isDefaultPick({ ...candidate, suggested: false }, new Set()), false);
});
