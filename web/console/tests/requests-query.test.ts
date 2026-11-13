// The request list's query (docs/06 6.4.3, docs/07 7.9.3): chips and the condition text combine with AND.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Scope } from "../src/app/scope.ts";
import { linkedCondition, planCounts, planList } from "../src/features/requests/query.ts";

const scope: Scope = { site: "emr", range: "1h", since: 1000, until: 2000 };

function params(query: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(query));
}

test("the default list covers the window and the site, and leaves bypass rows out", () => {
  const plan = planList({ q: "", chip: "judged", all: false, scope });
  assert.deepEqual(params(plan.query), { site: "emr", since_millis: "1000", until_millis: "2000" });
  assert.equal(plan.includesAll, false);
  assert.equal(plan.impossible, false);
  assert.deepEqual(plan.errors, []);
});

test("the switch brings bypass and unknown-site rows back", () => {
  const plan = planList({ q: "", chip: "judged", all: true, scope });
  assert.equal(params(plan.query).scope, "all");
  assert.equal(plan.includesAll, true);
});

test("a chip and the condition text that both name the outcome are intersected", () => {
  const plan = planList({ q: "outcome:blocked", chip: "attention", all: false, scope });
  assert.equal(params(plan.query).outcome, "blocked");
  assert.equal(plan.impossible, false);
});

test("an empty intersection is reported as impossible", () => {
  const plan = planList({ q: "outcome:allowed", chip: "blocked", all: false, scope });
  assert.equal(plan.impossible, true);
});

test("a lookup by request, session or exact path includes every row", () => {
  for (const q of [`id:req_${"0a".repeat(16)}`, `session:${"0a".repeat(8)}`, "path:/a/b"]) {
    const plan = planList({ q, chip: "judged", all: false, scope });
    assert.equal(plan.includesAll, true, q);
    assert.equal(params(plan.query).scope, "all", q);
  }
  const prefix = planList({ q: "path:/a/*", chip: "judged", all: false, scope });
  assert.equal(prefix.includesAll, false);
});

test("a site in the condition text wins over the scope's site", () => {
  const plan = planList({ q: "site:juice", chip: "judged", all: false, scope });
  assert.equal(params(plan.query).site, "juice");
});

test("the counts ignore the chip and count every row", () => {
  assert.deepEqual(params(planCounts("outcome:blocked", scope)), {
    outcome: "blocked",
    site: "emr",
    since_millis: "1000",
    until_millis: "2000",
    scope: "all",
  });
});

test("a link's own parameters become condition text, and none gives none", () => {
  assert.equal(linkedCondition({}), "");
  assert.notEqual(linkedCondition({ api: "GET /a" }), "");
});
