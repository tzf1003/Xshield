// URL search parameters and the scope they carry (docs/06 6.2.2, docs/07 7.10.3, 7.10.8).

import assert from "node:assert/strict";
import { test } from "node:test";
import { keepScope } from "../src/app/scope.ts";
import {
  flag,
  index,
  oneOf,
  str,
  validateGlobal,
  validateRequests,
} from "../src/app/search-schema.ts";

test("keepScope carries the scope and drops what belongs to the page", () => {
  assert.deepEqual(keepScope({ site: "emr", range: "6h", q: "outcome:blocked", peek: "r1" }), {
    site: "emr",
    range: "6h",
  });
});

test("keepScope reads a missing site as every site", () => {
  assert.deepEqual(keepScope({ range: "24h" }), { range: "24h" });
  assert.equal(keepScope({}).site, undefined);
});

test("a site or range the console cannot name reads as absent", () => {
  assert.deepEqual(validateGlobal({ site: "Not A Site!", range: "90d" }), {});
  assert.deepEqual(validateGlobal({ site: 7, range: ["1h"] }), {});
});

test("custom bounds are kept only with the custom range", () => {
  assert.deepEqual(validateGlobal({ range: "custom", since: "1000", until: "2000" }), {
    range: "custom",
    since: 1000,
    until: 2000,
  });
  assert.deepEqual(validateGlobal({ range: "1h", since: "1000", until: "2000" }), { range: "1h" });
  assert.deepEqual(validateGlobal({ range: "custom", since: "soon" }), { range: "custom" });
});

test("the small readers accept only what they name", () => {
  assert.equal(str("a"), "a");
  assert.equal(str(""), undefined);
  assert.equal(str(1), undefined);
  assert.equal(oneOf("b", ["a", "b"] as const), "b");
  assert.equal(oneOf("c", ["a", "b"] as const), undefined);
  assert.equal(flag("1"), "1");
  assert.equal(flag("true"), undefined);
  assert.equal(index("12"), 12);
  assert.equal(index("-1"), undefined);
  assert.equal(index("12345"), undefined);
  assert.equal(index(3), undefined);
});

test("the request list keeps its own parameters and drops an unknown chip or key", () => {
  const search = validateRequests({
    site: "emr",
    q: "outcome:blocked",
    chip: "blocked",
    scope: "all",
    live: "1",
    batch: "yes",
    api_unknown: "any",
    other: "x",
  });
  assert.equal(search.site, "emr");
  assert.equal(search.q, "outcome:blocked");
  assert.equal(search.chip, "blocked");
  assert.equal(search.scope, "all");
  assert.equal(search.live, "1");
  assert.equal(search.batch, undefined);
  assert.equal(search.api_unknown, "any");
  assert.equal("other" in search, false);
  assert.equal(validateRequests({ chip: "everything", scope: "some" }).chip, undefined);
  assert.equal(validateRequests({ chip: "everything", scope: "some" }).scope, undefined);
});
