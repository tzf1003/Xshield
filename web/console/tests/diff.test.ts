import { test } from "node:test";
import assert from "node:assert/strict";
import { diffSiteSpec, formatFieldValue } from "../src/diff.ts";
import type { SiteSpecJson } from "../src/types.ts";

const base: SiteSpecJson = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { cookie: "SESSIONID" },
  entries: ["/login", "/api/home"],
  bypass: ["/static/*"],
  mode: "observe",
  on_jev_unavailable: "deny",
};

test("diffSiteSpec: no changes between identical specs", () => {
  const changes = diffSiteSpec(base, { ...base });
  assert.deepEqual(changes, []);
});

test("diffSiteSpec: reports only the fields that changed", () => {
  const after: SiteSpecJson = {
    ...base,
    mode: "enforce",
    hosts: ["emr.example.com", "emr2.example.com"],
  };
  const changes = diffSiteSpec(base, after);
  const fields = changes.map((change) => change.field).sort();
  assert.deepEqual(fields, ["hosts", "mode"]);
  const modeChange = changes.find((change) => change.field === "mode");
  assert.equal(modeChange?.before, "observe");
  assert.equal(modeChange?.after, "enforce");
});

test("diffSiteSpec: before null means the entry created the site", () => {
  const changes = diffSiteSpec(null, base);
  assert.ok(changes.some((change) => change.field === "name" && change.after === "emr"));
  assert.ok(changes.every((change) => change.before === undefined));
});

test("diffSiteSpec: after null means the entry deleted the site", () => {
  const changes = diffSiteSpec(base, null);
  assert.ok(changes.every((change) => change.after === undefined));
  assert.ok(changes.some((change) => change.field === "name" && change.before === "emr"));
});

test("diffSiteSpec: both null (should not normally happen) yields no changes", () => {
  assert.deepEqual(diffSiteSpec(null, null), []);
});

test("formatFieldValue: arrays, objects, primitives and missing values", () => {
  assert.equal(formatFieldValue(["/a", "/b"]), "/a, /b");
  assert.equal(formatFieldValue([]), "（空）");
  assert.equal(formatFieldValue({ cookie: "SESSIONID" }), '{"cookie":"SESSIONID"}');
  assert.equal(formatFieldValue("observe"), "observe");
  assert.equal(formatFieldValue(undefined), "（不存在）");
});
