import assert from "node:assert/strict";
import { test } from "node:test";
import type { Readiness } from "../src/api/types.ts";
import { readinessRows } from "../src/features/sites/readiness-model.ts";

const NOW = 1793539200000;
const plain: Readiness = {
  observing_since_millis: null,
  would_block: {},
  open_suggestions: 0,
  jev_health: "ok",
  jev_p95_ms: 760,
  jev_timeout_ratio: 0,
  attempts: 0,
  functions: null,
  on_jev_unavailable: "deny",
};

test("the function rows appear only for a site that guards functions", () => {
  const base = readinessRows(plain, NOW).length;
  assert.equal(readinessRows({ ...plain, functions: null }, NOW).length, base);

  const attempted = readinessRows({ ...plain, functions: { attempts: 3, unknown: null } }, NOW);
  assert.equal(attempted.length, base + 1);
  assert.equal(attempted.find((row) => row.key === "functions-attempts")?.mark, "▲");
  assert.equal(
    attempted.some((row) => row.key === "functions-unknown"),
    false,
  );

  const asking = readinessRows({ ...plain, functions: { attempts: 0, unknown: 4 } }, NOW);
  assert.equal(asking.length, base + 2);
  assert.equal(asking.find((row) => row.key === "functions-attempts")?.mark, "✓");
  assert.equal(asking.find((row) => row.key === "functions-unknown")?.mark, "▲");
});
