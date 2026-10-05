import assert from "node:assert/strict";
import { test } from "node:test";
import type { WorkbenchObservation } from "../src/api.ts";
import { observationView } from "../src/operations/observation.ts";

const SNAPSHOT = "2026-10-04T02:00:00Z";
const STORED = "2026-10-03T21:15:00Z";

const observed = (
  source_state: WorkbenchObservation<string>["source_state"],
  value: string | null,
  reason_code: string,
  observed_at = SNAPSHOT,
): WorkbenchObservation<string> => ({ observed_at, source_state, reason_code, value });

test("a probed edge state is shown with the snapshot time and is not a stored value", () => {
  const view = observationView(observed("available", "healthy", "WORKBENCH_EDGE_PROBED"), "edge");
  assert.equal(view.state, "healthy");
  assert.equal(view.label, "健康");
  assert.equal(view.tone, "allow");
  assert.equal(view.observedAt, SNAPSHOT);
  assert.equal(view.stored, false);
  // A slow or silent edge is an observed "unavailable", not a missing value.
  const slow = observationView(
    observed("available", "unavailable", "WORKBENCH_EDGE_PROBED"),
    "edge",
  );
  assert.equal(slow.state, "unavailable");
  assert.equal(slow.tone, "deny");
});

test("the upstream value is the last stored observation and keeps its own time", () => {
  const view = observationView(
    observed("available", "degraded", "WORKBENCH_UPSTREAM_LAST_OBSERVED", STORED),
    "upstream",
  );
  assert.equal(view.state, "degraded");
  assert.equal(view.stored, true);
  assert.equal(view.observedAt, STORED);
  assert.match(view.reasonText, /最近一次持久化的健康读取/);
});

test("sources that were not observed are never healthy and carry no observation time", () => {
  for (const [observation, kind, label] of [
    [observed("unavailable", null, "WORKBENCH_UPSTREAM_NEVER_OBSERVED"), "upstream", "从未观察"],
    [observed("unavailable", null, "WORKBENCH_EDGE_NOT_CONFIGURED"), "edge", "未配置"],
    [observed("unavailable", null, "WORKBENCH_EDGE_STATE_UNKNOWN"), "edge", "状态未知"],
    [observed("unavailable", null, "WORKBENCH_EDGE_AUDIT_UNKNOWN"), "audit", "未观察到"],
    [observed("not_authorized", null, "WORKBENCH_EDGE_PROBED"), "edge", "无权读取"],
    [observed("unavailable", null, "SOMETHING_NEW"), "edge", "未观察"],
  ] as const) {
    const view = observationView(observation, kind);
    assert.equal(view.state, "unobserved", label);
    assert.equal(view.label, label);
    assert.equal(view.tone, "unknown", label);
    assert.equal(view.observedAt, null, label);
    assert.equal(view.stored, false, label);
  }
});

test("a stored upstream state outside the vocabulary is unrecognized at its own time", () => {
  const view = observationView(
    observed("unavailable", null, "WORKBENCH_UPSTREAM_STATE_UNKNOWN", STORED),
    "upstream",
  );
  assert.equal(view.state, "unrecognized");
  assert.equal(view.observedAt, STORED);
  assert.equal(view.stored, true);
  assert.equal(view.tone, "unknown");
});

test("an unexpected value from an available source is shown raw, never mapped to a state", () => {
  const view = observationView(observed("available", "HEALTHY", "WORKBENCH_EDGE_PROBED"), "edge");
  assert.equal(view.state, "unrecognized");
  assert.equal(view.label, "无法识别");
  assert.equal(view.raw, "HEALTHY");
  // Prototype members are not states either.
  assert.equal(
    observationView(observed("available", "constructor", "WORKBENCH_EDGE_PROBED"), "edge").state,
    "unrecognized",
  );
});
