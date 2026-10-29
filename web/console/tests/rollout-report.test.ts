import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteRevision } from "../src/api.ts";
import {
  decodeRolloutReport,
  reportTime,
  reportVerdict,
  rolloutReportQuery,
} from "../src/rollout-report.ts";
import { reportWindow } from "../src/sites/model/rollout.ts";

const request = {
  revision: "rollout-1",
  start: "2026-09-19T00:00:00Z",
  end: "2026-09-26T00:00:00Z",
};

const wire = (changes: Record<string, unknown> = {}) => ({
  schema_version: 1,
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
  tenant_id: "tenant_a",
  site_id: "site_a",
  watermark_scope: "configured_journal",
  as_of: "2026-09-26T00:00:01.000000Z",
  index_watermark: null,
  has_gaps: false,
  pending_segments: 0,
  index_complete: true,
  report_digest: "a".repeat(64),
  rollout_revision: "rollout-1",
  start: request.start,
  end: request.end,
  completed_requests: 40,
  observed_requests: 3,
  unrouted_refusals: 2,
  observations: [
    {
      operation_id: "orders.list",
      reason_code: "UI_ACTION_NOT_AVAILABLE",
      count: 2,
      last_seen: "2026-09-20T10:00:00.000000Z",
    },
    {
      operation_id: "",
      reason_code: "AUTH_REQUIRED",
      count: 1,
      last_seen: "2026-09-19T00:00:01.000000Z",
    },
  ],
  truncated: false,
  ...changes,
});

test("a report decodes only when its counts add up for the window that was asked", () => {
  const report = decodeRolloutReport(wire(), request);
  assert.equal(report.observed_requests, 3);
  assert.equal(report.observations[1]?.operation_id, "");
  assert.equal(reportVerdict(report), "would_deny");
  for (const changes of [
    { observed_requests: 4 },
    { observed_requests: 4, truncated: true, unrouted_refusals: 50 },
    { completed_requests: 2 },
    { index_complete: false },
    { report_digest: "A".repeat(64) },
    { rollout_revision: "rollout-2" },
    { end: "2026-09-25T00:00:00Z" },
    { extra: true },
    { schema_version: 2 },
  ]) {
    assert.throws(() => decodeRolloutReport(wire(changes), request), JSON.stringify(changes));
  }
  assert.ok(decodeRolloutReport(wire({ observed_requests: 4, truncated: true }), request));
});

test("the verdict never reads an incomplete or empty window as a pass", () => {
  const verdict = (changes: Record<string, unknown>) =>
    reportVerdict(decodeRolloutReport(wire(changes), request));
  assert.equal(verdict({ has_gaps: true, index_complete: false }), "incomplete");
  assert.equal(verdict({ pending_segments: 1, index_complete: false }), "incomplete");
  const none = { observed_requests: 0, unrouted_refusals: 0, observations: [] };
  assert.equal(verdict({ ...none, completed_requests: 0 }), "no_traffic");
  assert.equal(verdict(none), "clean");
});

test("the query keeps the route's exact UTC second spelling", () => {
  assert.equal(
    rolloutReportQuery(request),
    "revision=rollout-1&start=2026-09-19T00%3A00%3A00Z&end=2026-09-26T00%3A00%3A00Z",
  );
  for (const invalid of [
    { ...request, revision: "has space" },
    { ...request, start: "2026-09-19T00:00:00.000Z" },
    { ...request, end: request.start },
  ]) {
    assert.throws(() => rolloutReportQuery(invalid));
  }
  assert.equal(reportTime(1_789_776_000.9), "2026-09-19T00:00:00Z");
});

test("the report window starts with the first revision that carried the rollout", () => {
  const rollout = {
    mode: "observe" as const,
    observe_until_unix: 1_790_380_800,
    revision: "rollout-1",
  };
  const revision = (number: number, createdAt: string, label: string | null): SiteRevision => ({
    revision: number,
    policy_revision: "policy-r1",
    config_digest: "d".repeat(64),
    created_by: "admin",
    created_at: createdAt,
    config: {
      policy: label ? { rollout: { mode: "observe", observe_until_unix: 1, revision: label } } : {},
    },
  });
  const revisions = [
    revision(3, "2026-09-21T00:00:00Z", "rollout-1"),
    revision(2, "2026-09-19T12:00:00Z", "rollout-1"),
    revision(1, "2026-09-01T00:00:00Z", null),
  ];
  assert.deepEqual(reportWindow(rollout, revisions, 1_790_000_000), {
    revision: "rollout-1",
    start: "2026-09-19T12:00:00Z",
    end: reportTime(1_790_000_000),
  });
  // After the deadline the window ends there; without a matching revision it is the longest one.
  assert.equal(reportWindow(rollout, revisions, 1_800_000_000)?.end, "2026-09-26T00:00:00Z");
  assert.equal(reportWindow(rollout, [], 1_790_000_000)?.start, "2026-08-27T00:00:00Z");
  assert.equal(reportWindow(rollout, revisions, 1_789_000_000), null);
});
