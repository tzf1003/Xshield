import assert from "node:assert/strict";
import { test } from "node:test";
import {
  coverageReportQuery,
  coverageVerdict,
  decodeCoverageReport,
  share,
  validPathShape,
} from "../src/coverage-report.ts";

const request = { start: "2026-09-19T00:00:00Z", end: "2026-09-26T00:00:00Z" };

// The control plane's own HTTP regression (crates/xshield-control/src/tests/coverage_report.rs).
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
  start: request.start,
  end: request.end,
  completed_requests: 40,
  refused_requests: 5,
  observed_requests: 0,
  unrouted_refusals: 3,
  unshaped_unrouted_refusals: 1,
  routes: [{ operation_id: "orders.list", completed: 37, refused: 2, observed: 0 }],
  routes_truncated: false,
  refusals: [
    {
      operation_id: "",
      reason_code: "OPERATION_NOT_MATCHED",
      count: 3,
      last_seen: "2026-09-20T10:00:00.000000Z",
    },
    {
      operation_id: "orders.list",
      reason_code: "AUTH_REQUIRED",
      count: 2,
      last_seen: "2026-09-20T10:00:00.000000Z",
    },
  ],
  refusals_truncated: false,
  uncovered: [
    {
      method: "GET",
      path_shape: "/api/users/{}",
      count: 2,
      last_seen: "2026-09-20T10:00:00.000000Z",
    },
  ],
  uncovered_truncated: false,
  ...changes,
});

test("a report decodes only when its counts nest and add up for the window that was asked", () => {
  const report = decodeCoverageReport(wire(), request);
  assert.equal(report.refused_requests, 5);
  assert.equal(report.refusals[0]?.operation_id, "");
  assert.equal(report.uncovered[0]?.path_shape, "/api/users/{}");
  assert.equal(coverageVerdict(report), "uncovered");
  const refusal = wire().refusals[1];
  for (const changes of [
    { refused_requests: 6 },
    { refused_requests: 4 },
    { unrouted_refusals: 4 },
    { unshaped_unrouted_refusals: 4 },
    { unshaped_unrouted_refusals: 2 },
    { completed_requests: 4 },
    { observed_requests: 36 },
    { index_complete: false },
    { report_digest: "A".repeat(64) },
    { end: "2026-09-25T00:00:00Z" },
    { extra: true },
    { schema_version: 2 },
    // Routes may not claim more than the requests that matched one.
    { routes: [{ operation_id: "orders.list", completed: 38, refused: 2, observed: 0 }] },
    { routes: [{ operation_id: "orders.list", completed: 3, refused: 2, observed: 2 }] },
    // Lists are ordered by count, distinct and inside the window.
    { refusals: [refusal, wire().refusals[0]] },
    {
      refusals: [
        { ...refusal, count: 3 },
        { ...refusal, count: 2 },
      ],
    },
    {
      refusals: [wire().refusals[0], { ...refusal, last_seen: "2026-09-26T00:00:00.000000Z" }],
    },
    // A raw path that is not a shape never renders.
    {
      uncovered: [{ ...wire().uncovered[0], path_shape: "/api/users/12345" }],
    },
    { uncovered: [{ ...wire().uncovered[0], method: "get" }] },
  ]) {
    assert.throws(() => decodeCoverageReport(wire(changes), request), JSON.stringify(changes));
  }
  // A cut list stays below its total; a complete one equals it.
  assert.ok(decodeCoverageReport(wire({ refused_requests: 6, refusals_truncated: true }), request));
  assert.throws(() => decodeCoverageReport(wire({ refusals_truncated: true }), request));
  assert.ok(
    decodeCoverageReport(
      wire({
        completed_requests: 41,
        unrouted_refusals: 4,
        refused_requests: 6,
        refusals_truncated: true,
        uncovered_truncated: true,
      }),
      request,
    ),
  );
});

test("the verdict never reads an incomplete or empty window as covered", () => {
  const verdict = (changes: Record<string, unknown>) =>
    coverageVerdict(decodeCoverageReport(wire(changes), request));
  assert.equal(verdict({ has_gaps: true, index_complete: false }), "incomplete");
  assert.equal(verdict({ pending_segments: 1, index_complete: false }), "incomplete");
  const none = {
    refused_requests: 0,
    unrouted_refusals: 0,
    unshaped_unrouted_refusals: 0,
    routes: [],
    refusals: [],
    uncovered: [],
  };
  assert.equal(verdict({ ...none, completed_requests: 0 }), "no_traffic");
  assert.equal(
    verdict({
      ...none,
      routes: [{ operation_id: "orders.list", completed: 40, refused: 0, observed: 0 }],
    }),
    "covered",
  );
});

test("the query keeps the route's exact UTC second spelling and the 31-day limit", () => {
  assert.equal(
    coverageReportQuery(request),
    "start=2026-09-19T00%3A00%3A00Z&end=2026-09-26T00%3A00%3A00Z",
  );
  assert.ok(coverageReportQuery({ ...request, end: "2026-10-20T00:00:00Z" }));
  for (const invalid of [
    { ...request, start: "2026-09-19T00:00:00.000Z" },
    { ...request, end: request.start },
    { ...request, end: "2026-10-20T00:00:01Z" },
    { ...request, start: "2026-02-30T00:00:00Z" },
  ]) {
    assert.throws(() => coverageReportQuery(invalid), JSON.stringify(invalid));
  }
});

test("path shapes are exactly the ones the edge can produce", () => {
  for (const shape of [
    "/",
    "/{}",
    "/api/users/{}",
    "/api/v2/",
    "/a1b2/x",
    `/${"a".repeat(24)}`,
    `/${Array(9).fill("a").join("/")}/**`,
    `/${Array(10).fill("a").join("/")}`,
  ]) {
    assert.ok(validPathShape(shape), shape);
  }
  for (const shape of [
    "",
    "api",
    "//",
    "/a1b2c3",
    "/1abc",
    `/${"a".repeat(25)}`,
    "/a b",
    "/{x}",
    `/${Array(11).fill("a").join("/")}`,
    `/${Array(8).fill("a").join("/")}/**`,
    "/a/**/b",
  ]) {
    assert.ok(!validPathShape(shape), shape);
  }
});

test("shares read as whole percent from ten upward, otherwise one decimal", () => {
  assert.equal(share(0, 0), "—");
  assert.equal(share(0, 40), "0%");
  assert.equal(share(5, 40), "13%");
  assert.equal(share(1, 40), "2.5%");
  assert.equal(share(40, 40), "100%");
});
