import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../src/api-contract.ts";
import {
  conditionProblem,
  conditionToFilter,
  detectField,
  filterFields,
  MAX_CONDITIONS,
} from "../src/investigation/filter-fields.ts";
import {
  buildCausalityPlan,
  buildModelListPlan,
  buildSearchPlan,
  buildStreamPlan,
  displayPlan,
  emptyStreamFilters,
  extraFilterCount,
  outcomesFor,
  planKey,
  STREAM_PAGE_SIZE,
} from "../src/investigation/plans.ts";
import {
  decodePrefill,
  encodePrefill,
  filterAccepted,
  PREFILL_PARAM,
  presetKinds,
  searchLocation,
} from "../src/investigation/search-preset.ts";
import {
  fromAuditEvent,
  fromSearchEvent,
  toCausalRecord,
} from "../src/investigation/event-view.ts";
import { searchFixture } from "./fixtures.ts";

const WINDOW = { start: "2026-09-20T00:00:00Z", end: "2026-09-20T01:00:00Z" } as const;
const uuid = (n: number) => `018f2a3b-4c5d-7000-8000-${String(n).padStart(12, "0")}`;

function invalid(run: () => unknown, code = "CONTROL_QUERY_INVALID") {
  assert.throws(run, (error: unknown) => error instanceof ApiError && error.code === code);
}

test("the request stream is structured search with a fixed terminal event type", () => {
  const plan = buildStreamPlan(WINDOW, emptyStreamFilters);
  assert.deepEqual(plan, {
    schema_version: 3,
    ...WINDOW,
    filters: [{ kind: "text", field: "event_type", value: "request.completed" }],
    sort: "occurred_at_desc",
    limit: STREAM_PAGE_SIZE,
  });
  assert.equal(STREAM_PAGE_SIZE, 25);
});

test("outcome chips map to the outcomes a terminal event can carry", () => {
  // request.completed is ALLOW or DENY; only request.aborted can be UNKNOWN.
  assert.deepEqual(outcomesFor("request.completed"), ["all", "DENY", "ALLOW"]);
  assert.deepEqual(outcomesFor("request.aborted"), ["all", "DENY", "ALLOW", "UNKNOWN"]);
  const deny = buildStreamPlan(WINDOW, { ...emptyStreamFilters, outcome: "DENY" });
  assert.deepEqual(deny.filters, [
    { kind: "text", field: "event_type", value: "request.completed" },
    { kind: "outcome", value: "DENY" },
  ]);
  const aborted = buildStreamPlan(WINDOW, {
    ...emptyStreamFilters,
    terminal: "request.aborted",
    outcome: "UNKNOWN",
  });
  assert.deepEqual(aborted.filters, [
    { kind: "text", field: "event_type", value: "request.aborted" },
    { kind: "outcome", value: "UNKNOWN" },
  ]);
});

test("extra stream filters keep a fixed order and count", () => {
  const filters = {
    ...emptyStreamFilters,
    operationId: "orders.read",
    reasonCode: "WAF_QUERY_BLOCKED",
    traceId: "018f2a3b4c5d70008000000000000003",
    subjectRef: "operator-1",
  };
  const plan = buildStreamPlan(WINDOW, filters);
  assert.deepEqual(
    plan.filters.map((filter) => filter.kind),
    ["text", "text", "text", "trace_id", "subject_ref"],
  );
  assert.equal(extraFilterCount(filters), 4);
  assert.equal(extraFilterCount(emptyStreamFilters), 0);
  // The single gate refuses what the allowlist does not accept.
  invalid(() => buildStreamPlan(WINDOW, { ...emptyStreamFilters, operationId: "a b" }));
  invalid(() => buildStreamPlan(WINDOW, { ...emptyStreamFilters, traceId: "ABC" }));
  invalid(() => buildStreamPlan(WINDOW, { ...emptyStreamFilters, subjectRef: "a\u0000b" }));
  invalid(() => buildStreamPlan({ start: WINDOW.end, end: WINDOW.start }, emptyStreamFilters));
  invalid(() =>
    buildStreamPlan(
      { start: "2026-01-01T00:00:00Z", end: "2026-03-01T00:00:00Z" },
      emptyStreamFilters,
    ),
  );
});

test("a subject reference is masked in the displayed plan but kept in the query key", () => {
  const plan = buildStreamPlan(WINDOW, { ...emptyStreamFilters, subjectRef: "operator-1" });
  const shown = JSON.stringify(displayPlan(plan));
  assert.equal(shown.includes("operator-1"), false);
  assert.ok(shown.includes("[已隐藏]"));
  assert.ok(planKey(plan).includes("operator-1"), "different subjects are different queries");
  assert.equal(plan.filters.at(-1)?.kind, "subject_ref");
});

test("the search builder applies at most eight AND conditions and the allowlist", () => {
  const conditions = [
    { field: "request_id", value: `req_${uuid(1)}` },
    { field: "stage", value: "operation_admission" },
    { field: "outcome", value: "DENY" },
    { field: "confidence_at_most", value: "9000" },
  ] as const;
  const plan = buildSearchPlan({ window: WINDOW, conditions, sort: "occurred_at_asc", limit: 50 });
  assert.deepEqual(plan.filters, [
    { kind: "request_id", value: `req_${uuid(1)}` },
    { kind: "text", field: "stage", value: "operation_admission" },
    { kind: "outcome", value: "DENY" },
    { kind: "confidence_at_most", basis_points: 9000 },
  ]);
  assert.equal(plan.sort, "occurred_at_asc");
  assert.equal(MAX_CONDITIONS, 8);
  const nine = Array.from({ length: 9 }, () => ({ field: "stage", value: "a" }) as const);
  invalid(() =>
    buildSearchPlan({ window: WINDOW, conditions: nine, sort: "occurred_at_desc", limit: 25 }),
  );
  const eight = nine.slice(0, 8);
  assert.doesNotThrow(() =>
    buildSearchPlan({ window: WINDOW, conditions: eight, sort: "occurred_at_desc", limit: 25 }),
  );
  for (const limit of [0, 1001, 1.5, Number.NaN]) {
    invalid(() =>
      buildSearchPlan({ window: WINDOW, conditions: [], sort: "occurred_at_desc", limit }),
    );
  }
});

test("each condition is checked by the validator before it can be added", () => {
  assert.equal(conditionProblem({ field: "request_id", value: `req_${uuid(1)}` }), null);
  assert.match(
    conditionProblem({ field: "request_id", value: "req_123" }) ?? "",
    /请求 ID格式无效/,
  );
  assert.equal(conditionProblem({ field: "request_id", value: "" }), "请填写条件的值。");
  assert.match(
    conditionProblem({ field: "operation_id", value: "select * from events" }) ?? "",
    /字母、数字/,
  );
  assert.equal(conditionProblem({ field: "operation_id", value: "orders.read" }), null);
  assert.equal(conditionProblem({ field: "confidence_at_most", value: "0" }), null);
  assert.equal(conditionProblem({ field: "confidence_at_most", value: "10000" }), null);
  for (const bad of ["10001", "-1", "1.5", "abc", " "]) {
    assert.notEqual(conditionProblem({ field: "confidence_at_most", value: bad }), null, bad);
  }
  assert.equal(conditionProblem({ field: "outcome", value: "DENY" }), null);
  assert.notEqual(conditionProblem({ field: "outcome", value: "GRANTED" }), null);
  assert.equal(conditionProblem({ field: "subject_ref", value: "operator-1" }), null);
  assert.notEqual(conditionProblem({ field: "subject_ref", value: "x".repeat(257) }), null);
  assert.deepEqual(conditionToFilter({ field: "stage", value: "a" }), {
    kind: "text",
    field: "stage",
    value: "a",
  });
  // Every field of the catalogue is a field the allowlist knows.
  assert.equal(new Set(filterFields.map((field) => field.id)).size, filterFields.length);
  assert.equal(filterFields.length, 23);
});

test("a pasted ID picks its field through the shell classifier", () => {
  const expected: [string, string][] = [
    [`req_${uuid(1)}`, "request_id"],
    [`mdl_${uuid(2)}`, "model_call_id"],
    [`agt_${uuid(3)}`, "agent_run_id"],
    [`grant_${uuid(4)}`, "grant_id"],
    [`auth_${uuid(5)}`, "auth_binding_id"],
    [`calr_${uuid(6)}`, "calibration_report_id"],
    [`case_${uuid(7)}`, "case_id"],
    [`access_${uuid(8)}`, "evidence_access_request_id"],
    [`job_${uuid(10)}`, "job_id"],
    [`artifact_${uuid(11)}`, "artifact_id"],
    [`share_${uuid(13)}`, "share_grant_id"],
    [`ev_${uuid(12)}`, "event_id"],
    ["018f2a3b4c5d70008000000000000003", "trace_id"],
  ];
  for (const [value, field] of expected) {
    assert.equal(detectField(value)?.field, field, value);
    // Quotes and whitespace around a pasted value are tolerated, nothing else is rewritten.
    assert.equal(detectField(`  "${value}" `)?.field, field, value);
  }
  // An event ID is also a retention-lock ID: both are offered, the first is the default.
  assert.deepEqual(detectField(`ev_${uuid(12)}`)?.alternatives, ["event_id", "evidence_hold_id"]);
  // Not canonical, or not searchable: nothing is guessed.
  for (const bad of [
    "",
    "req_123",
    `req_${uuid(1).toUpperCase()}`,
    `req_${uuid(1)}x`,
    `export_${uuid(9)}`,
    "orders.read",
    "018f2a3b4c5d7000800000000000000",
  ]) {
    assert.equal(detectField(bad), null, bad);
  }
});

test("search presets round-trip through the route and reject anything non-canonical", () => {
  const preset = { kind: "trace_id", value: "018f2a3b4c5d70008000000000000003" } as const;
  assert.equal(encodePrefill(preset), "trace_id:018f2a3b4c5d70008000000000000003");
  assert.deepEqual(decodePrefill(encodePrefill(preset)), preset);
  const first = searchLocation(preset);
  assert.equal(first.to, "/investigation/search");
  assert.deepEqual(first.search, { [PREFILL_PARAM]: "trace_id:018f2a3b4c5d70008000000000000003" });
  // The same condition handed over twice is two navigations: the router must not see the second
  // as "already there", or the form would keep whatever the operator edited in between.
  assert.notEqual(searchLocation(preset).state.handOver, first.state.handOver);
  // A prefill can only name an ID: never a free-text condition such as a subject reference.
  assert.equal((presetKinds as readonly string[]).includes("subject_ref"), false);
  for (const bad of [
    undefined,
    7,
    "",
    "trace_id",
    ":x",
    "subject_ref:operator-1",
    "stage:operation_admission",
    "trace_id:NOT-A-TRACE",
    `request_id:req_${uuid(1)}\n`,
    `event_id:${`req_${uuid(1)}`}`,
  ]) {
    assert.equal(decodePrefill(bad), null, String(bad));
  }
  assert.equal(filterAccepted({ kind: "request_id", value: `req_${uuid(1)}` }), true);
  assert.equal(filterAccepted({ kind: "request_id", value: "x" }), false);
});

test("model list and causality plans go through their own validators", () => {
  assert.deepEqual(buildModelListPlan(WINDOW, 25), { ...WINDOW, limit: 25 });
  invalid(() => buildModelListPlan(WINDOW, 101), "CONTROL_MODEL_CALLS_REQUEST_INVALID");
  invalid(() => buildModelListPlan(WINDOW, 0), "CONTROL_MODEL_CALLS_REQUEST_INVALID");
  const plan = buildCausalityPlan({
    window: WINDOW,
    eventId: `ev_${uuid(1)}`,
    direction: "both",
    maxDepth: 2,
    maxNodes: 16,
  });
  assert.equal(plan.max_depth, 2);
  invalid(
    () =>
      buildCausalityPlan({
        window: WINDOW,
        eventId: `ev_${uuid(1)}`,
        direction: "both",
        maxDepth: 5,
        maxNodes: 16,
      }),
    "CONTROL_CAUSALITY_REQUEST_INVALID",
  );
  invalid(
    () =>
      buildCausalityPlan({
        window: WINDOW,
        eventId: "ev_1",
        direction: "both",
        maxDepth: 2,
        maxNodes: 16,
      }),
    "CONTROL_CAUSALITY_REQUEST_INVALID",
  );
});

test("both event wire shapes project to the same redacted view", async () => {
  const search = await searchFixture();
  const view = fromSearchEvent(search.events[1] as (typeof search.events)[number]);
  assert.equal(view.stage, "admission");
  assert.equal(view.traceId, "018f2a3b4c5d70008000000000000003");
  assert.equal(view.occurredAt.endsWith("Z"), true);
  const nullable = fromSearchEvent(search.events[0] as (typeof search.events)[number]);
  assert.equal(nullable.requestId, null);
  assert.equal(nullable.outcome, null);
  const audit = fromAuditEvent(
    {
      event_id: `ev_${uuid(1)}`,
      event_type: "stage.completed",
      stage: "",
      outcome: "",
      reason_code: "",
      proof_kind: "deterministic",
      confidence: null,
      confidence_status: "not_applicable",
      occurred_at: 1_789_891_830_123_456,
      request_seq: 1,
      duration_us: 24,
      policy_revision: "policy-r1",
      model_revision: "",
      model_call_id: null,
      evidence_refs: [],
      cause_event_ids: [`ev_${uuid(2)}`],
      sensitivity: "INTERNAL",
    },
    `req_${uuid(9)}`,
  );
  // Microseconds survive, empty strings become "not recorded".
  assert.equal(audit.occurredAt, "2026-09-20T08:10:30.123456Z");
  assert.equal(audit.stage, null);
  assert.equal(audit.reasonCode, null);
  assert.equal(audit.modelRevision, null);
  assert.deepEqual(toCausalRecord(audit), {
    event_id: `ev_${uuid(1)}`,
    event_type: "stage.completed",
    stage: null,
    cause_event_ids: [`ev_${uuid(2)}`],
  });
});
