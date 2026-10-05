/** Synthetic request-stream and search fixtures. They model wire contracts for browser tests. */
import { searchPlanDigest } from "../src/search.ts";
import type { SearchEvent, SearchPlan, SearchResponse } from "../src/search.ts";
import { summaryFixture } from "./fixtures";

const SCOPE = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};

export const STREAM_TRACE = "018f2a3b4c5d70008000000000000003";
export const streamRequestId = (index: number) =>
  `req_018f2a3b-4c5d-7000-8000-${String(2000 + index).padStart(12, "0")}`;
export const streamEventId = (index: number) =>
  `ev_018f2a3b-4c5d-7000-8000-${String(1000 + index).padStart(12, "0")}`;

const denyReasons = ["UI_ACTION_NOT_AVAILABLE", "WAF_QUERY_BLOCKED", "AUTH_REQUIRED"];
const allowReasons = ["PUBLIC_ENTRY_ALLOWED", "UI_ACTION_ALLOWED"];

/** One terminal event of the synthetic stream, newest first by `index`. */
export function streamRow(index: number, terminal: string, endMs: number): SearchEvent {
  const aborted = terminal === "request.aborted";
  const outcome = aborted
    ? index % 3 === 0
      ? "UNKNOWN"
      : "DENY"
    : index % 3 === 0
      ? "ALLOW"
      : "DENY";
  const reason =
    aborted && outcome === "UNKNOWN"
      ? "REQUEST_INCOMPLETE"
      : outcome === "ALLOW"
        ? (allowReasons[index % allowReasons.length] as string)
        : (denyReasons[index % denyReasons.length] as string);
  // 61 s older per row, plus a sub-second part, strictly decreasing and inside the window.
  const micros = BigInt(endMs - 1_500 - index * 61_000) * 1000n + 123_456n;
  const millis = Number(micros / 1000n);
  const iso = `${new Date(millis).toISOString().slice(0, 19)}.${String(micros % 1_000_000n).padStart(6, "0")}Z`;
  return {
    request_id: streamRequestId(index),
    event_id: streamEventId(index),
    trace_id: STREAM_TRACE,
    event_type: terminal,
    stage: null,
    outcome,
    reason_code: reason,
    proof_kind: null,
    confidence: null,
    confidence_status: null,
    occurred_at: iso,
    request_seq: 9,
    duration_us: aborted ? 0 : 84 + index * 1_300,
    policy_revision: "policy-demo-r3",
    model_revision: null,
    model_call_id: null,
    evidence_refs: [],
    cause_event_ids: [],
    sensitivity: "INTERNAL",
  };
}

export type StreamOptions = {
  /** Rows available in total for the plan's terminal type and outcome. */
  total?: number;
  /** Override the scan statistics reported by the index. */
  scanned?: { rows: number | null; bytes: number | null };
  hasGaps?: boolean;
  pendingSegments?: number;
};

function position(event: SearchEvent): bigint {
  const [head, fraction] = event.occurred_at.split(".");
  return BigInt(Date.parse(`${head}Z`)) * 1000n + BigInt((fraction ?? "").slice(0, 6));
}

/**
 * A search response for a request-stream plan: `event_type` selects completed or aborted rows,
 * an `outcome` filter narrows them, the cursor continues after the event it names.
 */
export async function streamFixture(
  plan: SearchPlan,
  cursor: string | undefined,
  options: StreamOptions = {},
): Promise<SearchResponse> {
  const terminalFilter = plan.filters.find(
    (item) => item.kind === "text" && item.field === "event_type",
  );
  const terminal = terminalFilter?.kind === "text" ? terminalFilter.value : "request.completed";
  const outcomeFilter = plan.filters.find((item) => item.kind === "outcome");
  const reasonFilter = plan.filters.find(
    (item) => item.kind === "text" && item.field === "reason_code",
  );
  const endMs = Date.parse(plan.end);
  const total = options.total ?? 40;
  let rows = Array.from({ length: total }, (_, index) => streamRow(index, terminal, endMs));
  if (outcomeFilter?.kind === "outcome") {
    rows = rows.filter((row) => row.outcome === outcomeFilter.value);
  }
  if (reasonFilter?.kind === "text")
    rows = rows.filter((row) => row.reason_code === reasonFilter.value);
  let start = 0;
  if (cursor) {
    const id = cursor.split(".")[2];
    start = rows.findIndex((row) => row.event_id === id) + 1;
  }
  const page = rows.slice(start, start + plan.limit);
  const last = page.at(-1);
  const more = start + plan.limit < rows.length;
  return {
    ...SCOPE,
    schema_version: 3,
    query_digest: (await searchPlanDigest(plan)) ?? "0".repeat(64),
    as_of: new Date(endMs + 400).toISOString(),
    index_watermark: summaryFixture().index_watermark,
    has_gaps: options.hasGaps ?? false,
    pending_segments: options.pendingSegments ?? 0,
    scanned_rows: options.scanned ? options.scanned.rows : 120,
    scanned_bytes: options.scanned ? options.scanned.bytes : 8_192,
    truncated: more,
    next_cursor: more && last ? `v1.${position(last)}.${last.event_id}.${"0".repeat(64)}` : null,
    events: page,
  };
}

/** One event of the paged search fixture; event 1 is an `evidence.deleted` without a request. */
export function pagedSearchEvent(
  sequence: number,
  sort: SearchPlan["sort"] = "occurred_at_desc",
): SearchEvent {
  const bare = sequence === 1;
  return {
    event_id: `ev_018f2a3b-4c5d-7000-8000-${String(sequence).padStart(12, "0")}`,
    event_type: bare ? "evidence.deleted" : "stage.completed",
    trace_id: STREAM_TRACE,
    request_id: bare ? null : "req_018f2a3b-4c5d-7000-8000-000000000001",
    stage: bare ? null : "admission",
    outcome: bare ? null : "DENY",
    reason_code: bare ? null : "SEARCH_SYNTHETIC_DENIAL",
    proof_kind: bare ? null : "deterministic",
    confidence: null,
    confidence_status: bare ? null : "not_applicable",
    occurred_at: `2026-09-20T08:10:30.${sort === "occurred_at_asc" ? 123453 + sequence : 123458 - sequence}Z`,
    request_seq: sequence,
    duration_us: 24,
    policy_revision: "policy-demo-r3",
    model_revision: null,
    model_call_id: null,
    evidence_refs: ["artifact_018f2a3b-4c5d-7000-8000-000000000011"],
    cause_event_ids: [],
    sensitivity: "INTERNAL",
  };
}

/**
 * A structured-search response that obeys the page contract: a first page holds exactly `limit`
 * events and offers a cursor (the server only says "more" with a full page); the page after it
 * holds one event and ends. Event numbers are 1..limit, then limit+1.
 */
export async function pagedSearchFixture(
  plan: SearchPlan,
  cursor?: string,
): Promise<SearchResponse> {
  const first = cursor === undefined;
  const events = first
    ? Array.from({ length: plan.limit }, (_, index) => pagedSearchEvent(index + 1, plan.sort))
    : [pagedSearchEvent(plan.limit + 1, plan.sort)];
  const last = events.at(-1) as SearchEvent;
  return {
    ...SCOPE,
    schema_version: 3,
    query_digest: (await searchPlanDigest(plan)) ?? "0".repeat(64),
    as_of: "2026-09-20T08:10:30.000Z",
    index_watermark: summaryFixture().index_watermark,
    has_gaps: true,
    pending_segments: 2,
    scanned_rows: null,
    scanned_bytes: 0,
    truncated: first,
    next_cursor: first ? `v1.${position(last)}.${last.event_id}.${"0".repeat(64)}` : null,
    events,
  };
}

/** Whether a plan is a request-stream plan (its `event_type` filter is a terminal request event). */
export function isStreamPlan(plan: SearchPlan): boolean {
  return plan.filters.some(
    (item) =>
      item.kind === "text" &&
      item.field === "event_type" &&
      (item.value === "request.completed" || item.value === "request.aborted"),
  );
}
