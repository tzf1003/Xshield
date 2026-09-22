/** Bounded investigation QueryPlan and redacted search wire contract.
 * Scope and cursor authentication belong to the server; this boundary rejects
 * malformed plans and responses before any fact enters the console state.
 */
import {
  ApiError,
  uuid,
  requestPattern,
  modelCallPattern,
  eventPattern,
  artifactPattern,
  grantPattern,
  bindingPattern,
  ensure,
  object,
  text,
  name,
  id,
  integer,
  choice,
  nullable,
  list,
  references,
  envelope,
  watermarked,
  pagination,
  confidence,
} from "./api-contract.ts";
import type { Envelope, Watermark } from "./api-contract.ts";

const textFields = [
  "event_type",
  "stage",
  "reason_code",
  "operation_id",
  "model_revision",
] as const;
const outcomes = [
  "PASS",
  "ALLOW",
  "DENY",
  "UNKNOWN",
  "ERROR",
  "SKIPPED",
  "CANCELLED",
] as const;
const idPatterns = {
  request_id: requestPattern,
  event_id: eventPattern,
  grant_id: grantPattern,
  auth_binding_id: bindingPattern,
  case_id: new RegExp(`^case_${uuid}$`),
  artifact_id: artifactPattern,
  calibration_report_id: new RegExp(`^calr_${uuid}$`),
};
export type SearchFilter =
  | { kind: keyof typeof idPatterns; value: string }
  | { kind: "text"; field: (typeof textFields)[number]; value: string }
  | { kind: "outcome"; value: (typeof outcomes)[number] }
  | { kind: "confidence_at_most"; basis_points: number };
export type SearchPlan = {
  schema_version: 3;
  start: string;
  end: string;
  filters: SearchFilter[];
  sort: "occurred_at_asc" | "occurred_at_desc";
  limit: number;
};
export type SearchEvent = {
  request_id: string | null;
  event_id: string;
  event_type: string;
  stage: string | null;
  outcome: string | null;
  reason_code: string | null;
  proof_kind: string | null;
  confidence: number | null;
  confidence_status: string | null;
  /** Exact UTC microseconds; never rounded to JavaScript milliseconds. */
  occurred_at: string;
  request_seq: number;
  duration_us: number;
  policy_revision: string;
  model_revision: string | null;
  /** Redacted model lifecycle link; the target endpoint reauthorizes access. */
  model_call_id: string | null;
  evidence_refs: string[];
  cause_event_ids: string[];
  sensitivity: string;
};
export type SearchResponse = Envelope & {
  schema_version: 3;
  query_digest: string;
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  scanned_rows: number | null;
  scanned_bytes: number | null;
  truncated: boolean;
  next_cursor: string | null;
  events: SearchEvent[];
};

function exactKeys(row: Record<string, unknown>, keys: string[]): void {
  ensure(
    Object.keys(row).length === keys.length &&
      keys.every((key) => Object.hasOwn(row, key)),
  );
}
function wholeSecond(value: unknown): string {
  const input = text(value, 40);
  ensure(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.0{1,9})?(?:Z|\+00:00)$/.test(
      input,
    ),
  );
  const time = Date.parse(input);
  ensure(Number.isFinite(time) && time >= 0 && time <= 10_413_792_000_000);
  // Date.parse normalizes invalid calendar days. Require an exact round trip.
  const normalized = new Date(time).toISOString().replace(".000Z", "Z");
  ensure(normalized.slice(0, 19) === input.slice(0, 19));
  return normalized;
}
function filter(value: unknown): SearchFilter {
  const row = object(value);
  const kind = choice(row.kind, [
    ...Object.keys(idPatterns),
    "text",
    "outcome",
    "confidence_at_most",
  ]);
  if (kind === "text") {
    exactKeys(row, ["kind", "field", "value"]);
    const value = text(row.value);
    ensure(/^[A-Za-z0-9_.:-]+$/.test(value));
    return { kind, field: choice(row.field, textFields), value };
  }
  if (kind === "confidence_at_most") {
    exactKeys(row, ["kind", "basis_points"]);
    return { kind, basis_points: integer(row.basis_points, 0, 10_000) };
  }
  exactKeys(row, ["kind", "value"]);
  if (kind === "outcome") return { kind, value: choice(row.value, outcomes) };
  const idKind = kind as keyof typeof idPatterns;
  return { kind: idKind, value: id(row.value, idPatterns[idKind]) };
}

/** Validate and copy a plan, retaining filter order and whole-second UTC bounds.
 * Throws a safe CONTROL_QUERY_INVALID before transport; never accepts scope,
 * SQL, extra keys, or a cursor as part of a new plan. Server limits may be lower.
 */
export function validateSearchPlan(value: unknown): SearchPlan {
  try {
    const row = object(value);
    exactKeys(row, [
      "schema_version",
      "start",
      "end",
      "filters",
      "sort",
      "limit",
    ]);
    ensure(row.schema_version === 3);
    const start = wholeSecond(row.start);
    const end = wholeSecond(row.end);
    const duration = Date.parse(end) - Date.parse(start);
    ensure(duration > 0 && duration <= 31 * 24 * 60 * 60 * 1000);
    return {
      schema_version: 3,
      start,
      end,
      filters: list(row.filters, 8, filter),
      sort: choice(row.sort, ["occurred_at_asc", "occurred_at_desc"]),
      limit: integer(row.limit, 1, 1000),
    };
  } catch {
    throw new ApiError("CONTROL_QUERY_INVALID");
  }
}

/** Mirror control::search::query_plan_digest to bind every page to its plan.
 * This checks response identity, not authorization; the server authenticates
 * the opaque signature with the credential and scope on every request.
 */
export async function searchPlanDigest(plan: SearchPlan): Promise<string> {
  let canonical = `${Date.parse(plan.start) / 1000}|${Date.parse(plan.end) / 1000}|${plan.sort === "occurred_at_asc" ? "asc" : "desc"}|${plan.limit}`;
  for (const item of plan.filters) {
    canonical +=
      item.kind === "confidence_at_most"
        ? `|confidence<=${item.basis_points}`
        : `|${item.kind === "text" ? item.field : item.kind}=${item.value}`;
  }
  try {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonical),
    );
    return Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  } catch {
    throw new ApiError("QUERY_DIGEST_UNAVAILABLE");
  }
}

type Position = { time: bigint; eventId: string };
function eventPosition(event: SearchEvent): Position {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{6})Z$/.exec(
    event.occurred_at,
  );
  ensure(match);
  const seconds = wholeSecond(`${match[1]}Z`);
  return {
    time: BigInt(Date.parse(seconds)) * 1000n + BigInt(match[2]!),
    eventId: event.event_id,
  };
}
function cursorPosition(cursor: string, plan: SearchPlan): Position {
  const match = new RegExp(
    `^v1\\.(0|[1-9][0-9]{0,16})\\.(ev_${uuid})\\.([a-f0-9]{64})$`,
  ).exec(cursor);
  ensure(typeof cursor === "string" && cursor.length <= 160 && match);
  const position = { time: BigInt(match[1]!), eventId: match[2]! };
  ensure(inWindow(position, plan));
  return position;
}
function inWindow(position: Position, plan: SearchPlan): boolean {
  return (
    position.time >= BigInt(Date.parse(plan.start)) * 1000n &&
    position.time < BigInt(Date.parse(plan.end)) * 1000n
  );
}
/** Validate only the public cursor shape and position. No signature is trusted here. */
export function validateSearchCursor(
  cursor: string | undefined,
  plan: SearchPlan,
): void {
  if (cursor === undefined) return;
  try {
    cursorPosition(cursor, plan);
  } catch {
    throw new ApiError("CONTROL_CURSOR_INVALID");
  }
}
function searchEvent(value: unknown): SearchEvent {
  const row = object(value);
  const proof_kind = nullable(row.proof_kind, (value) =>
    choice(value, ["deterministic", "model", "observation", "none"]),
  );
  const confidence_status = nullable(row.confidence_status, (value) =>
    choice(value, [
      "provided",
      "not_applicable",
      "not_provided",
      "unavailable",
    ]),
  );
  const facts = confidence(
    {
      ...row,
      proof_kind: proof_kind ?? "",
      confidence_status: confidence_status ?? "",
    },
    true,
  );
  const event_type = name(row.event_type);
  ensure(/^[a-z0-9_.]{3,128}$/.test(event_type));
  const model_revision = nullable(row.model_revision, name);
  const model_call_id = nullable(row.model_call_id, (value) =>
    id(value, modelCallPattern),
  );
  ensure(model_revision === null || proof_kind === "model");
  ensure((proof_kind === "model") === (model_call_id !== null));
  return {
    request_id: nullable(row.request_id, (value) => id(value, requestPattern)),
    event_id: id(row.event_id, eventPattern),
    event_type,
    stage: nullable(row.stage, name),
    outcome: nullable(row.outcome, (value) =>
      choice(value, [...outcomes, "not_sent", "unknown", "response_received"]),
    ),
    reason_code: nullable(row.reason_code, name),
    proof_kind,
    confidence: facts.confidence,
    confidence_status,
    occurred_at: text(row.occurred_at, 40),
    request_seq: integer(row.request_seq, 1, 0xffff_ffff),
    duration_us: integer(row.duration_us),
    policy_revision: name(row.policy_revision),
    model_revision,
    model_call_id,
    evidence_refs: references(
      row.evidence_refs,
      new RegExp(`^[a-z]+_${uuid}$`),
    ),
    cause_event_ids: references(row.cause_event_ids, eventPattern),
    sensitivity: choice(row.sensitivity, [
      "PUBLIC",
      "INTERNAL",
      "SENSITIVE",
      "RESTRICTED",
    ]),
  };
}

/** Project only metadata and verify digest, resource bounds and keyset ordering.
 * Empty results do not prove absence; watermark/gap facts remain independent.
 */
export function decodeSearchResponse(
  value: unknown,
  plan: SearchPlan,
  digest: string,
  cursor?: string,
): SearchResponse {
  const row = object(value);
  ensure(row.schema_version === 3 && row.query_digest === digest);
  const result: SearchResponse = {
    ...envelope(row),
    ...watermarked(row),
    ...pagination(row),
    schema_version: 3,
    query_digest: digest,
    pending_segments: integer(row.pending_segments),
    scanned_rows: nullable(row.scanned_rows, integer),
    scanned_bytes: nullable(row.scanned_bytes, integer),
    events: list(row.events, plan.limit, searchEvent),
  };
  ensure(!result.truncated || result.events.length === plan.limit);
  const seen = new Set<string>();
  let previous = cursor === undefined ? null : cursorPosition(cursor, plan);
  if (previous) seen.add(previous.eventId);
  for (const event of result.events) {
    const current = eventPosition(event);
    ensure(inWindow(current, plan) && !seen.has(current.eventId));
    if (previous) {
      const order =
        current.time === previous.time
          ? current.eventId > previous.eventId
            ? 1
            : -1
          : current.time > previous.time
            ? 1
            : -1;
      ensure(order === (plan.sort === "occurred_at_asc" ? 1 : -1));
    }
    seen.add(current.eventId);
    previous = current;
  }
  if (result.next_cursor !== null) {
    const next = cursorPosition(result.next_cursor, plan);
    ensure(
      previous &&
        next.time === previous.time &&
        next.eventId === previous.eventId,
    );
    ensure(result.next_cursor !== cursor);
  }
  return result;
}
