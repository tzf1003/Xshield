/** Audited retention history and exact mutation correlation. Holding an object
 * changes deletion eligibility; content authorization remains server-owned. */
import {
  ApiError,
  artifactPattern,
  bool,
  choice,
  ensure,
  envelope,
  eventPattern,
  id,
  list,
  nullable,
  object,
  pagination,
  timestamp,
  uuid,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";
import { casePattern, validCaseText } from "./cases.ts";

export const holdPattern = eventPattern;
const cursorPattern = new RegExp(`^v1\\.(ev_${uuid})\\.[a-f0-9]{64}(?![\\s\\S])`);
const MAX_NANOS_MILLIS = 9_223_372_036_854;
const MAX_LIFETIME_MILLIS = 30 * 24 * 60 * 60 * 1000;
export type HoldRecord = {
  hold_id: string;
  case_id: string;
  artifact_id: string;
  created_by: string;
  reason: string;
  created_at: string;
  hold_until: string;
  released_event_id: string | null;
  released_by: string | null;
  released_reason: string | null;
  released_at: string | null;
};
export type HoldMutation = Envelope & HoldRecord & { schema_version: 3; replayed: boolean };
export type HoldCollection = Envelope & {
  schema_version: 3;
  case_id: string;
  case_status: "open" | "closed";
  as_of: string;
  items: HoldRecord[];
  truncated: boolean;
  next_cursor: string | null;
};

export const validHoldReason = validCaseText;
/** Canonical UTC milliseconds within the backend signed-nanosecond range.
 * Past values remain valid input for exact replay; the database checks new TTLs. */
export function validHoldUntil(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?![\s\S])/.test(value)
  )
    return false;
  const millis = Date.parse(value);
  return (
    Number.isFinite(millis) &&
    millis >= 0 &&
    millis <= MAX_NANOS_MILLIS &&
    new Date(millis).toISOString() === value
  );
}
export function validateHoldUntil(value: unknown): asserts value is string {
  if (!validHoldUntil(value)) throw new ApiError("CONTROL_EVIDENCE_HOLD_REQUEST_INVALID");
}
export function validateHoldId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !holdPattern.test(value))
    throw new ApiError("CONTROL_EVIDENCE_HOLD_ID_INVALID");
}
export function validateHoldCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match = typeof cursor === "string" ? cursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}
function holdTime(value: unknown): string {
  ensure(validHoldUntil(value));
  return value;
}
function actor(value: unknown): string {
  ensure(validCaseText(value) && new TextEncoder().encode(value).byteLength <= 256);
  return value;
}
function reason(value: unknown): string {
  ensure(validHoldReason(value));
  return value;
}
function record(value: unknown): HoldRecord {
  const row = object(value);
  const result: HoldRecord = {
    hold_id: id(row.hold_id, holdPattern),
    case_id: id(row.case_id, casePattern),
    artifact_id: id(row.artifact_id, artifactPattern),
    created_by: actor(row.created_by),
    reason: reason(row.reason),
    created_at: holdTime(row.created_at),
    hold_until: holdTime(row.hold_until),
    released_event_id: nullable(row.released_event_id, (value) => id(value, eventPattern)),
    released_by: nullable(row.released_by, actor),
    released_reason: nullable(row.released_reason, reason),
    released_at: nullable(row.released_at, holdTime),
  };
  const lifetime = Date.parse(result.hold_until) - Date.parse(result.created_at);
  ensure(lifetime > 0 && lifetime <= MAX_LIFETIME_MILLIS);
  const released = result.released_event_id !== null;
  ensure(
    released === (result.released_by !== null) &&
      released === (result.released_reason !== null) &&
      released === (result.released_at !== null),
  );
  ensure(result.released_event_id !== result.hold_id);
  return result;
}
function mutation(value: unknown): HoldMutation {
  const row = object(value);
  ensure(row.schema_version === 3);
  return { ...envelope(row), ...record(row), schema_version: 3, replayed: bool(row.replayed) };
}
/** Creation replays may include a later release; compare all original inputs. */
export function decodeHoldCreated(
  value: unknown,
  caseId: string,
  artifactId: string,
  requestedReason: string,
  holdUntil: string,
  status: number,
): HoldMutation {
  const result = mutation(value);
  ensure(
    result.case_id === caseId &&
      result.artifact_id === artifactId &&
      result.reason === requestedReason &&
      result.hold_until === holdUntil,
  );
  ensure(status === (result.replayed ? 200 : 201));
  ensure(result.replayed || result.released_event_id === null);
  return result;
}
/** Release is bound to the supplied hold identity and exact reason. The server
 * returns the case/artifact association even when the caller only has a hold ID. */
export function decodeHoldReleased(
  value: unknown,
  holdId: string,
  requestedReason: string,
  status: number,
): HoldMutation {
  const result = mutation(value);
  ensure(
    status === 200 &&
      result.hold_id === holdId &&
      result.released_event_id !== null &&
      result.released_reason === requestedReason,
  );
  return result;
}
/** Each bounded page is a fresh observation in ascending hold identity order.
 * The cursor can continue only beyond the exact last returned identity. */
export function decodeHoldCollection(
  value: unknown,
  caseId: string,
  cursor?: string,
): HoldCollection {
  const row = object(value);
  ensure(row.schema_version === 3);
  const asOf = timestamp(row.as_of);
  ensure(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z(?![\s\S])/.test(asOf) && Date.parse(asOf) >= 0,
  );
  const result: HoldCollection = {
    ...envelope(row),
    schema_version: 3,
    case_id: id(row.case_id, casePattern),
    case_status: choice(row.case_status, ["open", "closed"]),
    as_of: asOf,
    items: list(row.items, 128, record),
    ...pagination(row),
  };
  ensure(result.case_id === caseId);
  let previous = validateHoldCursor(cursor);
  for (const item of result.items) {
    ensure(item.case_id === caseId && (previous === undefined || item.hold_id > previous));
    previous = item.hold_id;
  }
  if (result.next_cursor !== null) {
    const match = cursorPattern.exec(result.next_cursor);
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}
