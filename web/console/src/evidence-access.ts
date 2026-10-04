/** Evidence access observations and explicit mutations. These values describe
 * server records; every content read obtains fresh server authorization. */
import {
  ApiError,
  artifactPattern,
  uuid,
  bool,
  choice,
  ensure,
  envelope,
  eventPattern,
  id,
  integer,
  list,
  nullable,
  object,
  pagination,
  timestamp,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";
import { casePattern, validCaseText } from "./cases.ts";

export const accessPattern = new RegExp(`^access_${uuid}(?![\\s\\S])`);
const statuses = ["pending", "approved", "denied", "expired", "revoked"] as const;
export type AccessStatus = (typeof statuses)[number];
export type AccessListView = "mine" | "review";
export type AccessList = Envelope & {
  schema_version: 3;
  view: AccessListView;
  as_of: string;
  items: Array<{
    access_request_id: string;
    case_id: string;
    artifact_id: string;
    requested_by: string;
    access_kind: "sensitive_raw";
    stored_status: AccessStatus;
    requested_at: string;
    requested_event_id: string;
  }>;
  truncated: boolean;
  next_cursor: string | null;
};
const accessListCursorPattern = new RegExp(`^v1\\.(access_${uuid})\\.[0-9a-f]{64}(?![\\s\\S])`);

/** Validate the client-visible cursor shape. The server authenticates its scope,
 * subject and view binding anew; a cursor conveys no approval authority. */
export function validateAccessListCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match = typeof cursor === "string" ? accessListCursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}
export function validateAccessListView(view: unknown): asserts view is AccessListView {
  if (view !== "mine" && view !== "review")
    throw new ApiError("CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID");
}

/** Bounded, projected metadata from a live page. Sorting follows identity,
 * including across page boundaries; the next cursor must name the last row. */
export function decodeAccessList(
  value: unknown,
  view: AccessListView,
  cursor?: string,
): AccessList {
  const row = object(value);
  ensure(row.schema_version === 3 && row.view === view);
  const result: AccessList = {
    ...envelope(row),
    schema_version: 3,
    view,
    as_of: time(row.as_of, true),
    items: list(row.items, 128, (value) => {
      const item = object(value);
      return {
        ...targets(item),
        requested_by: subject(item.requested_by),
        access_kind: choice(item.access_kind, ["sensitive_raw"]),
        stored_status: choice(item.stored_status, statuses),
        requested_at: time(item.requested_at, true),
        requested_event_id: id(item.requested_event_id, eventPattern),
      };
    }),
    ...pagination(row),
  };
  let previous = validateAccessListCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.access_request_id < previous);
    ensure(view !== "review" || item.stored_status === "pending");
    previous = item.access_request_id;
  }
  if (result.next_cursor !== null) {
    const match = accessListCursorPattern.exec(result.next_cursor);
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}
export type AccessRequested = Envelope & {
  access_request_id: string;
  case_id: string;
  artifact_id: string;
  access_kind: "sensitive_raw";
  status: AccessStatus;
  requested_at: string;
  replayed: boolean;
};
export type AccessDecision = Envelope & {
  access_request_id: string;
  case_id: string;
  artifact_id: string;
  requested_by: string;
  decided_by: string;
  status: Exclude<AccessStatus, "pending">;
  decided_at: string;
  access_expires_at: string | null;
  replayed: boolean;
};
export type AccessInspection = Envelope & {
  schema_version: 3;
  as_of: string;
  max_approval_ttl_seconds: number;
  access_request: {
    access_request_id: string;
    case_id: string;
    artifact_id: string;
    requested_by: string;
    access_kind: "sensitive_raw";
    justification: string;
    stored_status: AccessStatus;
    requested_at: string;
    requested_event_id: string;
    decided_by: string | null;
    decision_reason: string | null;
    decision_ttl_seconds: number | null;
    decision_event_id: string | null;
    decided_at: string | null;
    access_expires_at: string | null;
    case_status: "open" | "closed";
    artifact_status: "active" | "deleted";
    artifact_expires_at: string;
    artifact_time_expired: boolean;
    capability_time_expired: boolean | null;
  };
};
/** The caller owns this bounded Blob and any temporary browser URL it creates.
 * Receipt by this client establishes no browser filesystem completion fact. */
export type EvidenceDownload = Envelope & {
  artifact_id: string;
  access_request_id: string;
  blob: Blob;
  bytes: number;
};

export function validateAccessId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !accessPattern.test(value))
    throw new ApiError("CONTROL_EVIDENCE_ACCESS_ID_INVALID");
}
function reason(value: unknown): string {
  ensure(validCaseText(value));
  return value;
}
function subject(value: unknown): string {
  ensure(validCaseText(value) && new TextEncoder().encode(value).length <= 256);
  return value;
}
function time(value: unknown, micros = false): string {
  const result = timestamp(value);
  ensure((micros ? /\.\d{6}Z$/ : /\.\d{3}Z$/).test(result));
  // Match the durable inspection's nonnegative, nanosecond-representable clock.
  ensure(Date.parse(result) >= 0 && microseconds(result) <= 9223372036854775n);
  return result;
}
/** Preserve microseconds when comparing expiry at the database snapshot edge. */
function microseconds(value: string): bigint {
  const fractional = value.slice(20, -1).padEnd(6, "0");
  return BigInt(Date.parse(value.slice(0, 19) + "Z")) * 1000n + BigInt(fractional);
}
function targets(row: Record<string, unknown>) {
  return {
    access_request_id: id(row.access_request_id, accessPattern),
    case_id: id(row.case_id, casePattern),
    artifact_id: id(row.artifact_id, artifactPattern),
  };
}
export function decodeAccessRequested(
  value: unknown,
  artifactId: string,
  caseId: string,
  status: number,
): AccessRequested {
  const row = object(value);
  const result: AccessRequested = {
    ...envelope(row),
    ...targets(row),
    access_kind: choice(row.access_kind, ["sensitive_raw"]),
    status: choice(row.status, statuses),
    requested_at: time(row.requested_at),
    replayed: bool(row.replayed),
  };
  ensure(result.artifact_id === artifactId && result.case_id === caseId);
  ensure(status === (result.replayed ? 200 : 201));
  ensure(result.replayed || result.status === "pending");
  return result;
}
export function decodeAccessDecision(
  value: unknown,
  accessId: string,
  decision: "approve" | "deny",
  ttlSeconds: number | null,
  status: number,
): AccessDecision {
  const row = object(value);
  const result: AccessDecision = {
    ...envelope(row),
    ...targets(row),
    requested_by: subject(row.requested_by),
    decided_by: subject(row.decided_by),
    status: choice(row.status, ["approved", "denied", "expired", "revoked"]),
    decided_at: time(row.decided_at),
    access_expires_at: nullable(row.access_expires_at, (value) => time(value)),
    replayed: bool(row.replayed),
  };
  ensure(status === 200 && result.access_request_id === accessId);
  ensure(result.requested_by !== result.decided_by);
  if (decision === "deny") {
    ensure(result.status === "denied" && result.access_expires_at === null);
  } else {
    ensure(result.status !== "denied" && (result.replayed || result.status === "approved"));
    ensure(result.access_expires_at !== null && ttlSeconds !== null);
    const duration = microseconds(result.access_expires_at) - microseconds(result.decided_at);
    // Mutation DTOs truncate to milliseconds. A positive sub-ms lease can
    // therefore have equal displayed endpoints; inspection retains exact time.
    ensure(duration >= 0n && duration <= BigInt(ttlSeconds) * 1_000_000n);
  }
  return result;
}
export function decodeAccessInspection(value: unknown, accessId: string): AccessInspection {
  const row = object(value);
  ensure(row.schema_version === 3);
  const source = object(row.access_request);
  const as_of = time(row.as_of, true);
  const detail: AccessInspection["access_request"] = {
    ...targets(source),
    requested_by: subject(source.requested_by),
    access_kind: choice(source.access_kind, ["sensitive_raw"]),
    justification: reason(source.justification),
    stored_status: choice(source.stored_status, statuses),
    requested_at: time(source.requested_at, true),
    requested_event_id: id(source.requested_event_id, eventPattern),
    decided_by: nullable(source.decided_by, subject),
    decision_reason: nullable(source.decision_reason, reason),
    decision_ttl_seconds: nullable(source.decision_ttl_seconds, (v) => integer(v, 1, 86400)),
    decision_event_id: nullable(source.decision_event_id, (v) => id(v, eventPattern)),
    decided_at: nullable(source.decided_at, (v) => time(v, true)),
    access_expires_at: nullable(source.access_expires_at, (v) => time(v, true)),
    case_status: choice(source.case_status, ["open", "closed"]),
    artifact_status: choice(source.artifact_status, ["active", "deleted"]),
    artifact_expires_at: time(source.artifact_expires_at, true),
    artifact_time_expired: bool(source.artifact_time_expired),
    capability_time_expired: nullable(source.capability_time_expired, bool),
  };
  ensure(detail.access_request_id === accessId);
  ensure(
    detail.artifact_time_expired ===
      microseconds(detail.artifact_expires_at) <= microseconds(as_of),
  );
  ensure(
    detail.capability_time_expired ===
      (detail.access_expires_at === null
        ? null
        : microseconds(detail.access_expires_at) <= microseconds(as_of)),
  );
  if (detail.stored_status === "pending") {
    ensure(
      [
        detail.decided_by,
        detail.decision_reason,
        detail.decision_ttl_seconds,
        detail.decision_event_id,
        detail.decided_at,
        detail.access_expires_at,
      ].every((v) => v === null),
    );
  } else {
    ensure(detail.decided_by !== null && detail.decided_by !== detail.requested_by);
    ensure(
      detail.decision_reason !== null &&
        detail.decision_event_id !== null &&
        detail.decided_at !== null,
    );
    ensure(detail.decision_event_id !== detail.requested_event_id);
    if (detail.stored_status === "denied") {
      ensure(detail.decision_ttl_seconds === null && detail.access_expires_at === null);
    } else {
      ensure(detail.decision_ttl_seconds !== null && detail.access_expires_at !== null);
      const duration = microseconds(detail.access_expires_at) - microseconds(detail.decided_at);
      ensure(duration > 0n && duration <= BigInt(detail.decision_ttl_seconds) * 1_000_000n);
      ensure(microseconds(detail.access_expires_at) <= microseconds(detail.artifact_expires_at));
    }
  }
  return {
    ...envelope(row),
    schema_version: 3,
    as_of,
    max_approval_ttl_seconds: integer(row.max_approval_ttl_seconds, 1, 86400),
    access_request: detail,
  };
}
