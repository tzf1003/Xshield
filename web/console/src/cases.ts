/** Investigator case metadata. Membership and catalog state grant no content
 * access or retention. Callers retain mutation keys and exact input on failure;
 * only the server can confirm a committed outcome.
 */
import {
  ApiError,
  artifactPattern,
  uuid,
  bool,
  choice,
  ensure,
  envelope,
  id,
  list,
  object,
  pagination,
  text,
  timestamp,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";

export const casePattern = new RegExp(`^case_${uuid}(?![\\s\\S])`);
const caseCursorPattern = new RegExp(
  `^v1\\.(artifact_${uuid})\\.[a-f0-9]{64}(?![\\s\\S])`,
);
const caseListCursorPattern = new RegExp(
  `^v1\\.(case_${uuid})\\.[a-f0-9]{64}(?![\\s\\S])`,
);
export type CaseFacts = {
  case_id: string;
  status: "open" | "closed";
  purpose: string;
  created_at: string;
};
export type CaseCreated = Envelope & CaseFacts & { replayed: boolean };
export type CaseList = Envelope & {
  schema_version: 3;
  as_of: string;
  items: CaseFacts[];
  truncated: boolean;
  next_cursor: string | null;
};
export type CaseItem = {
  artifact_id: string;
  added_by: string;
  added_at: string;
  catalog_status: "active" | "expired" | "deleted" | "unavailable";
};
export type CaseCollection = Envelope & {
  schema_version: 3;
  case: CaseFacts;
  as_of: string;
  items: CaseItem[];
  truncated: boolean;
  next_cursor: string | null;
};
export type CaseItemAdded = Envelope &
  Omit<CaseItem, "catalog_status"> & {
    schema_version: 3;
    case_id: string;
    replayed: boolean;
  };
export type CaseClosed = Envelope & {
  schema_version: 3;
  case_id: string;
  status: "closed";
  closed_at: string;
  replayed: boolean;
};

function validText(value: unknown, max: number): value is string {
  if (
    typeof value !== "string" ||
    !value.length ||
    value.length > max ||
    /\p{Cc}/u.test(value)
  )
    return false;
  const bytes = new TextEncoder().encode(value);
  return bytes.byteLength <= max && new TextDecoder().decode(bytes) === value;
}
/** Match the Rust boundary's UTF-8 byte cap and Unicode whitespace semantics. */
export function validCaseText(value: unknown): value is string {
  return (
    validText(value, 512) && !/^\p{White_Space}|\p{White_Space}$/u.test(value)
  );
}
export function validIdempotencyKey(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9_.:-]{16,128}(?![\s\S])/.test(value)
  );
}
export function validateCaseId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !casePattern.test(value))
    throw new ApiError("CONTROL_CASE_ID_INVALID");
}
export function validateCaseCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match =
    typeof cursor === "string" ? caseCursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}
export function validateCaseListCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match =
    typeof cursor === "string" ? caseListCursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}
function caseTime(value: unknown, micros = false): string {
  const result = timestamp(value);
  ensure((micros ? /\.\d{6}Z$/ : /\.\d{3}Z$/).test(result));
  return result;
}
function facts(value: unknown): CaseFacts {
  const row = object(value);
  ensure(validCaseText(row.purpose));
  return {
    case_id: id(row.case_id, casePattern),
    status: choice(row.status, ["open", "closed"]),
    purpose: row.purpose,
    created_at: caseTime(row.created_at),
  };
}
function added(value: Record<string, unknown>) {
  ensure(validText(value.added_by, 256));
  return {
    artifact_id: id(value.artifact_id, artifactPattern),
    added_by: value.added_by,
    added_at: caseTime(value.added_at),
  };
}

/** Owned case pages use descending case identity, not creation-time ordering.
 * Every page is a live database observation and carries no content capability.
 */
export function decodeCaseList(value: unknown, cursor?: string): CaseList {
  const row = object(value);
  ensure(row.schema_version === 3);
  const result: CaseList = {
    ...envelope(row),
    schema_version: 3,
    as_of: caseTime(row.as_of, true),
    items: list(row.items, 128, facts),
    ...pagination(row),
  };
  let previous = validateCaseListCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.case_id < previous);
    previous = item.case_id;
  }
  if (result.next_cursor !== null) {
    const match = caseListCursorPattern.exec(text(result.next_cursor, 160));
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}

/** Correlate the immutable creation input; exact replay may report a closed case. */
export function decodeCaseCreated(
  value: unknown,
  purpose: string,
  status: number,
): CaseCreated {
  const row = object(value);
  const result = {
    ...envelope(row),
    ...facts(row),
    replayed: bool(row.replayed),
  };
  ensure(result.purpose === purpose);
  ensure(status === (result.replayed ? 200 : 201));
  ensure(result.replayed || result.status === "open");
  return result;
}

/** Validate the case target and stable artifact ordering across signed pages.
 * Only allowlisted metadata survives; each page is a new database observation.
 */
export function decodeCaseCollection(
  value: unknown,
  target: string,
  cursor?: string,
): CaseCollection {
  const row = object(value);
  ensure(row.schema_version === 3);
  const result: CaseCollection = {
    ...envelope(row),
    schema_version: 3,
    case: facts(row.case),
    as_of: caseTime(row.as_of, true),
    items: list(row.items, 128, (value) => {
      const item = object(value);
      return {
        ...added(item),
        catalog_status: choice(item.catalog_status, [
          "active",
          "expired",
          "deleted",
          "unavailable",
        ]),
      };
    }),
    ...pagination(row),
  };
  ensure(result.case.case_id === target);
  let previous = validateCaseCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.artifact_id > previous);
    previous = item.artifact_id;
  }
  if (result.next_cursor !== null) {
    const match = caseCursorPattern.exec(text(result.next_cursor, 160));
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}

export function decodeCaseItemAdded(
  value: unknown,
  target: string,
  artifact: string,
  status: number,
): CaseItemAdded {
  const row = object(value);
  ensure(row.schema_version === 3 && row.case_id === target);
  const result = {
    ...envelope(row),
    ...added(row),
    schema_version: 3 as const,
    case_id: target,
    replayed: bool(row.replayed),
  };
  ensure(
    result.artifact_id === artifact && status === (result.replayed ? 200 : 201),
  );
  return result;
}
export function decodeCaseClosed(
  value: unknown,
  target: string,
  status: number,
): CaseClosed {
  const row = object(value);
  ensure(row.schema_version === 3 && row.case_id === target && status === 200);
  return {
    ...envelope(row),
    schema_version: 3,
    case_id: target,
    status: choice(row.status, ["closed"]),
    closed_at: caseTime(row.closed_at),
    replayed: bool(row.replayed),
  };
}
