/** Case-scoped durable job list (`GET /control/v1/cases/{case_id}/jobs`): every job the
 * caller's own case has produced, newest job_id first. Metadata only; no content access. */
import {
  ApiError,
  bool,
  choice,
  ensure,
  envelope,
  id,
  integer,
  list,
  nullable,
  object,
  pagination,
  text,
  timestamp,
  uuid,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";
import { casePattern, validateCaseId } from "./cases.ts";
import { jobPattern } from "./job-list.ts";
import type { JobStatus } from "./job-list.ts";

const kinds = ["case_analysis"] as const;
const statuses = ["queued", "running", "succeeded", "failed", "cancelled"] as const;

export type CaseJobListItem = {
  job_id: string;
  kind: (typeof kinds)[number];
  status: JobStatus;
  checkpoint: string;
  reason_code: string;
  retryable: boolean;
  artifact_count: number;
  active_artifact_count: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
};
export type CaseJobList = Envelope & {
  schema_version: 1;
  case_id: string;
  as_of: string;
  items: CaseJobListItem[];
  truncated: boolean;
  next_cursor: string | null;
};

const caseJobListCursorPattern = new RegExp(`^v1\\.(job_${uuid})\\.[0-9a-f]{64}(?![\\s\\S])`);

/** Validate the cursor shape only; the server binds it to the credential, subject, case and
 * page size, so a cursor minted for another case or caller is never replayable here. */
export function validateCaseJobListCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match = typeof cursor === "string" ? caseJobListCursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}

function time(value: unknown): string {
  const result = timestamp(value);
  ensure(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?![\s\S])/.test(result));
  return result;
}
function micros(value: unknown): string {
  const result = timestamp(value);
  ensure(/\.\d{6}Z(?![\s\S])/.test(result));
  return result;
}

function listItem(value: unknown): CaseJobListItem {
  const row = object(value);
  const item: CaseJobListItem = {
    job_id: id(row.job_id, jobPattern),
    kind: choice(row.kind, kinds),
    status: choice(row.status, statuses),
    checkpoint: text(row.checkpoint, 128),
    reason_code: text(row.reason_code, 128),
    retryable: bool(row.retryable),
    artifact_count: integer(row.artifact_count, 0, 1_000_000),
    active_artifact_count: integer(row.active_artifact_count, 0, 1_000_000),
    created_at: time(row.created_at),
    updated_at: time(row.updated_at),
    completed_at: nullable(row.completed_at, time),
  };
  // Mirrors the durable state machine: only queued and running jobs lack a completion time.
  const running = item.status === "queued" || item.status === "running";
  ensure(running ? item.completed_at === null : item.completed_at !== null);
  ensure(item.active_artifact_count <= item.artifact_count);
  ensure(Date.parse(item.created_at) <= Date.parse(item.updated_at));
  if (item.completed_at !== null) {
    ensure(Date.parse(item.created_at) <= Date.parse(item.completed_at));
  }
  return item;
}

/** A complete page from the live snapshot, scoped to one case. Order follows the job identity
 * across page boundaries, and the next cursor must name the last row it returned. */
export function decodeCaseJobList(value: unknown, caseId: string, cursor?: string): CaseJobList {
  validateCaseId(caseId);
  const row = object(value);
  ensure(row.schema_version === 1);
  const result: CaseJobList = {
    ...envelope(row),
    schema_version: 1,
    case_id: id(row.case_id, casePattern),
    as_of: micros(row.as_of),
    items: list(row.items, 128, listItem),
    ...pagination(row),
  };
  ensure(result.case_id === caseId);
  let previous = validateCaseJobListCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.job_id < previous);
    previous = item.job_id;
  }
  if (result.next_cursor !== null) {
    const match = caseJobListCursorPattern.exec(text(result.next_cursor, 160));
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}
