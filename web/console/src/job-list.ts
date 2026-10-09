/** Owner-scoped durable job list (`GET /control/v1/jobs`); metadata only, no owner reference. */
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
import { casePattern } from "./cases.ts";

export const jobPattern = new RegExp(`^job_${uuid}(?![\\s\\S])`);
const kinds = ["case_analysis"] as const;
const statuses = ["queued", "running", "succeeded", "failed", "cancelled"] as const;
export type JobStatus = (typeof statuses)[number];

export type JobListItem = {
  job_id: string;
  kind: (typeof kinds)[number];
  status: JobStatus;
  checkpoint: string;
  reason_code: string;
  retryable: boolean;
  case_id: string;
  artifact_count: number;
  active_artifact_count: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
};
export type JobList = Envelope & {
  schema_version: 1;
  as_of: string;
  items: JobListItem[];
  truncated: boolean;
  next_cursor: string | null;
};

const jobListCursorPattern = new RegExp(`^v1\\.(job_${uuid})\\.[0-9a-f]{64}(?![\\s\\S])`);

/** Validate the cursor shape only; the server authenticates its owner and scope binding, so a
 * cursor conveys no authority of its own. */
export function validateJobListCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match = typeof cursor === "string" ? jobListCursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}

/** Millisecond times for item fields; only the observation time keeps microseconds. */
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

function listItem(value: unknown): JobListItem {
  const row = object(value);
  const item: JobListItem = {
    job_id: id(row.job_id, jobPattern),
    kind: choice(row.kind, kinds),
    status: choice(row.status, statuses),
    checkpoint: text(row.checkpoint, 128),
    reason_code: text(row.reason_code, 128),
    retryable: bool(row.retryable),
    case_id: id(row.case_id, casePattern),
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

/** A complete page from the live snapshot. Order follows the job identity across page
 * boundaries, and the next cursor must name the last row it returned. */
export function decodeJobList(value: unknown, cursor?: string): JobList {
  const row = object(value);
  ensure(row.schema_version === 1);
  const result: JobList = {
    ...envelope(row),
    schema_version: 1,
    as_of: micros(row.as_of),
    items: list(row.items, 128, listItem),
    ...pagination(row),
  };
  let previous = validateJobListCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.job_id < previous);
    previous = item.job_id;
  }
  if (result.next_cursor !== null) {
    const match = jobListCursorPattern.exec(result.next_cursor);
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}
