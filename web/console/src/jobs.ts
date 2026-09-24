/** Durable, owner-scoped control jobs. Results remain metadata-only. */
import {
  ApiError,
  bool,
  choice,
  ensure,
  envelope,
  id,
  integer,
  jobPattern,
  nullable,
  object,
  text,
  timestamp,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";
import { casePattern } from "./cases.ts";

export type JobView = {
  job_id: string;
  kind: "case_analysis";
  status: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  checkpoint: string;
  reason_code: string;
  retryable: boolean;
  case_id: string;
  artifact_count: number;
  active_artifact_count: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  replayed: boolean;
};

export type JobResponse = Envelope & {
  found: boolean;
  job: JobView | null;
};

function view(value: unknown): JobView {
  const row = object(value);
  const replayed = row.replayed === undefined ? false : bool(row.replayed);
  const result: JobView = {
    job_id: id(row.job_id, jobPattern),
    kind: choice(row.kind, ["case_analysis"]),
    status: choice(row.status, [
      "queued",
      "running",
      "succeeded",
      "failed",
      "cancelled",
    ]),
    checkpoint: text(row.checkpoint, 128),
    reason_code: text(row.reason_code, 128),
    retryable: bool(row.retryable),
    case_id: id(row.case_id, casePattern),
    artifact_count: integer(row.artifact_count, 0, 1_000_000),
    active_artifact_count: integer(row.active_artifact_count, 0, 1_000_000),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    completed_at: nullable(row.completed_at, timestamp),
    replayed,
  };
  ensure(result.active_artifact_count <= result.artifact_count);
  ensure(
    (result.status === "queued" || result.status === "running") ===
      (result.completed_at === null),
  );
  return result;
}

/** Decode POST admission or GET status while keeping a missing job opaque. */
export function decodeJobResponse(
  value: unknown,
  status: number,
  expectedCaseId?: string,
): JobResponse {
  const row = object(value);
  const result: JobResponse = {
    ...envelope(row),
    found: bool(row.found),
    job:
      row.job === undefined || row.job === null ? null : view(row.job),
  };
  ensure(result.found === (result.job !== null));
  if (expectedCaseId !== undefined) {
    ensure(status === 202 && result.found && result.job?.case_id === expectedCaseId);
  } else {
    ensure(status === 200);
  }
  return result;
}

export function validateJobId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !jobPattern.test(value))
    throw new ApiError("CONTROL_JOB_ID_INVALID");
}
