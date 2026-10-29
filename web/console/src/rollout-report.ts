/** The observe → enforce exit report (`GET /control/v1/rollout-report`, docs/32 32.4). It states
 * what the index holds about one observe window; deciding whether to enforce stays with the
 * approver, and an index that has not caught up never reads as a pass. */
import {
  ApiError,
  bool,
  choice,
  ensure,
  envelope,
  integer,
  list,
  name,
  object,
  timestamp,
  watermarked,
} from "./api-contract.ts";
import type { Envelope, Watermark } from "./api-contract.ts";

/** `ROLLOUT_REPORT_ROWS_MAX`: the most (route, reason) rows one report lists. */
export const ROLLOUT_REPORT_ROWS_MAX = 200;

export type RolloutObservation = {
  /** Empty when the request's route was recorded before the window began. */
  operation_id: string;
  reason_code: string;
  count: number;
  last_seen: string;
};

export type RolloutReport = Envelope & {
  schema_version: 1;
  watermark_scope: "configured_journal";
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  index_complete: boolean;
  report_digest: string;
  rollout_revision: string;
  start: string;
  end: string;
  completed_requests: number;
  observed_requests: number;
  unrouted_refusals: number;
  observations: RolloutObservation[];
  truncated: boolean;
};

export type RolloutReportRequest = { revision: string; start: string; end: string };

const secondPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const revisionPattern = /^[A-Za-z0-9._-]{1,128}$/;

/** A UTC second as the route's exact boundary spelling. */
export const reportTime = (unix: number) =>
  new Date(Math.floor(unix) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

/** The report query string, refusing what the server would refuse anyway. */
export function rolloutReportQuery(request: RolloutReportRequest): string {
  if (
    !revisionPattern.test(request.revision) ||
    !secondPattern.test(request.start) ||
    !secondPattern.test(request.end) ||
    Date.parse(request.end) <= Date.parse(request.start)
  )
    throw new ApiError("CONTROL_ROLLOUT_REPORT_REQUEST_INVALID");
  return new URLSearchParams({
    revision: request.revision,
    start: request.start,
    end: request.end,
  }).toString();
}

const keys = [
  "schema_version",
  "request_id",
  "tenant_id",
  "site_id",
  "watermark_scope",
  "as_of",
  "index_watermark",
  "has_gaps",
  "pending_segments",
  "index_complete",
  "report_digest",
  "rollout_revision",
  "start",
  "end",
  "completed_requests",
  "observed_requests",
  "unrouted_refusals",
  "observations",
  "truncated",
];

function observation(value: unknown): RolloutObservation {
  const row = object(value);
  ensure(Object.keys(row).length === 4);
  return {
    operation_id: name(row.operation_id, true),
    reason_code: name(row.reason_code),
    count: integer(row.count, 1),
    last_seen: timestamp(row.last_seen),
  };
}

/** Strict decoding: the counts must add up exactly as the server checked them. */
export function decodeRolloutReport(value: unknown, request: RolloutReportRequest): RolloutReport {
  const row = object(value);
  ensure(
    row.schema_version === 1 &&
      Object.keys(row).length === keys.length &&
      keys.every((key) => Object.hasOwn(row, key)),
  );
  const report: RolloutReport = {
    ...envelope(row),
    ...watermarked(row),
    schema_version: 1,
    watermark_scope: choice(row.watermark_scope, ["configured_journal"]),
    pending_segments: integer(row.pending_segments),
    index_complete: bool(row.index_complete),
    report_digest: name(row.report_digest),
    rollout_revision: name(row.rollout_revision),
    start: timestamp(row.start),
    end: timestamp(row.end),
    completed_requests: integer(row.completed_requests),
    observed_requests: integer(row.observed_requests),
    unrouted_refusals: integer(row.unrouted_refusals),
    observations: list(row.observations, ROLLOUT_REPORT_ROWS_MAX, observation),
    truncated: bool(row.truncated),
  };
  ensure(/^[0-9a-f]{64}$/.test(report.report_digest));
  ensure(
    report.rollout_revision === request.revision &&
      report.start === request.start &&
      report.end === request.end,
  );
  ensure(report.index_complete === (!report.has_gaps && report.pending_segments === 0));
  const listed = report.observations.reduce((sum, item) => sum + item.count, 0);
  ensure(
    report.observed_requests <= report.completed_requests &&
      report.unrouted_refusals <= report.completed_requests - report.observed_requests &&
      (report.truncated ? listed < report.observed_requests : listed === report.observed_requests),
  );
  return report;
}

export type ReportVerdict = "incomplete" | "no_traffic" | "would_deny" | "clean";

/**
 * What the report lets one say, never a pass on its own: an index that is behind or has gaps
 * cannot judge; a window without traffic proves nothing; otherwise either something would have
 * been refused, or nothing in the window would have been.
 */
export function reportVerdict(report: RolloutReport): ReportVerdict {
  if (!report.index_complete) return "incomplete";
  if (report.completed_requests === 0) return "no_traffic";
  return report.observed_requests > 0 ? "would_deny" : "clean";
}
