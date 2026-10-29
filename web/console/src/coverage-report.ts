/** Refusal and coverage statistics (`GET /control/v1/coverage-report`, docs/29 29.39): traffic and
 * refusals per route and reason, and the endpoints no route covers, listed by method and path
 * shape only. Like the rollout report it states what the index holds; an index that has not
 * caught up makes every count a lower bound, never a complete picture. */
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
  text,
  timestamp,
  watermarked,
} from "./api-contract.ts";
import type { Envelope, Watermark } from "./api-contract.ts";

/** `COVERAGE_REPORT_ROWS_MAX`: the most routes, and the most (route, reason) rows, one report lists. */
export const COVERAGE_REPORT_ROWS_MAX = 200;
/** `COVERAGE_REPORT_UNCOVERED_MAX`: the most uncovered (method, path shape) rows. */
export const COVERAGE_REPORT_UNCOVERED_MAX = 100;
/** The server's limit on one window (29.37). */
export const COVERAGE_WINDOW_MAX_SECONDS = 31 * 24 * 60 * 60;

export type RouteTraffic = {
  operation_id: string;
  completed: number;
  /** Refused (`DENY`). */
  refused: number;
  /** Refusals an observe rollout forwarded; counted apart from `refused`. */
  observed: number;
};

export type RouteRefusal = {
  /** Empty for a request that matched no route. */
  operation_id: string;
  reason_code: string;
  count: number;
  last_seen: string;
};

export type UncoveredEndpoint = {
  method: string;
  /** Route words kept, every other segment `{}`; never the path the client sent. */
  path_shape: string;
  count: number;
  last_seen: string;
};

export type CoverageReport = Envelope & {
  schema_version: 1;
  watermark_scope: "configured_journal";
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  index_complete: boolean;
  report_digest: string;
  start: string;
  end: string;
  completed_requests: number;
  refused_requests: number;
  observed_requests: number;
  unrouted_refusals: number;
  unshaped_unrouted_refusals: number;
  routes: RouteTraffic[];
  routes_truncated: boolean;
  refusals: RouteRefusal[];
  refusals_truncated: boolean;
  uncovered: UncoveredEndpoint[];
  uncovered_truncated: boolean;
};

export type CoverageReportRequest = { start: string; end: string };

const secondPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/** The report query string, refusing what the server would refuse anyway. */
export function coverageReportQuery(request: CoverageReportRequest): string {
  const start = Date.parse(request.start);
  const end = Date.parse(request.end);
  if (
    !secondPattern.test(request.start) ||
    !secondPattern.test(request.end) ||
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    end <= start ||
    end - start > COVERAGE_WINDOW_MAX_SECONDS * 1000
  )
    throw new ApiError("CONTROL_COVERAGE_REPORT_REQUEST_INVALID");
  return new URLSearchParams({ start: request.start, end: request.end }).toString();
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
  "start",
  "end",
  "completed_requests",
  "refused_requests",
  "observed_requests",
  "unrouted_refusals",
  "unshaped_unrouted_refusals",
  "routes",
  "routes_truncated",
  "refusals",
  "refusals_truncated",
  "uncovered",
  "uncovered_truncated",
];

const methodPattern = /^[A-Z]{1,16}$/;
// A shape `xshield_core::path_shape` can produce: kept words, `{}`, or a final `**` past ten.
const shapeWord = /^(?:\{\}|[A-Za-z](?=(?:[^0-9]*[0-9]){0,2}[^0-9]*$)[A-Za-z0-9._-]{0,23})$/;

/** Mirrors `valid_path_shape`, so a raw path that slipped through never renders as a shape. */
export function validPathShape(shape: string): boolean {
  if (shape === "/") return true;
  if (!shape.startsWith("/") || shape.length > 251) return false;
  const segments = shape.slice(1).split("/");
  const last = segments.at(-1);
  const before = segments.slice(0, -1);
  const named = (segment: string) => shapeWord.test(segment);
  if (last === "**") return before.length === 9 && before.every(named);
  if (last === "") return before.length > 0 && before.length <= 10 && before.every(named);
  return segments.length <= 10 && segments.every(named);
}

function exactKeys(row: Record<string, unknown>, expected: readonly string[]) {
  ensure(
    Object.keys(row).length === expected.length && expected.every((key) => Object.hasOwn(row, key)),
  );
}

function route(value: unknown): RouteTraffic {
  const row = object(value);
  exactKeys(row, ["operation_id", "completed", "refused", "observed"]);
  const item = {
    operation_id: name(row.operation_id),
    completed: integer(row.completed, 1),
    refused: integer(row.refused),
    observed: integer(row.observed),
  };
  ensure(item.refused + item.observed <= item.completed);
  return item;
}

function refusal(value: unknown): RouteRefusal {
  const row = object(value);
  exactKeys(row, ["operation_id", "reason_code", "count", "last_seen"]);
  return {
    operation_id: name(row.operation_id, true),
    reason_code: name(row.reason_code),
    count: integer(row.count, 1),
    last_seen: timestamp(row.last_seen),
  };
}

function uncovered(value: unknown): UncoveredEndpoint {
  const row = object(value);
  exactKeys(row, ["method", "path_shape", "count", "last_seen"]);
  const item = {
    method: text(row.method, 16),
    path_shape: text(row.path_shape, 251),
    count: integer(row.count, 1),
    last_seen: timestamp(row.last_seen),
  };
  ensure(methodPattern.test(item.method) && validPathShape(item.path_shape));
  return item;
}

/** A complete list adds up to its total; a cut one stays below it. */
const addsUp = (listed: number, total: number, truncated: boolean) =>
  truncated ? listed < total : listed === total;

/** Most first, each key once, every row inside `[start, end)`. */
function ordered<T>(
  rows: readonly T[],
  count: (row: T) => number,
  identity: (row: T) => string,
  seen?: (row: T) => string,
  window?: { start: number; end: number },
) {
  ensure(new Set(rows.map(identity)).size === rows.length);
  rows.forEach((row, index) => {
    const previous = rows[index - 1];
    ensure(previous === undefined || count(row) <= count(previous));
    if (seen && window) {
      const at = Date.parse(seen(row));
      ensure(at >= window.start && at < window.end);
    }
  });
}

const sum = (counts: readonly number[]) => {
  const total = counts.reduce((left, right) => left + right, 0);
  ensure(Number.isSafeInteger(total));
  return total;
};

/** Strict decoding: the counts must nest and add up exactly as the server checked them. */
export function decodeCoverageReport(
  value: unknown,
  request: CoverageReportRequest,
): CoverageReport {
  const row = object(value);
  ensure(row.schema_version === 1);
  exactKeys(row, keys);
  const report: CoverageReport = {
    ...envelope(row),
    ...watermarked(row),
    schema_version: 1,
    watermark_scope: choice(row.watermark_scope, ["configured_journal"]),
    pending_segments: integer(row.pending_segments),
    index_complete: bool(row.index_complete),
    report_digest: name(row.report_digest),
    start: timestamp(row.start),
    end: timestamp(row.end),
    completed_requests: integer(row.completed_requests),
    refused_requests: integer(row.refused_requests),
    observed_requests: integer(row.observed_requests),
    unrouted_refusals: integer(row.unrouted_refusals),
    unshaped_unrouted_refusals: integer(row.unshaped_unrouted_refusals),
    routes: list(row.routes, COVERAGE_REPORT_ROWS_MAX, route),
    routes_truncated: bool(row.routes_truncated),
    refusals: list(row.refusals, COVERAGE_REPORT_ROWS_MAX, refusal),
    refusals_truncated: bool(row.refusals_truncated),
    uncovered: list(row.uncovered, COVERAGE_REPORT_UNCOVERED_MAX, uncovered),
    uncovered_truncated: bool(row.uncovered_truncated),
  };
  ensure(/^[0-9a-f]{64}$/.test(report.report_digest));
  ensure(report.start === request.start && report.end === request.end);
  ensure(report.index_complete === (!report.has_gaps && report.pending_segments === 0));
  ensure(
    report.unshaped_unrouted_refusals <= report.unrouted_refusals &&
      report.unrouted_refusals <= report.refused_requests &&
      report.refused_requests + report.observed_requests <= report.completed_requests,
  );
  const window = { start: Date.parse(report.start), end: Date.parse(report.end) };
  ordered(
    report.routes,
    (item) => item.completed,
    (item) => item.operation_id,
  );
  ordered(
    report.refusals,
    (item) => item.count,
    (item) => `${item.operation_id} ${item.reason_code}`,
    (item) => item.last_seen,
    window,
  );
  ordered(
    report.uncovered,
    (item) => item.count,
    (item) => `${item.method} ${item.path_shape}`,
    (item) => item.last_seen,
    window,
  );
  // Requests without a route are at least the unrouted refusals; the server alone knows the rest.
  const routed = sum(report.routes.map((item) => item.completed));
  ensure(routed <= report.completed_requests - report.unrouted_refusals);
  ensure(
    addsUp(
      sum(report.refusals.map((item) => item.count)),
      report.refused_requests,
      report.refusals_truncated,
    ),
  );
  ensure(
    addsUp(
      sum(report.uncovered.map((item) => item.count)),
      report.unrouted_refusals - report.unshaped_unrouted_refusals,
      report.uncovered_truncated,
    ),
  );
  return report;
}

export type CoverageVerdict = "incomplete" | "no_traffic" | "uncovered" | "covered";

/**
 * What the report lets one say: an index that is behind or has gaps cannot judge; a window
 * without traffic proves nothing; otherwise some refused requests matched no route, or none did.
 */
export function coverageVerdict(report: CoverageReport): CoverageVerdict {
  if (!report.index_complete) return "incomplete";
  if (report.completed_requests === 0) return "no_traffic";
  return report.unrouted_refusals > 0 ? "uncovered" : "covered";
}

/** `12.5%` of `total`, or `—` when there is nothing to divide. */
export function share(part: number, total: number): string {
  if (total === 0) return "—";
  const percent = (part / total) * 100;
  return `${percent >= 10 || percent === 0 ? percent.toFixed(0) : percent.toFixed(1)}%`;
}
