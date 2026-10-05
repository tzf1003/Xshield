/** Metadata-only investigation exports; package bytes remain a download-only Blob. */
import {
  ApiError,
  artifactPattern,
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
  requestPattern,
  text,
  timestamp,
  uuid,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";
import { casePattern, validCaseText } from "./cases.ts";

export const exportPattern = new RegExp(`^export_${uuid}(?![\\s\\S])`);
const statuses = [
  "pending_approval",
  "approved",
  "ready",
  "rejected",
  "expired",
  "failed",
] as const;
export type ExportStatus = (typeof statuses)[number];
export type InvestigationExport = Envelope & {
  export_id: string;
  case_id: string;
  requested_by: string;
  purpose: string;
  kind: "metadata_only";
  status: ExportStatus;
  decided_by: string | null;
  decided_at: string | null;
  decision_reason: string | null;
  expires_at: string | null;
  package_artifact_id: string | null;
  package_request_id: string | null;
  package_digest: string | null;
  package_bytes: number | null;
  download_count: number;
  created_at: string;
  updated_at: string;
  replayed: boolean;
};

export type ExportDownload = Envelope & {
  export_id: string;
  artifact_id: string;
  bytes: number;
  blob: Blob;
};

export function validateExportId(value: unknown): asserts value is string {
  if (typeof value !== "string" || !exportPattern.test(value))
    throw new ApiError("CONTROL_EXPORT_ID_INVALID");
}

function actor(value: unknown): string {
  ensure(validCaseText(value) && new TextEncoder().encode(value).byteLength <= 256);
  return value;
}
function purpose(value: unknown): string {
  ensure(validCaseText(value));
  return value;
}
function time(value: unknown): string {
  const result = timestamp(value);
  ensure(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z(?![\s\S])/.test(result));
  return result;
}

/** Validate a complete response and correlate it to the requested operation. */
export function decodeExportResponse(
  value: unknown,
  expectedExport?: string,
  expectedCase?: string,
): InvestigationExport {
  const row = object(value);
  ensure(
    Object.keys(row).length === 21 &&
      [
        "request_id",
        "tenant_id",
        "site_id",
        "export_id",
        "case_id",
        "requested_by",
        "purpose",
        "kind",
        "status",
        "decided_by",
        "decided_at",
        "decision_reason",
        "expires_at",
        "package_artifact_id",
        "package_request_id",
        "package_digest",
        "package_bytes",
        "download_count",
        "created_at",
        "updated_at",
        "replayed",
      ].every((key) => Object.hasOwn(row, key)),
  );
  const result: InvestigationExport = {
    ...envelope(row),
    export_id: id(row.export_id, exportPattern),
    case_id: id(row.case_id, casePattern),
    requested_by: actor(row.requested_by),
    purpose: purpose(row.purpose),
    kind: choice(row.kind, ["metadata_only"]),
    status: choice(row.status, statuses),
    decided_by: nullable(row.decided_by, actor),
    decided_at: nullable(row.decided_at, time),
    decision_reason: nullable(row.decision_reason, purpose),
    expires_at: nullable(row.expires_at, time),
    package_artifact_id: nullable(row.package_artifact_id, (item) => id(item, artifactPattern)),
    package_request_id: nullable(row.package_request_id, (item) => id(item, requestPattern)),
    package_digest: nullable(row.package_digest, (item) => {
      const digest = text(item, 64);
      ensure(/^[a-f0-9]{64}(?![\s\S])/.test(digest));
      return digest;
    }),
    package_bytes: nullable(row.package_bytes, (item) => integer(item, 0, 8 * 1024 * 1024)),
    download_count: integer(row.download_count, 0, 2),
    created_at: time(row.created_at),
    updated_at: time(row.updated_at),
    replayed: bool(row.replayed),
  };
  ensure(expectedExport === undefined || result.export_id === expectedExport);
  ensure(expectedCase === undefined || result.case_id === expectedCase);
  ensure(Date.parse(result.created_at) <= Date.parse(result.updated_at));
  const decided = result.status !== "pending_approval";
  ensure(
    decided ===
      (result.decided_by !== null && result.decided_at !== null && result.decision_reason !== null),
  );
  ensure(!["approved", "ready"].includes(result.status) || result.expires_at !== null);
  const packaged = result.status === "ready";
  ensure(
    packaged ===
      (result.package_artifact_id !== null &&
        result.package_request_id !== null &&
        result.package_digest !== null &&
        result.package_bytes !== null),
  );
  ensure(
    result.status === "ready" ||
      (result.package_artifact_id === null &&
        result.package_request_id === null &&
        result.package_digest === null &&
        result.package_bytes === null),
  );
  ensure(result.status === "pending_approval" ? result.download_count === 0 : true);
  return result;
}

export type ExportListView = "mine" | "review";
/** The list projection of 29.33: no purpose, decision reason or package identifiers. */
export type ExportListItem = {
  export_id: string;
  case_id: string;
  requested_by: string;
  status: ExportStatus;
  requested_at: string;
  decided_by: string | null;
  decided_at: string | null;
  expires_at: string | null;
};
export type ExportList = Envelope & {
  schema_version: 3;
  view: ExportListView;
  as_of: string;
  items: ExportListItem[];
  truncated: boolean;
  next_cursor: string | null;
};

const exportListCursorPattern = new RegExp(`^v1\\.(export_${uuid})\\.[0-9a-f]{64}(?![\\s\\S])`);

/** Validate the client-visible cursor shape; the server authenticates its scope, subject and
 * view binding anew, so a cursor conveys no approval authority. */
export function validateExportListCursor(cursor?: string): string | undefined {
  if (cursor === undefined) return undefined;
  const match = typeof cursor === "string" ? exportListCursorPattern.exec(cursor) : null;
  if (!match) throw new ApiError("CONTROL_CURSOR_INVALID");
  return match[1];
}
export function validateExportListView(view: unknown): asserts view is ExportListView {
  if (view !== "mine" && view !== "review")
    throw new ApiError("CONTROL_EXPORT_LIST_REQUEST_INVALID");
}

/** List items carry millisecond times; only the database observation keeps microseconds. */
function micros(value: unknown): string {
  const result = timestamp(value);
  ensure(/\.\d{6}Z(?![\s\S])/.test(result));
  return result;
}

function listItem(value: unknown): ExportListItem {
  const row = object(value);
  const item: ExportListItem = {
    export_id: id(row.export_id, exportPattern),
    case_id: id(row.case_id, casePattern),
    requested_by: actor(row.requested_by),
    status: choice(row.status, statuses),
    requested_at: time(row.requested_at),
    decided_by: nullable(row.decided_by, actor),
    decided_at: nullable(row.decided_at, time),
    expires_at: nullable(row.expires_at, time),
  };
  // A pending request has neither a decider nor a decision time; every other state has both.
  ensure(
    item.status === "pending_approval"
      ? item.decided_by === null && item.decided_at === null
      : item.decided_by !== null && item.decided_at !== null,
  );
  ensure(item.decided_by === null || item.decided_by !== item.requested_by);
  // 29.33: the expiry exists only after approval; a rejection or a pending request has none.
  ensure(!["approved", "ready"].includes(item.status) || item.expires_at !== null);
  ensure(!["pending_approval", "rejected"].includes(item.status) || item.expires_at === null);
  const requested = Date.parse(item.requested_at);
  const decidedAt = item.decided_at === null ? requested : Date.parse(item.decided_at);
  ensure(requested <= decidedAt);
  ensure(item.expires_at === null || decidedAt <= Date.parse(item.expires_at));
  return item;
}

/** Bounded, projected metadata from a live page. Order follows the export identity, also across
 * page boundaries; the next cursor must name the last row; a review page holds pending rows only. */
export function decodeExportList(
  value: unknown,
  view: ExportListView,
  cursor?: string,
): ExportList {
  const row = object(value);
  ensure(row.schema_version === 3 && row.view === view);
  const result: ExportList = {
    ...envelope(row),
    schema_version: 3,
    view,
    as_of: micros(row.as_of),
    items: list(row.items, 128, listItem),
    ...pagination(row),
  };
  let previous = validateExportListCursor(cursor);
  for (const item of result.items) {
    ensure(previous === undefined || item.export_id < previous);
    ensure(view !== "review" || item.status === "pending_approval");
    previous = item.export_id;
  }
  if (result.next_cursor !== null) {
    const match = exportListCursorPattern.exec(result.next_cursor);
    ensure(match && result.items.length > 0 && match[1] === previous);
  }
  return result;
}
