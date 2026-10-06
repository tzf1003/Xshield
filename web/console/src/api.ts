/** Control API boundary. Credentials remain in this client's memory. */
import {
  ApiError,
  messages,
  uuid,
  requestPattern,
  artifactPattern,
  modelCallPattern,
  agentRunPattern,
  calibrationReportPattern,
  eventPattern,
  grantPattern,
  bindingPattern,
  cursorPattern,
  ensure,
  object,
  text,
  name,
  id,
  integer,
  bool,
  choice,
  nullable,
  list,
  timestamp,
  references,
  envelope,
  watermarked,
  pagination,
  confidence,
} from "./api-contract.ts";
import type { Envelope, Watermark, ErrorCode } from "./api-contract.ts";
export { ApiError } from "./api-contract.ts";
export type { Envelope, Watermark } from "./api-contract.ts";
import {
  validateSearchPlan,
  validateSearchCursor,
  searchPlanDigest,
  decodeSearchResponse,
  validateCausalityPlan,
  decodeCausalityResponse,
} from "./search.ts";
import type { SearchPlan, SearchResponse, CausalityPlan, CausalityResponse } from "./search.ts";
export type { CausalityPlan, CausalityResponse } from "./search.ts";
import { decodeGrantResponse, decodeBindingResponse } from "./ledger.ts";
import type { GrantResponse, BindingResponse } from "./ledger.ts";
import {
  validateCaseId,
  validateCaseCursor,
  validateCaseListCursor,
  validCaseText,
  validIdempotencyKey,
  decodeCaseCreated,
  decodeCaseList,
  decodeCaseCollection,
  decodeCaseItemAdded,
  decodeCaseClosed,
} from "./cases.ts";
import type { CaseCreated, CaseList, CaseCollection, CaseItemAdded, CaseClosed } from "./cases.ts";
import { decodeJobResponse, validateJobId } from "./jobs.ts";
import type { JobResponse } from "./jobs.ts";
export type { JobResponse } from "./jobs.ts";
import {
  validateAccessId,
  decodeAccessRequested,
  decodeAccessInspection,
  decodeAccessDecision,
  accessPattern,
  decodeAccessList,
  validateAccessListCursor,
  validateAccessListView,
} from "./evidence-access.ts";
import type {
  AccessRequested,
  AccessInspection,
  AccessDecision,
  EvidenceDownload,
  AccessList,
  AccessListView,
} from "./evidence-access.ts";
import {
  decodeHoldCreated,
  decodeHoldReleased,
  decodeHoldCollection,
  validHoldReason,
  validateHoldUntil,
  validateHoldId,
  validateHoldCursor,
} from "./evidence-holds.ts";
import type { HoldMutation, HoldCollection } from "./evidence-holds.ts";
import {
  decodeExportList,
  decodeExportResponse,
  validateExportId,
  validateExportListCursor,
  validateExportListView,
  exportPattern,
} from "./exports.ts";
import type { ExportDownload, ExportList, ExportListView, InvestigationExport } from "./exports.ts";
export type Stage = {
  stage: string;
  outcome: string;
  reason_code: string;
  proof_kind: string;
  confidence: number | null;
  confidence_status: string;
  first_request_seq: number;
  last_request_seq: number;
  duration_us: number;
  event_count: number;
};
export type Summary = {
  event_count: number;
  first_occurred_at: string;
  last_occurred_at: string;
  method: string | null;
  operation_id: string | null;
  decision: "ALLOW" | "DENY" | "UNKNOWN" | null;
  reason_code: string | null;
  status: number | null;
  origin_state: "not_sent" | "unknown" | "response_received" | null;
  duration_us: number | null;
  forwarded: boolean;
  terminal: boolean;
  business_result_confirmed: boolean;
  stages: Stage[];
};
export type SummaryResponse = Envelope & {
  source_request_id: string;
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  found: boolean;
  completeness: "complete" | "pending" | "pending_index" | "not_found";
  summary: Summary | null;
};
export type AuditEvent = {
  event_id: string;
  event_type: string;
  stage: string;
  outcome: string;
  reason_code: string;
  proof_kind: string;
  confidence: number | null;
  confidence_status: string;
  /** Existing timeline wire contract: Unix microseconds, not milliseconds. */
  occurred_at: number;
  request_seq: number;
  duration_us: number;
  policy_revision: string;
  model_revision: string;
  /** Redacted model lifecycle link; the target endpoint reauthorizes access. */
  model_call_id: string | null;
  evidence_refs: string[];
  cause_event_ids: string[];
  sensitivity: string;
};
export type EventsResponse = Envelope & {
  source_request_id: string;
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  truncated: boolean;
  next_cursor: string | null;
  events: AuditEvent[];
};
/** Display metadata only; object locators, key references and digests stay outside the UI. */
export type Manifest = {
  recorded_at: string;
  schema_version: 3;
  artifact_id: string;
  request_id: string;
  tenant_id: string;
  site_id: string;
  kind: string;
  content_type: string;
  capture_status: "complete";
  fidelity: "entity_exact" | "semantic" | "redacted";
  bytes_observed: number;
  bytes_saved: number;
  classification: "INTERNAL" | "SENSITIVE" | "RESTRICTED";
  example_only: false;
  parent_refs: string[];
  expires_at: string;
};
export type EvidenceResponse = Envelope & {
  source_request_id: string;
  truncated: boolean;
  next_cursor: string | null;
  artifacts: Manifest[];
};
export type ArtifactResponse = Envelope & {
  source_artifact_id: string;
  found: boolean;
  artifact: Manifest | null;
};
export type ModelCallFacts = {
  provider: "typesafe" | "vercel_ai_gateway" | null;
  provider_model_id: string | null;
  model_revision: string;
  prompt_revision: string;
  question_type: "choice" | "score" | "noul";
  status: "started" | "requested" | "success" | "error" | "timeout" | "cancelled";
  reason_code: string;
  confidence: number | null;
  confidence_status: string;
  duration_us: number;
  input_artifact_id: string | null;
  output_artifact_id: string | null;
  call_artifact_id: string | null;
};
export type ModelCallEvent = ModelCallFacts & {
  event_id: string;
  event_type: string;
  request_id: string;
  occurred_at: string;
  request_seq: number;
  evidence_refs: string[];
  cause_event_ids: string[];
  sensitivity: string;
};
export type ModelCall = ModelCallFacts & {
  model_call_id: string;
  request_id: string;
  events: ModelCallEvent[];
  lifecycle_complete: boolean;
};
export type ModelCallResponse = Envelope & {
  source_model_call_id: string;
  watermark_scope: "configured_journal";
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  found: boolean;
  completeness: "complete" | "pending" | "partial" | "not_indexed";
  model_call: ModelCall | null;
};

export type AgentRunEvent = {
  event_id: string;
  event_type:
    | "agent.started"
    | "agent.tool_called"
    | "agent.tool_result"
    | "agent.artifact_created"
    | "agent.finished";
  request_id: string | null;
  trace_id: string;
  occurred_at: string;
  request_seq: number;
  outcome: string | null;
  reason_code: string | null;
  evidence_refs: string[];
  cause_event_ids: string[];
  sensitivity: "PUBLIC" | "INTERNAL" | "SENSITIVE" | "RESTRICTED";
};
export type AgentRun = {
  agent_run_id: string;
  lifecycle_complete: boolean;
  events: AgentRunEvent[];
};
export type AgentRunResponse = Envelope & {
  source_agent_run_id: string;
  watermark_scope: "configured_journal";
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  found: boolean;
  completeness: "complete" | "partial" | "not_indexed";
  agent_run: AgentRun | null;
};
/** A bounded, descending discovery window. The server binds the opaque cursor
 * to this exact plan and the authenticated scope; it is never decoded here. */
export type ModelCallListPlan = {
  start: string;
  end: string;
  limit: number;
};
/** One redacted latest-in-window model-call observation. It has no evidence,
 * provider body, probability or numerical confidence field. */
export type ModelCallListItem = {
  model_call_id: string;
  request_id: string;
  occurred_at: string;
  provider: "typesafe" | "vercel_ai_gateway" | null;
  provider_model_id: string | null;
  model_revision: string;
  prompt_revision: string;
  question_type: "choice" | "score" | "noul";
  latest_status: "started" | "requested" | "success" | "error" | "timeout" | "cancelled";
  latest_reason_code: string;
  latest_confidence_status: "provided" | "not_applicable" | "not_provided" | "unavailable";
};
export type ModelCallListResponse = Envelope & {
  schema_version: 3;
  start: string;
  end: string;
  watermark_scope: "configured_journal";
  as_of: string;
  index_watermark: Watermark | null;
  has_gaps: boolean;
  pending_segments: number;
  scanned_rows: number | null;
  scanned_bytes: number | null;
  items: ModelCallListItem[];
  truncated: boolean;
  next_cursor: string | null;
};

/** Frozen restricted calibration-report metadata. This projection deliberately
 * contains no report body, source sample, label, probability, metric, prompt,
 * storage locator, integrity material, or content-read capability. */
export type CalibrationReport = {
  report_id: string;
  report_artifact_id: string;
  completed_at: string;
  reported_at: string;
  reported_event_id: string;
  body_expires_at: string;
  approval_ref: string;
  dataset_revision: string;
  label_revision: string;
  task_revision: string;
  threshold_policy_revision: string;
  mapping_revision: string;
  evaluation_manifest_artifact_id: string;
  training_manifest_artifact_id: string;
  calibration_manifest_artifact_id: string;
  label_manifest_artifact_id: string;
  provider: string;
  provider_model_id: string;
  model_revision: string;
  prompt_revision: string;
  resolved_model_revision: string | null;
  lineage_review_id: string | null;
  /** Dedicated encrypted report-body retention tombstone, never a read grant. */
  body_status: "active" | "deleted";
};

export type CalibrationReportResponse = Envelope & {
  schema_version: 3;
  source_report_id: string;
  found: boolean;
  as_of: string | null;
  report: CalibrationReport | null;
};

/** Authenticated snapshot of one configured audit journal's publication into
 * its analytical index. It is deliberately separate from request eligibility,
 * Outbox delivery, and service-wide health. */
export type AuditHealthResponse = Envelope & {
  target_id: string;
  table: string;
  as_of: string;
  metadata_retention_days: number;
  closed_segments: number;
  closed_segment_bytes: number;
  published_segments: number;
  pending_segments: number;
  unsealed_segments: number;
  has_gaps: boolean;
  index_watermark: Watermark | null;
};

export type WorkbenchObservation<T> = {
  observed_at: string;
  source_state: "available" | "partial" | "unavailable" | "not_authorized";
  reason_code: string;
  value: T | null;
};

export type WorkbenchSite = {
  site_id: string;
  display_name: string;
  public_origin: string;
  edge: WorkbenchObservation<string>;
  upstream: WorkbenchObservation<string>;
  audit: WorkbenchObservation<string>;
  current_revision: number | null;
  apply_state: string;
  reason_code: string;
  updated_at: string;
};

export type WorkbenchAudit = Omit<AuditHealthResponse, "request_id" | "tenant_id" | "site_id">;

export type WorkbenchOverviewResponse = Envelope & {
  as_of: string;
  completeness: "complete" | "partial" | "unavailable";
  index_watermark: Watermark | null;
  has_gaps: boolean;
  posture: WorkbenchObservation<string>;
  sites: WorkbenchSite[];
  queues: unknown[];
  recent_activity: unknown[];
  audit: WorkbenchObservation<WorkbenchAudit>;
};

function modelCallListTime(value: unknown): string {
  const result = timestamp(value);
  // The route's signed query vocabulary has exactly-second UTC boundaries.
  ensure(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(result));
  return result;
}

function decodeWorkbenchObservation<T>(
  value: unknown,
  decode: (value: unknown) => T,
): WorkbenchObservation<T> {
  const row = object(value);
  ensure(
    Object.keys(row).length === 4 &&
      ["observed_at", "source_state", "reason_code", "value"].every((key) =>
        Object.hasOwn(row, key),
      ),
  );
  const source_state = choice(row.source_state, [
    "available",
    "partial",
    "unavailable",
    "not_authorized",
  ] as const);
  return {
    observed_at: timestamp(row.observed_at),
    source_state,
    reason_code: name(row.reason_code),
    value: row.value === null ? null : decode(row.value),
  };
}

function decodeWorkbenchAudit(value: unknown): WorkbenchAudit {
  const row = object(value);
  ensure(
    Object.keys(row).length === 11 &&
      [
        "target_id",
        "table",
        "as_of",
        "metadata_retention_days",
        "closed_segments",
        "closed_segment_bytes",
        "published_segments",
        "pending_segments",
        "unsealed_segments",
        "has_gaps",
        "index_watermark",
      ].every((key) => Object.hasOwn(row, key)),
  );
  const result = {
    ...watermarked(row),
    target_id: name(row.target_id),
    table: name(row.table),
    as_of: timestamp(row.as_of),
    metadata_retention_days: integer(row.metadata_retention_days, 1, 3650),
    closed_segments: integer(row.closed_segments),
    closed_segment_bytes: integer(row.closed_segment_bytes),
    published_segments: integer(row.published_segments),
    pending_segments: integer(row.pending_segments),
    unsealed_segments: integer(row.unsealed_segments),
    has_gaps: bool(row.has_gaps),
  } satisfies WorkbenchAudit;
  ensure(result.published_segments + result.pending_segments === result.closed_segments);
  ensure(result.unsealed_segments <= result.pending_segments);
  return result;
}

function decodeWorkbenchOverview(value: unknown, status: number): WorkbenchOverviewResponse {
  ensure(status === 200);
  const row = object(value);
  ensure(
    Object.keys(row).length === 12 &&
      [
        "request_id",
        "tenant_id",
        "site_id",
        "as_of",
        "completeness",
        "index_watermark",
        "has_gaps",
        "posture",
        "sites",
        "queues",
        "recent_activity",
        "audit",
      ].every((key) => Object.hasOwn(row, key)),
  );
  const sites = list(row.sites, 128, (item) => {
    const site = object(item);
    ensure(Object.keys(site).length === 10);
    return {
      site_id: name(site.site_id),
      display_name: text(site.display_name),
      public_origin: text(site.public_origin),
      edge: decodeWorkbenchObservation(site.edge, text),
      upstream: decodeWorkbenchObservation(site.upstream, text),
      audit: decodeWorkbenchObservation(site.audit, text),
      current_revision: site.current_revision === null ? null : integer(site.current_revision),
      apply_state: text(site.apply_state),
      reason_code: name(site.reason_code),
      updated_at: timestamp(site.updated_at),
    };
  });
  return {
    ...envelope(row),
    as_of: timestamp(row.as_of),
    completeness: choice(row.completeness, ["complete", "partial", "unavailable"] as const),
    index_watermark:
      row.index_watermark === null
        ? null
        : (() => {
            const watermark = object(row.index_watermark);
            return {
              producer_boot_id: id(watermark.producer_boot_id, new RegExp(`^${uuid}$`)),
              producer_sequence: integer(watermark.producer_sequence, 1),
            };
          })(),
    has_gaps: bool(row.has_gaps),
    posture: decodeWorkbenchObservation(row.posture, text),
    sites,
    queues: list(row.queues, 256, (item) => item),
    recent_activity: list(row.recent_activity, 256, (item) => item),
    audit: decodeWorkbenchObservation(row.audit, decodeWorkbenchAudit),
  };
}

/** Validate a local list plan before it can become an audited GET request. */
export function validateModelCallListPlan(value: unknown): ModelCallListPlan {
  try {
    const row = object(value);
    ensure(
      Object.keys(row).length === 3 &&
        ["start", "end", "limit"].every((key) => Object.hasOwn(row, key)),
    );
    const start = modelCallListTime(row.start);
    const end = modelCallListTime(row.end);
    const duration = Date.parse(end) - Date.parse(start);
    ensure(
      duration > 0 &&
        duration <= 31 * 24 * 60 * 60 * 1000 &&
        Date.parse(start) >= 0 &&
        Date.parse(end) <= 10_413_792_000_000,
    );
    return { start, end, limit: integer(row.limit, 1, 100) };
  } catch {
    throw new ApiError("CONTROL_MODEL_CALLS_REQUEST_INVALID");
  }
}

function modelCallListItem(value: unknown): ModelCallListItem {
  const row = object(value);
  ensure(
    Object.keys(row).length === 11 &&
      [
        "model_call_id",
        "request_id",
        "occurred_at",
        "provider",
        "provider_model_id",
        "model_revision",
        "prompt_revision",
        "question_type",
        "latest_status",
        "latest_reason_code",
        "latest_confidence_status",
      ].every((key) => Object.hasOwn(row, key)),
  );
  const result: ModelCallListItem = {
    model_call_id: id(row.model_call_id, modelCallPattern),
    request_id: id(row.request_id, requestPattern),
    occurred_at: timestamp(row.occurred_at),
    provider: nullable(row.provider, (item) => choice(item, ["typesafe", "vercel_ai_gateway"])),
    provider_model_id: nullable(row.provider_model_id, (item) => text(item)),
    model_revision: name(row.model_revision),
    prompt_revision: name(row.prompt_revision),
    question_type: choice(row.question_type, ["choice", "score", "noul"]),
    latest_status: choice(row.latest_status, [
      "started",
      "requested",
      "success",
      "error",
      "timeout",
      "cancelled",
    ]),
    latest_reason_code: name(row.latest_reason_code),
    latest_confidence_status: choice(row.latest_confidence_status, [
      "provided",
      "not_applicable",
      "not_provided",
      "unavailable",
    ]),
  };
  ensure(result.question_type !== "noul" || result.latest_confidence_status === "not_applicable");
  ensure(result.latest_status === "success" || result.latest_confidence_status !== "provided");
  return result;
}

type ModelCallListPosition = { time: bigint; modelCallId: string };
function modelCallListPosition(item: ModelCallListItem): ModelCallListPosition {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d{6})Z$/.exec(item.occurred_at);
  // The model-call index and its keyset cursor operate at exact microseconds.
  ensure(match !== null);
  const millis = Date.parse(`${match[1]!}Z`);
  ensure(Number.isSafeInteger(millis));
  return {
    time: BigInt(millis) * 1000n + BigInt(match[2]!),
    modelCallId: item.model_call_id,
  };
}

const maxBytes = 16 * 1024 * 1024;
function stage(value: unknown): Stage {
  const row = object(value);
  const first_request_seq = integer(row.first_request_seq, 1, 0xffff_ffff);
  return {
    stage: name(row.stage),
    outcome: choice(row.outcome, ["PASS", "DENY", "UNKNOWN", "ERROR", "SKIPPED", "CANCELLED"]),
    reason_code: name(row.reason_code),
    ...confidence(row),
    first_request_seq,
    last_request_seq: integer(row.last_request_seq, first_request_seq, 0xffff_ffff),
    duration_us: integer(row.duration_us),
    event_count: integer(row.event_count, 1),
  };
}
function summary(value: unknown): Summary {
  const row = object(value);
  const result: Summary = {
    event_count: integer(row.event_count, 1),
    first_occurred_at: timestamp(row.first_occurred_at),
    last_occurred_at: timestamp(row.last_occurred_at),
    method: nullable(row.method, (item) => {
      const method = text(item, 16);
      ensure(/^[A-Z]+$/.test(method));
      return method;
    }),
    operation_id: nullable(row.operation_id, name),
    decision: nullable(row.decision, (item) => choice(item, ["ALLOW", "DENY", "UNKNOWN"])),
    reason_code: nullable(row.reason_code, name),
    status: nullable(row.status, (item) => integer(item, 100, 599)),
    origin_state: nullable(row.origin_state, (item) =>
      choice(item, ["not_sent", "unknown", "response_received"]),
    ),
    duration_us: nullable(row.duration_us, integer),
    forwarded: bool(row.forwarded),
    terminal: bool(row.terminal),
    business_result_confirmed: bool(row.business_result_confirmed),
    stages: list(row.stages, 128, stage),
  };
  ensure(
    result.business_result_confirmed ===
      (result.terminal && result.origin_state === "response_received"),
  );
  ensure(
    result.terminal ||
      [
        result.decision,
        result.reason_code,
        result.status,
        result.origin_state,
        result.duration_us,
      ].every((item) => item === null),
  );
  ensure(new Set(result.stages.map((item) => item.stage)).size === result.stages.length);
  return result;
}
function auditEvent(value: unknown): AuditEvent {
  const row = object(value);
  const result = {
    event_id: id(row.event_id, eventPattern),
    event_type: name(row.event_type),
    stage: name(row.stage, true),
    outcome: choice(row.outcome, [
      "",
      "PASS",
      "ALLOW",
      "DENY",
      "UNKNOWN",
      "ERROR",
      "SKIPPED",
      "CANCELLED",
      "not_sent",
      "unknown",
      "response_received",
    ]),
    reason_code: name(row.reason_code, true),
    ...confidence(row, true),
    occurred_at: integer(row.occurred_at, -Number.MAX_SAFE_INTEGER),
    request_seq: integer(row.request_seq, 1, 0xffff_ffff),
    duration_us: integer(row.duration_us),
    policy_revision: name(row.policy_revision),
    model_revision: name(row.model_revision, true),
    model_call_id: nullable(row.model_call_id, (item) => id(item, modelCallPattern)),
    evidence_refs: references(row.evidence_refs, new RegExp(`^[a-z]+_${uuid}$`)),
    cause_event_ids: references(row.cause_event_ids, eventPattern),
    sensitivity: choice(row.sensitivity, ["PUBLIC", "INTERNAL", "SENSITIVE", "RESTRICTED"]),
  };
  ensure((result.proof_kind === "model") === (result.model_call_id !== null));
  return result;
}
function manifest(value: unknown, scope: Envelope, request?: string, artifact?: string): Manifest {
  const row = object(value);
  ensure(row.schema_version === 3 && row.example_only === false);
  const result: Manifest = {
    recorded_at: timestamp(row.recorded_at),
    schema_version: 3,
    artifact_id: id(row.artifact_id, artifactPattern),
    request_id: id(row.request_id, requestPattern),
    tenant_id: name(row.tenant_id),
    site_id: name(row.site_id),
    kind: name(row.kind),
    content_type: text(row.content_type, 256),
    capture_status: choice(row.capture_status, ["complete"]),
    fidelity: choice(row.fidelity, ["entity_exact", "semantic", "redacted"]),
    bytes_observed: integer(row.bytes_observed, 0, 64 * 1024 * 1024),
    bytes_saved: integer(row.bytes_saved, 0, 64 * 1024 * 1024),
    classification: choice(row.classification, ["INTERNAL", "SENSITIVE", "RESTRICTED"]),
    example_only: false,
    parent_refs: references(row.parent_refs, artifactPattern, 64),
    expires_at: timestamp(row.expires_at),
  };
  ensure(result.tenant_id === scope.tenant_id && result.site_id === scope.site_id);
  ensure(
    (request === undefined || result.request_id === request) &&
      (artifact === undefined || result.artifact_id === artifact),
  );
  ensure(result.bytes_observed === result.bytes_saved);
  return result;
}

const modelEventTypes = {
  started: "model.started",
  requested: "model.requested",
  success: "model.responded",
  error: "model.failed",
  timeout: "model.timeout",
  cancelled: "model.cancelled",
} as const;
function modelFacts(row: Record<string, unknown>): ModelCallFacts {
  const { confidence: value, confidence_status } = confidence({
    ...row,
    proof_kind: "model",
  });
  const provider = nullable(row.provider, (item) =>
    choice(item, ["typesafe", "vercel_ai_gateway"] as const),
  );
  const provider_model_id = nullable(row.provider_model_id, (item) => text(item));
  ensure(
    provider === null
      ? provider_model_id === null
      : provider_model_id === (provider === "typesafe" ? "jev-1.13.0" : "typesafe-ai/jev"),
  );
  const result: ModelCallFacts = {
    provider,
    provider_model_id,
    model_revision: name(row.model_revision),
    prompt_revision: name(row.prompt_revision),
    question_type: choice(row.question_type, ["choice", "score", "noul"]),
    status: choice(row.status, [
      "started",
      "requested",
      "success",
      "error",
      "timeout",
      "cancelled",
    ]),
    reason_code: name(row.reason_code),
    confidence: value,
    confidence_status,
    duration_us: integer(row.duration_us),
    input_artifact_id: nullable(row.input_artifact_id, (item) => id(item, artifactPattern)),
    output_artifact_id: nullable(row.output_artifact_id, (item) => id(item, artifactPattern)),
    call_artifact_id: nullable(row.call_artifact_id, (item) => id(item, artifactPattern)),
  };
  ensure(result.question_type !== "noul" || result.confidence_status === "not_applicable");
  ensure(result.status === "success" || result.confidence === null);
  ensure(!["requested", "success"].includes(result.status) || result.input_artifact_id !== null);
  ensure(
    result.status !== "success" ||
      (result.output_artifact_id !== null && result.call_artifact_id !== null),
  );
  return result;
}
function modelCall(value: unknown, target: string): ModelCall {
  const row = object(value);
  const result: ModelCall = {
    ...modelFacts(row),
    model_call_id: id(row.model_call_id, modelCallPattern),
    request_id: id(row.request_id, requestPattern),
    lifecycle_complete: bool(row.lifecycle_complete),
    events: list(row.events, 3, (value) => {
      const event = object(value);
      const result: ModelCallEvent = {
        ...modelFacts(event),
        event_id: id(event.event_id, eventPattern),
        event_type: name(event.event_type),
        request_id: id(event.request_id, requestPattern),
        occurred_at: timestamp(event.occurred_at),
        request_seq: integer(event.request_seq, 1, 0xffff_ffff),
        evidence_refs: references(event.evidence_refs, new RegExp(`^[a-z]+_${uuid}$`)),
        cause_event_ids: references(event.cause_event_ids, eventPattern, 1),
        sensitivity: choice(event.sensitivity, ["PUBLIC", "INTERNAL", "SENSITIVE", "RESTRICTED"]),
      };
      ensure(result.event_type === modelEventTypes[result.status]);
      ensure(result.cause_event_ids.length === (result.status === "started" ? 0 : 1));
      for (const reference of [
        result.input_artifact_id,
        result.output_artifact_id,
        result.call_artifact_id,
      ])
        ensure(reference === null || result.evidence_refs.includes(reference));
      ensure(
        result.status !== "started" ||
          [result.input_artifact_id, result.output_artifact_id, result.call_artifact_id].every(
            (item) => item === null,
          ),
      );
      ensure(
        result.status !== "requested" ||
          (result.output_artifact_id === null && result.call_artifact_id === null),
      );
      return result;
    }),
  };
  ensure(result.model_call_id === target && result.events.length > 0);
  const first = result.events[0]!;
  const latest = result.events.at(-1)!;
  const identity = [
    "request_id",
    "provider",
    "provider_model_id",
    "model_revision",
    "prompt_revision",
    "question_type",
  ] as const;
  const latestFacts = [
    "status",
    "reason_code",
    "confidence",
    "confidence_status",
    "duration_us",
  ] as const;
  ensure(latestFacts.every((field) => result[field] === latest[field]));
  ensure(new Set(result.events.map((event) => event.event_id)).size === result.events.length);
  ensure(new Set(result.events.map((event) => event.event_type)).size === result.events.length);
  ensure(new Set(result.events.flatMap((event) => event.evidence_refs)).size <= 256);
  let continuous = true;
  // Retention may hide a predecessor. Visible send boundaries must still link
  // directly, and request sequence stays authoritative across clock rollback.
  for (let index = 0; index < result.events.length; index++) {
    const event = result.events[index]!;
    ensure(identity.every((field) => event[field] === result[field]));
    ensure(
      !result.events.slice(index).some((later) => event.cause_event_ids.includes(later.event_id)),
    );
    if (index === 0) continue;
    const previous = result.events[index - 1]!;
    const direct = event.cause_event_ids[0] === previous.event_id;
    ensure(event.request_seq > previous.request_seq && event.status !== "started");
    ensure(["started", "requested"].includes(previous.status));
    ensure(
      previous.status !== "requested" || event.input_artifact_id === previous.input_artifact_id,
    );
    ensure((previous.status !== "requested" && event.status !== "requested") || direct);
    ensure(
      previous.status !== "started" || !direct || ["requested", "error"].includes(event.status),
    );
    continuous &&= direct;
  }
  for (const field of ["input_artifact_id", "output_artifact_id", "call_artifact_id"] as const) {
    const refs = new Set(result.events.map((event) => event[field]).filter((ref) => ref !== null));
    ensure(refs.size <= 1 && result[field] === (refs.values().next().value ?? null));
  }
  ensure(
    result.lifecycle_complete ===
      (first.status === "started" &&
        !["started", "requested"].includes(latest.status) &&
        continuous),
  );
  return result;
}

const agentEventTypes = [
  "agent.started",
  "agent.tool_called",
  "agent.tool_result",
  "agent.artifact_created",
  "agent.finished",
] as const;
const agentTracePattern = /^[0-9a-f]{32}$/;
const agentOutcomes = [
  "PASS",
  "ALLOW",
  "DENY",
  "UNKNOWN",
  "ERROR",
  "SKIPPED",
  "CANCELLED",
  "not_sent",
  "unknown",
  "response_received",
] as const;

function agentRunEvent(value: unknown): AgentRunEvent {
  const row = object(value);
  ensure(
    Object.keys(row).length === 11 &&
      [
        "event_id",
        "event_type",
        "request_id",
        "trace_id",
        "occurred_at",
        "request_seq",
        "outcome",
        "reason_code",
        "evidence_refs",
        "cause_event_ids",
        "sensitivity",
      ].every((key) => Object.hasOwn(row, key)),
  );
  return {
    event_id: id(row.event_id, eventPattern),
    event_type: choice(row.event_type, agentEventTypes),
    request_id: nullable(row.request_id, (item) => id(item, requestPattern)),
    trace_id: id(row.trace_id, agentTracePattern),
    occurred_at: timestamp(row.occurred_at),
    request_seq: integer(row.request_seq, 1, 0xffff_ffff),
    outcome: nullable(row.outcome, (item) => choice(item, agentOutcomes)),
    reason_code: nullable(row.reason_code, name),
    evidence_refs: references(row.evidence_refs, new RegExp(`^[a-z]+_${uuid}$`)),
    cause_event_ids: references(row.cause_event_ids, eventPattern),
    sensitivity: choice(row.sensitivity, ["PUBLIC", "INTERNAL", "SENSITIVE", "RESTRICTED"]),
  };
}

function agentRun(value: unknown, target: string): AgentRun {
  const row = object(value);
  ensure(
    Object.keys(row).length === 3 &&
      ["agent_run_id", "lifecycle_complete", "events"].every((key) => Object.hasOwn(row, key)),
  );
  const result: AgentRun = {
    agent_run_id: id(row.agent_run_id, agentRunPattern),
    lifecycle_complete: bool(row.lifecycle_complete),
    events: list(row.events, 64, agentRunEvent),
  };
  ensure(result.agent_run_id === target && result.events.length > 0);
  const seen = new Set<string>();
  let started = false;
  let finished = false;
  let previousSeq = 0;
  for (const [index, event] of result.events.entries()) {
    ensure(!seen.has(event.event_id) && event.request_seq > previousSeq);
    seen.add(event.event_id);
    previousSeq = event.request_seq;
    if (event.event_type === "agent.started") {
      ensure(!started && !finished);
      started = true;
    } else if (event.event_type === "agent.finished") {
      ensure(started && !finished);
      finished = true;
    } else {
      ensure(!finished);
    }
    ensure(
      !event.cause_event_ids.some((cause) =>
        result.events.slice(index).some((later) => later.event_id === cause),
      ),
    );
  }
  ensure(
    result.lifecycle_complete ===
      (started && finished && result.events[0]?.event_type === "agent.started"),
  );
  return result;
}

async function readJson(response: Response, signal: AbortSignal): Promise<unknown> {
  ensure(
    response.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() ===
      "application/json",
  );
  const length = response.headers.get("content-length");
  if (length !== null) {
    ensure(/^\d+$/.test(length) && Number.isSafeInteger(Number(length)));
    if (Number(length) > maxBytes) throw new ApiError("RESPONSE_TOO_LARGE", response.status);
  }
  ensure(response.body !== null);
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let body = "";
  const cancel = () => {
    void reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      signal.throwIfAborted();
      const chunk = await reader.read();
      signal.throwIfAborted();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes) throw new ApiError("RESPONSE_TOO_LARGE", response.status);
      body += decoder.decode(chunk.value, { stream: true });
    }
    body += decoder.decode();
    try {
      return JSON.parse(body) as unknown;
    } catch {
      throw new ApiError("INVALID_RESPONSE", response.status);
    }
  } catch (error) {
    if (signal.aborted || error instanceof ApiError) throw error;
    throw new ApiError("INVALID_RESPONSE", response.status);
  } finally {
    signal.removeEventListener("abort", cancel);
    // Cancellation need not wait for a remote stream to acknowledge it.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

const maxEvidenceBytes = 64 * 1024 * 1024;
async function readEvidence(
  response: Response,
  signal: AbortSignal,
  artifactId: string,
  accessId: string,
): Promise<EvidenceDownload> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    // Validate every header before taking a body reader. Filenames are fixed
    // locally; server-controlled disposition values never become browser URLs.
    ensure(response.status === 200);
    const headers = response.headers;
    const base = envelope({
      request_id: headers.get("X-Xshield-Request-Id"),
      tenant_id: headers.get("X-Xshield-Tenant-Id"),
      site_id: headers.get("X-Xshield-Site-Id"),
    });
    ensure(id(headers.get("X-Xshield-Artifact-Id"), artifactPattern) === artifactId);
    ensure(id(headers.get("X-Xshield-Evidence-Access-Request"), accessPattern) === accessId);
    ensure(headers.get("content-type") === "application/octet-stream");
    ensure(headers.get("content-disposition") === 'attachment; filename="evidence.bin"');
    ensure(headers.get("x-content-type-options") === "nosniff");
    const cache = headers
      .get("cache-control")
      ?.split(",")
      .map((v) => v.trim().toLowerCase());
    ensure(cache?.includes("private") && cache.includes("no-store") && !cache.includes("public"));
    ensure(headers.get("content-encoding") === null);
    const length = headers.get("content-length");
    ensure(length !== null && /^(0|[1-9][0-9]*)(?![\s\S])/.test(length));
    const expected = Number(length);
    ensure(Number.isSafeInteger(expected));
    if (expected > maxEvidenceBytes) throw new ApiError("RESPONSE_TOO_LARGE");
    ensure(response.body !== null);
    reader = response.body.getReader();
    const buffer = new Uint8Array(expected);
    let bytes = 0;
    // Native fetch aborts its body, but an explicit cancellation bridge also
    // covers an already-delivered or application-provided stalled stream.
    const cancel = () => {
      void reader?.cancel().catch(() => {});
    };
    signal.addEventListener("abort", cancel, { once: true });
    try {
      while (true) {
        signal.throwIfAborted();
        const chunk = await reader.read();
        signal.throwIfAborted();
        if (chunk.done) break;
        const next = bytes + chunk.value.byteLength;
        if (next > maxEvidenceBytes) throw new ApiError("RESPONSE_TOO_LARGE");
        ensure(next <= expected);
        buffer.set(chunk.value, bytes);
        bytes = next;
      }
      ensure(bytes === expected);
      return {
        ...base,
        artifact_id: artifactId,
        access_request_id: accessId,
        bytes,
        blob: new Blob([buffer], { type: "application/octet-stream" }),
      };
    } finally {
      signal.removeEventListener("abort", cancel);
      // One bounded buffer avoids per-chunk allocation amplification. Blob
      // construction copies it; clear this owned intermediate on every path.
      buffer.fill(0);
    }
  } finally {
    if (reader) {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    } else {
      void response.body?.cancel().catch(() => {});
    }
  }
}

const maxExportBytes = 8 * 1024 * 1024;
async function readExport(
  response: Response,
  signal: AbortSignal,
  exportId: string,
  expectedArtifactId: string,
  expectedBytes: number,
): Promise<ExportDownload> {
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  try {
    ensure(response.status === 200);
    const headers = response.headers;
    const base = envelope({
      request_id: headers.get("X-Xshield-Request-Id"),
      tenant_id: headers.get("X-Xshield-Tenant-Id"),
      site_id: headers.get("X-Xshield-Site-Id"),
    });
    ensure(id(headers.get("X-Xshield-Export-Id"), exportPattern) === exportId);
    const artifactId = id(headers.get("X-Xshield-Package-Artifact-Id"), artifactPattern);
    ensure(artifactId === expectedArtifactId);
    ensure(headers.get("content-type") === "application/json");
    ensure(
      headers.get("content-disposition") === 'attachment; filename="investigation-export.json"',
    );
    ensure(headers.get("x-content-type-options") === "nosniff");
    ensure(headers.get("content-encoding") === null);
    const cache = headers
      .get("cache-control")
      ?.split(",")
      .map((value) => value.trim().toLowerCase());
    ensure(cache?.includes("private") && cache.includes("no-store") && !cache.includes("public"));
    const length = headers.get("content-length");
    ensure(length !== null && /^(0|[1-9][0-9]*)(?![\s\S])/.test(length));
    const expected = Number(length);
    ensure(Number.isSafeInteger(expected));
    if (expected > maxExportBytes) throw new ApiError("RESPONSE_TOO_LARGE");
    ensure(expected === expectedBytes);
    ensure(response.body !== null);
    reader = response.body.getReader();
    const buffer = new Uint8Array(expected);
    let bytes = 0;
    const cancel = () => {
      void reader?.cancel().catch(() => {});
    };
    signal.addEventListener("abort", cancel, { once: true });
    try {
      while (true) {
        signal.throwIfAborted();
        const chunk = await reader.read();
        signal.throwIfAborted();
        if (chunk.done) break;
        const next = bytes + chunk.value.byteLength;
        if (next > maxExportBytes) throw new ApiError("RESPONSE_TOO_LARGE");
        ensure(next <= expected);
        buffer.set(chunk.value, bytes);
        bytes = next;
      }
      ensure(bytes === expected);
      return {
        ...base,
        export_id: exportId,
        artifact_id: artifactId,
        bytes,
        blob: new Blob([buffer], { type: "application/json" }),
      };
    } finally {
      signal.removeEventListener("abort", cancel);
      buffer.fill(0);
    }
  } finally {
    if (reader) {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    } else {
      void response.body?.cancel().catch(() => {});
    }
  }
}

export type BrowserSession = {
  subject: string;
  tenant_id: string;
  site_id: string;
  csrf_token: string;
  roles: string[];
  session_expires_at: string;
  idle_expires_at: string;
  last_reauthenticated_at: string | null;
  step_up_valid: boolean;
};

/**
 * Admission of one route. `auth_entry` (an approved authentication entry, edge `AUTH_ENTRY`) and
 * `share_entry` (the fixed, resource-bound read a share credential redeems, edge `SHARE_ENTRY`)
 * exist only on routes; the site's own entry is never either.
 */
export type RouteAdmission =
  | "public"
  | "auth_entry"
  | "authenticated_root"
  | "ui_action_required"
  | "share_entry";

/** Identity establishment on an `auth_entry` route (`xshield_core::site::flow::SiteAuthBinding`). */
export type SiteAuthBinding = {
  success_status: number;
  principal_pointer: string;
  authorization_context_pointer: string;
  bearer_pointer: string;
  credential_ttl_seconds: number;
  session_ttl_seconds: number;
};

/** Binding revocation on an `authenticated_root` logout route. */
export type SiteAuthRevoke = { success_status: number };

/** One approved page build of a `SENSOR_HTML` route. */
export type SiteSensorHtmlAdapter = {
  adapter_revision: string;
  origin_sha256: string;
  injection_offset: number;
};

/** The approved builds of a `SENSOR_HTML` page; `additional_adapters` is omitted when empty. */
export type SiteSensorHtml = SiteSensorHtmlAdapter & {
  additional_adapters?: SiteSensorHtmlAdapter[];
};

/** Page issuance settings of a `SENSOR_HTML` page root. */
export type SitePageActions = { mapping_revision: string; max_active_pages: number };

/** The page root that issues this first-hop UI action. */
export type SiteIssuedBy = { page_operation_id: string; ttl_seconds: number };

/** Response-derived resource qualification for one resource route. */
export type SiteResourceGrant = {
  success_status: number;
  items_pointer: string;
  resource_pointer: string;
  action_ref_field: string;
  target_operation_id: string;
  target_mapping_revision: string;
  ttl_seconds: number;
  max_items: number;
  max_active_grants: number;
};

/** What a pagination query parameter selects; there is deliberately no cursor kind. */
export type PaginationKind = "page" | "page_size" | "offset";

/** One declared pagination parameter; `max_value` exists only for `page_size`. */
export type SiteQueryParameter = {
  name: string;
  kind: PaginationKind;
  max_value?: number;
};

/**
 * The pagination-shaped query parameters a route may carry
 * (`xshield_core::query_pagination::SiteQueryPagination`). Absent means any query is refused.
 */
export type SiteQueryPagination = { parameters: SiteQueryParameter[] };

/**
 * Share issuance on a UI-action resource route (`xshield_core::site::share::SiteShareIssue`):
 * the edge adds `token_field` to a successful JSON object response, carrying a read-only
 * credential for the one resource the request was qualified for, redeemable at the
 * `share_entry` route `target_operation_id`.
 */
export type SiteShareIssue = {
  success_status: number;
  token_field: string;
  target_operation_id: string;
  issuance_rule_id: string;
  ttl_seconds: number;
  max_active_shares: number;
};

/**
 * A credential refresh or an authorization-context switch on an `authenticated_root` route
 * (`xshield_core::site::flow::SiteAuthTransition`, edge `response.auth_refresh` and
 * `response.auth_context_switch`). No session lease: neither extends the session.
 */
export type SiteAuthTransition = {
  success_status: number;
  principal_pointer: string;
  authorization_context_pointer: string;
  bearer_pointer: string;
  credential_ttl_seconds: number;
};

/**
 * One route exactly as the server stores it. The browser provenance-flow blocks at the end are
 * present only when set (the server omits unset ones), so a decoded route serializes back to the
 * same JSON and a save can never drop or default a block it carried.
 */
export type SiteRouteConfig = {
  operation_id: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  security_entry: RouteAdmission;
  source_action: string | null;
  resource_type: string | null;
  view_profile: string | null;
  resource_query_parameter: string | null;
  resource_path_parameter: string | null;
  request_crypto: Record<string, unknown> | null;
  response_crypto: Record<string, unknown> | null;
  response_mode: "" | "BUFFERED_JSON" | "SENSOR_HTML";
  max_response_bytes: number;
  auth_binding?: SiteAuthBinding;
  auth_revoke?: SiteAuthRevoke;
  sensor_html?: SiteSensorHtml;
  page_actions?: SitePageActions;
  issued_by?: SiteIssuedBy;
  resource_grant?: SiteResourceGrant;
  query_pagination?: SiteQueryPagination;
  share_issue?: SiteShareIssue;
  auth_refresh?: SiteAuthTransition;
  auth_context_switch?: SiteAuthTransition;
};

/** The flow blocks of a route, in the server's field order. */
export const routeFlowKeys = [
  "auth_binding",
  "auth_revoke",
  "sensor_html",
  "page_actions",
  "issued_by",
  "resource_grant",
  "query_pagination",
  "share_issue",
  "auth_refresh",
  "auth_context_switch",
] as const satisfies readonly (keyof SiteRouteConfig)[];

export type SitePolicyConfig = {
  routes: SiteRouteConfig[];
  identity: {
    enabled: boolean;
    cookie_name: string;
    credential_header: string;
    profile: string;
    session_ttl_seconds: number;
    generation: number;
  };
  crypto: {
    adapter_revision: string;
    failure_strategy: string;
    protocol_version: string | null;
  };
  waf: {
    enabled: boolean;
    blocked_headers: string[];
    blocked_query_fragments: string[];
    max_cookie_bytes: number;
  };
  limits: {
    max_request_body_bytes: number;
    max_response_body_bytes: number;
    requests_per_second: number;
    burst: number;
  };
  health_check: {
    path: string;
    interval_seconds: number;
    timeout_ms: number;
    expected_status: number;
  };
  secret_refs: SiteSecretReference[];
  /** Depth limit of the public static-asset fallback; 0 turns it off (server default 5, max 16). */
  static_asset_max_path_depth: number;
  /** Whether the edge asks the origin to enforce object ownership (server default false). */
  origin_object_access_enforced: boolean;
};

export type SiteSecretReference = {
  kind: "tls" | "session_hmac" | "request_crypto" | "response_crypto" | "model";
  secret_ref: string;
  key_id: string;
  state: "active" | "pending_rotation" | "retired" | "unavailable";
};

export type SiteConfig = {
  display_name: string;
  public_origin: string;
  upstream_address: string;
  upstream_server_name: string;
  upstream_tls: boolean;
  listen_port: number;
  entry_path: string;
  security_entry: "public" | "authenticated_root" | "ui_action_required";
  sensor_enabled: boolean;
  policy_revision: string;
  status: "draft" | "active" | "paused";
  policy: SitePolicyConfig;
  revision: number;
  config_digest: string;
  updated_by: string;
  created_at: string;
  updated_at: string;
  /** The edge projection, for display only; `null` when the server cannot produce it. */
  gateway_config: Record<string, unknown> | null;
};
export type SiteConfigResponse = Envelope & {
  found: boolean;
  desired_revision: number | null;
  active_revision: number | null;
  apply_state: "active" | "pending" | "failed" | "paused" | null;
  apply_id: string | null;
  reason_code: string | null;
  requires_approval: boolean | null;
  config_digest: string | null;
  config: SiteConfig | null;
  edge_health?: Record<string, unknown>;
};

export type SiteListItem = {
  site_id: string;
  display_name: string;
  public_origin: string;
  listen_port: number;
  security_entry: SiteConfig["security_entry"];
  sensor_enabled: boolean;
  policy_revision: string;
  status: SiteConfig["status"];
  revision: number;
  config_digest: string;
  updated_by: string;
  updated_at: string;
  desired_revision: number;
  active_revision: number | null;
  apply_id: string;
  apply_state: "active" | "pending" | "failed" | "paused";
  reason_code: string;
  requires_approval: boolean;
};

/** Canonical management API key ID (`key_` + UUID). */
export const apiKeyIdPattern = /^key_[0-9a-f-]{36}(?![\s\S])/;

export type ManagementApiKeyRecord = {
  api_key_id: string;
  tenant_id: string;
  subject: string;
  display_name: string;
  key_prefix: string;
  status: "active" | "revoked";
  expires_at: string;
  created_at: string;
  last_used_at: string | null;
};
/** `GET /agent-api-keys`: metadata only; the server returns no scope, fingerprint or secret. */
export type ManagementApiKeyList = { request_id: string; keys: ManagementApiKeyRecord[] };
export type ManagementApiKeyResponse = {
  request_id: string;
  api_key_id: string;
  /** The plaintext, returned exactly once; callers must never store, log or display it twice. */
  api_key: string;
  key_prefix: string;
  expires_at: string;
  scopes: Array<{ tenant_id: string; site_id: string; capabilities: string[] }>;
};
export type ManagementApiKeyRevoked = {
  request_id: string;
  api_key_id: string;
  status: "revoked";
};

const keyPrefixPattern = /^xsk_[A-Za-z0-9]{4,32}$/;

function exactFields(row: Record<string, unknown>, keys: readonly string[]): void {
  ensure(Object.keys(row).length === keys.length && keys.every((key) => Object.hasOwn(row, key)));
}

function decodeManagementApiKeys(value: unknown, status: number): ManagementApiKeyList {
  ensure(status === 200);
  const row = object(value);
  exactFields(row, ["request_id", "keys"]);
  return {
    request_id: id(row.request_id, requestPattern),
    keys: list(row.keys, 1024, (item) => {
      const key = object(item);
      exactFields(key, [
        "api_key_id",
        "tenant_id",
        "subject",
        "display_name",
        "key_prefix",
        "status",
        "expires_at",
        "created_at",
        "last_used_at",
      ]);
      return {
        api_key_id: id(key.api_key_id, apiKeyIdPattern),
        tenant_id: name(key.tenant_id),
        subject: text(key.subject, 256),
        display_name: text(key.display_name),
        key_prefix: id(key.key_prefix, keyPrefixPattern),
        status: choice(key.status, ["active", "revoked"] as const),
        expires_at: timestamp(key.expires_at),
        created_at: timestamp(key.created_at),
        last_used_at: key.last_used_at === null ? null : timestamp(key.last_used_at),
      };
    }),
  };
}
function decodeManagementApiKey(value: unknown, status: number): ManagementApiKeyResponse {
  ensure(status === 201);
  const row = object(value);
  exactFields(row, ["request_id", "api_key_id", "api_key", "key_prefix", "expires_at", "scopes"]);
  const result = {
    request_id: id(row.request_id, requestPattern),
    api_key_id: id(row.api_key_id, apiKeyIdPattern),
    api_key: id(row.api_key, /^xsk_[A-Za-z0-9]{16,128}$/),
    key_prefix: id(row.key_prefix, keyPrefixPattern),
    expires_at: timestamp(row.expires_at),
    scopes: list(row.scopes, 32, (item) => {
      const scope = object(item);
      exactFields(scope, ["tenant_id", "site_id", "capabilities"]);
      return {
        tenant_id: name(scope.tenant_id),
        site_id: name(scope.site_id),
        capabilities: list(scope.capabilities, 16, (capability) => name(capability)),
      };
    }),
  };
  ensure(result.scopes.length > 0 && result.api_key.startsWith(result.key_prefix));
  return result;
}
function decodeManagementApiKeyRevoked(apiKeyId: string) {
  return (value: unknown, status: number): ManagementApiKeyRevoked => {
    ensure(status === 200);
    const row = object(value);
    exactFields(row, ["request_id", "api_key_id", "status"]);
    ensure(row.api_key_id === apiKeyId && row.status === "revoked");
    return {
      request_id: id(row.request_id, requestPattern),
      api_key_id: apiKeyId,
      status: "revoked",
    };
  };
}
export type SiteListResponse = Envelope & {
  sites: SiteListItem[];
  truncated: boolean;
  next_cursor: string | null;
};
export type SiteDeleteResponse = Envelope & { reason_code: string };
export type SiteApplyResponse = Envelope & {
  listen_port: number;
  desired_revision: number;
  active_revision: number | null;
  config_digest: string;
  apply_state: "active" | "pending" | "failed" | "paused";
  apply_id: string;
  reason_code: string;
  requires_approval: boolean;
  edge_health?: Record<string, unknown>;
};
export type SiteValidationResponse = Envelope & {
  revision: number;
  config_digest: string;
  valid: boolean;
  reason_code: string;
};
export type SiteRevision = {
  revision: number;
  policy_revision: string;
  config_digest: string;
  config: Record<string, unknown>;
  created_by: string;
  created_at: string;
};
export type SiteRevisionsResponse = Envelope & {
  revisions: SiteRevision[];
};

/**
 * Refuses a member the console does not model. The console saves by sending its whole draft, so
 * a member it skipped while decoding would silently disappear (or reset to a default) with the
 * next save; failing the read instead keeps an editor from ever writing such a loss back.
 */
function knownFields(row: Record<string, unknown>, keys: readonly string[]): void {
  ensure(Object.keys(row).every((key) => keys.includes(key)));
}

const routeKeys: readonly string[] = [
  "operation_id",
  "method",
  "path",
  "security_entry",
  "source_action",
  "resource_type",
  "view_profile",
  "resource_query_parameter",
  "resource_path_parameter",
  "request_crypto",
  "response_crypto",
  "response_mode",
  "max_response_bytes",
  ...routeFlowKeys,
];

const pointer = (value: unknown) => {
  const result = text(value, 512);
  ensure(result.startsWith("/"));
  return result;
};
const status = (value: unknown) => integer(value, 100, 599);
const lease = (value: unknown) => integer(value, 0, 86_400);

function decodeAuthBinding(value: unknown): SiteAuthBinding {
  const row = object(value);
  exactFields(row, [
    "success_status",
    "principal_pointer",
    "authorization_context_pointer",
    "bearer_pointer",
    "credential_ttl_seconds",
    "session_ttl_seconds",
  ]);
  return {
    success_status: status(row.success_status),
    principal_pointer: pointer(row.principal_pointer),
    authorization_context_pointer: pointer(row.authorization_context_pointer),
    bearer_pointer: pointer(row.bearer_pointer),
    credential_ttl_seconds: lease(row.credential_ttl_seconds),
    session_ttl_seconds: lease(row.session_ttl_seconds),
  };
}

function decodeAuthRevoke(value: unknown): SiteAuthRevoke {
  const row = object(value);
  exactFields(row, ["success_status"]);
  return { success_status: status(row.success_status) };
}

function decodeSensorAdapter(row: Record<string, unknown>): SiteSensorHtmlAdapter {
  return {
    adapter_revision: name(row.adapter_revision),
    origin_sha256: id(row.origin_sha256, /^[0-9a-f]{64}$/),
    injection_offset: integer(row.injection_offset, 0, 16_777_216),
  };
}

function decodeSensorHtml(value: unknown): SiteSensorHtml {
  const row = object(value);
  knownFields(row, [
    "adapter_revision",
    "origin_sha256",
    "injection_offset",
    "additional_adapters",
  ]);
  const primary = decodeSensorAdapter(row);
  if (row.additional_adapters === undefined) return primary;
  // The server omits an empty list; an empty list here would not round-trip.
  const additional = list(row.additional_adapters, 15, (item) => {
    const adapter = object(item);
    exactFields(adapter, ["adapter_revision", "origin_sha256", "injection_offset"]);
    return decodeSensorAdapter(adapter);
  });
  ensure(additional.length > 0);
  return { ...primary, additional_adapters: additional };
}

function decodePageActions(value: unknown): SitePageActions {
  const row = object(value);
  exactFields(row, ["mapping_revision", "max_active_pages"]);
  return {
    mapping_revision: name(row.mapping_revision),
    max_active_pages: integer(row.max_active_pages, 1, 1_000),
  };
}

function decodeIssuedBy(value: unknown): SiteIssuedBy {
  const row = object(value);
  exactFields(row, ["page_operation_id", "ttl_seconds"]);
  return { page_operation_id: name(row.page_operation_id), ttl_seconds: lease(row.ttl_seconds) };
}

function decodeResourceGrant(value: unknown): SiteResourceGrant {
  const row = object(value);
  exactFields(row, [
    "success_status",
    "items_pointer",
    "resource_pointer",
    "action_ref_field",
    "target_operation_id",
    "target_mapping_revision",
    "ttl_seconds",
    "max_items",
    "max_active_grants",
  ]);
  return {
    success_status: status(row.success_status),
    items_pointer: pointer(row.items_pointer),
    resource_pointer: pointer(row.resource_pointer),
    action_ref_field: name(row.action_ref_field),
    target_operation_id: name(row.target_operation_id),
    target_mapping_revision: name(row.target_mapping_revision),
    ttl_seconds: lease(row.ttl_seconds),
    max_items: integer(row.max_items, 1, 1_000),
    max_active_grants: integer(row.max_active_grants, 1, 5_000),
  };
}

function decodeAuthTransition(value: unknown): SiteAuthTransition {
  const row = object(value);
  exactFields(row, [
    "success_status",
    "principal_pointer",
    "authorization_context_pointer",
    "bearer_pointer",
    "credential_ttl_seconds",
  ]);
  return {
    success_status: status(row.success_status),
    principal_pointer: pointer(row.principal_pointer),
    authorization_context_pointer: pointer(row.authorization_context_pointer),
    bearer_pointer: pointer(row.bearer_pointer),
    credential_ttl_seconds: lease(row.credential_ttl_seconds),
  };
}

function decodeShareIssue(value: unknown): SiteShareIssue {
  const row = object(value);
  exactFields(row, [
    "success_status",
    "token_field",
    "target_operation_id",
    "issuance_rule_id",
    "ttl_seconds",
    "max_active_shares",
  ]);
  return {
    success_status: status(row.success_status),
    token_field: name(row.token_field),
    target_operation_id: name(row.target_operation_id),
    issuance_rule_id: name(row.issuance_rule_id),
    ttl_seconds: lease(row.ttl_seconds),
    max_active_shares: integer(row.max_active_shares, 1, 5_000),
  };
}

function decodeQueryPagination(value: unknown): SiteQueryPagination {
  const row = object(value);
  exactFields(row, ["parameters"]);
  return {
    parameters: list(row.parameters, 4, (item) => {
      const parameter = object(item);
      knownFields(parameter, ["name", "kind", "max_value"]);
      ensure(parameter.name !== undefined && parameter.kind !== undefined);
      const kind = (["page", "page_size", "offset"] as const).find(
        (candidate) => candidate === text(parameter.kind, 16),
      );
      ensure(kind !== undefined);
      return {
        name: text(parameter.name, 64),
        kind,
        // The server omits an unset bound, so an absent key must stay absent to round-trip.
        ...(parameter.max_value === undefined
          ? {}
          : { max_value: integer(parameter.max_value, 0, 1_000_000) }),
      };
    }),
  };
}

/** The flow blocks a stored route carries, in the server's order and only when present. */
function decodeRouteFlow(route: Record<string, unknown>): Partial<SiteRouteConfig> {
  return {
    ...(route.auth_binding === undefined
      ? {}
      : { auth_binding: decodeAuthBinding(route.auth_binding) }),
    ...(route.auth_revoke === undefined
      ? {}
      : { auth_revoke: decodeAuthRevoke(route.auth_revoke) }),
    ...(route.sensor_html === undefined
      ? {}
      : { sensor_html: decodeSensorHtml(route.sensor_html) }),
    ...(route.page_actions === undefined
      ? {}
      : { page_actions: decodePageActions(route.page_actions) }),
    ...(route.issued_by === undefined ? {} : { issued_by: decodeIssuedBy(route.issued_by) }),
    ...(route.resource_grant === undefined
      ? {}
      : { resource_grant: decodeResourceGrant(route.resource_grant) }),
    ...(route.query_pagination === undefined
      ? {}
      : { query_pagination: decodeQueryPagination(route.query_pagination) }),
    ...(route.share_issue === undefined
      ? {}
      : { share_issue: decodeShareIssue(route.share_issue) }),
    ...(route.auth_refresh === undefined
      ? {}
      : { auth_refresh: decodeAuthTransition(route.auth_refresh) }),
    ...(route.auth_context_switch === undefined
      ? {}
      : { auth_context_switch: decodeAuthTransition(route.auth_context_switch) }),
  };
}

function decodeSitePolicy(value: unknown): SitePolicyConfig {
  const defaults: SitePolicyConfig = {
    routes: [],
    identity: {
      enabled: false,
      cookie_name: "__Host-xshield_sid",
      credential_header: "Authorization",
      profile: "default",
      session_ttl_seconds: 3600,
      generation: 1,
    },
    crypto: {
      adapter_revision: "observe-v1",
      failure_strategy: "fail_closed",
      protocol_version: null,
    },
    waf: {
      enabled: true,
      blocked_headers: [],
      blocked_query_fragments: [],
      max_cookie_bytes: 8192,
    },
    limits: {
      max_request_body_bytes: 1_048_576,
      max_response_body_bytes: 16_777_216,
      requests_per_second: 1000,
      burst: 2000,
    },
    health_check: { path: "/health", interval_seconds: 15, timeout_ms: 2000, expected_status: 200 },
    secret_refs: [],
    // Core's default: the identity-less static fallback is off unless a site opts in.
    static_asset_max_path_depth: 0,
    origin_object_access_enforced: false,
  };
  if (value === undefined) return defaults;
  const row = object(value);
  knownFields(row, Object.keys(defaults));
  const optionalObject = (item: unknown): Record<string, unknown> | null =>
    item === null || item === undefined ? null : object(item);
  const identity = row.identity === undefined ? defaults.identity : object(row.identity);
  const crypto = row.crypto === undefined ? defaults.crypto : object(row.crypto);
  const waf = row.waf === undefined ? defaults.waf : object(row.waf);
  const limits = row.limits === undefined ? defaults.limits : object(row.limits);
  const health = row.health_check === undefined ? defaults.health_check : object(row.health_check);
  return {
    routes: list(row.routes ?? [], 256, (item): SiteRouteConfig => {
      const route = object(item);
      knownFields(route, routeKeys);
      return {
        operation_id: name(route.operation_id),
        method: choice(route.method, [
          "GET",
          "POST",
          "PUT",
          "PATCH",
          "DELETE",
        ]) as SiteRouteConfig["method"],
        path: text(route.path, 256),
        security_entry: choice(route.security_entry, [
          "public",
          "auth_entry",
          "authenticated_root",
          "ui_action_required",
          "share_entry",
        ]),
        source_action: route.source_action === null ? null : name(route.source_action),
        resource_type: route.resource_type === null ? null : name(route.resource_type),
        view_profile: route.view_profile === null ? null : name(route.view_profile),
        resource_query_parameter:
          route.resource_query_parameter === null ? null : name(route.resource_query_parameter),
        resource_path_parameter:
          route.resource_path_parameter === null ? null : name(route.resource_path_parameter),
        request_crypto: optionalObject(route.request_crypto),
        response_crypto: optionalObject(route.response_crypto),
        response_mode: choice(route.response_mode ?? "", [
          "",
          "BUFFERED_JSON",
          "SENSOR_HTML",
        ]) as SiteRouteConfig["response_mode"],
        max_response_bytes: integer(route.max_response_bytes ?? 1_048_576, 1, 16_777_216),
        ...decodeRouteFlow(route),
      };
    }),
    identity: {
      enabled: bool(identity.enabled),
      cookie_name: text(identity.cookie_name, 128),
      credential_header: text(identity.credential_header, 128),
      profile: text(identity.profile, 128),
      session_ttl_seconds: integer(identity.session_ttl_seconds, 1, 86_400),
      generation: integer(identity.generation, 1),
    },
    crypto: {
      adapter_revision: text(crypto.adapter_revision, 128),
      failure_strategy: text(crypto.failure_strategy, 64),
      protocol_version: crypto.protocol_version === null ? null : name(crypto.protocol_version),
    },
    waf: {
      enabled: bool(waf.enabled),
      blocked_headers: list(waf.blocked_headers ?? [], 64, (item) => text(item, 128)),
      blocked_query_fragments: list(waf.blocked_query_fragments ?? [], 32, (item) => {
        const fragment = text(item, 128);
        ensure(fragment.length >= 3 && /^[\x20-\x7e]+$/.test(fragment));
        return fragment;
      }),
      max_cookie_bytes: integer(waf.max_cookie_bytes, 1, 1_048_576),
    },
    limits: {
      max_request_body_bytes: integer(limits.max_request_body_bytes, 1, 16_777_216),
      max_response_body_bytes: integer(limits.max_response_body_bytes, 1, 16_777_216),
      requests_per_second: integer(limits.requests_per_second, 1, 1_000_000),
      burst: integer(limits.burst, 1, 2_000_000),
    },
    health_check: {
      path: text(health.path, 256),
      interval_seconds: integer(health.interval_seconds, 1, 3600),
      timeout_ms: integer(health.timeout_ms, 100, 30_000),
      expected_status: integer(health.expected_status, 100, 599),
    },
    secret_refs: list(row.secret_refs ?? [], 32, (item) => {
      const secret = object(item);
      return {
        kind: choice(secret.kind, [
          "tls",
          "session_hmac",
          "request_crypto",
          "response_crypto",
          "model",
        ]),
        secret_ref: text(secret.secret_ref, 512),
        key_id: name(secret.key_id),
        state: choice(secret.state, ["active", "pending_rotation", "retired", "unavailable"]),
      };
    }),
    // The server always sends both; a missing field means the server's default. Dropping them
    // here would silently reset them to the defaults on every save.
    static_asset_max_path_depth:
      row.static_asset_max_path_depth === undefined
        ? defaults.static_asset_max_path_depth
        : integer(row.static_asset_max_path_depth, 0, 16),
    origin_object_access_enforced:
      row.origin_object_access_enforced === undefined
        ? defaults.origin_object_access_enforced
        : bool(row.origin_object_access_enforced),
  };
}

function decodeSiteConfig(value: unknown, status: number): SiteConfigResponse {
  ensure(status === 200 || status === 201);
  const row = object(value);
  const found = bool(row.found);
  if (!found)
    return {
      ...envelope(row),
      found: false,
      desired_revision: null,
      active_revision: null,
      apply_state: null,
      apply_id: null,
      reason_code: null,
      config_digest: null,
      config: null,
      requires_approval:
        row.requires_approval === undefined || row.requires_approval === null
          ? null
          : bool(row.requires_approval),
      edge_health: row.edge_health === undefined ? undefined : object(row.edge_health),
    };
  ensure(row.config !== null);
  const config = object(row.config);
  return {
    ...envelope(row),
    found,
    desired_revision: integer(row.desired_revision, 1),
    active_revision: row.active_revision === null ? null : integer(row.active_revision, 1),
    apply_state: choice(row.apply_state, [
      "active",
      "pending",
      "failed",
      "paused",
    ]) as SiteConfigResponse["apply_state"],
    apply_id: name(row.apply_id),
    reason_code: name(row.reason_code),
    requires_approval: bool(row.requires_approval),
    config_digest: text(row.config_digest, 64),
    edge_health: row.edge_health === undefined ? undefined : object(row.edge_health),
    config: {
      display_name: text(config.display_name, 128),
      public_origin: text(config.public_origin, 512),
      upstream_address: text(config.upstream_address, 128),
      upstream_server_name: text(config.upstream_server_name, 253),
      upstream_tls: bool(config.upstream_tls),
      listen_port: integer(config.listen_port, 6100, 65535),
      entry_path: text(config.entry_path, 256),
      security_entry: choice(config.security_entry, [
        "public",
        "authenticated_root",
        "ui_action_required",
      ]),
      sensor_enabled: bool(config.sensor_enabled),
      policy_revision: name(config.policy_revision),
      status: choice(config.status, ["draft", "active", "paused"]),
      policy: decodeSitePolicy(config.policy),
      revision: integer(config.revision, 1),
      config_digest: text(config.config_digest, 64),
      updated_by: text(config.updated_by, 256),
      created_at: timestamp(config.created_at),
      updated_at: timestamp(config.updated_at),
      gateway_config: config.gateway_config === null ? null : object(config.gateway_config),
    },
  };
}

function decodeSiteList(value: unknown, status: number): SiteListResponse {
  ensure(status === 200);
  const row = object(value);
  return {
    ...envelope(row),
    truncated: row.truncated === undefined ? false : bool(row.truncated),
    next_cursor:
      row.next_cursor === undefined || row.next_cursor === null ? null : name(row.next_cursor),
    sites: list(row.sites, 128, (item) => {
      const site = object(item);
      return {
        site_id: name(site.site_id),
        display_name: text(site.display_name, 128),
        public_origin: text(site.public_origin, 512),
        listen_port: integer(site.listen_port, 6100, 65535),
        security_entry: choice(site.security_entry, [
          "public",
          "authenticated_root",
          "ui_action_required",
        ]),
        sensor_enabled: bool(site.sensor_enabled),
        policy_revision: name(site.policy_revision),
        status: choice(site.status, ["draft", "active", "paused"]),
        revision: integer(site.revision, 1),
        config_digest: text(site.config_digest, 64),
        updated_by: text(site.updated_by, 256),
        updated_at: timestamp(site.updated_at),
        desired_revision: integer(site.desired_revision, 1),
        active_revision: site.active_revision === null ? null : integer(site.active_revision, 1),
        apply_id: name(site.apply_id),
        apply_state: choice(site.apply_state, [
          "active",
          "pending",
          "failed",
          "paused",
        ]) as SiteListItem["apply_state"],
        reason_code: name(site.reason_code),
        requires_approval: bool(site.requires_approval),
      };
    }),
  };
}

function decodeSiteDelete(value: unknown, status: number): SiteDeleteResponse {
  ensure(status === 200 || status === 404);
  const row = object(value);
  return { ...envelope(row), reason_code: name(row.reason_code) };
}

function decodeSiteApply(value: unknown, status: number): SiteApplyResponse {
  ensure(status === 200);
  const row = object(value);
  return {
    ...envelope(row),
    listen_port: integer(row.listen_port, 6100, 65535),
    desired_revision: integer(row.desired_revision, 1),
    active_revision: row.active_revision === null ? null : integer(row.active_revision, 1),
    config_digest: text(row.config_digest, 64),
    apply_state: choice(row.apply_state, [
      "active",
      "pending",
      "failed",
      "paused",
    ]) as SiteApplyResponse["apply_state"],
    apply_id: name(row.apply_id),
    reason_code: name(row.reason_code),
    requires_approval: bool(row.requires_approval),
    edge_health: row.edge_health === undefined ? undefined : object(row.edge_health),
  };
}

function decodeSiteValidation(value: unknown, status: number): SiteValidationResponse {
  ensure(status === 200 || status === 422);
  const row = object(value);
  return {
    ...envelope(row),
    revision: integer(row.revision, 1),
    config_digest: text(row.config_digest, 64),
    valid: bool(row.valid),
    reason_code: name(row.reason_code),
  };
}

function decodeSiteRevisions(value: unknown, status: number): SiteRevisionsResponse {
  ensure(status === 200);
  const row = object(value);
  return {
    ...envelope(row),
    revisions: list(row.revisions, 128, (item) => {
      const revision = object(item);
      return {
        revision: integer(revision.revision, 1),
        policy_revision: name(revision.policy_revision),
        config_digest: text(revision.config_digest, 64),
        config: object(revision.config),
        created_by: text(revision.created_by, 256),
        created_at: timestamp(revision.created_at),
      };
    }),
  };
}

/** Authenticates the HttpOnly browser cookie and returns only its CSRF companion. */
export async function bootstrapBrowserSession(signal?: AbortSignal): Promise<BrowserSession> {
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort(), 15_000);
  const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
  let status = 0;
  try {
    const response = await fetch("/control/v1/session", {
      method: "GET",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: combined,
    });
    status = response.status;
    const value = await readJson(response, combined);
    if (!response.ok) {
      const row = object(value);
      const requestId =
        typeof row.request_id === "string" && requestPattern.test(row.request_id)
          ? row.request_id
          : null;
      const code =
        typeof row.error_code === "string" &&
        Object.hasOwn(messages, row.error_code) &&
        row.error_code.startsWith("CONTROL_")
          ? (row.error_code as ErrorCode)
          : "HTTP_ERROR";
      throw new ApiError(code, status, requestId);
    }
    const row = object(value);
    ensure(
      Object.keys(row).sort().join(",") ===
        "csrf_token,idle_expires_at,last_reauthenticated_at,roles,session_expires_at,site_id,step_up_valid,subject,tenant_id",
    );
    const csrfToken = text(row.csrf_token, 64);
    ensure(/^[0-9a-f]{64}$/.test(csrfToken));
    return {
      subject: text(row.subject, 256),
      tenant_id: name(row.tenant_id),
      site_id: name(row.site_id),
      csrf_token: csrfToken,
      session_expires_at: timestamp(row.session_expires_at),
      idle_expires_at: timestamp(row.idle_expires_at),
      last_reauthenticated_at: nullable(row.last_reauthenticated_at, timestamp),
      step_up_valid: bool(row.step_up_valid),
      roles: list(row.roles, 10, (item) =>
        choice(item, [
          "observer",
          "investigator",
          "sensitive_evidence_reader",
          "sensitive_evidence_approver",
          "policy_author",
          "policy_approver",
          "release_operator",
          "audit_administrator",
          "key_administrator",
          "system_admin",
        ]),
      ),
    };
  } catch (error) {
    if (signal?.aborted) throw new ApiError("REQUEST_ABORTED", status);
    if (deadline.signal.aborted) throw new ApiError("REQUEST_TIMEOUT", status);
    if (error instanceof ApiError)
      throw new ApiError(error.code, status || error.status, error.requestId);
    throw new ApiError("NETWORK_UNAVAILABLE", status);
  } finally {
    clearTimeout(timer);
    deadline.abort();
  }
}

/** Fixed scoped endpoints. Bearers are machine/test-only; browsers use OIDC cookies. */
export class ControlClient {
  #authorization: string | null;
  #csrfToken: string | null;
  constructor(token?: string, csrfToken?: string) {
    if (token === undefined) {
      if (csrfToken !== undefined && !/^[0-9a-f]{64}$/.test(csrfToken))
        throw new ApiError("INVALID_CREDENTIAL");
      this.#authorization = null;
      this.#csrfToken = csrfToken ?? null;
      return;
    }
    if (
      typeof token !== "string" ||
      token.length > 512 ||
      /[\u0000-\u001f\u007f-\u009f]/.test(token)
    )
      throw new ApiError("INVALID_CREDENTIAL");
    const bytes = new TextEncoder().encode(token).byteLength;
    if (bytes < 32 || bytes > 512) throw new ApiError("INVALID_CREDENTIAL");
    this.#authorization = `Bearer ${token}`;
    this.#csrfToken = null;
    try {
      // Browser header serialization must preserve the exact server credential.
      if (
        new Headers({ Authorization: this.#authorization }).get("Authorization") !==
        this.#authorization
      )
        throw new ApiError("INVALID_CREDENTIAL");
    } catch {
      throw new ApiError("INVALID_CREDENTIAL");
    }
  }

  async #request<T>(
    path: string,
    decode: (value: unknown, status: number) => T,
    signal?: AbortSignal,
    body?: string,
    idempotencyKey?: string,
  ): Promise<T> {
    return this.#transport(
      path,
      async (response, combined) => decode(await readJson(response, combined), response.status),
      signal,
      body,
      idempotencyKey,
    );
  }

  async #transport<T>(
    path: string,
    consume: (response: Response, signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
    body?: string,
    idempotencyKey?: string,
    accessId?: string,
    methodOverride?: string,
    options?: { headers?: Record<string, string>; acceptStatuses?: readonly number[] },
  ): Promise<T> {
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), 15_000);
    const combined = signal ? AbortSignal.any([signal, deadline.signal]) : deadline.signal;
    let status = 0;
    try {
      combined.throwIfAborted();
      const response = await fetch(`/control/v1/${path}`, {
        method:
          methodOverride ??
          (body === undefined
            ? "GET"
            : path === "site-config" || path.endsWith("/config")
              ? "PUT"
              : "POST"),
        headers: {
          ...(this.#authorization === null ? {} : { Authorization: this.#authorization }),
          Accept: accessId === undefined ? "application/json" : "application/octet-stream",
          ...(accessId === undefined ? {} : { "X-Xshield-Evidence-Access-Request": accessId }),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(body === undefined || this.#csrfToken === null
            ? {}
            : { "X-Xshield-CSRF": this.#csrfToken }),
          ...(idempotencyKey === undefined ? {} : { "Idempotency-Key": idempotencyKey }),
          ...(options?.headers ?? {}),
        },
        ...(body === undefined ? {} : { body }),
        credentials: this.#authorization === null ? "same-origin" : "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: combined,
      });
      status = response.status;
      if (!response.ok && !options?.acceptStatuses?.includes(response.status)) {
        const value = await readJson(response, combined);
        const row = object(value);
        const requestId =
          typeof row.request_id === "string" && requestPattern.test(row.request_id)
            ? row.request_id
            : null;
        const code =
          typeof row.error_code === "string" &&
          Object.hasOwn(messages, row.error_code) &&
          (row.error_code.startsWith("CONTROL_") || row.error_code === "AUDIT_DURABILITY_FAILED")
            ? (row.error_code as ErrorCode)
            : "HTTP_ERROR";
        throw new ApiError(code, status, requestId);
      }
      return await consume(response, combined);
    } catch (error) {
      if (signal?.aborted) throw new ApiError("REQUEST_ABORTED", status);
      if (deadline.signal.aborted) throw new ApiError("REQUEST_TIMEOUT", status);
      if (error instanceof ApiError)
        throw new ApiError(error.code, status || error.status, error.requestId);
      throw new ApiError("NETWORK_UNAVAILABLE", status);
    } finally {
      clearTimeout(timer);
      deadline.abort();
    }
  }

  async logoutBrowserSession(signal?: AbortSignal): Promise<void> {
    ensure(this.#authorization === null && this.#csrfToken !== null);
    await this.#transport(
      "session/logout",
      async (response, combined) => {
        if (!response.ok) {
          const row = object(await readJson(response, combined));
          const requestId =
            typeof row.request_id === "string" && requestPattern.test(row.request_id)
              ? row.request_id
              : null;
          const code =
            typeof row.error_code === "string" &&
            Object.hasOwn(messages, row.error_code) &&
            row.error_code.startsWith("CONTROL_")
              ? (row.error_code as ErrorCode)
              : "HTTP_ERROR";
          throw new ApiError(code, response.status, requestId);
        }
        ensure(response.status === 204);
      },
      signal,
      "",
    );
  }

  async startReauthentication(signal?: AbortSignal): Promise<string> {
    ensure(this.#authorization === null && this.#csrfToken !== null);
    return this.#request(
      "auth/oidc/reauth/start",
      (value) => {
        const row = object(value);
        ensure(
          Object.keys(row).sort().join(",") ===
            "authorization_url,request_id,schema_version,site_id,tenant_id",
        );
        ensure(row.schema_version === 3);
        ensure(typeof row.request_id === "string" && requestPattern.test(row.request_id));
        name(row.tenant_id);
        name(row.site_id);
        const target = new URL(text(row.authorization_url, 4_096));
        ensure(
          (target.protocol === "https:" ||
            (target.protocol === "http:" &&
              ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname))) &&
            target.username === "" &&
            target.password === "",
        );
        return target.href;
      },
      signal,
      "",
    );
  }

  async summary(requestId: string, signal?: AbortSignal): Promise<SummaryResponse> {
    this.#requestId(requestId);
    return this.#request(
      `requests/${requestId}`,
      (value) => {
        const row = object(value);
        const base = envelope(row);
        ensure(row.source_request_id === requestId);
        const result: SummaryResponse = {
          ...base,
          ...watermarked(row),
          source_request_id: requestId,
          pending_segments: integer(row.pending_segments),
          found: bool(row.found),
          completeness: choice(row.completeness, [
            "complete",
            "pending",
            "pending_index",
            "not_found",
          ]),
          summary: nullable(row.summary, summary),
        };
        ensure(result.found === (result.summary !== null));
        const expected = result.summary
          ? result.summary.terminal
            ? "complete"
            : "pending"
          : result.pending_segments > 0 || result.has_gaps
            ? "pending_index"
            : "not_found";
        ensure(result.completeness === expected);
        return result;
      },
      signal,
    );
  }

  async events(requestId: string, cursor?: string, signal?: AbortSignal): Promise<EventsResponse> {
    this.#requestId(requestId);
    return this.#request(
      `requests/${requestId}/events${this.#cursor(cursor)}`,
      (value) => {
        const row = object(value);
        ensure(row.source_request_id === requestId);
        const result = {
          ...envelope(row),
          ...watermarked(row),
          ...pagination(row),
          source_request_id: requestId,
          events: list(row.events, 1000, auditEvent),
        };
        ensure(!result.truncated || result.events.length > 0);
        ensure(new Set(result.events.map((item) => item.event_id)).size === result.events.length);
        for (let index = 1; index < result.events.length; index++) {
          const previous = result.events[index - 1]!;
          const current = result.events[index]!;
          ensure(
            current.request_seq > previous.request_seq ||
              (current.request_seq === previous.request_seq &&
                current.event_id > previous.event_id),
          );
        }
        return result;
      },
      signal,
    );
  }

  async evidence(
    requestId: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<EvidenceResponse> {
    this.#requestId(requestId);
    return this.#request(
      `requests/${requestId}/evidence${this.#cursor(cursor)}`,
      (value) => {
        const row = object(value);
        const base = envelope(row);
        ensure(row.source_request_id === requestId);
        const result = {
          ...base,
          ...pagination(row),
          source_request_id: requestId,
          artifacts: list(row.artifacts, 128, (item) => manifest(item, base, requestId)),
        };
        ensure(!result.truncated || result.artifacts.length > 0);
        for (let index = 1; index < result.artifacts.length; index++)
          ensure(result.artifacts[index]!.artifact_id > result.artifacts[index - 1]!.artifact_id);
        return result;
      },
      signal,
    );
  }

  async artifact(artifactId: string, signal?: AbortSignal): Promise<ArtifactResponse> {
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    return this.#request(
      `artifacts/${artifactId}`,
      (value) => {
        const row = object(value);
        const base = envelope(row);
        ensure(row.source_artifact_id === artifactId);
        const result = {
          ...base,
          source_artifact_id: artifactId,
          found: bool(row.found),
          artifact: nullable(row.artifact, (item) => manifest(item, base, undefined, artifactId)),
        };
        ensure(result.found === (result.artifact !== null));
        return result;
      },
      signal,
    );
  }

  /** Read scoped lifecycle metadata; the server audits the lookup. Invalid IDs,
   * contradictory history and bounded transport failures become safe ApiError values.
   * Evidence bodies remain behind their separately authorized content endpoint. */
  async modelCall(modelCallId: string, signal?: AbortSignal): Promise<ModelCallResponse> {
    if (typeof modelCallId !== "string" || !modelCallPattern.test(modelCallId))
      throw new ApiError("CONTROL_MODEL_CALL_ID_INVALID");
    return this.#request(
      `model-calls/${modelCallId}`,
      (value) => {
        const row = object(value);
        ensure(row.source_model_call_id === modelCallId);
        const result: ModelCallResponse = {
          ...envelope(row),
          ...watermarked(row),
          source_model_call_id: modelCallId,
          watermark_scope: choice(row.watermark_scope, ["configured_journal"]),
          pending_segments: integer(row.pending_segments),
          found: bool(row.found),
          completeness: choice(row.completeness, ["complete", "pending", "partial", "not_indexed"]),
          model_call: nullable(row.model_call, (item) => modelCall(item, modelCallId)),
        };
        ensure(result.found === (result.model_call !== null));
        const expected =
          result.model_call === null
            ? "not_indexed"
            : result.model_call.lifecycle_complete
              ? "complete"
              : ["started", "requested"].includes(result.model_call.status)
                ? "pending"
                : "partial";
        ensure(result.completeness === expected);
        return result;
      },
      signal,
    );
  }

  /** Read one AuditAdministrator-scoped calibration-report projection. The
   * encrypted body is never requested by this route, and active retention is
   * not a content-read authorization or a policy/publication decision. */
  async calibrationReport(
    reportId: string,
    signal?: AbortSignal,
  ): Promise<CalibrationReportResponse> {
    if (typeof reportId !== "string" || !calibrationReportPattern.test(reportId))
      throw new ApiError("CONTROL_CALIBRATION_REPORT_ID_INVALID");
    return this.#request(
      `calibration-reports/${reportId}`,
      (value) => {
        const row = object(value);
        ensure(
          row.schema_version === 3 &&
            Object.keys(row).length === 8 &&
            [
              "schema_version",
              "request_id",
              "tenant_id",
              "site_id",
              "source_report_id",
              "found",
              "as_of",
              "report",
            ].every((key) => Object.hasOwn(row, key)),
        );
        const result: CalibrationReportResponse = {
          ...envelope(row),
          schema_version: 3,
          source_report_id: id(row.source_report_id, calibrationReportPattern),
          found: bool(row.found),
          as_of: nullable(row.as_of, timestamp),
          report: nullable(row.report, (value) => {
            const details = object(value);
            ensure(
              Object.keys(details).length === 23 &&
                [
                  "report_id",
                  "report_artifact_id",
                  "completed_at",
                  "reported_at",
                  "reported_event_id",
                  "body_expires_at",
                  "approval_ref",
                  "dataset_revision",
                  "label_revision",
                  "task_revision",
                  "threshold_policy_revision",
                  "mapping_revision",
                  "evaluation_manifest_artifact_id",
                  "training_manifest_artifact_id",
                  "calibration_manifest_artifact_id",
                  "label_manifest_artifact_id",
                  "provider",
                  "provider_model_id",
                  "model_revision",
                  "prompt_revision",
                  "resolved_model_revision",
                  "lineage_review_id",
                  "body_status",
                ].every((key) => Object.hasOwn(details, key)),
            );
            const report: CalibrationReport = {
              report_id: id(details.report_id, calibrationReportPattern),
              report_artifact_id: id(details.report_artifact_id, artifactPattern),
              completed_at: timestamp(details.completed_at),
              reported_at: timestamp(details.reported_at),
              reported_event_id: id(details.reported_event_id, eventPattern),
              body_expires_at: timestamp(details.body_expires_at),
              approval_ref: name(details.approval_ref),
              dataset_revision: name(details.dataset_revision),
              label_revision: name(details.label_revision),
              task_revision: name(details.task_revision),
              threshold_policy_revision: name(details.threshold_policy_revision),
              mapping_revision: name(details.mapping_revision),
              evaluation_manifest_artifact_id: id(
                details.evaluation_manifest_artifact_id,
                artifactPattern,
              ),
              training_manifest_artifact_id: id(
                details.training_manifest_artifact_id,
                artifactPattern,
              ),
              calibration_manifest_artifact_id: id(
                details.calibration_manifest_artifact_id,
                artifactPattern,
              ),
              label_manifest_artifact_id: id(details.label_manifest_artifact_id, artifactPattern),
              provider: name(details.provider),
              provider_model_id: text(details.provider_model_id),
              model_revision: name(details.model_revision),
              prompt_revision: name(details.prompt_revision),
              resolved_model_revision: nullable(details.resolved_model_revision, name),
              lineage_review_id: nullable(details.lineage_review_id, (item) =>
                id(item, new RegExp(`^calrev_${uuid}$`)),
              ),
              body_status: choice(details.body_status, ["active", "deleted"]),
            };
            ensure(
              Date.parse(report.completed_at) <= Date.parse(report.reported_at) &&
                Date.parse(report.reported_at) < Date.parse(report.body_expires_at),
            );
            return report;
          }),
        };
        ensure(result.source_report_id === reportId);
        ensure(result.found === (result.report !== null));
        ensure((result.as_of !== null) === result.found);
        ensure(!result.report || result.report.report_id === reportId);
        return result;
      },
      signal,
    );
  }

  /** Read the separately audited, redacted lifecycle for one Agent run. */
  async agentRun(agentRunId: string, signal?: AbortSignal): Promise<AgentRunResponse> {
    if (typeof agentRunId !== "string" || !agentRunPattern.test(agentRunId))
      throw new ApiError("CONTROL_AGENT_RUN_ID_INVALID");
    return this.#request(
      `agent-runs/${agentRunId}`,
      (value) => {
        const row = object(value);
        ensure(
          Object.keys(row).length === 12 &&
            [
              "request_id",
              "tenant_id",
              "site_id",
              "source_agent_run_id",
              "watermark_scope",
              "as_of",
              "index_watermark",
              "has_gaps",
              "pending_segments",
              "found",
              "completeness",
              "agent_run",
            ].every((key) => Object.hasOwn(row, key)),
        );
        const result: AgentRunResponse = {
          ...envelope(row),
          ...watermarked(row),
          source_agent_run_id: id(row.source_agent_run_id, agentRunPattern),
          watermark_scope: choice(row.watermark_scope, ["configured_journal"]),
          pending_segments: integer(row.pending_segments),
          found: bool(row.found),
          completeness: choice(row.completeness, ["complete", "partial", "not_indexed"]),
          agent_run: nullable(row.agent_run, (item) => agentRun(item, agentRunId)),
        };
        ensure(result.source_agent_run_id === agentRunId);
        ensure(result.found === (result.agent_run !== null));
        const expected =
          result.agent_run === null
            ? "not_indexed"
            : result.agent_run.lifecycle_complete
              ? "complete"
              : "partial";
        ensure(result.completeness === expected);
        return result;
      },
      signal,
    );
  }

  /** Discover redacted model-call metadata inside a fixed UTC window. The
   * cursor remains opaque: every continued page is still scope- and
   * server-authorized, while opening a row uses the separate detail endpoint.
   */
  async modelCalls(
    value: unknown,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<ModelCallListResponse> {
    const plan = validateModelCallListPlan(value);
    if (cursor !== undefined && (typeof cursor !== "string" || !cursorPattern.test(cursor)))
      throw new ApiError("CONTROL_CURSOR_INVALID");
    const parameters = new URLSearchParams({
      start: plan.start,
      end: plan.end,
      limit: String(plan.limit),
    });
    if (cursor !== undefined) parameters.set("cursor", cursor);
    return this.#request(
      `model-calls?${parameters.toString()}`,
      (value) => {
        const row = object(value);
        ensure(
          row.schema_version === 3 &&
            Object.keys(row).length === 16 &&
            [
              "schema_version",
              "request_id",
              "tenant_id",
              "site_id",
              "start",
              "end",
              "watermark_scope",
              "as_of",
              "index_watermark",
              "has_gaps",
              "pending_segments",
              "scanned_rows",
              "scanned_bytes",
              "items",
              "truncated",
              "next_cursor",
            ].every((key) => Object.hasOwn(row, key)),
        );
        const result: ModelCallListResponse = {
          ...envelope(row),
          ...watermarked(row),
          ...pagination(row),
          schema_version: 3,
          start: modelCallListTime(row.start),
          end: modelCallListTime(row.end),
          watermark_scope: choice(row.watermark_scope, ["configured_journal"]),
          pending_segments: integer(row.pending_segments),
          scanned_rows: nullable(row.scanned_rows, integer),
          scanned_bytes: nullable(row.scanned_bytes, integer),
          items: list(row.items, plan.limit, modelCallListItem),
        };
        ensure(result.start === plan.start && result.end === plan.end);
        ensure(!result.truncated || result.items.length === plan.limit);
        const start = BigInt(Date.parse(plan.start)) * 1000n;
        const end = BigInt(Date.parse(plan.end)) * 1000n;
        const seen = new Set<string>();
        let previous: ModelCallListPosition | null = null;
        for (const item of result.items) {
          const current = modelCallListPosition(item);
          ensure(current.time >= start && current.time < end);
          ensure(!seen.has(current.modelCallId));
          if (previous)
            ensure(
              current.time < previous.time ||
                (current.time === previous.time && current.modelCallId < previous.modelCallId),
            );
          seen.add(current.modelCallId);
          previous = current;
        }
        ensure(result.next_cursor === null || result.next_cursor !== cursor);
        return result;
      },
      signal,
    );
  }

  /** Read the configured journal-to-index publication snapshot. Every call is
   * separately authorized and audited by the server; this client never polls. */
  async health(signal?: AbortSignal): Promise<AuditHealthResponse> {
    return this.#request(
      "audit/health",
      (value) => {
        const row = object(value);
        ensure(
          Object.keys(row).length === 14 &&
            [
              "request_id",
              "tenant_id",
              "site_id",
              "target_id",
              "table",
              "as_of",
              "metadata_retention_days",
              "closed_segments",
              "closed_segment_bytes",
              "published_segments",
              "pending_segments",
              "unsealed_segments",
              "has_gaps",
              "index_watermark",
            ].every((key) => Object.hasOwn(row, key)),
        );
        const result: AuditHealthResponse = {
          ...envelope(row),
          ...watermarked(row),
          target_id: name(row.target_id),
          table: name(row.table),
          metadata_retention_days: integer(row.metadata_retention_days, 1, 3_650),
          closed_segments: integer(row.closed_segments),
          closed_segment_bytes: integer(row.closed_segment_bytes),
          published_segments: integer(row.published_segments),
          pending_segments: integer(row.pending_segments),
          unsealed_segments: integer(row.unsealed_segments),
        };
        ensure(
          BigInt(result.published_segments) + BigInt(result.pending_segments) ===
            BigInt(result.closed_segments),
        );
        ensure(result.unsealed_segments <= result.pending_segments);
        return result;
      },
      signal,
    );
  }

  /** Read the server-projected operating snapshot once; callers own refresh cadence. */
  async workbenchOverview(signal?: AbortSignal): Promise<WorkbenchOverviewResponse> {
    return this.#request("workbench/overview", decodeWorkbenchOverview, signal);
  }

  /** Read an Observer grant snapshot; online eligibility is checked separately.
   * Rejects malformed IDs before transport, retains the server's audit boundary,
   * and applies the shared timeout, byte cap and safe error contract.
   */
  async grant(grantId: string, signal?: AbortSignal): Promise<GrantResponse> {
    if (typeof grantId !== "string" || !grantPattern.test(grantId))
      throw new ApiError("CONTROL_GRANT_ID_INVALID");
    return this.#request(
      `grants/${grantId}`,
      (value) => decodeGrantResponse(value, grantId),
      signal,
    );
  }

  /** Read an Observer identity-ledger snapshot, without reading credentials.
   * Server authorization and audit remain mandatory; malformed observations
   * and bounded transport failures return safe ApiError values.
   */
  async binding(bindingId: string, signal?: AbortSignal): Promise<BindingResponse> {
    if (typeof bindingId !== "string" || !bindingPattern.test(bindingId))
      throw new ApiError("CONTROL_BINDING_ID_INVALID");
    return this.#request(
      `auth-bindings/${bindingId}`,
      (value) => decodeBindingResponse(value, bindingId),
      signal,
    );
  }

  /** Execute an Investigator read query with durable server-side access audit.
   * Copies the validated plan before asynchronous work, binds its response
   * digest and cursor position, and shares the bounded credential-safe transport.
   * Search permission never grants content or Observer access.
   */
  async search(plan: SearchPlan, cursor?: string, signal?: AbortSignal): Promise<SearchResponse> {
    const frozen = validateSearchPlan(plan);
    validateSearchCursor(cursor, frozen);
    if (signal?.aborted) throw new ApiError("REQUEST_ABORTED");
    const digest = await searchPlanDigest(frozen);
    const body = JSON.stringify({
      ...frozen,
      ...(cursor === undefined ? {} : { cursor }),
    });
    if (new TextEncoder().encode(body).byteLength > 8 * 1024)
      throw new ApiError("CONTROL_QUERY_INVALID");
    return this.#request(
      "search",
      (value) => decodeSearchResponse(value, frozen, digest, cursor),
      signal,
      body,
    );
  }

  /** Execute an Investigator-only bounded causality traversal.
   * The root, UTC window and graph limits are validated before transport; the
   * response remains a redacted event projection with no payload access.
   */
  async causality(plan: CausalityPlan, signal?: AbortSignal): Promise<CausalityResponse> {
    const frozen = validateCausalityPlan(plan);
    if (signal?.aborted) throw new ApiError("REQUEST_ABORTED");
    const body = JSON.stringify(frozen);
    if (new TextEncoder().encode(body).byteLength > 4 * 1024)
      throw new ApiError("CONTROL_CAUSALITY_REQUEST_INVALID");
    return this.#request(
      "causality",
      (value) => decodeCausalityResponse(value, frozen),
      signal,
      body,
    );
  }

  /** List only the authenticated owner's cases in descending identity order.
   * Each page is freshly authorized; the cursor cannot select a different scope.
   */
  async cases(cursor?: string, signal?: AbortSignal): Promise<CaseList> {
    validateCaseListCursor(cursor);
    return this.#request(
      `cases${this.#cursor(cursor)}`,
      (value, status) => {
        ensure(status === 200);
        return decodeCaseList(value, cursor);
      },
      signal,
    );
  }

  /** Create an owned investigation case; no automatic retries. Keep the original
   * key and purpose until a durable response resolves any uncertain outcome.
   */
  async createCase(purpose: string, key: string, signal?: AbortSignal): Promise<CaseCreated> {
    if (!validCaseText(purpose)) throw new ApiError("CONTROL_CASE_REQUEST_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      "cases",
      (value, status) => decodeCaseCreated(value, purpose, status),
      signal,
      JSON.stringify({ purpose }),
      key,
    );
  }

  /** Read one owned case page. This Investigator endpoint grants no Observer or content access. */
  async caseItems(caseId: string, cursor?: string, signal?: AbortSignal): Promise<CaseCollection> {
    validateCaseId(caseId);
    validateCaseCursor(cursor);
    return this.#request(
      `cases/${caseId}/items${this.#cursor(cursor)}`,
      (value, status) => {
        ensure(status === 200);
        return decodeCaseCollection(value, caseId, cursor);
      },
      signal,
    );
  }

  /** Associate an active evidence reference. The server rechecks owner, scope,
   * open state and capacity; callers retain the exact key and targets for retry.
   */
  async addCaseItem(
    caseId: string,
    artifactId: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<CaseItemAdded> {
    validateCaseId(caseId);
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `cases/${caseId}/items`,
      (value, status) => decodeCaseItemAdded(value, caseId, artifactId, status),
      signal,
      JSON.stringify({ artifact_id: artifactId }),
      key,
    );
  }

  /** Close an owned case with an explicit reason. An interrupted response is
   * not evidence of rollback; only replay with the same key and parameters.
   */
  async closeCase(
    caseId: string,
    reason: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<CaseClosed> {
    validateCaseId(caseId);
    if (!validCaseText(reason)) throw new ApiError("CONTROL_CASE_CLOSE_REQUEST_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `cases/${caseId}/close`,
      (value, status) => decodeCaseClosed(value, caseId, status),
      signal,
      JSON.stringify({ reason }),
      key,
    );
  }

  /** Start the bounded, metadata-only case inventory analysis. Keep the exact
   * key and case ID until the durable 202 response resolves any uncertainty. */
  async analyzeCase(caseId: string, key: string, signal?: AbortSignal): Promise<JobResponse> {
    validateCaseId(caseId);
    this.#idempotencyKey(key);
    return this.#request(
      `cases/${caseId}/analyze`,
      (value, status) => decodeJobResponse(value, status, caseId),
      signal,
      "",
      key,
    );
  }

  /** Read one owner-scoped durable job; a foreign or unknown job is opaque. */
  async job(jobId: string, signal?: AbortSignal): Promise<JobResponse> {
    validateJobId(jobId);
    return this.#request(
      `jobs/${jobId}`,
      (value, status) => decodeJobResponse(value, status),
      signal,
    );
  }

  /** Request a metadata-only package for an owned case. The package is not
   * created until an independent approver commits the decision. */
  async requestExport(
    caseId: string,
    purpose: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<InvestigationExport> {
    validateCaseId(caseId);
    if (!validCaseText(purpose)) throw new ApiError("CONTROL_EXPORT_INPUT_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      "exports",
      (value, status) => {
        const result = decodeExportResponse(value, undefined, caseId);
        ensure(status === (result.replayed ? 200 : 202));
        ensure(result.replayed || result.status === "pending_approval");
        ensure(result.purpose === purpose);
        return result;
      },
      signal,
      JSON.stringify({ case_id: caseId, purpose }),
      key,
    );
  }

  /** Read the requester's own export history or the independent review queue (29.33). Every
   * page is freshly authorized and audited, the cursor is bound to the view, and a listing
   * grants neither approval nor download capability. No automatic reads. */
  async exportList(
    view: ExportListView,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<ExportList> {
    validateExportListView(view);
    validateExportListCursor(cursor);
    const query = `?view=${view}${cursor === undefined ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
    return this.#request(
      `exports${query}`,
      (value, status) => {
        ensure(status === 200);
        return decodeExportList(value, view, cursor);
      },
      signal,
    );
  }

  /** Read one scope-bound export projection; no package bytes are requested. */
  async exportStatus(exportId: string, signal?: AbortSignal): Promise<InvestigationExport> {
    validateExportId(exportId);
    return this.#request(
      `exports/${exportId}`,
      (value, status) => {
        ensure(status === 200);
        return decodeExportResponse(value, exportId);
      },
      signal,
    );
  }

  /** Commit an independent approval or denial with the exact retry inputs. */
  async decideExport(
    exportId: string,
    decision: "approve" | "deny",
    reason: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<InvestigationExport> {
    validateExportId(exportId);
    if (!validCaseText(reason) || !["approve", "deny"].includes(decision))
      throw new ApiError("CONTROL_EXPORT_INPUT_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `exports/${exportId}/${decision}`,
      (value, status) => {
        const result = decodeExportResponse(value, exportId);
        ensure(status === 200);
        ensure(
          decision === "deny"
            ? result.status === "rejected"
            : result.status === "ready" || (result.replayed && result.status === "approved"),
        );
        ensure(result.decision_reason === reason);
        return result;
      },
      signal,
      JSON.stringify({ reason }),
      key,
    );
  }

  /** Download the bounded metadata package after fresh server authorization. */
  async downloadExport(
    exportId: string,
    expectedArtifactId: string,
    expectedBytes: number,
    signal?: AbortSignal,
  ): Promise<ExportDownload> {
    validateExportId(exportId);
    ensure(id(expectedArtifactId, artifactPattern) === expectedArtifactId);
    ensure(
      Number.isSafeInteger(expectedBytes) && expectedBytes >= 0 && expectedBytes <= maxExportBytes,
    );
    return this.#transport(
      `exports/${exportId}/download`,
      (response, combined) =>
        readExport(response, combined, exportId, expectedArtifactId, expectedBytes),
      signal,
    );
  }

  /** Create a scoped retention hold. Preserve exact inputs and the key for
   * uncertain outcomes; the server checks role, target state and new deadlines. */
  async createEvidenceHold(
    caseId: string,
    artifactId: string,
    reason: string,
    holdUntil: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<HoldMutation> {
    validateCaseId(caseId);
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    if (!validHoldReason(reason)) throw new ApiError("CONTROL_EVIDENCE_HOLD_REQUEST_INVALID");
    validateHoldUntil(holdUntil);
    this.#idempotencyKey(key);
    return this.#request(
      `cases/${caseId}/holds`,
      (value, status) => decodeHoldCreated(value, caseId, artifactId, reason, holdUntil, status),
      signal,
      JSON.stringify({ artifact_id: artifactId, reason, hold_until: holdUntil }),
      key,
    );
  }

  /** Release a hold once; an exact retry confirms any uncertain transaction. */
  async releaseEvidenceHold(
    holdId: string,
    reason: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<HoldMutation> {
    validateHoldId(holdId);
    if (!validHoldReason(reason)) throw new ApiError("CONTROL_EVIDENCE_HOLD_REQUEST_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `evidence-holds/${holdId}/release`,
      (value, status) => decodeHoldReleased(value, holdId, reason, status),
      signal,
      JSON.stringify({ reason }),
      key,
    );
  }

  /** Read a bounded, independently authorized and audited hold-history page. */
  async evidenceHolds(
    caseId: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<HoldCollection> {
    validateCaseId(caseId);
    validateHoldCursor(cursor);
    return this.#request(
      `cases/${caseId}/holds${this.#cursor(cursor)}`,
      (value, status) => {
        ensure(status === 200);
        return decodeHoldCollection(value, caseId, cursor);
      },
      signal,
    );
  }

  /** Submit one access application. Preserve its key and exact parameters for
   * uncertain results; only an explicit replay can establish durable status. */
  async requestEvidenceAccess(
    artifactId: string,
    caseId: string,
    justification: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<AccessRequested> {
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    validateCaseId(caseId);
    if (!validCaseText(justification))
      throw new ApiError("CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `artifacts/${artifactId}/access`,
      (value, status) => decodeAccessRequested(value, artifactId, caseId, status),
      signal,
      JSON.stringify({ case_id: caseId, access_kind: "sensitive_raw", justification }),
      key,
    );
  }

  /** Read owned history or independent review work, bounded by a server-bound
   * cursor. Every page is freshly authorized and audited; no automatic reads. */
  async evidenceAccessList(
    view: AccessListView,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<AccessList> {
    validateAccessListView(view);
    validateAccessListCursor(cursor);
    const query = `?view=${view}${cursor === undefined ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
    return this.#request(
      `evidence-access-requests${query}`,
      (value, status) => {
        ensure(status === 200);
        return decodeAccessList(value, view, cursor);
      },
      signal,
    );
  }

  /** Inspect one scoped historical record, with server-side access auditing. */
  async evidenceAccess(accessId: string, signal?: AbortSignal): Promise<AccessInspection> {
    validateAccessId(accessId);
    return this.#request(
      `evidence-access-requests/${accessId}`,
      (value, status) => {
        ensure(status === 200);
        return decodeAccessInspection(value, accessId);
      },
      signal,
    );
  }

  /** Record an independent decision once. Server role, ownership and expiry
   * checks are authoritative; failures retain the exact caller-owned retry input. */
  async decideEvidenceAccess(
    accessId: string,
    decision: "approve" | "deny",
    reason: string,
    ttlSeconds: number | null,
    key: string,
    signal?: AbortSignal,
  ): Promise<AccessDecision> {
    validateAccessId(accessId);
    if (
      !validCaseText(reason) ||
      !["approve", "deny"].includes(decision) ||
      (decision === "deny"
        ? ttlSeconds !== null
        : typeof ttlSeconds !== "number" ||
          !Number.isSafeInteger(ttlSeconds) ||
          ttlSeconds < 1 ||
          ttlSeconds > 86400)
    )
      throw new ApiError("CONTROL_EVIDENCE_ACCESS_DECISION_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `evidence-access-requests/${accessId}/${decision}`,
      (value, status) => decodeAccessDecision(value, accessId, decision, ttlSeconds, status),
      signal,
      JSON.stringify(decision === "approve" ? { reason, ttl_seconds: ttlSeconds } : { reason }),
      key,
    );
  }

  /** Fetch a bounded binary attachment under fresh server authorization. The
   * entire request and body share one deadline; the caller owns Blob disposal. */
  async downloadEvidence(
    artifactId: string,
    accessId: string,
    signal?: AbortSignal,
  ): Promise<EvidenceDownload> {
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    validateAccessId(accessId);
    return this.#transport(
      `artifacts/${artifactId}/content`,
      (response, combined) => readEvidence(response, combined, artifactId, accessId),
      signal,
      undefined,
      undefined,
      accessId,
    );
  }

  async siteList(signal?: AbortSignal, cursor?: string, limit = 100): Promise<SiteListResponse> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new ApiError("CONTROL_CURSOR_INVALID");
    const query = new URLSearchParams({ limit: String(limit) });
    if (cursor !== undefined) {
      this.#cursor(cursor);
      query.set("cursor", cursor);
    }
    return this.#request(`sites?${query.toString()}`, decodeSiteList, signal);
  }

  /** Key metadata of the tenant. Browser session with KeyAdministrator or SystemAdmin only. */
  async managementApiKeys(signal?: AbortSignal): Promise<ManagementApiKeyList> {
    return this.#request("agent-api-keys", decodeManagementApiKeys, signal);
  }

  /**
   * Issues a key. The reply carries its plaintext once. The server does not deduplicate by
   * `Idempotency-Key` here: repeating a create whose first attempt committed issues a second key.
   */
  async createManagementApiKey(
    value: {
      subject: string;
      display_name: string;
      expires_at: string;
      scopes: ReadonlyArray<{
        tenant_id: string;
        site_id: string;
        capabilities: readonly string[];
      }>;
    },
    key: string,
    signal?: AbortSignal,
  ): Promise<ManagementApiKeyResponse> {
    this.#idempotencyKey(key);
    return this.#request(
      "agent-api-keys",
      decodeManagementApiKey,
      signal,
      JSON.stringify(value),
      key,
    );
  }

  /**
   * Revokes `apiKeyId` and issues its replacement in one transaction; a refused request leaves
   * the old key alive, and a repeat after success finds the old key gone (404) and issues nothing.
   */
  async rotateManagementApiKey(
    apiKeyId: string,
    value: {
      subject: string;
      display_name: string;
      expires_at: string;
      scopes: ReadonlyArray<{
        tenant_id: string;
        site_id: string;
        capabilities: readonly string[];
      }>;
    },
    key: string,
    signal?: AbortSignal,
  ): Promise<ManagementApiKeyResponse> {
    if (!apiKeyIdPattern.test(apiKeyId)) throw new ApiError("CONTROL_API_KEY_NOT_FOUND");
    this.#idempotencyKey(key);
    return this.#request(
      `agent-api-keys/${apiKeyId}/rotate`,
      decodeManagementApiKey,
      signal,
      JSON.stringify(value),
      key,
    );
  }

  async revokeManagementApiKey(
    apiKeyId: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<ManagementApiKeyRevoked> {
    if (!apiKeyIdPattern.test(apiKeyId)) throw new ApiError("CONTROL_API_KEY_NOT_FOUND");
    this.#idempotencyKey(key);
    return this.#request(
      `agent-api-keys/${apiKeyId}/revoke`,
      decodeManagementApiKeyRevoked(apiKeyId),
      signal,
      "",
      key,
    );
  }

  async createSite(
    siteId: string,
    value: Omit<
      SiteConfig,
      "revision" | "config_digest" | "updated_by" | "created_at" | "updated_at" | "gateway_config"
    >,
    key: string,
    signal?: AbortSignal,
  ): Promise<SiteConfigResponse> {
    const parsedSiteId = name(siteId);
    this.#idempotencyKey(key);
    return this.#request(
      "sites",
      decodeSiteConfig,
      signal,
      JSON.stringify({ site_id: parsedSiteId, ...value }),
      key,
    );
  }

  async siteConfig(siteId?: string, signal?: AbortSignal): Promise<SiteConfigResponse> {
    const path = siteId === undefined ? "site-config" : `sites/${name(siteId)}/config`;
    return this.#request(path, decodeSiteConfig, signal);
  }

  async deleteSite(siteId: string, key: string, signal?: AbortSignal): Promise<SiteDeleteResponse> {
    this.#idempotencyKey(key);
    const path = `sites/${name(siteId)}`;
    return this.#transport(
      path,
      async (response, combined) =>
        decodeSiteDelete(await readJson(response, combined), response.status),
      signal,
      undefined,
      key,
      undefined,
      "DELETE",
    );
  }

  /** Observe edge/upstream health for one site; the backend audits each read. */
  async siteHealth(siteId: string, signal?: AbortSignal): Promise<SiteApplyResponse> {
    return this.#request("sites/" + name(siteId) + "/health", decodeSiteApply, signal);
  }

  async siteStatus(siteId: string, signal?: AbortSignal): Promise<SiteApplyResponse> {
    return this.#request(`sites/${name(siteId)}/status`, decodeSiteApply, signal);
  }

  /**
   * Validates the persisted configuration. A failed validation is a normal answer (422 with
   * `valid: false`), not a transport error. The key is optional: the server ignores it, the
   * console sends it so the frozen request it displays is the request that was sent.
   */
  async validateSite(
    siteId: string,
    signal?: AbortSignal,
    key?: string,
  ): Promise<SiteValidationResponse> {
    if (key !== undefined) this.#idempotencyKey(key);
    return this.#transport(
      `sites/${name(siteId)}/validate`,
      async (response, combined) =>
        decodeSiteValidation(await readJson(response, combined), response.status),
      signal,
      "",
      key,
      undefined,
      undefined,
      { acceptStatuses: [422] },
    );
  }

  async siteRevisions(siteId: string, signal?: AbortSignal): Promise<SiteRevisionsResponse> {
    return this.#request(`sites/${name(siteId)}/revisions`, decodeSiteRevisions, signal);
  }

  async applySite(siteId: string, key: string, signal?: AbortSignal): Promise<SiteApplyResponse> {
    this.#idempotencyKey(key);
    return this.#transport(
      `sites/${name(siteId)}/apply`,
      async (response, combined) =>
        decodeSiteApply(await readJson(response, combined), response.status),
      signal,
      "",
      key,
    );
  }

  /**
   * `expectedConfigDigest` pins the approval to the configuration the reviewer looked at: the
   * server answers 409 CONTROL_SITE_APPROVAL_REVISION_MISMATCH when the staged revision is no
   * longer that one. 64 lowercase hex characters, exactly as `config_digest` is reported.
   */
  async approveSite(
    siteId: string,
    key: string,
    signal?: AbortSignal,
    expectedConfigDigest?: string,
  ): Promise<SiteApplyResponse> {
    this.#idempotencyKey(key);
    if (expectedConfigDigest !== undefined && !/^[0-9a-f]{64}$/.test(expectedConfigDigest)) {
      throw new ApiError("CONTROL_SITE_CONFIG_REQUEST_INVALID");
    }
    return this.#transport(
      `sites/${name(siteId)}/approve`,
      async (response, combined) =>
        decodeSiteApply(await readJson(response, combined), response.status),
      signal,
      "",
      key,
      undefined,
      undefined,
      expectedConfigDigest === undefined
        ? undefined
        : { headers: { "X-Xshield-Expected-Config-Digest": expectedConfigDigest } },
    );
  }

  async rollbackSite(
    siteId: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<SiteApplyResponse> {
    this.#idempotencyKey(key);
    return this.#transport(
      `sites/${name(siteId)}/rollback`,
      async (response, combined) =>
        decodeSiteApply(await readJson(response, combined), response.status),
      signal,
      "",
      key,
    );
  }

  async saveSiteConfig(
    siteId: string | undefined,
    value: Omit<
      SiteConfig,
      "revision" | "config_digest" | "updated_by" | "created_at" | "updated_at" | "gateway_config"
    >,
    key: string,
    signal?: AbortSignal,
  ): Promise<SiteConfigResponse> {
    this.#idempotencyKey(key);
    const path = siteId === undefined ? "site-config" : `sites/${name(siteId)}/config`;
    return this.#request(path, decodeSiteConfig, signal, JSON.stringify(value), key);
  }

  #idempotencyKey(key: string): void {
    if (!validIdempotencyKey(key)) throw new ApiError("CONTROL_IDEMPOTENCY_KEY_INVALID");
  }
  #requestId(requestId: string): void {
    if (typeof requestId !== "string" || !requestPattern.test(requestId))
      throw new ApiError("CONTROL_REQUEST_ID_INVALID");
  }
  #cursor(cursor?: string): string {
    if (cursor === undefined) return "";
    if (typeof cursor !== "string" || !cursorPattern.test(cursor))
      throw new ApiError("CONTROL_CURSOR_INVALID");
    return `?cursor=${encodeURIComponent(cursor)}`;
  }
}
