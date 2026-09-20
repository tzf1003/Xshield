/** Control API boundary. Credentials remain in this client's memory. */
import {
  ApiError,
  messages,
  uuid,
  requestPattern,
  artifactPattern,
  modelCallPattern,
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
} from "./search.ts";
import type { SearchPlan, SearchResponse } from "./search.ts";
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
import type {
  CaseCreated,
  CaseList,
  CaseCollection,
  CaseItemAdded,
  CaseClosed,
} from "./cases.ts";
import {
  validateAccessId, decodeAccessRequested, decodeAccessInspection,
  decodeAccessDecision, accessPattern,
  decodeAccessList, validateAccessListCursor, validateAccessListView,
} from "./evidence-access.ts";
import type {
  AccessRequested, AccessInspection, AccessDecision, EvidenceDownload,
  AccessList, AccessListView,
} from "./evidence-access.ts";
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
  question_type: "choice" | "noul";
  status:
    | "started"
    | "requested"
    | "success"
    | "error"
    | "timeout"
    | "cancelled";
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

const maxBytes = 16 * 1024 * 1024;
function stage(value: unknown): Stage {
  const row = object(value);
  const first_request_seq = integer(row.first_request_seq, 1, 0xffff_ffff);
  return {
    stage: name(row.stage),
    outcome: choice(row.outcome, [
      "PASS",
      "DENY",
      "UNKNOWN",
      "ERROR",
      "SKIPPED",
      "CANCELLED",
    ]),
    reason_code: name(row.reason_code),
    ...confidence(row),
    first_request_seq,
    last_request_seq: integer(
      row.last_request_seq,
      first_request_seq,
      0xffff_ffff,
    ),
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
    decision: nullable(row.decision, (item) =>
      choice(item, ["ALLOW", "DENY", "UNKNOWN"]),
    ),
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
  ensure(
    new Set(result.stages.map((item) => item.stage)).size ===
      result.stages.length,
  );
  return result;
}
function auditEvent(value: unknown): AuditEvent {
  const row = object(value);
  return {
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
    evidence_refs: references(
      row.evidence_refs,
      new RegExp(`^[a-z]+_${uuid}$`),
    ),
    cause_event_ids: references(row.cause_event_ids, eventPattern),
    sensitivity: choice(row.sensitivity, [
      "PUBLIC",
      "INTERNAL",
      "SENSITIVE",
      "RESTRICTED",
    ]),
  };
}
function manifest(
  value: unknown,
  scope: Envelope,
  request?: string,
  artifact?: string,
): Manifest {
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
    classification: choice(row.classification, [
      "INTERNAL",
      "SENSITIVE",
      "RESTRICTED",
    ]),
    example_only: false,
    parent_refs: references(row.parent_refs, artifactPattern, 64),
    expires_at: timestamp(row.expires_at),
  };
  ensure(
    result.tenant_id === scope.tenant_id && result.site_id === scope.site_id,
  );
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
  const provider_model_id = nullable(row.provider_model_id, (item) =>
    text(item),
  );
  ensure(
    provider === null
      ? provider_model_id === null
      : provider_model_id ===
          (provider === "typesafe" ? "jev-1.13.0" : "typesafe-ai/jev"),
  );
  const result: ModelCallFacts = {
    provider,
    provider_model_id,
    model_revision: name(row.model_revision),
    prompt_revision: name(row.prompt_revision),
    question_type: choice(row.question_type, ["choice", "noul"]),
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
    input_artifact_id: nullable(row.input_artifact_id, (item) =>
      id(item, artifactPattern),
    ),
    output_artifact_id: nullable(row.output_artifact_id, (item) =>
      id(item, artifactPattern),
    ),
    call_artifact_id: nullable(row.call_artifact_id, (item) =>
      id(item, artifactPattern),
    ),
  };
  ensure(
    result.question_type !== "noul" ||
      result.confidence_status === "not_applicable",
  );
  ensure(result.status === "success" || result.confidence === null);
  ensure(
    !["requested", "success"].includes(result.status) ||
      result.input_artifact_id !== null,
  );
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
        evidence_refs: references(
          event.evidence_refs,
          new RegExp(`^[a-z]+_${uuid}$`),
        ),
        cause_event_ids: references(event.cause_event_ids, eventPattern, 1),
        sensitivity: choice(event.sensitivity, [
          "PUBLIC",
          "INTERNAL",
          "SENSITIVE",
          "RESTRICTED",
        ]),
      };
      ensure(result.event_type === modelEventTypes[result.status]);
      ensure(
        result.cause_event_ids.length === (result.status === "started" ? 0 : 1),
      );
      for (const reference of [
        result.input_artifact_id,
        result.output_artifact_id,
        result.call_artifact_id,
      ])
        ensure(reference === null || result.evidence_refs.includes(reference));
      ensure(
        result.status !== "started" ||
          [
            result.input_artifact_id,
            result.output_artifact_id,
            result.call_artifact_id,
          ].every((item) => item === null),
      );
      ensure(
        result.status !== "requested" ||
          (result.output_artifact_id === null &&
            result.call_artifact_id === null),
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
  ensure(
    new Set(result.events.map((event) => event.event_id)).size ===
      result.events.length,
  );
  ensure(
    new Set(result.events.map((event) => event.event_type)).size ===
      result.events.length,
  );
  ensure(
    new Set(result.events.flatMap((event) => event.evidence_refs)).size <= 256,
  );
  let continuous = true;
  // Retention may hide a predecessor. Visible send boundaries must still link
  // directly, and request sequence stays authoritative across clock rollback.
  for (let index = 0; index < result.events.length; index++) {
    const event = result.events[index]!;
    ensure(identity.every((field) => event[field] === result[field]));
    ensure(
      !result.events
        .slice(index)
        .some((later) => event.cause_event_ids.includes(later.event_id)),
    );
    if (index === 0) continue;
    const previous = result.events[index - 1]!;
    const direct = event.cause_event_ids[0] === previous.event_id;
    ensure(
      event.request_seq > previous.request_seq && event.status !== "started",
    );
    ensure(["started", "requested"].includes(previous.status));
    ensure(
      previous.status !== "requested" ||
        event.input_artifact_id === previous.input_artifact_id,
    );
    ensure(
      (previous.status !== "requested" && event.status !== "requested") ||
        direct,
    );
    ensure(
      previous.status !== "started" ||
        !direct ||
        ["requested", "error"].includes(event.status),
    );
    continuous &&= direct;
  }
  for (const field of [
    "input_artifact_id",
    "output_artifact_id",
    "call_artifact_id",
  ] as const) {
    const refs = new Set(
      result.events.map((event) => event[field]).filter((ref) => ref !== null),
    );
    ensure(
      refs.size <= 1 && result[field] === (refs.values().next().value ?? null),
    );
  }
  ensure(
    result.lifecycle_complete ===
      (first.status === "started" &&
        !["started", "requested"].includes(latest.status) &&
        continuous),
  );
  return result;
}

async function readJson(
  response: Response,
  signal: AbortSignal,
): Promise<unknown> {
  ensure(
    response.headers
      .get("content-type")
      ?.split(";")[0]
      ?.trim()
      .toLowerCase() === "application/json",
  );
  const length = response.headers.get("content-length");
  if (length !== null) {
    ensure(/^\d+$/.test(length) && Number.isSafeInteger(Number(length)));
    if (Number(length) > maxBytes)
      throw new ApiError("RESPONSE_TOO_LARGE", response.status);
  }
  ensure(response.body !== null);
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let body = "";
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    while (true) {
      signal.throwIfAborted();
      const chunk = await reader.read();
      signal.throwIfAborted();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxBytes)
        throw new ApiError("RESPONSE_TOO_LARGE", response.status);
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
  response: Response, signal: AbortSignal, artifactId: string, accessId: string,
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
    const cache = headers.get("cache-control")?.split(",").map((v) => v.trim().toLowerCase());
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
    const cancel = () => { void reader?.cancel().catch(() => {}); };
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
      return { ...base, artifact_id: artifactId, access_request_id: accessId,
        bytes, blob: new Blob([buffer], { type: "application/octet-stream" }) };
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

/** Fixed scoped endpoints. Callers own session disposal, scope checks and mutation retry input. */
export class ControlClient {
  #authorization: string;
  constructor(token: string) {
    if (
      typeof token !== "string" ||
      token.length > 512 ||
      /[\u0000-\u001f\u007f-\u009f]/.test(token)
    )
      throw new ApiError("INVALID_CREDENTIAL");
    const bytes = new TextEncoder().encode(token).byteLength;
    if (bytes < 32 || bytes > 512) throw new ApiError("INVALID_CREDENTIAL");
    this.#authorization = `Bearer ${token}`;
    try {
      // Browser header serialization must preserve the exact server credential.
      if (
        new Headers({ Authorization: this.#authorization }).get(
          "Authorization",
        ) !== this.#authorization
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
    return this.#transport(path, async (response, combined) =>
      decode(await readJson(response, combined), response.status),
    signal, body, idempotencyKey);
  }

  async #transport<T>(
    path: string,
    consume: (response: Response, signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
    body?: string,
    idempotencyKey?: string,
    accessId?: string,
  ): Promise<T> {
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(), 15_000);
    const combined = signal
      ? AbortSignal.any([signal, deadline.signal])
      : deadline.signal;
    let status = 0;
    try {
      combined.throwIfAborted();
      const response = await fetch(`/control/v1/${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          Authorization: this.#authorization,
          Accept: accessId === undefined ? "application/json" : "application/octet-stream",
          ...(accessId === undefined ? {} : { "X-Xshield-Evidence-Access-Request": accessId }),
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
          ...(idempotencyKey === undefined
            ? {}
            : { "Idempotency-Key": idempotencyKey }),
        },
        ...(body === undefined ? {} : { body }),
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: combined,
      });
      status = response.status;
      if (!response.ok) {
        const value = await readJson(response, combined);
        const row = object(value);
        const requestId =
          typeof row.request_id === "string" &&
          requestPattern.test(row.request_id)
            ? row.request_id
            : null;
        const code =
          typeof row.error_code === "string" &&
          Object.hasOwn(messages, row.error_code) &&
          (row.error_code.startsWith("CONTROL_") ||
            row.error_code === "AUDIT_DURABILITY_FAILED")
            ? (row.error_code as ErrorCode)
            : "HTTP_ERROR";
        throw new ApiError(code, status, requestId);
      }
      return await consume(response, combined);
    } catch (error) {
      if (signal?.aborted) throw new ApiError("REQUEST_ABORTED", status);
      if (deadline.signal.aborted)
        throw new ApiError("REQUEST_TIMEOUT", status);
      if (error instanceof ApiError)
        throw new ApiError(error.code, status || error.status, error.requestId);
      throw new ApiError("NETWORK_UNAVAILABLE", status);
    } finally {
      clearTimeout(timer);
      deadline.abort();
    }
  }

  async summary(
    requestId: string,
    signal?: AbortSignal,
  ): Promise<SummaryResponse> {
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

  async events(
    requestId: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<EventsResponse> {
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
        ensure(
          new Set(result.events.map((item) => item.event_id)).size ===
            result.events.length,
        );
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
          artifacts: list(row.artifacts, 128, (item) =>
            manifest(item, base, requestId),
          ),
        };
        ensure(!result.truncated || result.artifacts.length > 0);
        for (let index = 1; index < result.artifacts.length; index++)
          ensure(
            result.artifacts[index]!.artifact_id >
              result.artifacts[index - 1]!.artifact_id,
          );
        return result;
      },
      signal,
    );
  }

  async artifact(
    artifactId: string,
    signal?: AbortSignal,
  ): Promise<ArtifactResponse> {
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
          artifact: nullable(row.artifact, (item) =>
            manifest(item, base, undefined, artifactId),
          ),
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
  async modelCall(
    modelCallId: string,
    signal?: AbortSignal,
  ): Promise<ModelCallResponse> {
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
          completeness: choice(row.completeness, [
            "complete",
            "pending",
            "partial",
            "not_indexed",
          ]),
          model_call: nullable(row.model_call, (item) =>
            modelCall(item, modelCallId),
          ),
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
  async binding(
    bindingId: string,
    signal?: AbortSignal,
  ): Promise<BindingResponse> {
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
  async search(
    plan: SearchPlan,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<SearchResponse> {
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
  async createCase(
    purpose: string,
    key: string,
    signal?: AbortSignal,
  ): Promise<CaseCreated> {
    if (!validCaseText(purpose))
      throw new ApiError("CONTROL_CASE_REQUEST_INVALID");
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
  async caseItems(
    caseId: string,
    cursor?: string,
    signal?: AbortSignal,
  ): Promise<CaseCollection> {
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
    if (!validCaseText(reason))
      throw new ApiError("CONTROL_CASE_CLOSE_REQUEST_INVALID");
    this.#idempotencyKey(key);
    return this.#request(
      `cases/${caseId}/close`,
      (value, status) => decodeCaseClosed(value, caseId, status),
      signal,
      JSON.stringify({ reason }),
      key,
    );
  }

  /** Submit one access application. Preserve its key and exact parameters for
   * uncertain results; only an explicit replay can establish durable status. */
  async requestEvidenceAccess(
    artifactId: string, caseId: string, justification: string, key: string,
    signal?: AbortSignal,
  ): Promise<AccessRequested> {
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    validateCaseId(caseId);
    if (!validCaseText(justification))
      throw new ApiError("CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID");
    this.#idempotencyKey(key);
    return this.#request(`artifacts/${artifactId}/access`,
      (value, status) => decodeAccessRequested(value, artifactId, caseId, status),
      signal, JSON.stringify({ case_id: caseId, access_kind: "sensitive_raw", justification }), key);
  }

  /** Read owned history or independent review work, bounded by a server-bound
   * cursor. Every page is freshly authorized and audited; no automatic reads. */
  async evidenceAccessList(view: AccessListView, cursor?: string, signal?: AbortSignal): Promise<AccessList> {
    validateAccessListView(view);
    validateAccessListCursor(cursor);
    const query = `?view=${view}${cursor === undefined ? "" : `&cursor=${encodeURIComponent(cursor)}`}`;
    return this.#request(`evidence-access-requests${query}`, (value, status) => {
      ensure(status === 200);
      return decodeAccessList(value, view, cursor);
    }, signal);
  }

  /** Inspect one scoped historical record, with server-side access auditing. */
  async evidenceAccess(accessId: string, signal?: AbortSignal): Promise<AccessInspection> {
    validateAccessId(accessId);
    return this.#request(`evidence-access-requests/${accessId}`, (value, status) => {
      ensure(status === 200);
      return decodeAccessInspection(value, accessId);
    }, signal);
  }

  /** Record an independent decision once. Server role, ownership and expiry
   * checks are authoritative; failures retain the exact caller-owned retry input. */
  async decideEvidenceAccess(
    accessId: string, decision: "approve" | "deny", reason: string,
    ttlSeconds: number | null, key: string, signal?: AbortSignal,
  ): Promise<AccessDecision> {
    validateAccessId(accessId);
    if (!validCaseText(reason) || !["approve", "deny"].includes(decision) ||
        (decision === "deny" ? ttlSeconds !== null :
          typeof ttlSeconds !== "number" || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 86400))
      throw new ApiError("CONTROL_EVIDENCE_ACCESS_DECISION_INVALID");
    this.#idempotencyKey(key);
    return this.#request(`evidence-access-requests/${accessId}/${decision}`,
      (value, status) => decodeAccessDecision(value, accessId, decision, ttlSeconds, status),
      signal, JSON.stringify(decision === "approve" ? { reason, ttl_seconds: ttlSeconds } : { reason }), key);
  }

  /** Fetch a bounded binary attachment under fresh server authorization. The
   * entire request and body share one deadline; the caller owns Blob disposal. */
  async downloadEvidence(
    artifactId: string, accessId: string, signal?: AbortSignal,
  ): Promise<EvidenceDownload> {
    if (typeof artifactId !== "string" || !artifactPattern.test(artifactId))
      throw new ApiError("CONTROL_ARTIFACT_ID_INVALID");
    validateAccessId(accessId);
    return this.#transport(`artifacts/${artifactId}/content`,
      (response, combined) => readEvidence(response, combined, artifactId, accessId),
      signal, undefined, undefined, accessId);
  }

  #idempotencyKey(key: string): void {
    if (!validIdempotencyKey(key))
      throw new ApiError("CONTROL_IDEMPOTENCY_KEY_INVALID");
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
