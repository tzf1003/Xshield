/** Read-only control API boundary. Credentials remain in this client's memory. */
export type Watermark = { producer_boot_id: string; producer_sequence: number };
export type Envelope = {
  request_id: string;
  tenant_id: string;
  site_id: string;
};
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

const messages = {
  CONTROL_AUTH_REQUIRED: "管理凭证无效或已过期，请重新连接。",
  CONTROL_SCOPE_DENIED: "当前身份没有此作用域的只读权限。",
  CONTROL_RATE_LIMITED: "管理请求已达频率上限，请稍后重试。",
  CONTROL_REQUEST_ID_INVALID: "请输入规范的请求 ID。",
  CONTROL_ARTIFACT_ID_INVALID: "证据 ID 格式无效。",
  CONTROL_CURSOR_INVALID: "分页凭证已失效，请重新查询。",
  CONTROL_CURSOR_UNAVAILABLE: "分页服务暂时不可用，请稍后重试。",
  CONTROL_INDEX_UNAVAILABLE: "审计索引暂时不可用，请稍后重试。",
  CONTROL_CATALOG_UNAVAILABLE: "证据目录暂时不可用，请稍后重试。",
  CONTROL_HEALTH_UNAVAILABLE: "索引水位暂时不可用，请稍后重试。",
  CONTROL_RATE_UNAVAILABLE: "管理服务暂时不可用，请稍后重试。",
  CONTROL_CLOCK_UNAVAILABLE: "管理服务暂时不可用，请稍后重试。",
  CONTROL_INTERNAL: "管理服务暂时不可用，请稍后重试。",
  AUDIT_DURABILITY_FAILED: "必需的访问审计暂时不可用，结果尚未释放。",
  INVALID_CREDENTIAL: "请输入有效的管理凭证。",
  INVALID_RESPONSE: "服务响应未通过契约校验，请联系管理员。",
  RESPONSE_TOO_LARGE: "服务响应超过读取上限，请联系管理员。",
  REQUEST_TIMEOUT: "查询超时，请稍后重试。",
  REQUEST_ABORTED: "查询已取消。",
  NETWORK_UNAVAILABLE: "无法连接管理服务，请检查连接后重试。",
  HTTP_ERROR: "管理服务返回异常状态，请联系管理员。",
} as const;
type ErrorCode = keyof typeof messages;

/** Safe diagnostics: server messages, response bodies and transport errors are never retained. */
export class ApiError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly requestId: string | null;
  constructor(code: ErrorCode, status = 0, requestId: string | null = null) {
    super(messages[code]);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

const uuid =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const requestPattern = new RegExp(`^req_${uuid}$`);
const artifactPattern = new RegExp(`^artifact_${uuid}$`);
const eventPattern = new RegExp(`^ev_${uuid}$`);
const cursorPattern = /^[A-Za-z0-9_.-]{1,160}$/;
const maxBytes = 16 * 1024 * 1024;

function ensure(condition: unknown): asserts condition {
  if (!condition) throw new ApiError("INVALID_RESPONSE");
}
function object(value: unknown): Record<string, unknown> {
  ensure(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}
function text(value: unknown, max = 128, empty = false): string {
  ensure(
    typeof value === "string" &&
      value.length <= max &&
      (empty || value.length > 0),
  );
  ensure(!/[\u0000-\u001f\u007f]/.test(value));
  return value;
}
function name(value: unknown, empty = false): string {
  const result = text(value, 128, empty);
  ensure((empty && result === "") || /^[A-Za-z0-9_.-]+$/.test(result));
  return result;
}
function id(value: unknown, pattern: RegExp): string {
  const result = text(value);
  ensure(pattern.test(result));
  return result;
}
function integer(
  value: unknown,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): number {
  ensure(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value >= min &&
      value <= max,
  );
  return value;
}
function bool(value: unknown): boolean {
  ensure(typeof value === "boolean");
  return value;
}
function choice<T extends string>(value: unknown, values: readonly T[]): T {
  ensure(
    typeof value === "string" && (values as readonly string[]).includes(value),
  );
  return value as T;
}
function nullable<T>(value: unknown, decode: (value: unknown) => T): T | null {
  return value === null ? null : decode(value);
}
function list<T>(
  value: unknown,
  max: number,
  decode: (value: unknown) => T,
): T[] {
  ensure(Array.isArray(value) && value.length <= max);
  return value.map(decode);
}
function timestamp(value: unknown): string {
  const result = text(value, 40);
  ensure(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/.test(
      result,
    ),
  );
  ensure(Number.isFinite(Date.parse(result)));
  return result;
}
function references(value: unknown, pattern: RegExp, max = 256): string[] {
  const result = list(value, max, (item) => id(item, pattern));
  ensure(new Set(result).size === result.length);
  return result;
}
function envelope(value: Record<string, unknown>): Envelope {
  return {
    request_id: id(value.request_id, requestPattern),
    tenant_id: name(value.tenant_id),
    site_id: name(value.site_id),
  };
}
function watermarked(value: Record<string, unknown>) {
  return {
    as_of: timestamp(value.as_of),
    has_gaps: bool(value.has_gaps),
    index_watermark: nullable(value.index_watermark, (item) => {
      const watermark = object(item);
      return {
        producer_boot_id: id(
          watermark.producer_boot_id,
          new RegExp(`^${uuid}$`),
        ),
        producer_sequence: integer(watermark.producer_sequence, 1),
      };
    }),
  };
}
function pagination(value: Record<string, unknown>) {
  const truncated = bool(value.truncated);
  const next_cursor = nullable(value.next_cursor, (item) => {
    const cursor = text(item, 160);
    ensure(cursorPattern.test(cursor));
    return cursor;
  });
  ensure(truncated === (next_cursor !== null));
  return { truncated, next_cursor };
}
function confidence(value: Record<string, unknown>, allowEmpty = false) {
  const proof_kind = choice(
    value.proof_kind,
    allowEmpty
      ? (["", "deterministic", "model", "observation", "none"] as const)
      : (["deterministic", "model", "observation", "none"] as const),
  );
  const confidence_status = choice(
    value.confidence_status,
    allowEmpty
      ? ([
          "",
          "provided",
          "not_applicable",
          "not_provided",
          "unavailable",
        ] as const)
      : ([
          "provided",
          "not_applicable",
          "not_provided",
          "unavailable",
        ] as const),
  );
  const confidence = nullable(value.confidence, (item) => {
    ensure(
      typeof item === "number" &&
        Number.isFinite(item) &&
        item >= 0 &&
        item <= 1,
    );
    return item;
  });
  ensure((confidence !== null) === (confidence_status === "provided"));
  ensure(
    proof_kind !== "deterministic" ||
      (confidence === null && confidence_status === "not_applicable"),
  );
  ensure(
    !["SKIPPED", "CANCELLED"].includes(String(value.outcome)) ||
      confidence === null,
  );
  return { proof_kind, confidence, confidence_status };
}
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
  try {
    while (true) {
      signal.throwIfAborted();
      const chunk = await reader.read();
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
    // Cancellation need not wait for a remote stream to acknowledge it.
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Four fixed GET routes. Callers own session disposal and cross-response scope checks. */
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

  async #get<T>(
    path: string,
    decode: (value: unknown) => T,
    signal?: AbortSignal,
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
        method: "GET",
        headers: {
          Authorization: this.#authorization,
          Accept: "application/json",
        },
        credentials: "omit",
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
      return decode(value);
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
    return this.#get(
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
    return this.#get(
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
    return this.#get(
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
    return this.#get(
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
