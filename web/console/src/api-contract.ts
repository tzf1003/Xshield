/** Shared control wire validation and safe diagnostics; no transport or credentials. */
export type Watermark = { producer_boot_id: string; producer_sequence: number };
export type Envelope = {
  request_id: string;
  tenant_id: string;
  site_id: string;
};
export const messages = {
  CONTROL_AUTH_REQUIRED: "管理凭证无效或已过期，请重新连接。",
  CONTROL_SCOPE_DENIED: "当前身份没有此作用域的只读权限。",
  CONTROL_RATE_LIMITED: "管理请求已达频率上限，请稍后重试。",
  CONTROL_REQUEST_ID_INVALID: "请输入规范的请求 ID。",
  CONTROL_ARTIFACT_ID_INVALID: "证据 ID 格式无效。",
  CONTROL_MODEL_CALL_ID_INVALID: "请输入规范的模型调用 ID。",
  CONTROL_QUERY_INVALID: "查询计划无效，请检查 UTC 时间范围、条件和页大小。",
  CONTROL_QUERY_BUDGET_EXCEEDED:
    "查询超出服务预算，请缩小时间范围或细化条件；精确 ID 查询请联系管理员。",
  CONTROL_QUERY_CAPACITY_EXHAUSTED: "调查查询服务繁忙，请稍后重试。",
  CONTROL_QUERY_TIMEOUT: "调查查询超时，请稍后重试。",
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
  QUERY_DIGEST_UNAVAILABLE:
    "当前环境无法验证查询摘要，请使用 HTTPS 或本机浏览器。",
  HTTP_ERROR: "管理服务返回异常状态，请联系管理员。",
} as const;
export type ErrorCode = keyof typeof messages;

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

export const uuid =
  "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
export const requestPattern = new RegExp(`^req_${uuid}$`);
export const artifactPattern = new RegExp(`^artifact_${uuid}$`);
export const modelCallPattern = new RegExp(`^mdl_${uuid}$`);
export const eventPattern = new RegExp(`^ev_${uuid}$`);
export const cursorPattern = /^[A-Za-z0-9_.-]{1,160}$/;

export function ensure(condition: unknown): asserts condition {
  if (!condition) throw new ApiError("INVALID_RESPONSE");
}
export function object(value: unknown): Record<string, unknown> {
  ensure(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}
export function text(value: unknown, max = 128, empty = false): string {
  ensure(
    typeof value === "string" &&
      value.length <= max &&
      (empty || value.length > 0),
  );
  ensure(!/[\u0000-\u001f\u007f]/.test(value));
  return value;
}
export function name(value: unknown, empty = false): string {
  const result = text(value, 128, empty);
  ensure((empty && result === "") || /^[A-Za-z0-9_.-]+$/.test(result));
  return result;
}
export function id(value: unknown, pattern: RegExp): string {
  const result = text(value);
  ensure(pattern.test(result));
  return result;
}
export function integer(
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
export function bool(value: unknown): boolean {
  ensure(typeof value === "boolean");
  return value;
}
export function choice<T extends string>(
  value: unknown,
  values: readonly T[],
): T {
  ensure(
    typeof value === "string" && (values as readonly string[]).includes(value),
  );
  return value as T;
}
export function nullable<T>(
  value: unknown,
  decode: (value: unknown) => T,
): T | null {
  return value === null ? null : decode(value);
}
export function list<T>(
  value: unknown,
  max: number,
  decode: (value: unknown) => T,
): T[] {
  ensure(Array.isArray(value) && value.length <= max);
  return value.map(decode);
}
export function timestamp(value: unknown): string {
  const result = text(value, 40);
  ensure(
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/.test(
      result,
    ),
  );
  const time = Date.parse(result);
  ensure(Number.isFinite(time));
  // Preserve recorded calendar facts; Date.parse otherwise normalizes bad days.
  ensure(new Date(time).toISOString().slice(0, 19) === result.slice(0, 19));
  return result;
}
export function references(
  value: unknown,
  pattern: RegExp,
  max = 256,
): string[] {
  const result = list(value, max, (item) => id(item, pattern));
  ensure(new Set(result).size === result.length);
  return result;
}
export function envelope(value: Record<string, unknown>): Envelope {
  return {
    request_id: id(value.request_id, requestPattern),
    tenant_id: name(value.tenant_id),
    site_id: name(value.site_id),
  };
}
export function watermarked(value: Record<string, unknown>) {
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
export function pagination(value: Record<string, unknown>) {
  const truncated = bool(value.truncated);
  const next_cursor = nullable(value.next_cursor, (item) => {
    const cursor = text(item, 160);
    ensure(cursorPattern.test(cursor));
    return cursor;
  });
  ensure(truncated === (next_cursor !== null));
  return { truncated, next_cursor };
}
export function confidence(value: Record<string, unknown>, allowEmpty = false) {
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
