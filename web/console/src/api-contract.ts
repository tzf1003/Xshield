/** Shared control wire validation and safe diagnostics; no transport or credentials. */
export type Watermark = { producer_boot_id: string; producer_sequence: number };
export type Envelope = {
  request_id: string;
  tenant_id: string;
  site_id: string;
};
export const messages = {
  CONTROL_AUTH_REQUIRED: "管理会话无效或已过期，请重新登录。",
  CONTROL_CSRF_REQUIRED: "管理会话校验已过期，请重新登录。",
  CONTROL_STEP_UP_REQUIRED: "读取原文前须完成两分钟内的 MFA 再认证。",
  CONTROL_OIDC_REAUTH_REQUEST_INVALID: "再认证请求无效，请重新开始操作。",
  CONTROL_SESSION_UNAVAILABLE: "管理会话服务暂时不可用，请稍后重试。",
  CONTROL_SCOPE_DENIED: "当前身份没有此作用域的操作权限。",
  CONTROL_RATE_LIMITED: "管理请求已达频率上限，请稍后重试。",
  CONTROL_REQUEST_ID_INVALID: "请输入规范的请求 ID。",
  CONTROL_ARTIFACT_ID_INVALID: "证据 ID 格式无效。",
  CONTROL_MODEL_CALL_ID_INVALID: "请输入规范的模型调用 ID。",
  CONTROL_AGENT_RUN_ID_INVALID: "请输入规范的 Agent 运行 ID。",
  CONTROL_CALIBRATION_REPORT_ID_INVALID: "请输入规范的校准报告 ID。",
  CONTROL_CALIBRATION_REPORT_READ_REQUEST_INVALID: "校准报告查询请求无效，请核对报告 ID。",
  CONTROL_CALIBRATION_REPORT_BUSY: "校准报告查询服务繁忙，请稍后重试。",
  CONTROL_CALIBRATION_REPORT_NOT_AVAILABLE: "当前身份和范围内校准报告不可用。",
  CONTROL_CALIBRATION_REPORT_STORE_UNAVAILABLE: "校准报告存储暂时不可用，请稍后重试。",
  CONTROL_MODEL_CALLS_REQUEST_INVALID:
    "模型调用列表条件无效，请检查 UTC 时间窗、页大小和分页凭证。",
  CONTROL_MODEL_CALLS_INDEX_UNAVAILABLE: "模型调用索引暂时不可用，请稍后重试。",
  CONTROL_MODEL_CALLS_HEALTH_UNAVAILABLE: "模型调用索引水位暂时不可用，请稍后重试。",
  CONTROL_GRANT_ID_INVALID: "请输入规范的资格 ID。",
  CONTROL_BINDING_ID_INVALID: "请输入规范的身份绑定 ID。",
  CONTROL_GRANT_STORE_UNAVAILABLE: "资格账本暂时不可用，请稍后重试。",
  CONTROL_BINDING_STORE_UNAVAILABLE: "身份账本暂时不可用，请稍后重试。",
  CONTROL_CASE_ID_INVALID: "请输入规范的案件 ID。",
  CONTROL_CASE_REQUEST_INVALID: "案件用途须为 1–512 UTF-8 字节，且不含控制字符或首尾空白。",
  CONTROL_CASE_CLOSE_REQUEST_INVALID: "关闭理由须为 1–512 UTF-8 字节，且不含控制字符或首尾空白。",
  CONTROL_CASE_EVIDENCE_REQUEST_INVALID: "请选择有效的案件与证据 ID。",
  CONTROL_IDEMPOTENCY_KEY_INVALID: "幂等键须为 16–128 个 ASCII 字母、数字或 -_.:。",
  CONTROL_IDEMPOTENCY_CONFLICT: "幂等键已绑定其他参数，请核对原始请求。",
  CONTROL_IDEMPOTENCY_UNAVAILABLE: "幂等服务暂时不可用，请保留原键与参数。",
  CONTROL_CASE_NOT_AVAILABLE: "当前身份和范围内案件不可用。",
  CONTROL_CASE_EVIDENCE_TARGET_UNAVAILABLE:
    "当前案件或证据不可关联，请核对归属、案件状态及证据期限。",
  CONTROL_CASE_EVIDENCE_CONFLICT: "证据关联冲突，请核对原键、参数和现有案件集合。",
  CONTROL_CASE_CLOSE_CONFLICT: "关闭请求冲突，请核对原键与参数。",
  CONTROL_CASE_CAPACITY_EXCEEDED: "开放案件已达容量上限，请关闭或复用现有案件。",
  CONTROL_CASE_EVIDENCE_LIMIT_EXCEEDED: "案件证据引用已达容量上限。",
  CONTROL_CASE_BUSY: "案件服务繁忙，请保留原键与参数后重试。",
  CONTROL_CASE_EVIDENCE_BUSY: "案件证据服务繁忙，请稍后重试。",
  CONTROL_CASE_CLOSE_BUSY: "案件关闭服务繁忙，请保留原键与参数后重试。",
  CONTROL_CASE_ANALYSIS_BUSY: "案件分析服务繁忙，请保留原键与参数后重试。",
  CONTROL_CASE_ANALYSIS_STORE_UNAVAILABLE:
    "案件分析存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_CASE_ANALYSIS_TARGET_UNAVAILABLE: "当前身份和范围内案件分析目标不可用。",
  CONTROL_EXPORT_ID_INVALID: "请输入规范的导出 ID。",
  CONTROL_EXPORT_BODY_INVALID: "导出请求无效，请重新填写后重试。",
  CONTROL_EXPORT_INPUT_INVALID: "导出参数无效，请核对用途与决策理由。",
  CONTROL_EXPORT_TARGET_UNAVAILABLE: "当前案件或导出目标不可用。",
  CONTROL_EXPORT_STORE_UNAVAILABLE: "导出状态存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_EXPORT_STORAGE_UNAVAILABLE: "导出包存储暂时不可用，请稍后重试。",
  CONTROL_EXPORT_STORAGE_CORRUPT: "导出包完整性验证未通过，内容尚未释放。",
  CONTROL_EXPORT_PACKAGE_TOO_LARGE: "导出范围超过包大小上限，请缩小案件范围。",
  CONTROL_EXPORT_STEP_UP_REQUIRED: "导出审批或下载需要两分钟内的 MFA 再认证。",
  CONTROL_EXPORT_NOT_FOUND: "当前身份和范围内导出记录不可用。",
  CONTROL_EXPORT_NOT_AVAILABLE: "导出包当前不可用，请重新读取状态。",
  CONTROL_EXPORT_CAPACITY_EXHAUSTED: "导出读取容量已占满，请稍后重试。",
  CONTROL_EXPORT_SELF_APPROVAL: "导出申请须由另一位具备审批权限的主体处理。",
  CONTROL_EXPORT_ALREADY_DECIDED: "导出已完成决策，请读取当前状态。",
  CONTROL_JOB_ID_INVALID: "请输入规范的任务 ID。",
  CONTROL_JOB_STORE_UNAVAILABLE: "任务状态暂时不可用，请稍后重试。",
  CONTROL_CASE_STORE_UNAVAILABLE: "案件存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_CASE_EVIDENCE_STORE_UNAVAILABLE:
    "案件证据存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_EVIDENCE_HOLD_ID_INVALID: "请输入规范的保留锁 ID。",
  CONTROL_EVIDENCE_HOLD_REQUEST_INVALID: "请填写 1–512 UTF-8 字节的规范理由与 UTC 毫秒保留期限。",
  CONTROL_EVIDENCE_HOLD_STORE_UNAVAILABLE:
    "保留锁存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_EVIDENCE_HOLD_CONFLICT: "保留锁请求冲突，请核对原键、参数和现有保留记录。",
  CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE: "当前范围内的案件、证据或保留锁不可用。",
  CONTROL_EVIDENCE_HOLD_LIMIT_EXCEEDED: "保留锁已达容量上限，请先处理现有记录。",
  CONTROL_EVIDENCE_HOLD_BUSY: "保留锁服务繁忙，请稍后使用原键与参数重试。",
  CONTROL_EVIDENCE_ACCESS_ID_INVALID: "请输入规范的访问申请 ID。",
  CONTROL_EVIDENCE_ACCESS_REQUEST_ID_INVALID: "访问申请 ID 格式无效。",
  CONTROL_EVIDENCE_ACCESS_REQUEST_INVALID:
    "请选择有效的案件，并填写 1–512 UTF-8 字节的规范访问理由。",
  CONTROL_EVIDENCE_ACCESS_TARGET_UNAVAILABLE:
    "当前案件或证据不可申请访问，请核对归属、状态与期限。",
  CONTROL_EVIDENCE_ACCESS_CAPACITY_EXCEEDED: "待决访问申请已达容量上限，请先处理现有申请。",
  CONTROL_EVIDENCE_ACCESS_BUSY: "证据访问服务繁忙，请稍后重试。",
  CONTROL_EVIDENCE_ACCESS_STORE_UNAVAILABLE:
    "申请存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_EVIDENCE_ACCESS_READ_REQUEST_INVALID: "访问申请查询参数无效，请核对申请 ID。",
  CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE: "当前身份和范围内访问申请不可用。",
  CONTROL_EVIDENCE_ACCESS_READ_STORE_UNAVAILABLE: "访问申请查询暂时不可用，请稍后重试。",
  CONTROL_EVIDENCE_ACCESS_LIST_REQUEST_INVALID: "请选择有效的申请列表范围并重新读取。",
  CONTROL_EVIDENCE_ACCESS_DECISION_INVALID: "请填写规范的决策理由与有效批准期限。",
  CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT: "申请已有决策或幂等参数冲突，请核对原键与参数。",
  CONTROL_EVIDENCE_ACCESS_DECISION_TARGET_UNAVAILABLE: "申请或批准目标当前不可用，请重新查询详情。",
  CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED: "申请须由另一位具备审批权限的主体处理。",
  CONTROL_EVIDENCE_ACCESS_DECISION_STORE_UNAVAILABLE:
    "决策存储暂时不可用；写入结果可能未知，请保留原键与参数。",
  CONTROL_EVIDENCE_ACCESS_REQUEST_REQUIRED: "读取证据需要有效的访问申请引用。",
  CONTROL_EVIDENCE_READ_REQUEST_INVALID: "证据读取请求无效，请核对目标与访问申请。",
  CONTROL_EVIDENCE_READ_NOT_AVAILABLE: "当前证据读取资格不可用，请核对申请、归属与期限。",
  CONTROL_EVIDENCE_READ_STORE_UNAVAILABLE: "读取资格服务暂时不可用，请稍后重试。",
  CONTROL_EVIDENCE_READ_UNAVAILABLE: "证据内容服务暂时不可用，请稍后重试。",
  CONTROL_EVIDENCE_READ_CAPACITY_EXHAUSTED: "证据读取容量已占满，请稍后重试。",
  CONTROL_EVIDENCE_READ_CORRUPT: "证据完整性验证未通过，内容尚未释放。",
  CONTROL_EVIDENCE_READ_TOO_LARGE: "证据内容超过服务读取上限，请联系管理员。",
  CONTROL_QUERY_INVALID: "查询计划无效，请检查 UTC 时间范围、条件和页大小。",
  CONTROL_QUERY_BUDGET_EXCEEDED:
    "查询超出服务预算，请缩小时间范围或细化条件；精确 ID 查询请联系管理员。",
  CONTROL_QUERY_CAPACITY_EXHAUSTED: "调查查询服务繁忙，请稍后重试。",
  CONTROL_QUERY_TIMEOUT: "调查查询超时，请稍后重试。",
  CONTROL_CAUSALITY_REQUEST_INVALID: "因果查询条件无效，请检查 UTC 时间窗、方向和遍历上限。",
  CONTROL_CAUSALITY_TIMEOUT: "因果查询超时，请缩小范围或稍后重试。",
  CONTROL_CAUSALITY_INDEX_UNAVAILABLE: "因果事件索引暂时不可用，请稍后重试。",
  CONTROL_CAUSALITY_HEALTH_UNAVAILABLE: "因果索引水位暂时不可用，请稍后重试。",
  CONTROL_CURSOR_INVALID: "分页凭证已失效，请重新查询。",
  CONTROL_CURSOR_UNAVAILABLE: "分页服务暂时不可用，请稍后重试。",
  CONTROL_SITE_ID_INVALID: "站点 ID 格式无效。",
  CONTROL_SITE_CURSOR_INVALID: "站点分页凭证已失效，请重新查询。",
  CONTROL_SITE_CONFIG_UNAVAILABLE: "站点配置存储暂时不可用，请稍后重试。",
  CONTROL_SITE_APPLY_STATE_UNAVAILABLE: "站点发布状态暂时不可用，请稍后重试。",
  CONTROL_SITE_NOT_FOUND: "当前身份和范围内站点不可用。",
  CONTROL_SITE_CONFIG_REQUEST_INVALID: "站点配置请求无效，请检查输入字段。",
  CONTROL_SITE_POLICY_INVALID: "站点策略未通过校验，请修正后重试。",
  CONTROL_SITE_PORT_UNAVAILABLE: "站点监听端口不可用，请选择其他端口。",
  CONTROL_SITE_APPROVAL_REQUIRED: "该发布需要独立审批后才能继续。",
  CONTROL_SITE_APPROVAL_SELF_REJECTED: "发布者不能审批自己的变更。",
  CONTROL_SITE_APPROVAL_NOT_REQUIRED: "当前发布不需要审批。",
  CONTROL_SITE_ROLLBACK_UNAVAILABLE: "站点回滚状态暂时不可用，请稍后重试。",
  CONTROL_SITE_HEALTH_UNAVAILABLE: "站点健康状态暂时不可用，请稍后重试。",
  CONTROL_SITE_HEALTH_CLIENT_UNAVAILABLE: "站点健康检查客户端暂时不可用，请稍后重试。",
  CONTROL_SITE_UPSTREAM_INVALID: "上游地址无效，请检查站点配置。",
  CONTROL_SITE_SSRF_BLOCKED: "上游地址被安全策略拒绝。",
  CONTROL_SITE_UPSTREAM_UNAVAILABLE: "上游服务暂时不可用，请稍后重试。",
  CONTROL_SITE_UPSTREAM_STATUS_UNEXPECTED: "上游返回了未预期的状态，请检查健康路径。",
  CONTROL_SITE_DELETE_EDGE_NOT_CONFIRMED: "edge 尚未确认站点删除，当前未完成操作。",
  CONTROL_SITE_DELETE_CONCURRENT_UPDATE: "站点正在被其他操作更新，请重新读取后重试。",
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
  REQUEST_TIMEOUT: "请求超时；写入结果可能未知，请使用原键与参数确认。",
  REQUEST_ABORTED: "客户端请求已取消；已准入的服务端操作仍可能完成。",
  NETWORK_UNAVAILABLE: "无法连接管理服务，请检查连接后重试。",
  QUERY_DIGEST_UNAVAILABLE: "当前环境无法验证查询摘要，请使用 HTTPS 或本机浏览器。",
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

export const uuid = "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
// JavaScript's $ also matches before a trailing line terminator. IDs must
// consume the entire input, both before transport and when decoding a reply.
const endOfInput = "(?![\\s\\S])";
export const requestPattern = new RegExp(`^req_${uuid}${endOfInput}`);
export const artifactPattern = new RegExp(`^artifact_${uuid}${endOfInput}`);
export const modelCallPattern = new RegExp(`^mdl_${uuid}${endOfInput}`);
export const agentRunPattern = new RegExp(`^agt_${uuid}${endOfInput}`);
export const jobPattern = new RegExp(`^job_${uuid}${endOfInput}`);
export const calibrationReportPattern = new RegExp(`^calr_${uuid}${endOfInput}`);
export const eventPattern = new RegExp(`^ev_${uuid}${endOfInput}`);
export const grantPattern = new RegExp(`^grant_${uuid}${endOfInput}`);
export const bindingPattern = new RegExp(`^auth_${uuid}${endOfInput}`);
export const sharePattern = new RegExp(`^share_${uuid}${endOfInput}`);
export const cursorPattern = /^[A-Za-z0-9_.-]{1,160}$/;

export function ensure(condition: unknown): asserts condition {
  if (!condition) throw new ApiError("INVALID_RESPONSE");
}
export function object(value: unknown): Record<string, unknown> {
  ensure(value !== null && typeof value === "object" && !Array.isArray(value));
  return value as Record<string, unknown>;
}
export function text(value: unknown, max = 128, empty = false): string {
  ensure(typeof value === "string" && value.length <= max && (empty || value.length > 0));
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
  ensure(pattern.exec(result)?.[0] === result);
  return result;
}
export function integer(value: unknown, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  ensure(typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max);
  return value;
}
export function bool(value: unknown): boolean {
  ensure(typeof value === "boolean");
  return value;
}
export function choice<T extends string>(value: unknown, values: readonly T[]): T {
  ensure(typeof value === "string" && (values as readonly string[]).includes(value));
  return value as T;
}
export function nullable<T>(value: unknown, decode: (value: unknown) => T): T | null {
  return value === null ? null : decode(value);
}
export function list<T>(value: unknown, max: number, decode: (value: unknown) => T): T[] {
  ensure(Array.isArray(value) && value.length <= max);
  return value.map(decode);
}
export function timestamp(value: unknown): string {
  const result = text(value, 40);
  ensure(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|\+00:00)$/.test(result));
  const time = Date.parse(result);
  ensure(Number.isFinite(time));
  // Preserve recorded calendar facts; Date.parse otherwise normalizes bad days.
  ensure(new Date(time).toISOString().slice(0, 19) === result.slice(0, 19));
  return result;
}
export function references(value: unknown, pattern: RegExp, max = 256): string[] {
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
        producer_boot_id: id(watermark.producer_boot_id, new RegExp(`^${uuid}$`)),
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
      ? (["", "provided", "not_applicable", "not_provided", "unavailable"] as const)
      : (["provided", "not_applicable", "not_provided", "unavailable"] as const),
  );
  const confidence = nullable(value.confidence, (item) => {
    ensure(typeof item === "number" && Number.isFinite(item) && item >= 0 && item <= 1);
    return item;
  });
  ensure((confidence !== null) === (confidence_status === "provided"));
  ensure(
    proof_kind !== "deterministic" ||
      (confidence === null && confidence_status === "not_applicable"),
  );
  ensure(!["SKIPPED", "CANCELLED"].includes(String(value.outcome)) || confidence === null);
  return { proof_kind, confidence, confidence_status };
}
