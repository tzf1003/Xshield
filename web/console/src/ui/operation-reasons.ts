import type { ReasonEntry, ReasonTone } from "./reason-codes.ts";

/**
 * Plain-language text for the stable codes behind the workbench, the management API keys, the
 * browser session, the audit publication read and the case-analysis jobs. It extends the site
 * dictionary in `reason-codes.ts` (whose `reasonText` consults this table second); the two tables
 * never repeat a code, so every code has exactly one wording.
 *
 * `label` is the short word shown inside a pill or a table cell, `text` what the code means and
 * `action` what the operator can do next. tests/operation-reasons.test.ts scans the Rust sources
 * (`workbench.rs`, `management_api_key.rs`, `api_key_authz.rs`, `identity.rs`, the audit-health
 * and API-key codes of `lib.rs`, and the job codes) and fails when a code has no entry here or in
 * the site dictionary, and when a `WORKBENCH_*` code lacks a Chinese label and explanation.
 */
export type OperationReasonEntry = ReasonEntry & Readonly<{ label: string }>;

const entry = (
  tone: ReasonTone,
  label: string,
  text: string,
  action: string,
): OperationReasonEntry => ({ tone, label, text, action });

const NONE = "无需操作。";

export const operationReasons = {
  // ---- Workbench snapshot (crates/xshield-control/src/workbench.rs) ----
  WORKBENCH_OVERVIEW_READ: entry(
    "success",
    "快照已读取",
    "工作台快照已读取；本次读取已写入管理审计。",
    NONE,
  ),
  WORKBENCH_POSTURE_SCOPED: entry(
    "info",
    "按身份投影",
    "快照只汇总当前身份可见的来源：看不到的站点或审计观察不计入，也不代表它们健康。",
    "需要完整视图时，请具备相应角色的同事查看。",
  ),
  WORKBENCH_EDGE_PROBED: entry(
    "info",
    "实时探测",
    "读取快照时控制面实时探测了 edge 进程（最长等待 2 秒）；“不可用”表示 edge 没有回答、回答过慢或报告自身不可用。",
    NONE,
  ),
  WORKBENCH_EDGE_STATE_UNKNOWN: entry(
    "warning",
    "状态未知",
    "edge 已配置，但没有报告可识别的状态；不能据此判断它是否在服务。",
    "稍后刷新快照；持续出现请检查 edge 进程与其健康接口。",
  ),
  WORKBENCH_EDGE_NOT_CONFIGURED: entry(
    "neutral",
    "未配置",
    "控制面没有配置 edge 健康探测，所以没有观察 edge；这既不表示健康，也不表示故障。",
    "需要观察时请部署方配置 edge 健康探测。",
  ),
  WORKBENCH_EDGE_AUDIT_PROBED: entry(
    "info",
    "实时探测",
    "edge 在同一次探测中报告了它的耐久审计屏障；“不可用”表示 edge 当前无法保证请求审计落盘。",
    NONE,
  ),
  WORKBENCH_EDGE_AUDIT_UNKNOWN: entry(
    "warning",
    "未观察到",
    "edge 没有报告耐久审计屏障的可识别状态（或 edge 未配置、未回答）；不能据此判断审计能否落盘。",
    "检查 edge 进程与其审计目录，恢复后刷新快照。",
  ),
  WORKBENCH_UPSTREAM_LAST_OBSERVED: entry(
    "info",
    "上次观察",
    "源站状态是最近一次持久化的健康读取结果，带有它自己的观察时间，可能已经过时；读取快照本身不会探测源站。",
    "需要当前状态时点击“刷新健康”（会在服务端写入一条审计与一条观察记录）。",
  ),
  WORKBENCH_UPSTREAM_NEVER_OBSERVED: entry(
    "neutral",
    "从未观察",
    "该站点还没有任何一次健康读取，所以没有源站观察值。",
    "点击“刷新健康”读取一次（会在服务端写入一条审计与一条观察记录）。",
  ),
  WORKBENCH_UPSTREAM_STATE_UNKNOWN: entry(
    "warning",
    "无法识别",
    "最近一次健康观察存在，但记录的源站状态不在可识别范围内，不按健康处理。",
    "点击“刷新健康”重新读取；持续出现请联系管理员。",
  ),
  WORKBENCH_AUDIT_READ: entry(
    "success",
    "已读取",
    "快照包含审计发布观察：配置 journal 到索引目标的封存段发布状态。",
    NONE,
  ),
  WORKBENCH_AUDIT_NOT_AUTHORIZED: entry(
    "neutral",
    "未包含",
    "快照没有包含审计发布观察：当前身份没有 AuditAdministrator 角色，或该角色的发布状态读取失败（两种情况服务端使用同一原因码）。",
    "具备 AuditAdministrator 的同事可在“审计发布状态”页手动读取。",
  ),

  // ---- Management API keys (management_api_key.rs, api_key_authz.rs, lib.rs) ----
  CONTROL_API_KEYS_LISTED: entry(
    "success",
    "已读取",
    "Key 列表已读取：只有元数据，不含任何明文、指纹或范围。",
    NONE,
  ),
  CONTROL_API_KEY_CREATED: entry(
    "success",
    "已创建",
    "Agent API Key 已创建；明文只在这一次响应中出现。",
    "立即把明文保存到安全位置，关闭后无法再次查看。",
  ),
  CONTROL_API_KEY_REVOKED: entry(
    "success",
    "已撤销",
    "Key 已撤销并立即失效；之后使用它的请求会以 CONTROL_API_KEY_INVALID 被拒绝。",
    NONE,
  ),
  CONTROL_API_KEY_ROTATED_OUT: entry(
    "info",
    "已轮换（旧）",
    "旧 Key 在轮换事务中被撤销，与新 Key 的签发同时生效。",
    "把新 Key 部署给 Agent。",
  ),
  CONTROL_API_KEY_ROTATED_IN: entry(
    "success",
    "已轮换（新）",
    "轮换签发了新 Key；新明文只在这一次响应中出现。",
    "立即保存新明文并部署给 Agent。",
  ),
  CONTROL_API_KEY_AUTHENTICATED: entry(
    "success",
    "认证通过",
    "Agent 使用该 Key 通过了认证；“最近使用”每分钟最多更新一次。",
    NONE,
  ),
  CONTROL_API_KEY_REQUEST_INVALID: entry(
    "danger",
    "请求无效",
    "请求正文不是服务端接受的形状（字段缺失、多余或类型错误）；没有任何改变。",
    "刷新页面后重新填写；仍失败请联系管理员。",
  ),
  CONTROL_API_KEY_EXPIRY_INVALID: entry(
    "danger",
    "到期时间无效",
    "到期时间必须晚于服务端当前时间，且不超过 90 天之后；没有任何改变。",
    "改选 7、30 或 90 天预设，或把自定义时间设在 90 天以内。",
  ),
  CONTROL_API_KEY_SCOPE_INVALID: entry(
    "danger",
    "主体、名称或范围无效",
    "Agent 主体须为 1–128 个 ASCII 字母、数字或 . _ : @ / -，并以字母或数字开头；名称为 1–128 个字符，不能含控制、零宽或双向覆盖字符，也不能有首尾空白；范围只能是当前租户的站点，site.create 只能授予“整个租户”，“整个租户”也不能搭配其他能力。没有任何改变。",
    "按表单提示修正后重新提交；服务端不会替你裁剪或规范化输入。",
  ),
  CONTROL_API_KEY_SCOPE_FORBIDDEN: entry(
    "danger",
    "超出签发者权限",
    "请求的能力超过了当前会话自身可以行使的权限，整个请求被拒绝，不会裁剪后继续；轮换时旧 Key 保持有效。",
    "去掉当前角色无法行使的能力，或请具备相应角色的同事签发。只持有 KeyAdministrator 的会话只能撤销或轮换。",
  ),
  CONTROL_API_KEY_NOT_FOUND: entry(
    "warning",
    "Key 不存在或已撤销",
    "Key 不存在、属于其他租户或已被撤销。若这是结果未知之后的重试，先前那次尝试可能已经生效。",
    "刷新列表核对 Key 的当前状态。",
  ),
  CONTROL_API_KEY_UNAVAILABLE: entry(
    "danger",
    "Key 服务不可用",
    "Key 存储或签发组件暂时不可用；这次创建、轮换或撤销可能没有完成，也可能已经提交。",
    "刷新列表核对；写入结果未知时只能原样重试。",
  ),
  CONTROL_API_KEY_INVALID: entry(
    "danger",
    "Key 无效",
    "请求携带的 Key 未知、已过期或已撤销（HTTP 401）。",
    "为 Agent 换用一把有效的 Key。",
  ),
  CONTROL_API_KEY_SITE_EXISTS: entry(
    "warning",
    "站点已存在",
    "只持有 site.create 的 Key 不能读取或覆盖已存在的站点（HTTP 409）。",
    "改用同时持有该站点 site.config.write 的 Key，或由人员确认。",
  ),

  // ---- Browser session and OIDC (identity.rs) ----
  // The generic transport codes (CONTROL_AUTH_REQUIRED, CONTROL_CSRF_REQUIRED, CONTROL_RATE_*,
  // CONTROL_SESSION_UNAVAILABLE) keep the API client's safe message; they are not repeated here.
  CONTROL_BROWSER_SESSION_READ: entry(
    "success",
    "会话已读取",
    "浏览器管理会话的主体、范围与角色已读取。",
    NONE,
  ),
  CONTROL_BROWSER_SESSION_REVOKED: entry(
    "success",
    "已退出",
    "浏览器管理会话已在服务端撤销。",
    NONE,
  ),
  CONTROL_SESSION_REVOKED: entry(
    "warning",
    "会话已撤销",
    "这个浏览器会话已被撤销，不能再使用。",
    "重新登录。",
  ),
  CONTROL_ENTROPY_UNAVAILABLE: entry(
    "danger",
    "随机源不可用",
    "服务端无法生成安全随机数，登录或再认证没有开始。",
    "稍后重试；持续出现请联系部署方。",
  ),
  CONTROL_OIDC_LOGIN_STARTED: entry("info", "登录已开始", "企业身份登录已开始。", NONE),
  CONTROL_OIDC_LOGIN_COMPLETED: entry(
    "success",
    "登录完成",
    "企业身份登录完成，已建立管理会话。",
    NONE,
  ),
  CONTROL_OIDC_LOGIN_DENIED: entry(
    "danger",
    "登录被拒绝",
    "身份提供方拒绝了这次登录。",
    "确认账号状态后重新登录。",
  ),
  CONTROL_OIDC_MFA_REQUIRED: entry(
    "danger",
    "需要多因素认证",
    "身份提供方没有给出所要求的认证等级（MFA）。",
    "使用多因素认证重新登录。",
  ),
  CONTROL_OIDC_SUBJECT_NOT_PROVISIONED: entry(
    "danger",
    "身份未登记",
    "该身份不在部署侧的角色清单中，不能进入管理后台。",
    "请管理员登记该主体及其角色。",
  ),
  CONTROL_OIDC_STATE_INVALID: entry(
    "danger",
    "登录状态无效",
    "登录回调携带的状态与本浏览器发起的登录不一致。",
    "重新开始登录。",
  ),
  CONTROL_OIDC_STATE_EXPIRED: entry("warning", "登录已超时", "登录状态已过期。", "重新开始登录。"),
  CONTROL_OIDC_CALLBACK_INVALID: entry(
    "danger",
    "回调无效",
    "身份提供方的回调参数无效。",
    "重新开始登录。",
  ),
  CONTROL_OIDC_TOKEN_REJECTED: entry(
    "danger",
    "令牌交换失败",
    "身份提供方拒绝了令牌交换。",
    "重新开始登录；仍失败请联系管理员。",
  ),
  CONTROL_OIDC_ID_TOKEN_MISSING: entry(
    "danger",
    "缺少 ID Token",
    "令牌响应中没有 ID Token。",
    "联系管理员核对身份提供方配置。",
  ),
  CONTROL_OIDC_ID_TOKEN_REJECTED: entry(
    "danger",
    "ID Token 无效",
    "ID Token 的签名、受众或期限没有通过验证。",
    "重新登录；仍失败请联系管理员。",
  ),
  CONTROL_OIDC_ISSUER_MISMATCH: entry(
    "danger",
    "签发者不一致",
    "令牌签发者与配置的身份提供方不一致。",
    "联系管理员核对身份提供方配置。",
  ),
  CONTROL_OIDC_ACCESS_TOKEN_HASH_INVALID: entry(
    "danger",
    "令牌摘要不匹配",
    "Access Token 与 ID Token 中的摘要（at_hash）不匹配。",
    "重新登录；仍失败请联系管理员。",
  ),
  CONTROL_OIDC_AUTH_TIME_STALE: entry(
    "warning",
    "认证时间过旧",
    "再认证返回的认证时间过旧，不能证明刚刚完成了 MFA。",
    "在身份提供方重新完成认证。",
  ),
  CONTROL_OIDC_TRANSACTION_UNAVAILABLE: entry(
    "danger",
    "登录事务不可用",
    "登录事务存储暂时不可用。",
    "稍后重试。",
  ),
  CONTROL_OIDC_UNAVAILABLE: entry(
    "danger",
    "身份提供方不可用",
    "身份提供方暂时不可用。",
    "稍后重试。",
  ),
  CONTROL_OIDC_REAUTH_STARTED: entry("info", "再认证已开始", "MFA 再认证已开始。", NONE),
  CONTROL_OIDC_REAUTH_VERIFIED: entry(
    "success",
    "再认证完成",
    "MFA 再认证已完成；两分钟内的高危操作可以继续。",
    NONE,
  ),
  CONTROL_OIDC_REAUTH_REQUEST_INVALID: entry(
    "danger",
    "再认证请求无效",
    "再认证请求无效，没有开始。",
    "从需要再认证的操作重新开始。",
  ),
  CONTROL_OIDC_REAUTH_SESSION_INVALID: entry(
    "danger",
    "无法再认证",
    "再认证没有对应到当前浏览器会话；机器凭证没有再认证路径。",
    "使用企业身份登录后重试。",
  ),

  // ---- Audit publication read (lib.rs) ----
  CONTROL_HEALTH_READ: entry(
    "success",
    "已读取",
    "审计发布状态已读取；本次读取已写入管理审计。",
    NONE,
  ),
  CONTROL_HEALTH_UNAVAILABLE: entry(
    "warning",
    "暂不可用",
    "审计发布观察暂时不可用（journal 或索引状态读取失败）。",
    "稍后手动重新读取。",
  ),

  // ---- Case-analysis jobs (jobs.rs, xshield-postgres control_job.rs) ----
  CONTROL_CASE_ANALYSIS_COMPLETE: entry(
    "success",
    "清单分析完成",
    "案件清单分析已完成：只统计了案件成员与当前有效的目录引用数量，没有读取证据内容、调用模型或创建任何资格。",
    NONE,
  ),
  CONTROL_CASE_ANALYSIS_CREATED: entry("success", "已创建", "案件清单分析任务已创建。", NONE),
  CONTROL_CASE_ANALYSIS_REPLAYED: entry(
    "info",
    "原请求重放",
    "这是同一幂等请求的重放，返回的是原来的任务。",
    NONE,
  ),
  CONTROL_CASE_ANALYSIS_BUSY: entry(
    "warning",
    "服务繁忙",
    "案件分析服务繁忙，任务没有创建。",
    "稍后用原请求重试。",
  ),
  CONTROL_CASE_ANALYSIS_STORE_UNAVAILABLE: entry(
    "danger",
    "存储不可用",
    "案件分析存储暂时不可用；这次提交的结果可能未知。",
    "只能用原请求原样重试来确认。",
  ),
  CONTROL_CASE_ANALYSIS_TARGET_UNAVAILABLE: entry(
    "warning",
    "案件不可用",
    "案件不属于本人或不在当前范围内。",
    "回到案件工作台核对案件。",
  ),
  CONTROL_JOB_READ: entry("success", "已读取", "任务状态已读取；本次读取已写入管理审计。", NONE),
  CONTROL_JOB_ID_INVALID: entry(
    "danger",
    "任务 ID 无效",
    "任务 ID 必须是 job_ 加小写 UUIDv7。",
    "检查后重新输入。",
  ),
  CONTROL_JOB_STORE_UNAVAILABLE: entry(
    "warning",
    "任务存储不可用",
    "任务状态存储暂时不可用。",
    "稍后重新读取。",
  ),
} as const satisfies Record<string, OperationReasonEntry>;

export type OperationReasonCode = keyof typeof operationReasons;

/** The entry of a code in this table, or `null`; prototype members are never codes. */
export function operationReason(code: string | null | undefined): OperationReasonEntry | null {
  if (!code || !Object.hasOwn(operationReasons, code)) return null;
  return operationReasons[code as OperationReasonCode];
}
