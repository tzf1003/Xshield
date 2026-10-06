import { messages } from "../api-contract.ts";
import { operationReason } from "./operation-reasons.ts";

/**
 * Human text and a recommended next action for every site, apply, edge and health reason code
 * the Rust sources can emit. tests/reason-codes.test.ts scans those sources and fails when a
 * code appears without an entry here, so the console can never show a bare code to an operator.
 *
 * The raw code is always shown next to the text (support quotes it); the text never repeats
 * server detail, request bodies or credentials.
 */
export type ReasonTone = "success" | "info" | "warning" | "danger" | "neutral";

export type ReasonEntry = Readonly<{
  /** What happened, in plain words. */
  text: string;
  /** What the operator should do next. */
  action: string;
  tone: ReasonTone;
}>;

const entry = (tone: ReasonTone, text: string, action: string): ReasonEntry => ({
  text,
  action,
  tone,
});

const NONE = "无需操作。";

export const reasonDictionary = {
  // ---- Successful facts: the server records them as the reason of a finished operation ----
  CONTROL_SITES_LISTED: entry("success", "站点列表已读取。", NONE),
  CONTROL_SITE_CONFIG_READ: entry("success", "站点配置已读取。", NONE),
  CONTROL_SITE_STATUS_READ: entry("success", "站点状态已读取。", NONE),
  CONTROL_SITE_REVISIONS_READ: entry("success", "修订历史已读取。", NONE),
  CONTROL_SITE_HEALTH_OBSERVED: entry("success", "健康观察已读取。", NONE),
  CONTROL_SITE_CONFIG_CREATED: entry(
    "success",
    "站点已创建，配置保存为第一个修订。",
    "到“发布”页查看这个修订是否需要审批。",
  ),
  CONTROL_SITE_CONFIG_UPDATED: entry(
    "success",
    "配置已保存为新的修订。",
    "到“发布”页查看它是否需要审批，以及 edge 何时开始使用。",
  ),
  CONTROL_SITE_CONFIG_REPLAYED: entry(
    "info",
    "这是同一次保存请求的重放：结果与首次相同，没有产生新修订。",
    NONE,
  ),
  CONTROL_SITE_VALIDATED: entry("success", "已保存的配置通过了服务端校验。", NONE),
  CONTROL_SITE_APPROVED: entry("info", "已批准，等待 edge 确认应用。", "稍后读取状态确认已生效。"),
  CONTROL_SITE_APPROVED_AND_APPLIED: entry("success", "已批准，edge 已确认并开始使用。", NONE),
  CONTROL_SITE_APPROVED_PENDING: entry(
    "warning",
    "已批准，但 edge 尚未确认；edge 仍在使用上一份已确认的配置。",
    "稍后刷新状态；长时间未生效时点击“应用”重试，并检查 edge 应用通道。",
  ),
  CONTROL_SITE_APPLY_ACTIVE: entry("success", "edge 已确认当前配置。", NONE),
  CONTROL_SITE_PAUSED: entry(
    "neutral",
    "站点处于暂停状态，edge 不对外提供服务。",
    "需要恢复服务时把状态改为“启用”，保存并经审批后应用。",
  ),
  CONTROL_SITE_DELETED: entry("success", "站点已删除，监听端口已释放。", NONE),
  CONTROL_SITE_DELETE_REPLAYED: entry("info", "这是同一次删除请求的重放：结果与首次相同。", NONE),
  CONTROL_SITE_UPSTREAM_HEALTHY: entry("success", "源站健康检查通过。", NONE),

  // ---- Approval and release state ----
  CONTROL_SITE_APPROVAL_REQUIRED: entry(
    "warning",
    "这次变更涉及安全相关配置，需要另一位审批人批准后才会发布；在此期间 edge 继续使用上一份已批准的配置。",
    "请具备“策略审批”角色的同事在“发布”页审阅差异后批准。",
  ),
  CONTROL_SITE_APPROVAL_NOT_REQUIRED: entry(
    "info",
    "当前修订不需要审批。",
    "无需批准，直接应用即可。",
  ),
  CONTROL_SITE_APPROVAL_SELF_REJECTED: entry(
    "danger",
    "审批人不能批准自己提交的修订。",
    "请由另一位具备“策略审批”角色的同事批准。",
  ),
  CONTROL_SITE_APPROVAL_REVISION_MISMATCH: entry(
    "danger",
    "待审批的修订在您审阅之后发生了变化，本次批准没有生效。",
    "重新读取站点，审阅新的差异后再批准。",
  ),
  CONTROL_SITE_DRAFT_NOT_APPLICABLE: entry(
    "warning",
    "草稿站点不会发布到 edge，因此不能应用。",
    "把状态改为“启用”并保存；它属于上线变更，需审批后才会应用。",
  ),
  CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED: entry(
    "danger",
    "这次写入已被更新的保存取代，请求没有创建新修订。",
    "不要原样重试：重新读取站点，在最新配置上重新修改。",
  ),
  CONTROL_SITE_ROLLBACK_UNAVAILABLE: entry(
    "warning",
    "没有可回滚的目标：站点此前没有生效过其他修订。",
    "在“发布”页查看修订历史；需要还原内容时由配置管理员保存所需配置。",
  ),
  CONTROL_SITE_INDEPENDENT_APPROVAL_REQUIRED: entry(
    "warning",
    "该修订改变了浏览器来源流程（认证入口、SENSOR_HTML 页面、页面签发或资源资格），只能由另一位审批人批准；“直接应用”能力不能代替审批，什么也没有发布。",
    "请具备“策略审批”角色的同事在“发布”页审阅差异后批准。",
  ),

  // ---- Request validation ----
  CONTROL_SITE_ID_INVALID: entry(
    "danger",
    "站点 ID 格式不正确：只允许字母、数字和 _ . -，最长 123 个字符。",
    "修改站点 ID 后重试。",
  ),
  CONTROL_SITE_NOT_FOUND: entry(
    "warning",
    "站点不存在，或当前身份看不到它。",
    "回到站点列表确认站点 ID 与访问范围。",
  ),
  CONTROL_SITE_CURSOR_INVALID: entry("warning", "站点分页凭证已失效。", "刷新列表重新加载。"),
  CONTROL_SITE_CONFIG_REQUEST_INVALID: entry(
    "danger",
    "配置没有通过服务端校验（公开入口、监听端口、名称或必填字段不合法）。",
    "按表单中的提示逐项修正后再保存。",
  ),
  CONTROL_SITE_POLICY_INVALID: entry(
    "danger",
    "路由或策略不合法，例如路径重复、准入与操作来源不匹配、限额冲突、引用格式错误。",
    "到“路由与操作”“WAF 与限流”“加密”检查并修正。",
  ),
  CONTROL_SITE_AUTH_FLOW_INVALID: entry(
    "danger",
    "认证入口或身份建立/撤销规则不合法：auth_binding 只能用于认证入口，auth_revoke 只能用于已认证根，成功状态、JSON 指针或期限越界。",
    "在“路由与操作”打开认证入口或登出路由，按“身份建立”“身份撤销”中的提示修正后重新保存。",
  ),
  CONTROL_SITE_SENSOR_HTML_INVALID: entry(
    "danger",
    "SENSOR_HTML 页面不合法：需要启用浏览器探针、GET 方法和完整的构建适配（64 位小写摘要、小于响应上限的注入偏移、不重复的构建），且不能同时加密或签发身份与资格。",
    "在“路由与操作”打开页面路由，用“从页面源码计算”重新填写摘要与偏移，并在“安全入口”启用浏览器探针后重新保存。",
  ),
  CONTROL_SITE_PAGE_ACTIONS_INVALID: entry(
    "danger",
    "页面签发不合法：page_actions 只能用于已认证的 SENSOR_HTML 页面根，每个页面签发 1–16 个动作，issued_by 必须指向这样的页面，且只能用于非资源的界面操作路由。",
    "在“路由与操作”核对页面路由的“页面签发动作”和各动作路由的“由页面签发”后重新保存。",
  ),
  CONTROL_SITE_RESOURCE_GRANT_INVALID: entry(
    "danger",
    "响应资源资格不合法：目标必须是已存在、绑定资源的“必须有界面操作来源”路由，指针、数量、期限需在边界内。",
    "在“路由与操作”打开列表路由，核对“响应资源资格”的目标详情路由与参数后重新保存。",
  ),
  CONTROL_SITE_ACTION_DESCRIPTOR_CONFLICT: entry(
    "danger",
    "同一操作来源与映射修订被两条路由赋予了不同含义，edge 无法为它建立唯一的动作描述。",
    "为其中一条路由换用不同的操作来源或映射修订后重新保存。",
  ),
  CONTROL_SITE_POLICY_REVISION_REUSED: entry(
    "danger",
    "这个策略版本（policy_revision）标签已经绑定本站点另一组页面动作描述（或已被 edge 停用）。同一标签只能对应一组描述，否则 edge 会拒绝整个租户的快照，所以本次变更没有保存、没有批准或没有下发。",
    "为改变了页面动作的这次变更设置一个从未用过的新策略版本标签后重新保存；回到某个已用过的标签时，页面动作必须与当时完全相同。",
  ),
  CONTROL_SITE_FEATURE_UNSUPPORTED: entry(
    "danger",
    "配置使用了控制面尚不能管理的 edge 功能（分享签发、凭证续期、上下文切换、证据采集、兼容加密、分享或服务身份入口），整份配置未保存。",
    "移除这些字段；需要这些功能时由部署方另行评估。",
  ),
  CONTROL_SITE_PORT_UNAVAILABLE: entry(
    "danger",
    "监听端口已被占用，或不在可分配范围内。",
    "把监听端口改为 0（自动分配），或选择 6100–65535 内未被占用的端口。",
  ),
  CONTROL_SITE_UPSTREAM_INVALID: entry(
    "danger",
    "上游配置不合法：地址必须是 IP 字面量加端口（IPv6 写作 [地址]:端口），服务名必须是域名而不是 IP。",
    "修改上游地址或服务名后重试。",
  ),
  CONTROL_SITE_SSRF_BLOCKED: entry(
    "danger",
    "上游地址被安全策略拒绝：内网、回环、链路本地、云元数据、文档示例网段，以及 IPv4 映射或转换形式的地址都不能作为上游。",
    "改用源站的公网 IP 字面量；本地靶场需要部署方显式开启回环放行。",
  ),

  // ---- Storage and dependency failures ----
  CONTROL_SITE_CONFIG_UNAVAILABLE: entry(
    "danger",
    "站点配置存储暂时不可用。",
    "稍后重试；如果是写入，结果可能未知，请使用“确认后原样重试”。",
  ),
  CONTROL_SITE_APPLY_STATE_UNAVAILABLE: entry(
    "danger",
    "站点发布状态存储暂时不可用。",
    "稍后重试；如果是批准或应用，结果可能未知，请使用“确认后原样重试”。",
  ),
  CONTROL_SITE_HEALTH_UNAVAILABLE: entry(
    "warning",
    "站点健康观察暂时不可用。",
    "稍后重新读取健康状态。",
  ),
  CONTROL_SITE_HEALTH_CLIENT_UNAVAILABLE: entry(
    "warning",
    "控制面的健康探测组件暂时不可用。",
    "稍后重新读取；持续失败请联系部署方。",
  ),
  CONTROL_SITE_UPSTREAM_UNAVAILABLE: entry(
    "danger",
    "控制面无法连接源站（超时或拒绝连接）。",
    "确认源站在线、端口开放，且防火墙允许控制面访问。",
  ),
  CONTROL_SITE_UPSTREAM_STATUS_UNEXPECTED: entry(
    "warning",
    "源站的健康路径返回了与期望不符的状态码。",
    "核对“策略与健康”中的健康检查路径与期望状态码。",
  ),
  CONTROL_SITE_DELETE_EDGE_NOT_CONFIRMED: entry(
    "danger",
    "edge 尚未确认已移除该站点：站点保持暂停，记录没有删除。",
    "稍后重试删除；仍失败请检查 edge 应用通道。",
  ),
  CONTROL_SITE_DELETE_CONCURRENT_UPDATE: entry(
    "warning",
    "站点正被其他操作修改，删除没有执行。",
    "重新读取站点，确认后再决定是否删除。",
  ),
  CONTROL_SITE_DELETE_STEP_UP_REQUIRED: entry(
    "warning",
    "删除站点需要两分钟内完成的 MFA 再认证；站点和 edge 都没有变化。",
    "点击“重新验证高危操作”完成再认证，然后在两分钟内重试同一个请求。",
  ),
  CONTROL_STEP_UP_REQUIRED: entry(
    "warning",
    "批准需要两分钟内完成的 MFA 再认证。",
    "点击“重新验证高危操作”完成再认证，然后重新审阅并批准。",
  ),
  CONTROL_IDEMPOTENCY_CONFLICT: entry(
    "danger",
    "同一个幂等键已被用于内容不同的请求。",
    "不要重试：重新读取站点，以新的请求重新提交。",
  ),
  CONTROL_IDEMPOTENCY_KEY_INVALID: entry(
    "danger",
    "请求缺少合法的幂等键。",
    "刷新页面后重试；仍失败请联系管理员。",
  ),
  CONTROL_CURSOR_UNAVAILABLE: entry("warning", "分页服务暂时不可用。", "稍后刷新列表。"),
  CONTROL_SCOPE_DENIED: entry(
    "danger",
    "当前身份没有这个站点操作的权限。",
    "确认所需角色，必要时联系管理员；隐藏入口不等于授权，服务端会逐次校验。",
  ),

  // ---- Edge apply channel ----
  EDGE_APPLY_CONFIRMED: entry("success", "edge 已确认并开始使用该配置。", NONE),
  EDGE_APPLY_NOT_CONFIRMED: entry(
    "warning",
    "edge 还没有确认这份配置；它仍在使用上一份已确认的配置。",
    "稍后刷新状态；长时间未确认时点击“应用”重试，并检查 edge 应用通道。",
  ),
  EDGE_DIRECT_APPLY_CONFIRMED: entry(
    "info",
    "该修订由持有直接应用能力的 Agent Key 应用，edge 已确认，并留下了审批记录。",
    "在审计中核对调用主体。",
  ),
  EDGE_DIRECT_APPLY_NOT_CONFIRMED: entry(
    "warning",
    "Agent 的直接应用没有得到 edge 确认。",
    "刷新状态；需要时由发布操作员重新应用。",
  ),
  EDGE_UNAVAILABLE: entry(
    "danger",
    "控制面连不上 edge 的应用通道。",
    "检查 edge 进程和应用通道地址，恢复后点击“应用”。",
  ),
  EDGE_APPLY_REJECTED: entry(
    "danger",
    "edge 拒绝了这份配置快照。",
    "把请求 ID 提供给管理员核对 edge 日志。",
  ),
  EDGE_APPLY_STALE_REVISION: entry(
    "warning",
    "edge 已经在使用更新的快照，这次落后的应用被拒绝。",
    "刷新状态确认 active 版本；仍需要时重新应用。",
  ),
  EDGE_APPLY_VALIDATION_FAILED: entry(
    "danger",
    "edge 的编译器拒绝了这份配置（与控制面校验不一致）。",
    "检查路由与策略，并把请求 ID 提供给管理员。",
  ),
  EDGE_APPLY_SCOPE_DENIED: entry(
    "danger",
    "快照的租户范围与该 edge 不匹配，edge 拒绝应用。",
    "联系部署方核对控制面与 edge 的租户配置。",
  ),
  EDGE_APPLY_LISTENER_UNAVAILABLE: entry(
    "danger",
    "edge 无法绑定配置所需的监听端口。",
    "更换监听端口，或检查端口是否被其他进程占用。",
  ),
  EDGE_APPLY_IDEMPOTENCY_CONFLICT: entry(
    "danger",
    "edge 收到同一应用标识但内容不同的快照。",
    "重新应用；仍失败请联系管理员。",
  ),
  EDGE_APPLY_DESCRIPTOR_CONFLICT: entry(
    "danger",
    "edge 拒绝了整份快照：某个站点由配置推导的界面动作描述与该策略修订已登记的描述不一致（摘要不同、修订已停用或某条描述含义改变）。租户内其他站点的变更同样没有生效，edge 继续使用上一份快照。",
    "改变页面动作、路由或映射后，用新的策略修订号重新保存并应用；同一修订号不能改变含义。edge 应答中的 site_id 指明出问题的站点。",
  ),
  EDGE_APPLY_DESCRIPTOR_UNAVAILABLE: entry(
    "danger",
    "edge 无法把站点的界面动作描述写入 PostgreSQL（数据库不可达、超时，或 edge 启动时没有配置身份存储），拒绝了整份快照；租户内其他站点的变更同样没有生效，edge 继续使用上一份快照。",
    "恢复 edge 的数据库连接，或为 edge 配置身份存储后重新应用。",
  ),
  EDGE_APPLY_SIGNATURE_INVALID: entry(
    "danger",
    "edge 验签失败：控制面与 edge 的应用密钥不一致。",
    "联系部署方核对两端的应用密钥配置。",
  ),
  EDGE_APPLY_SIGNATURE_UNAVAILABLE: entry(
    "danger",
    "签名组件不可用，应用请求没有发出或没有通过验证。",
    "联系部署方检查应用密钥配置。",
  ),
  EDGE_APPLY_PAYLOAD_INVALID: entry(
    "danger",
    "控制面无法生成合法的快照，应用请求没有发出。",
    "把请求 ID 提供给管理员。",
  ),
  EDGE_APPLY_ACK_INVALID: entry(
    "danger",
    "edge 的回执与请求不匹配，已按“未确认”处理。",
    "刷新状态；仍未确认时重新应用并检查 edge。",
  ),
  EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE: entry(
    "danger",
    "edge 无法持久化快照，拒绝切换配置；它继续使用上一份快照。",
    "检查 edge 快照目录的磁盘空间与权限后重新应用。",
  ),
  EDGE_HEALTH_UNAVAILABLE: entry(
    "warning",
    "edge 健康接口不可用。",
    "稍后重新读取；持续失败请检查 edge 进程。",
  ),
  EDGE_HEALTH_INVALID: entry(
    "warning",
    "edge 返回了无法识别的健康数据。",
    "把请求 ID 提供给管理员。",
  ),
} as const satisfies Record<string, ReasonEntry>;

export type ReasonCode = keyof typeof reasonDictionary;

/** Risk tokens of `assess_change_risk` (crates/xshield-core/src/site/risk.rs). */
export type RiskToken =
  | "ACTIVATION"
  | "TAKEDOWN"
  | "UPSTREAM_CHANGED"
  | "ORIGIN_CHANGED"
  | "LISTEN_PORT_CHANGED"
  | "ENTRY_CHANGED"
  | "ROUTES_CHANGED"
  | "IDENTITY_CHANGED"
  | "CRYPTO_CHANGED"
  | "WAF_CHANGED"
  | "LIMITS_CHANGED"
  | "HEALTH_CHECK_CHANGED"
  | "SECRET_REFS_CHANGED"
  | "SENSOR_CHANGED"
  | "STATIC_ASSET_POLICY_CHANGED"
  | "OBJECT_ACCESS_CHANGED"
  | "AUTH_ENTRY_CHANGED"
  | "SENSOR_HTML_CHANGED"
  | "PAGE_ACTIONS_CHANGED"
  | "RESOURCE_GRANT_CHANGED"
  | "OTHER_CHANGE";

export const riskDictionary: Record<RiskToken, Readonly<{ label: string; detail: string }>> = {
  ACTIVATION: {
    label: "站点开始对外服务",
    detail: "新建即启用、草稿转启用或暂停转启用都属于上线，无论其余字段是否变化。",
  },
  TAKEDOWN: {
    label: "正在服务的站点将被停止",
    detail: "把正在服务的站点暂停或改回草稿，会让它从 edge 消失。",
  },
  UPSTREAM_CHANGED: {
    label: "上游变更",
    detail: "上游地址、服务名或 TLS 模式决定流量发往哪里。",
  },
  ORIGIN_CHANGED: {
    label: "公开 origin 变更",
    detail: "公开 origin 用于 Host 路由和浏览器探针。",
  },
  LISTEN_PORT_CHANGED: { label: "内部监听端口变更", detail: "edge 将在另一个端口上监听该站点。" },
  ENTRY_CHANGED: { label: "入口路径或入口准入变更", detail: "决定谁能进入站点的第一道门。" },
  ROUTES_CHANGED: {
    label: "路由变更",
    detail: "路由的增删改，包括准入、操作来源、资源绑定、加解密、响应模式与大小。",
  },
  IDENTITY_CHANGED: { label: "身份绑定变更", detail: "身份 profile、会话期限或代际发生变化。" },
  CRYPTO_CHANGED: { label: "站点加密适配变更", detail: "适配器、失败策略或协议版本发生变化。" },
  WAF_CHANGED: {
    label: "WAF 变更",
    detail: "启用状态、拦截请求头、查询阻断片段或 Cookie 上限发生变化。",
  },
  LIMITS_CHANGED: {
    label: "限额变更",
    detail: "请求/响应体与速率限额的任何方向变化（包括调高）都需审批。",
  },
  HEALTH_CHECK_CHANGED: {
    label: "健康检查变更",
    detail: "健康检查路径、间隔、超时或期望状态发生变化。",
  },
  SECRET_REFS_CHANGED: {
    label: "密钥引用变更",
    detail: "引用、Key ID 或状态发生变化（不含密钥正文）。",
  },
  SENSOR_CHANGED: { label: "浏览器探针变更", detail: "探针注入的开关发生变化。" },
  STATIC_ASSET_POLICY_CHANGED: {
    label: "静态资源兜底深度变更",
    detail: "公开静态资源的路径深度上限发生变化。",
  },
  OBJECT_ACCESS_CHANGED: {
    label: "源站对象级校验标记变更",
    detail: "是否向源站传递对象所有者校验标记发生变化。",
  },
  AUTH_ENTRY_CHANGED: {
    label: "认证入口或身份建立/撤销变更",
    detail: "决定谁获得或失去身份绑定；只能由独立审批人批准，直接应用能力不能代替。",
  },
  SENSOR_HTML_CHANGED: {
    label: "SENSOR_HTML 页面变更",
    detail: "决定 edge 向哪些固定摘要的页面构建注入探针并放行；只能由独立审批人批准。",
  },
  PAGE_ACTIONS_CHANGED: {
    label: "页面签发动作变更",
    detail: "决定页面交付时签发哪些首跳界面操作；只能由独立审批人批准。",
  },
  RESOURCE_GRANT_CHANGED: {
    label: "响应资源资格变更",
    detail: "决定列表响应为哪些资源签发哪个详情动作；只能由独立审批人批准。",
  },
  OTHER_CHANGE: {
    label: "其他安全相关字段变更",
    detail: "未被上面任何分类命名的差异，按默认规则同样视为风险。",
  },
};

export type ReasonView = ReasonEntry & Readonly<{ code: string; known: boolean }>;

const fallbackAction = "把原因码和请求 ID 提供给管理员。";

/**
 * Text for any reason or error code. Site, apply, edge and health codes come from the
 * dictionary; generic control codes fall back to the safe message table of the API client, and
 * anything else is reported honestly as unrecognized (with the raw code kept visible).
 */
export function reasonText(code: string | null | undefined): ReasonView {
  if (code === null || code === undefined || code === "") {
    return { code: "", known: false, tone: "neutral", text: "服务端没有给出原因。", action: NONE };
  }
  if (Object.hasOwn(reasonDictionary, code)) {
    return { ...reasonDictionary[code as ReasonCode], code, known: true };
  }
  // Workbench, API-key, session, audit-publication and job codes (src/ui/operation-reasons.ts).
  const operation = operationReason(code);
  if (operation) return { ...operation, code, known: true };
  if (Object.hasOwn(messages, code)) {
    return {
      code,
      known: true,
      tone: "danger",
      text: messages[code as keyof typeof messages],
      action: fallbackAction,
    };
  }
  return {
    code,
    known: false,
    tone: "neutral",
    text: "服务端返回了控制台尚未识别的原因码。",
    action: fallbackAction,
  };
}

export function riskText(token: RiskToken): Readonly<{ label: string; detail: string }> {
  return riskDictionary[token];
}
