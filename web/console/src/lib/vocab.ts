// Every user-visible word for decisions, outcomes, Jev answers, failures and errors lives here
// (docs/07 7.10.5, docs/06 6.6). Components read from this file; none of them spells these out.

import type {
  DecisionPath,
  ImpactKind,
  JevAccess,
  JevAttack,
  JevConclusion,
  JevFailure,
  JevHealth,
  JevRoute,
  NameReasonCode,
  ObjectEventKind,
  ObjectReason,
  ObjectSide,
  ObjectSource,
  ObjectState,
  Outcome,
  RefusedReason,
  ResponseSkip,
  SuggestionKind,
  UnknownApiReason,
  UpstreamError,
  ValueKind,
} from "../api/types.ts";
import type { ParseFailure } from "./logical-path.ts";

export type Tone = "blocked" | "would" | "unjudged" | "ok" | "neutral";

export const DECISION_INFO: Record<DecisionPath, { name: string; icon: string; desc: string }> = {
  bypass: { name: "绕过", icon: "→", desc: "命中绕过规则，不判定，直接转发" },
  fast_allow: { name: "快速放行", icon: "»", desc: "需核验的值都已核验，没有调用 Jev" },
  cached_allow: { name: "缓存放行", icon: "↺", desc: "复用缓存时长内 Jev 对同一请求的放行" },
  jev_allow: { name: "Jev 通过", icon: "✦", desc: "Jev 判定访问有依据、内容无攻击" },
  jev_deny: {
    name: "Jev 拒绝",
    icon: "✦",
    desc: "Jev 判定越权或攻击；观察模式下网关的结论是“本应拦截”",
  },
  jev_unavailable: {
    name: "Jev 不可用",
    icon: "∅",
    desc: "Jev 超时、出错、调用达到上限或答不上来，按站点设置处理",
  },
  no_session: { name: "无会话", icon: "⊘", desc: "没有会话凭证，路径也不是入口" },
  body_not_inspectable: {
    name: "请求体不可判定",
    icon: "⊟",
    desc: "请求体超过 48 KiB 或没有 Content-Length，返回 413",
  },
  unknown_site: { name: "未知站点", icon: "⊗", desc: "Host 不属于任何站点，返回 404" },
};

export const OUTCOME_INFO: Record<
  Outcome,
  { name: string; icon: string; tone: Tone; desc: string }
> = {
  allowed: { name: "放行", icon: "○", tone: "neutral", desc: "转发给源站" },
  blocked: {
    name: "拦截",
    icon: "■",
    tone: "blocked",
    desc: "网关返回 401 / 403 / 404 / 413，没有转发",
  },
  would_block: {
    name: "本应拦截",
    icon: "▲",
    tone: "would",
    desc: "观察模式下本应拦截，照常转发",
  },
  unjudged: {
    name: "未经判定",
    icon: "◆",
    tone: "unjudged",
    desc: "Jev 不可用且站点设置为放行，没有判定就转发",
  },
};

export const CONTEXT_LABEL: Record<"session" | "address", string> = {
  session: "会话",
  address: "地址",
};

export const CONTEXT_DESC: Record<"session" | "address", string> = {
  session: "上下文来自会话凭证",
  address: "未登录请求按客户端地址",
};

export const ACCESS_LABEL: Record<JevAccess, string> = {
  ALLOW: "有依据",
  DENY: "越权",
  UNKNOWN: "不确定",
};

export const ATTACK_LABEL: Record<JevAttack, string> = {
  BENIGN: "无攻击",
  ATTACK: "攻击",
  UNKNOWN: "不确定",
};

/** Jev's own conclusion. "放行 / 拦截 / 本应拦截" name the gateway's action only (docs/06 6.6). */
export const CONCLUSION_LABEL: Record<JevConclusion, string> = {
  allow: "通过",
  deny: "拒绝",
  unknown: "无法判定",
};

export const ROUTE_LABEL: Record<JevRoute, string> = {
  gateway: "经 AI Gateway",
  direct: "直连 TypeSafe",
  custom: "自定义地址",
};

export const VALUE_KIND_LABEL: Record<ValueKind, string> = {
  reference: "引用",
  route: "路由词",
  input: "输入",
};

export const HEALTH_LABEL: Record<JevHealth, { name: string; icon: string; tone: Tone }> = {
  ok: { name: "正常", icon: "●", tone: "ok" },
  idle: { name: "空闲", icon: "○", tone: "neutral" },
  degraded: { name: "降级", icon: "▲", tone: "would" },
  down: { name: "不可用", icon: "■", tone: "blocked" },
};

export const FAILURE_INFO: Record<JevFailure, { short: string; desc: string }> = {
  JEV_TIMEOUT: { short: "超时", desc: "超过所用超时仍未返回" },
  JEV_RATE_LIMITED: { short: "服务限流", desc: "模型服务返回 429" },
  JEV_TRANSPORT: { short: "连接失败", desc: "连接、TLS 或协议错误" },
  JEV_HTTP_ERROR: { short: "服务出错", desc: "模型服务返回非 200 状态" },
  JEV_RESPONSE_TOO_LARGE: { short: "响应过大", desc: "响应超过 64 KiB" },
  JEV_RESPONSE_INVALID: { short: "响应无效", desc: "响应结构不符合约定" },
  JEV_UNKNOWN: { short: "答不上来", desc: "最高项是 UNKNOWN 或两项并列" },
  JEV_STATE_TOO_LARGE: { short: "上下文过大", desc: "裁剪后仍超过 8 KiB，没有调用" },
  JEV_CALL_LIMIT: { short: "达到上限", desc: "会话或地址每分钟调用次数用完，没有调用" },
};

export const SKIP_LABEL: Record<ResponseSkip, string> = {
  status: "非 2xx",
  content_type: "类型不是 JSON 或 HTML",
  compressed: "响应被压缩",
  too_large: "超过 1 MiB",
  head: "HEAD 请求",
  not_forwarded: "请求没有转发",
};

export const UPSTREAM_LABEL: Record<UpstreamError, string> = {
  connect_refused: "连接被拒绝",
  connect_timeout: "连接超时",
  read_timeout: "读取超时",
  tls: "TLS 握手失败",
  other: "其他错误",
};

export const REFUSED_LABEL: Record<RefusedReason, string> = {
  unauthenticated: "未登录",
  forbidden: "越权或攻击，已拦截",
  body_not_inspectable: "请求体不可判定",
  unknown_site: "未知站点",
};

export const SUGGESTION_INFO: Record<SuggestionKind, string> = {
  entry_candidate: "登记入口",
  bypass_candidate: "加入绕过",
  upload_candidate: "上传接口加入绕过",
  raise_jev_timeout: "调大 Jev 超时",
  raise_call_limit: "调大调用上限",
  secret_field_candidate: "追加脱敏词",
  hot_would_block: "本应拦截集中的路径",
  object_proposals: "对象表待确认",
  route_rule_candidate: "可能是统一网关",
};

export const IMPACT_INFO: Record<ImpactKind, string> = {
  no_session_to_entry: "无会话请求改为按入口判定",
  entry_to_no_session: "入口请求改为无会话判定",
  judged_to_bypass: "不再判定，直接转发",
  bypass_to_judged: "开始判定",
  would_block_to_blocked: "观察模式切为拦截",
  blocked_to_would_block: "拦截切回观察",
  jev_timeout: "Jev 超时变化",
  call_limit: "调用上限变化",
  cache: "放行缓存变化",
  secret_fields: "脱敏范围变化",
  api_split: "按接口拆分",
  entry_unreachable: "入口不再命中",
  new_fast_allow: "新增快速放行",
  back_to_jev: "改回 Jev",
  cache_by_api: "缓存按接口区分",
};

export const WARNING_TEXT: Record<string, string> = {
  SESSION_CHANGED: "会话凭证改变后，现有会话的上下文全部作废，用户需要重新从入口进入",
  HOSTS_CHANGED: "Host 改变后流量路由也改变，无法从历史记录可靠预估",
  SYNONYMS_CHANGED: "同义词改变核验结果，无法从历史记录预估影响，保存后请观察一段时间",
  CACHE_RAISED: "放行缓存调大后，缓存放行的覆盖范围无法从历史记录预估",
  INTERFACE_UNVERIFIED: "接口名没有在历史里核对过，按接口和前缀入口的数字可能不完整",
};

export const PARAM_INFO = {
  jev_timeout_ms: {
    label: "Jev 超时",
    unit: "ms",
    min: 100,
    max: 30000,
    cost: "调大：慢链路下少按 Jev 不可用处理，但要判定的请求最多多等这么久；调小：反之",
  },
  session_calls_per_minute: {
    label: "会话调用上限",
    unit: "次/分钟",
    min: 1,
    max: 600,
    cost: "调大：单个会话能消耗的模型费用上限提高",
  },
  address_calls_per_minute: {
    label: "地址调用上限",
    unit: "次/分钟",
    min: 1,
    max: 600,
    cost: "NAT 或代理后多个用户共用一个地址时需要调大；调大后未登录请求能消耗的额度也提高",
  },
  allow_cache_minutes: {
    label: "放行缓存时长",
    unit: "分钟",
    min: 0,
    max: 60,
    cost: "调大：调用次数减少；修改配置或提示词后，旧的放行结论仍复用到期",
  },
  secret_fields: {
    label: "追加脱敏词",
    unit: "个",
    min: 0,
    max: 32,
    cost: "被脱敏的值 Jev 只看到长度，无法判断它是否越权。只加纯输入字段，不要加对象引用字段",
  },
  synonyms: {
    label: "同义词",
    unit: "组",
    min: 0,
    max: 32,
    cost: "加错会让短 ID 跨对象类型被当成已核验，放宽越权判定。只加确实指同一对象的词",
  },
} as const;

export const ERROR_TEXT: Record<string, string> = {
  UNAUTHENTICATED: "登录已过期，请重新登录",
  INVALID_PASSWORD: "口令不正确",
  LOGIN_RATE_LIMITED: "尝试次数过多，请 10 分钟后再试",
  SITE_NOT_FOUND: "站点不存在，可能已被删除",
  REQUEST_NOT_FOUND: "找不到这个请求",
  SITE_EXISTS: "已有同名站点",
  SITE_NAME_MISMATCH: "配置里的站点名与地址中的不一致",
  SITE_HOST_TAKEN: "Host 已属于其他站点",
  VERSION_CONFLICT: "配置已被修改",
  ROLLBACK_TARGET_DELETED: "目标版本是删除操作，不能回滚到它",
  SITE_CONFIG_MALFORMED: "配置不是有效的 JSON 对象，或含有不认识的字段",
  SITE_CONFIG_NAME_INVALID: "站点名只能用小写字母、数字、-、_，最长 64 个字符",
  SITE_CONFIG_HOSTS_INVALID: "Host 不能为空，最多 16 个，每个必须是有效的主机名",
  SITE_CONFIG_ORIGIN_INVALID: "源站地址必须是 http://主机[:端口] 或 https://主机[:端口]，不带路径",
  SITE_CONFIG_SESSION_INVALID: "会话凭证需要一个有效的 Cookie 名或请求头名",
  SITE_CONFIG_ENTRIES_INVALID: "入口至少一条、最多 64 条；每条以 / 开头，* 只能在末尾",
  SITE_CONFIG_BYPASS_INVALID: "绕过最多 64 条，规则格式同入口",
  SITE_CONFIG_ADVANCED_INVALID: "高级判定参数有误，请检查各项的取值范围",
  INVALID_FILTER: "筛选条件有误",
  WINDOW_TOO_LARGE: "时间范围最长 7 天",
  TOO_MANY_IDS: "一次最多对照 1000 个请求 ID",
  BODY_TOO_LARGE: "内容过大（配置最大 64 KiB，导入文件最大 100 MiB）",
  INTERNAL: "控制面出错，请稍后重试；问题持续时查看控制面日志",
};

/** The message for an API error code, falling back to a generic line that never echoes data. */
export function errorText(code: string | undefined): string {
  if (!code) return "请求失败，请稍后重试";
  return ERROR_TEXT[code] ?? `请求失败（${code}）`;
}

export const RANGE_LABEL = {
  "15m": "15 分钟",
  "1h": "1 小时",
  "6h": "6 小时",
  "24h": "24 小时",
  "7d": "7 天",
} as const;

// Words of the learning side of the site pages (docs/06 6.4.9, design 5 and 6): object classes in the history and
// the impact of a save, who made a version, and the notes that say how far an estimate can be trusted.

/** An object class in words, e.g. `doctor` is 医生. A class the console does not name is shown by its id. */
export const OBJECT_KIND_LABEL: Record<string, string> = {
  doctor: "医生",
  patient: "患者",
  document: "文档",
};

/** Who made a version: the learning task writes the automatic kinds, the one administrator the rest. */
export const AUTHOR_LABEL = {
  learning: "学习任务",
  admin: "管理员",
} as const;

/** The notes of an impact that the history cannot estimate exactly. */
export const IMPACT_NOTE = {
  /** The interface name comes from a request header, which the history does not keep. */
  afterSave: "保存后开始统计",
  /** The window kept only the first few sources of each value. */
  approximate: "来源只记录了前 3 个，结果是近似值",
  /** A cache change is a warning only: it is not counted. */
  notCounted: "只提示，不计数",
} as const;

// ------------------------------------------------------------------ interface-name rules (header-routes-design 2, 3)

/** The place a location of a rule reads its value from. */
export const ROUTE_SOURCE_LABEL: Record<"header" | "query" | "body", string> = {
  header: "请求头",
  query: "查询参数",
  body: "正文字段",
};

/** Why a request's interface name could not be read, in words. */
export const UNKNOWN_REASON_TEXT: Record<UnknownApiReason, string> = {
  missing: "这个位置没有值",
  repeated: "这个位置出现了多次，无法确定用哪一个",
  conflict: "同一段的几个位置取到的值不一致",
  invalid_name: "取到的值不是规整的名字（只允许字母、数字、. _ -，最长 64 个字符）",
  body_unsupported: "正文不是 JSON 或表单，或字段路径上是数组（批量调用）",
  body_not_json: "正文不是合法的 JSON（加密的正文也是这种情况）",
  body_too_large: "正文超过解析上限（48 KiB），读不到名字",
  route_subpath: "路径以 / 结尾，后面没有接口名",
};

export const UNKNOWN_API_LABEL = "未知接口";

export const ROUTE_HELP =
  "默认用 URL 路径作为接口名。只有接口名放在请求头、查询参数或正文字段里的路径才需要规则。";
export const ROUTE_SOURCE_HELP =
  "请求头名不分大小写。正文字段写成 a.b.c，不支持数组下标；正文是其他格式或加密时取不到，按未知接口处理。";
export const ROUTE_LOCATION_HELP = "同一段里的位置都出现时，值必须一致，不一致按未知接口处理。";
export const ROUTE_SINGLE_HINT =
  "每一段都只写了一个位置。如果源站在别处也接受接口名，请一并写上，否则网关和源站可能认成两个接口。";
export const ROUTE_ACK_LABEL = "我确认源站只认这里";
export const ROUTE_HEADER_NOTE = "过去的判定记录没有保存请求头，保存后才开始按接口统计。";
export const ROUTE_ADD_LOCATION = "＋ 源站也认的位置";
export const ROUTE_ADD_SEGMENT = "＋ 添加一段";
export const ROUTE_DELETE_SEGMENT = "删除这一段";
export const ROUTE_ADD_RULE = "＋ 添加规则";
export const ROUTE_DELETE_RULE = "删除规则";
export const ROUTE_CANDIDATE_TITLE = "按最近记录补全";
export const ROUTE_REWRITE_HINT = "改写为逻辑路径，例如：";
export const ROUTE_RECORD_WINDOW = "最近 500 条记录";
export const ROUTE_UNKNOWN_LINK = "查看这些请求";

export const ROUTE_TESTER_HELP =
  "粘贴一个完整的 HTTP 请求，或只输入一个路径。只在浏览器里解析，不会上传，也不会存进草稿。";
export const ROUTE_TESTER_NO_CREDENTIAL = "没有需要隐藏的凭证值";
export const ROUTE_TESTER_UNKNOWN_JUDGE = "不算入口，不走绕过，交给 Jev";

/** What the tester says when a pasted request cannot be read. */
export const ROUTE_TEST_FAILURE: Record<ParseFailure, string> = {
  request_line: "没有读到请求行：应写成「方法 路径」，例如 GET /api/x，或只输入一个以 / 开头的路径",
  target: "请求地址要以 / 开头，或是完整的 http:// 或 https:// 地址",
  header_line: "有一行请求头没有冒号，请检查粘贴的内容",
};

// ------------------------------------------------------------------ interface names and object classes
// Design 4 and 9 of console-design-objects-routes.md: the request trace, the request detail and the
// explanation read these words. `{src}` in a reason stands for the source that went wrong.

export const API_LABEL = {
  /** The short word of the detail's interface line. */
  api: "接口",
  name: "接口名",
  logical: "逻辑路径",
  unknown: "未知接口",
  object: "类别",
  objectMap: "对象表",
  inferred: "名字推断",
  mismatch: "类别不同",
} as const;

/** Where a rule reads a name segment from (`header.X-Service-Id` is a header). */
export const API_SOURCE_LABEL: Record<"header" | "query" | "body" | "path", string> = {
  header: "请求头",
  query: "查询参数",
  body: "正文字段",
  path: "URL 路径",
};

/** Why a name could not be read (types.ts `UnknownApiReason`); `desc` is the hover text. */
export const UNKNOWN_API_REASON: Record<UnknownApiReason, { text: string; desc: string }> = {
  missing: { text: "{src} 没有出现", desc: "规则要求的位置里没有接口名" },
  repeated: {
    text: "{src} 出现了多次",
    desc: "同一个位置出现多次时不取，源站可能取前一个，也可能取后一个",
  },
  conflict: { text: "{src} 与同组的位置不一致", desc: "源站在几个位置都认的接口名必须相同" },
  invalid_name: {
    text: "{src} 的值不合规",
    desc: "接口名只能用字母、数字、. _ - /，最长 64 个字符",
  },
  body_unsupported: {
    text: "正文结构不支持取 {src}",
    desc: "路径上遇到数组（例如批量调用）时不取",
  },
  body_not_json: { text: "正文不是 JSON，无法取 {src}", desc: "正文必须能解析成 JSON 才能取字段" },
  body_too_large: { text: "正文超过解析上限，无法取 {src}", desc: "超过解析上限的正文不解析" },
  route_subpath: {
    text: "路径在规则之下还有子路径",
    desc: "规则路径之下的子路径，接口名的位置不确定",
  },
};

// ------------------------------------------------------------------ the object map (console design 3, 9)
// Words of the site's object map tab, its drawer, the declaration and synonym dialogs, the learning settings
// and the cold start. Record text is never written here; it arrives as data and is shown as text nodes.

export const OBJECT_STATE_INFO: Record<
  ObjectState,
  { name: string; icon: string; tone: Tone; desc: string }
> = {
  pending: { name: "学习中", icon: "◌", tone: "neutral", desc: "在攒证据，还没有提议类别" },
  proposed: { name: "待确认", icon: "?", tone: "would", desc: "规则或 agent 给出了类别，未生效" },
  confirmed: { name: "已确认", icon: "●", tone: "ok", desc: "已生效：快速放行按这个类别核验" },
  ambiguous: { name: "有歧义", icon: "◇", tone: "unjudged", desc: "确实有歧义，永久交给 Jev 判定" },
  suspended: {
    name: "已暂停",
    icon: "▲",
    tone: "blocked",
    desc: "出现异常，暂停使用，退回名字推断",
  },
  retired: { name: "已过期", icon: "○", tone: "neutral", desc: "30 天没有出现" },
};

export const OBJECT_SIDE_INFO: Record<ObjectSide, { name: string; icon: string; desc: string }> = {
  request: { name: "请求", icon: "→", desc: "请求里的位置：路径、查询参数、请求体" },
  response: { name: "响应", icon: "←", desc: "源站响应里的字段" },
};

export const OBJECT_SOURCE_LABEL: Record<ObjectSource, string> = {
  admin: "管理员声明",
  rule: "规则",
  agent: "agent",
};

/** Words of the object map tab: the banner, the cold start and the wizard's object step, the drawer and its suspension
 *  section, the path positions, the automatic changes and the learning settings. Record text is never written here: it
 *  arrives as data and is shown as text nodes. */
export const OBJECT_TEXT = {
  tab: "对象表",
  search: "搜索类别、字段、路径",
  classes: "类别",
  viewLabel: "视图",
  view: { byClass: "按类别", byPosition: "按位置" },
  table: "位置列表",
  uses24h: "24 小时使用",
  declareButton: "＋ 声明字段归类",
  fromSynonyms: "从同义词改写…",
  learningButton: "学习设置 ⚙",
  none: "没有符合条件的位置。",
  columns: { slot: "位置", state: "类别与状态", source: "来源", basis: "依据", seen: "最近出现" },
  banner: {
    view: "查看",
    knowIt: "知道了",
    more: "等",
    pausedLine: (count: number) => `${count} 个位置已自动暂停，判定已退回名字推断：`,
    anomalyLine: (count: number) => `${count} 个已确认的位置出现异常，自动暂停已关闭，仍在生效：`,
    taskLine: (time: string, count: number) => `学习任务 ${time} 自动收紧了 ${count} 个位置：`,
  },
  noClasses: "还没有类别。学习中的位置在“按位置”里可以看到。",
  classCard: {
    rename: "改名",
    merge: "合并到…",
    split: "拆分…",
    unavailable: "改名、合并、拆分需要对象表接口，暂未提供。",
    description: "说明",
    fields: "常见字段",
    routes: "相关路由",
    pick: "选一个类别，查看它的位置。",
    positions: "位置",
    paused: (count: number) => `已暂停 ${count}`,
  },
  drawer: {
    flowsOut: "这个位置的值之后用在：",
    flowsIn: "这个位置的值之前出现在：",
    examples: "示例请求",
    shape: "响应结构（不含值）",
    format: "格式",
    condition: "条件",
    agent: "agent 结论",
    agentChoice: "选择",
    agentConfidence: "置信度",
    agentCites: "依据",
    agentReason: "理由（模型输出，按文本显示）",
    impact: "影响",
    scope: "范围",
    scopeOf: (scope: string) => `仅 ${scope}（证据里的接口）`,
    history: "历史",
    proposal: (name: string) => `提议：${name}`,
    confirmPreview: "确认后：",
    confirmLine: (side: string, key: string, cls: string, scope: string) =>
      `对象表 ＋ ${side} ${key} 归为${cls}（仅 ${scope}）`,
    noField: "这个位置没有字段名，不能用字段归类确认。",
    noClass: "还没有提议的类别，先用“改为其他类别…”选一个。",
    confirm: "确认…",
    reclass: "改为其他类别…",
    ambiguous: "标为有歧义",
    ignore: "忽略",
    dismissed: "已忽略这个位置的提议，学习任务不再提议同一结论。",
    markedAmbiguous: "已标为有歧义，之后交给 Jev 判定。",
  },
  suspension: {
    title: "暂停",
    paused: "已暂停",
    pausedBy: (at: string, version: number | null) =>
      version === null ? `${at} · 学习任务` : `${at} · 学习任务 · v${version}`,
    pausedByAdmin: (at: string) => `${at} · 管理员`,
    reason: "原因",
    examples: "示例",
    previous: "暂停前",
    previousLine: (cls: string, date: string, who: string) => `${cls}（${date} 由 ${who} 确认）`,
    previousNone: "没有已确认的类别",
    now: "现在",
    nowSame: (basis: string, kind: string) =>
      `判定退回名字推断：${basis} 得到 ${kind}。名字推断与暂停前相同，快速放行多半不变。想让它更严，可以标为有歧义。`,
    nowDiff: (basis: string, kind: string) =>
      `判定退回名字推断：${basis} 得到 ${kind}。与暂停前不同，按 ${kind} 核验。`,
    nowNone: "判定退回名字推断：没有可用的名字，这个位置的值都交给 Jev。",
    inEffect: (cls: string) => `仍在生效：判定照常按 ${cls} 核验，暂停没有停用它。`,
    effectOff: "自动暂停已关闭，检测到异常后只提示，不停用。",
    notApplied: "暂停尚未影响判定，网关升级后才会停用它。",
    evidence: "证据现在",
    warn: "暂停属于收紧，已经生效。重新确认会恢复快速放行，需要保存。",
    keepPaused: "保持暂停",
    keepEffect: "保持生效",
    keptPaused: "已保持暂停。这个位置继续按名字推断判定，之后可以在这里重新确认。",
    keptEffect: "已保持生效。这次异常只做提示，位置仍按原来的类别核验。",
    reconfirm: (cls: string) => `重新确认为${cls}…`,
    reject: "驳回",
    nameOnly: "名字推断",
    inEffectShort: "仍在生效",
    stopUse: "暂停使用…",
    stopNote: "保存后这个位置不再按对象表核验，判定退回名字推断。",
    stopMissing: "这个位置不在配置里，没有要停用的条目。",
    ambiguousAfterStop: "先暂停使用并保存，再驳回或标为有歧义。",
  },
  pathParam: {
    label: (method: string, route: string, ordinal: number, segment: number) =>
      `路由 ${method} ${route} 的第 ${ordinal} 个路径参数（path[${segment}]）`,
    literal: (method: string, route: string, segment: number) =>
      `路由 ${method} ${route} 的第 ${segment} 段（从 0 数，不是路径参数）`,
    template: "被指到的段",
    routeOnly: "只对这个方法和路由，精确匹配；路由改版后是新的位置。",
    after: (label: string, cls: string) => `对象表 ＋ ${label} = ${cls}`,
    confirmHint: "确认后：",
    noProposal: "还没有提议的类别，先用“改为其他类别…”选一个。",
    pickNote: "选好类别后再确认。",
    inDraft: "已在草稿里",
    inDraftReason: (cls: string) => `草稿里这个位置已归为${cls}，保存或撤销草稿后再改。`,
    full: "对象表最多 2,048 个位置，类别最多 64 个。先清理已过期的位置。",
    unsupported: "路径参数的确认需要网关升级，暂不可用。现在可以驳回或标为有歧义。",
    confirmLabel: "确认…",
    pickClass: "改为其他类别…",
  },
  declare: {
    title: "声明字段归类",
    field: "字段",
    fieldHint: "忽略大小写和 _、-：doc_id、docId、DocID 是同一个",
    kind: "类别",
    kindNew: "＋ 新类别",
    kindNewLabel: "新类别的 id",
    kindHint: "3 到 24 个小写字母，结尾的 s 不计",
    scope: "范围",
    scopeOnly: "仅这些接口",
    scopeAll: "全站",
    scopeAllNote: "站点里同名字段指两种东西时会错放行",
    scopeAllWarn: (targets: string) => `站点里同名字段指两种东西：${targets}。全站生效会错放行。`,
    scopeHint: "路径写法同入口，例如 /api/appointments*",
    paths: "接口路径",
    scopeEmpty: "至少填一个接口路径，或选全站。",
    matches: "会匹配",
    matchesInside: "范围内",
    matchesOutside: "范围外",
    outside: (count: number) => `另有 ${count} 个同名位置不在范围内`,
    noMatches: "最近的记录里没有这个字段名。",
    draft: "预估影响并加入草稿",
    save: "预估影响并保存…",
    cancel: "取消",
  },
  synonyms: {
    title: "从同义词改写",
    intro: "每组同义词改写成字段归类：逐个位置选择归为哪一类、限定在哪些接口，然后删除这组同义词。",
    groupWarn: (word: string, other: string) => `会让路径里的 ${word} 也算成 ${other}`,
    none: "最近的记录里没有这组词的位置，直接删除这组同义词。",
    builtin: "内置的同义词不能改写。",
    empty: "没有可以改写的同义词。",
    affected: "这组同义词实际影响的位置",
    classTo: "归为",
    scopeTo: "范围",
    scopeEvidence: "仅证据里的接口",
    scopeAll: "全站",
    apply: "改写并加入草稿",
  },
  learning: {
    title: "学习设置",
    intro: "学习设置属于站点配置：改动走保存对话框，保存后产生新版本。",
    pending: "网关接受对象表的学习设置之后，这里的开关才能保存。现在只能查看当前的值。",
    autoLearn: { name: "自动学习", help: "关闭后只用手工声明，已确认的位置照常生效" },
    autoTighten: {
      name: "自动收紧（推荐）",
      help: "只会让快速放行变少的改动自动生效，例如把同时指医生和文档的 doc 拆成两个类别。每次都写成新版本，作者为“学习任务”，可以撤销。关闭后这类改动进入待确认。",
    },
    autoPause: {
      name: "自动暂停（推荐）",
      help: "已确认的位置出现异常时自动停用，判定退回名字推断。异常包括：证据转向别的类别、按它快速放行后源站 403/404 比例升高、同一位置 Jev 拒绝增多。恢复属于放宽，需要你确认。关闭后只提示，不停用。",
    },
    agent: {
      name: "agent",
      help: "规则判不了的位置是否交给 agent",
      unavailable: "没有配置模型，agent 暂不可用。",
      notReady: "学习代理还没有上线，暂不可用。",
      daily: "每日调用上限",
    },
    thresholds: {
      name: "学习门槛",
      help: "调低会更快学到，也更容易被少数会话影响",
      atLeast: "至少",
      usesLabel: "至少使用次数",
      sessionsLabel: "至少会话数",
      uses: "次使用",
      sessions: "个会话",
    },
    status: {
      schedule: (time: string) => `学习任务每小时执行一次，上次 ${time}`,
      never: "学习任务还没有执行过",
      tightened: (count: number) => `近 7 天自动收紧 ${count} 次`,
      paused: (count: number) => `近 7 天自动暂停 ${count} 次`,
      notApplied: "开关会保存，执行要等网关升级后生效",
    },
    on: "开",
    off: "关",
    unchanged: "没有改动",
    save: "保存…",
  },
  coldStart: {
    title: "还没有对象表",
    intro: (hours: number, count: number) =>
      `从最近 ${hours} 小时的请求里识别出 ${count} 个名字明确的位置。确认后它们作为学习的起点，其余位置照常判定。`,
    windowLine: (hours: number, records: number) =>
      `最近 ${hours} 小时 · ${records.toLocaleString("en-US")} 条判定记录`,
    explain:
      "下面是名字明确的位置。确认后同一类别的值可以直接核验，作为学习的起点；其余位置照常判定。",
    explainSave: "确认走保存对话框，会产生新版本，不改变站点模式。",
    selectAll: (picked: number, total: number) => `全选（已选 ${picked} / ${total}）`,
    filter: "筛选位置",
    noTraffic: "还没有判定记录",
    noTrafficText:
      "站点刚创建，还没有经过网关的请求。开始接流量后，名字明确的位置会出现在对象表顶部，到时再确认。",
    none: "最近的请求里没有名字明确的位置。有请求后再来看，或在对象表里手工声明。",
    noneChosen: "没有选中的位置",
    pathOnly: "只在路径参数里，没有字段名，不能确认；学习会处理。",
    later: "稍后再说",
    skip: "跳过，进入站点",
    enter: "进入站点",
    skipped: "对象表还是空的，学习照常进行。",
    errorHint: "跳过不影响站点，之后可以在对象表里确认同一份列表。",
    confirm: (count: number) => `确认 ${count} 个位置…`,
    summary: (fields: number, slots: number, classes: number, names: string) =>
      `确认后：字段归类 ＋${fields} 条 · 对象表位置 ＋${slots} 条 · 新类别 ${classes} 个${names === "" ? "" : `（${names}）`}`,
    changed: "已改",
    changedFrom: (proposal: string) => `系统提议：${proposal}`,
    note: "名字推断的规则，与判定时相同",
    newClass: "＋ 新类别…",
    newClassId: "新类别的 id",
    newClassName: "名字",
    conflict: (cls: string) => `草稿里这个位置已归为${cls}，保存或撤销草稿后再改。`,
    inDraft: "已在草稿里",
  },
  wizard: {
    title: "对象表（可选）",
    text: "创建后，最近的请求里名字明确的位置会列为候选类别，可以在对象表里一次确认。现在可以跳过。",
    open: "创建后确认对象表起点（可跳过）",
    step: "对象表起点（可选）",
    saved: (count: number, version: number) =>
      `已确认 ${count} 个位置，版本 v${version}。其余位置继续学习。`,
    missing: "这个站点不存在，已回到站点列表。",
  },
  events: {
    title: "自动变更",
    meta: (days: number, open: number) => `近 ${days} 天 · 未处理 ${open}`,
    open: "未处理",
    all: "全部",
    kind: "类型",
    kindAll: "全部",
    empty: "没有符合条件的变更。",
    kinds: { auto_tighten: "自动收紧", auto_pause: "自动暂停", anomaly: "检测到异常" },
    task: "学习任务",
    version: (version: number) => `v${version}`,
    scope: (from: string, to: string) => `范围 ${from} → ${to}`,
    reason: "原因",
    impact: "影响",
    sample: "示例",
    anomalyNote: "自动暂停已关闭，只提示，不停用。",
    statusOpen: "未处理",
    acknowledged: (by: string, at: string) => `已知悉 · ${by} ${at}`,
    undone: (version: number | null) => (version === null ? "已撤销" : `已撤销 · v${version}`),
    superseded: "已被后续改动取代（之后又改了这个位置，不可撤销）",
    actions: {
      knowIt: "知道了",
      viewVersion: "查看版本",
      undo: "撤销…",
      open: "打开位置",
      keepPaused: "保持暂停",
      keepEffect: "保持生效",
      reconfirm: "重新确认…",
    },
    blockedAfter: "这个位置之后又改过，请在位置抽屉里处理。",
    blockedDraft: "草稿里有未保存的改动涉及这个位置。",
    noteUndo: (version: number) => `撤销自动收紧 v${version}`,
    noteReconfirm: (key: string, version: number | null) =>
      version === null ? `重新确认 ${key}（自动暂停）` : `重新确认 ${key}（自动暂停 v${version}）`,
    noteWizard: "接入时确认对象表起点",
    failed: "这次操作没有完成，请重试。",
    nothingToUndo: "这次变更没有可以放回的条目。",
  },
  dismissInvalid: "这个位置已经不在对象表里，刷新后再试。",
};

/** The name rule that named a class, in words (console design 1.5). */
export function nameReasonText(
  code: NameReasonCode,
  word: string | null,
  field: string | null,
): string {
  switch (code) {
    case "field_name":
      return `字段名 ${field ?? "—"}`;
    case "parent_name":
      return `裸 id，取父对象 ${word ?? "—"}`;
    case "endpoint_name":
      return `裸 id，取接口名 ${word ?? "—"}`;
    case "route_word":
      return `路由词 ${word ?? "—"} 紧挨在前`;
  }
}

/** A share from 0 to 1 in whole percent; a missing share is a dash. */
export function percentOf(share: number | null | undefined): string {
  return share === null || share === undefined ? "—" : `${Math.round(share * 100)}%`;
}

/** The evidence of an automatic change or a pause, in words (console design 2.3, the table of its reasons). */
export function reasonText(reason: ObjectReason, side: ObjectSide, cls: string | null): string {
  const response = side === "response";
  switch (reason.code) {
    case "evidence_drift": {
      const now = response ? "之后用在" : "来自";
      const before = response ? "用在" : "来自";
      return `证据转向：${percentOf(reason.after)} 的值${now} ${reason.key ?? "—"}（之前 ${percentOf(reason.before)} ${before} ${reason.key_before ?? "—"}）`;
    }
    case "origin_4xx_rise":
      return `快速放行后源站 ${reason.status ?? "403/404"} 比例从 ${percentOf(reason.before)} 升到 ${percentOf(reason.after)}（${reason.days ?? "—"} 天 ${reason.total ?? "—"} 次中 ${reason.hits ?? "—"} 次）`;
    case "jev_deny_rise":
      return `Jev 拒绝增多：${reason.days ?? "—"} 天 ${reason.after ?? "—"} 次，之前 ${reason.before ?? "—"} 次`;
    case "split": {
      const [first = "—", second = "—"] = reason.classes ?? [];
      return `${cls ?? "—"} 同时指两类对象，拆成 ${first} 与 ${second}`;
    }
  }
}

/** The kinds of automatic change, with their icon. */
export const OBJECT_EVENT_INFO: Record<ObjectEventKind, { name: string; icon: string }> = {
  auto_tighten: { name: "自动收紧", icon: "●" },
  auto_pause: { name: "自动暂停", icon: "▲" },
  anomaly: { name: "检测到异常", icon: "▲" },
};

/** The messages of field declarations (lib/objects-validate.ts). */
export const DECLARE_TEXT = {
  fieldEmpty: "字段名不能为空",
  fieldLong: "字段名最多 32 个字符",
  fieldChars: "字段名只能用字母、数字、_ 和 -",
  kindFormat: "类别 id 为 3 到 24 个小写字母",
  scopeMany: "范围最多 8 个路径",
  scopeDup: "范围里有重复的路径",
  countMax: "字段归类最多 32 条",
  duplicate: (field: string) => `字段 ${field} 在重叠的范围里已经归过类`,
  conflict: (field: string, kind: string) =>
    `字段 ${field} 在重叠的范围里已归为 ${kind}，不能同时归为别的类别`,
  shape: (where: string) => `字段归类 ${where} 的格式不对`,
  learningShape: "学习设置的格式不对",
  classesShape: "对象表的类别格式不对",
  slotsShape: "对象表的位置格式不对",
  classShape: (index: number) => `对象表第 ${index} 个类别的格式不对`,
  slotShape: (index: number) => `对象表第 ${index} 个位置的格式不对`,
  classCountMax: "对象表最多 64 个类别",
  slotCountMax: "对象表最多 2,048 个位置",
  classDuplicate: (id: string) => `类别 ${id} 重复了`,
  classNameEmpty: "类别名不能为空",
  classNameLong: "类别名最多 32 个字符",
  slotDuplicate: (key: string) => `位置 ${key} 在对象表里已经有一条`,
  slotClassUnknown: (key: string, cls: string) => `位置 ${key} 的类别 ${cls} 还没有声明`,
  slotKeyFormat: "位置的格式不对：应为“方法 /路径 位置”",
  slotKeyLong: "位置键最多 256 个字节",
  unknownKey: (key: string) => `未知字段 ${key}`,
  label: (field: string, kind: string, scope: string | null) =>
    `字段 ${field} 归为${kind}（${scope === null ? "全站" : `仅 ${scope}`}）`,
};

/** The learning settings in words, for the change list and the version conflict. */
export const LEARNING_TEXT = {
  autoLearn: "自动学习",
  autoTighten: "自动收紧",
  agent: "agent",
  agentDaily: "agent 每日上限",
  uses: "学习门槛 使用次数",
  sessions: "学习门槛 会话数",
  autoPause: "自动暂停",
  on: "开",
  off: "关",
} as const;
