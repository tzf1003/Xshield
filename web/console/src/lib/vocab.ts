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
  ObjectSide,
  ObjectSource,
  ObjectState,
  Outcome,
  RefusedReason,
  ResponseSkip,
  SuggestionKind,
  UpstreamError,
  ValueKind,
} from "../api/types.ts";

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

/** Words of the drawer's source line and the counters, keyed by the state each one filters on. */
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
    paused: "已自动暂停",
    task: (time: string) => `学习任务 ${time}`,
    view: "查看",
    undo: "撤销",
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
    noField: "路径参数没有字段名，不能用字段归类确认。",
    noClass: "还没有提议的类别，先用“改为其他类别…”选一个。",
    confirm: "确认…",
    reclass: "改为其他类别…",
    ambiguous: "标为有歧义",
    ignore: "忽略",
    dismissed: "已忽略这个位置的提议，学习任务不再提议同一结论。",
    markedAmbiguous: "已标为有歧义，之后交给 Jev 判定。",
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
    autoLearn: { name: "自动学习", help: "关闭后只用手工声明，已确认的位置照常生效" },
    autoTighten: {
      name: "自动收紧",
      help: "只会让快速放行变少的改动是否自动生效；关闭后也进入待确认",
    },
    agent: {
      name: "agent",
      help: "规则判不了的位置是否交给 agent",
      unavailable: "没有配置模型，agent 暂不可用。",
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
    autoPause: { name: "自动暂停", help: "已确认位置出现异常时自动暂停" },
    on: "开",
    off: "关",
    unchanged: "没有改动",
    save: "保存…",
  },
  coldStart: {
    title: "还没有对象表",
    intro: (hours: number, count: number) =>
      `从最近 ${hours} 小时的请求里识别出 ${count} 个名字明确的类别。确认后它们作为学习的起点，其余位置照常判定。`,
    none: "最近的请求里没有名字明确的位置。有请求后再来看，或在下面的声明里手工归类。",
    pathOnly: "只在路径参数里，没有字段名，不能确认；学习会处理。",
    later: "稍后再说",
    skipped: "对象表还是空的，学习照常进行。",
    confirm: (count: number) => `确认 ${count} 个类别…`,
  },
  wizard: {
    title: "对象表（可选）",
    text: "创建后，最近的请求里名字明确的位置会列为候选类别，可以在对象表里一次确认。现在可以跳过。",
    open: "创建后打开对象表",
  },
  dismissInvalid: "这个位置已经不在对象表里，刷新后再试。",
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
  unknownKey: (key: string) => `未知字段 ${key}`,
  label: (field: string, kind: string, scope: string | null) =>
    `字段 ${field} 归为 ${kind}（${scope === null ? "全站" : `仅 ${scope}`}）`,
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
