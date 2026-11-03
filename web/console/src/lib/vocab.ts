// Every user-visible word for decisions, outcomes, Jev answers, failures and errors lives here
// (docs/07 7.10.5, docs/06 6.6). Components read from this file; none of them spells these out.

import type {
  AgentProvider,
  DecisionPath,
  ImpactKind,
  JevAccess,
  JevAttack,
  JevConclusion,
  JevFailure,
  JevHealth,
  JevRoute,
  ModelSource,
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
  ENV_KEY_MISSING: "环境变量里没有可用的密钥，不能改回",
  INTERNAL: "控制面出错，请稍后重试；问题持续时查看控制面日志",
};

/** The message for an API error code, falling back to a generic line that never echoes data. */
export function errorText(code: string | undefined): string {
  if (!code) return "请求失败，请稍后重试";
  return ERROR_TEXT[code] ?? `请求失败（${code}）`;
}

// ------------------------------------------------------------------ models (系统 · 模型, design 2 and 7)

export const MODEL_ROUTE_LABEL: Record<JevRoute, string> = {
  gateway: "Vercel AI Gateway",
  direct: "TypeSafe 直连",
  custom: "自定义地址",
};

export const MODEL_PROVIDER_LABEL: Record<AgentProvider, string> = {
  vercel_gateway: "Vercel AI Gateway（OpenAI 兼容）",
  custom: "自定义 OpenAI 兼容地址",
};

export const MODEL_SOURCE_LABEL: Record<ModelSource, string> = {
  console: "控制台",
  env: "环境变量",
};

/** The words of a field in a change list or a history row. */
export const MODEL_FIELD_LABEL: Record<string, string> = {
  route: "线路",
  provider: "提供方",
  endpoint: "地址",
  model: "模型",
  timeout_ms: "超时",
  key: "密钥",
  share_key_with_jev: "与 Jev 共用密钥",
};

/** Failure codes of a call or a test in words: the 6.6.4 Jev codes, plus the ones only a test reports (design 2.4). */
export const MODEL_FAILURE_TEXT: Record<string, string> = {
  JEV_TIMEOUT: "超时",
  JEV_RATE_LIMITED: "服务限流",
  JEV_TRANSPORT: "连接失败",
  JEV_HTTP_ERROR: "服务出错",
  JEV_RESPONSE_INVALID: "响应无效",
  dns: "域名解析失败",
  tls: "TLS 错误",
  answer_invalid: "回答不能解析",
};

/** A failed call's HTTP status in a few words, for a card's status line. */
export const MODEL_STATUS_TEXT: Record<number, string> = {
  401: "401 未授权",
  451: "451 地区不能直连",
  429: "429 服务限流",
};

/** Error codes a gateway reports for a console version it could not load (design 2.1). Unknown codes show as they are. */
export const MODEL_LOAD_ERROR_TEXT: Record<string, string> = {
  MODEL_KEY_UNREADABLE: "密钥无法解密",
  MODEL_CONFIG_INVALID: "配置不符合要求",
};

export const MODEL_TEXT = {
  tab: "模型",
  jevTitle: "Jev 判定模型",
  agentTitle: "学习代理模型",
  agentLead: "学习代理在规则判不了某个位置的类别时，用这个模型给出提议。",
  agentOff: "没有配置时，各站点的学习代理开关保持关闭，学习照常按规则进行。",
  unset: "未配置",
  noCallYet: "已配置，还没有调用过",
  lastOk: "最近一次成功",
  lastFailed: (failure: string) => `最近一次失败：${failure}`,
  failing: (failure: string) => `最近 5 次调用失败：${failure}`,
  onlineNone: "没有在线的网关",
  loadedOf: (loaded: number, online: number, version: number) =>
    `${loaded}/${online} 个网关已加载第 ${version} 版`,
  loadWaiting: (version: number) => `等待网关加载第 ${version} 版…`,
  loadBehind: (edge: string, version: number | null) =>
    version === null ? `${edge} 还没有加载配置` : `${edge} 仍在用第 ${version} 版`,
  loadEnv: (online: number) => `${online} 个网关读取环境变量的配置`,
  rowProvider: "提供方",
  rowRoute: "线路",
  rowEndpoint: "地址",
  rowModel: "模型",
  rowKey: "密钥",
  rowTimeout: "超时",
  rowSource: "来源",
  rowUsageHour: "最近 1 小时",
  rowUsageToday: "今天",
  keySet: (last4: string, when: string) => `已设置 · 末 4 位 …${last4} · ${when} 更新`,
  keyUnset: "未设置",
  keyFromEnv: (name: string | null) => `来自环境变量 ${name ?? "（名字未知）"}`,
  keyShared: "与 Jev 共用",
  timeoutJev: (ms: string, overrides: number) =>
    overrides > 0
      ? `${ms}（站点可在高级判定参数里覆盖，${overrides} 个站点覆盖了）`
      : `${ms}（站点可在高级判定参数里覆盖）`,
  timeoutAgent: (seconds: number) => `${seconds} 秒`,
  sourceConsole: (version: number, when: string) => `控制台第 ${version} 版 · ${when}`,
  sourceEnv: "环境变量（控制台里还没有配置，网关仍读环境变量）",
  overridden: (names: string) => ` · 环境变量 ${names} 已被覆盖`,
  usageJev: (calls: string, failRate: string, p95: string) =>
    `调用 ${calls} · 失败 ${failRate} · p95 ${p95}`,
  usageAgent: (calls: number, ok: number, failed: number, top: string | null, sites: number) =>
    `调用 ${calls} · 成功 ${ok} · 失败 ${failed}${top ? `（${top}）` : ""} · ${sites} 个站点开启了学习代理`,
  linkJevCalls: "查看 Jev 调用 →",
  siteUsage: "各站点用量",
  btnHistory: "变更记录",
  btnTest: "测试连接",
  btnTesting: "正在测试…",
  btnCancelTest: "取消测试",
  btnEdit: "编辑…",
  btnTakeOver: "改由控制台管理…",
  btnBackToEnv: "改回环境变量…",
  btnConfigure: "配置…",
  btnReplaceKey: "替换…",
  btnCancelReplace: "取消替换",
  btnRestoreDefault: "恢复默认",
  btnSave: "保存…",
  btnCancel: "取消",
  btnReload: "重新载入",
  btnSaveVersion: (version: number) => `保存第 ${version} 版`,
  btnRestore: (version: number) => `恢复到第 ${version} 版…`,
  revealKey: "按住显示密钥",
  lineGateway: "线路",
  directWarn: "部分地区直连会返回 451，一般保持默认。",
  endpointFixed: "由线路决定",
  modelPlaceholder: "例如 供应商/模型名",
  timeoutHintJev: "站点的 advanced.jev_timeout_ms 优先",
  timeoutHintAgent: "学习代理按位置调用、不在请求路径上，可以比 Jev 宽松。",
  shareKeyLabel: "与 Jev 共用密钥",
  shareKeyHelp:
    "只在两边都是 Vercel AI Gateway 时可选。选中后不单独保存密钥，Jev 换密钥时学习代理跟着换。",
  keyHelp: "密钥只写不读，保存后只显示末 4 位；保存后旧密钥立即作废。",
  keyEnvHelp: "控制台读不到环境变量里的密钥，请重新填写。",
  keyRequired: "请填写密钥",
  keyWhitespace: "密钥里不能有空白",
  testFootJev: "测试从控制台发出。保存后以网关的加载状态为准。",
  testFootAgent: "测试从控制台发出，学习任务也从控制台发出。",
  testCooldown: (seconds: number) => `${seconds} 秒后可再测`,
  testTooOften: "10 秒内只能测试一次",
  noUsageYet: "还没有调用",
  noChanges: "这次没有改动。",
  savingNow: "正在保存…",
  modelSwitchTitle: (model: string) => `模型名也换成 ${model} 吗？`,
  modelSwitchYes: (model: string) => `换成 ${model}`,
  modelSwitchKeep: "保留当前",
  timeoutHelp: (min: number, max: number, fallback: number, hint: string) =>
    `${min} 到 ${max}，默认 ${fallback}。${hint}`,
  impactAgentNone: "没有站点开启学习代理，保存只影响之后开启的站点。",
  colAction: "操作",
  testDetail: "模型返回的错误正文（不可信文本）",
  testSucceeded: "成功",
  testOkJev: "模型返回了合法的回答",
  testAnswerInvalid: "能连上，但回答不能解析",
  testWrongModelHint: "多半是模型名填错了，换成了一个不是 Jev 的模型。",
  testWrongAgentHint: "输出不符合结构约束。",
  testFailDns: "连不上：域名解析失败",
  testFailTls: "连不上：TLS 错误",
  testFailTransport: "连不上：连接失败",
  testFailTimeout: (ms: string) => `失败：超时（${ms} ms）`,
  testFailUnauthorized: "失败：401 未授权，密钥不对或已过期",
  testFailRegion: "失败：451，这个地区不能直连",
  testFailRate: "失败：429，服务限流",
  testFailOther: (status: number | null, name: string) =>
    status === null ? `失败：${name}` : `失败：${status}，${name}`,
  testUnknown: "未知错误",
  endpointRequired: "请填写地址",
  endpointLong: "地址最长 2048 个字符",
  endpointQuery: "地址里不能有查询串或片段",
  endpointUrl: "地址格式不对，例如 https://主机名/路径",
  endpointScheme: "地址必须以 https:// 开头（回环地址可以用 http://）",
  endpointCredentials: "地址里不能带用户名和密码",
  modelRequired: "请填写模型名",
  modelLong: "模型名最长 200 个字符",
  modelChars: "模型名只能用字母、数字和 . _ : / @ -",
  timeoutRange: (min: number, max: number, unit: string) =>
    `${min} 到 ${max} 之间的整数，单位${unit}`,
  unitMs: "毫秒",
  unitSeconds: "秒",
  saveTitle: (name: string, version: number) => `保存${name}（第 ${version} 版）`,
  sectionChanges: "改动",
  sectionImpact: "影响",
  sectionTest: "测试",
  noteLabel: "备注",
  notePlaceholder: "例如 换成新版 Jev",
  impactJev: (sites: number, current: number | null) =>
    current === null
      ? `全部 ${sites} 个站点的 Jev 调用改用新配置。网关约 5 秒内加载。`
      : `全部 ${sites} 个站点的 Jev 调用改用新配置。网关约 5 秒内加载；加载失败的网关继续用第 ${current} 版。`,
  impactAgent: (sites: number) =>
    `开启了学习代理的 ${sites} 个站点下一次学习起改用新配置。学习代理只产生提议，放宽仍要人确认。`,
  impactFailClosed: (sites: string[]) =>
    `▲ ${sites.length} 个站点处于拦截模式，Jev 失败时拒绝请求：${sites.join("、")}`,
  impactTimeoutOverrides: (count: number) => `${count} 个站点覆盖了超时，它们继续用自己的超时。`,
  testedOk: (time: string) => `✓ ${time} 用这份配置测试成功`,
  testedMissing: "! 这份配置还没有测试成功",
  ackUntested: "我知道没有测试成功，仍然保存",
  failClosedSave: "保存后如果 Jev 调用失败，这些站点会拒绝请求。",
  conflict: (version: number) =>
    version === 0
      ? "配置已被改动（控制台里现在没有这组配置），你的改动还没有保存。"
      : `配置已被改为第 ${version} 版，你的改动还没有保存。`,
  keyReplaced: (old: string | null, next: string) =>
    old === null ? `已设置（…${next}）` : `已替换（…${old} → …${next}）`,
  keyKept: (last4: string | null) => (last4 === null ? "没有设置" : `保持当前的 …${last4}`),
  changeYes: "是",
  changeNo: "否",
  restoreNote: (version: number) => `恢复到第 ${version} 版`,
  backTitle: "改回环境变量？",
  backBody: "控制台里的这组配置会被删除，网关改为读取环境变量。之前的版本仍可在变更记录里恢复。",
  backOk: "改回环境变量",
  historyTitle: "变更记录",
  historyEmpty: "还没有变更记录。",
  historyNoChange: "没有改动",
  historyTested: "成功",
  historyUntested: "没有测试",
  colVersion: "版本",
  colTime: "时间",
  colChanges: "改了什么",
  colNote: "备注",
  colTest: "测试",
  colSite: "站点",
  colUsed: "今天已用 / 上限",
  colFailed: "失败",
  colLast: "上次调用",
  sitesEmpty: "没有站点。",
  siteOff: "未开启",
  edgeSourceConsole: (version: number) => `控制台第 ${version} 版`,
  edgeSourceEnv: "环境变量",
  edgeBehind: (version: number, reason: string) => `▲ 未加载第 ${version} 版：${reason}`,
  edgeLinkModels: "查看模型配置",
  edgeNoLoadReason: "还没有加载",
  attentionNotLoaded: (version: number, edges: string, reason: string) =>
    `▲ ${edges} 没有加载 Jev 模型配置第 ${version} 版：${reason}`,
  attentionAction: "查看模型配置",
} as const;

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
    pending: "网关接受对象表的学习设置之后，这里的开关才能保存。现在只能查看当前的值。",
    autoLearn: { name: "自动学习", help: "关闭后只用手工声明，已确认的位置照常生效" },
    autoTighten: {
      name: "自动收紧",
      help: "只会让快速放行变少的改动是否自动生效；关闭后也进入待确认",
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
