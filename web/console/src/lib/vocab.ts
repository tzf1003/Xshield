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
