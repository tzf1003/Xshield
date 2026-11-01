// One-sentence explanation of a decision (docs/06 6.4.4). A pure function over the record, with no
// model call: the reason comes from the decision path and the outcome adds what happens next.

import type {
  DecisionPath,
  JevAccess,
  JevAttack,
  JevRecord,
  Outcome,
  Trace,
  TraceValue,
} from "../api/types.ts";
import { clip } from "./format.ts";
import { shortRequestId } from "./ids.ts";

export type ExplainInput = {
  decision_path: DecisionPath;
  outcome: Outcome;
  status: number | null;
  host: string;
  context?: "session" | "address" | null;
  trace: Trace;
  jev: JevRecord | null;
};

const FAILURE_REASON: Record<string, string> = {
  JEV_TIMEOUT: "Jev 调用超时",
  JEV_RATE_LIMITED: "模型服务限流（429）",
  JEV_TRANSPORT: "连接模型服务失败",
  JEV_HTTP_ERROR: "模型服务返回错误",
  JEV_RESPONSE_TOO_LARGE: "Jev 响应超过 64 KiB",
  JEV_RESPONSE_INVALID: "Jev 响应格式不符合约定",
  JEV_UNKNOWN: "Jev 答不上来",
  JEV_STATE_TOO_LARGE: "上下文裁剪后仍超过 8 KiB，没有调用 Jev",
  JEV_CALL_LIMIT: "调用次数已达上限，没有调用 Jev",
};

const SOURCE_REASON: Record<string, string> = {
  connect_refused: "连接被拒绝",
  connect_timeout: "连接超时",
  read_timeout: "读取超时",
  tls: "TLS 握手失败",
  other: "出错",
};

export function topOf<T extends string>(probabilities: Partial<Record<T, number>> | null): T | null {
  if (!probabilities) return null;
  let best: T | null = null;
  let bestValue = -1;
  for (const [key, value] of Object.entries(probabilities) as Array<[T, number]>) {
    if (value > bestValue) {
      best = key;
      bestValue = value;
    }
  }
  return best;
}

function percentOf(probabilities: Record<string, number> | null | undefined, key: string): string {
  const value = probabilities?.[key];
  return value === undefined ? "—" : `${Math.round(value * 100)}%`;
}

function locationWord(at: string): string {
  if (at.startsWith("path")) return "路径里的";
  if (at.startsWith("query")) return "查询串里的";
  if (at.startsWith("body")) return "请求体里的";
  return "";
}

/** The first value that the origin showed as something else (the case behind a DENY). */
function offendingValue(values: TraceValue[]): TraceValue | undefined {
  return values.find((value) => !value.inert && value.seen && !value.verified);
}

function reasonOf(input: ExplainInput): string {
  const { trace, jev } = input;
  const values = trace.values ?? [];
  switch (input.decision_path) {
    case "bypass":
      return `命中绕过规则 ${trace.bypass ?? ""}，没有判定，直接转发。`;
    case "unknown_site":
      return `Host ${input.host} 不属于任何站点。`;
    case "body_not_inspectable":
      return "请求体超过 48 KiB 判定上限或没有 Content-Length，无法判定。需要上传大文件的接口可以加入绕过，但绕过后不做越权判定。";
    case "no_session":
      return "请求没有会话凭证，路径也不是入口。";
    case "fast_allow": {
      const needed = values.filter((value) => !value.inert).length;
      return needed > 0
        ? `${needed} 个需核验的值都已核验，没有调用 Jev。`
        : "请求里没有需要核验的值，没有调用 Jev。";
    }
    case "cached_allow":
      return trace.cache_source
        ? `同一会话此前的相同请求已由 Jev 放行（${shortRequestId(trace.cache_source)}），在缓存时长内直接复用。`
        : "同一会话此前的相同请求已由 Jev 放行，在缓存时长内直接复用。";
    case "jev_allow":
      return `Jev 判定访问有依据（ALLOW ${percentOf(jev?.access, "ALLOW")}）、内容无攻击（BENIGN ${percentOf(jev?.attack, "BENIGN")}）。`;
    case "jev_deny": {
      const attackTop = topOf<JevAttack>(jev?.attack ?? null);
      if (attackTop === "ATTACK") {
        const target = values.find((value) => !value.inert);
        const where = target ? `${locationWord(target.at)} ${target.at} 的值` : "请求值";
        return `Jev 判定为攻击（ATTACK ${percentOf(jev?.attack, "ATTACK")}）：${where}含 \`${clip(target?.value ?? "", 24)}\`。`;
      }
      const value = offendingValue(values);
      const source = value?.sources[0];
      const place = value ? `${locationWord(value.at)}${clip(value.value, 24)}` : "请求的值";
      const history = source
        ? `没有以同类对象出现过，只以 ${source.field} 出现在 ${source.request} 的响应里`
        : "从未出现过";
      return `Jev 判定越权（DENY ${percentOf(jev?.access, "DENY")}）：${place} 在这个会话里${history}。`;
    }
    case "jev_unavailable": {
      if (!jev) return "Jev 不可用，没有调用 Jev。";
      if (jev.failure === "JEV_CALL_LIMIT") {
        const scope = input.context === "address" ? "地址" : "会话";
        return `本${scope}每分钟 Jev 调用已达上限，没有调用 Jev。`;
      }
      if (jev.failure === "JEV_TIMEOUT") {
        return `Jev 调用超时（${jev.timeout_ms} ms）。`;
      }
      if (jev.failure === "JEV_UNKNOWN") {
        return `Jev 答不上来（UNKNOWN ${percentOf(jev.access, "UNKNOWN")}）。`;
      }
      if (jev.failure === "JEV_HTTP_ERROR" && jev.http_status !== null) {
        return `模型服务返回 ${jev.http_status}。`;
      }
      return `${jev.failure ? (FAILURE_REASON[jev.failure] ?? "Jev 不可用") : "Jev 不可用"}。`;
    }
    default:
      return "";
  }
}

function actionOf(input: ExplainInput): string {
  switch (input.outcome) {
    case "blocked":
      return input.status === null ? "" : `返回 ${input.status}。`;
    case "would_block":
      return "站点处于观察模式，请求照常转发。";
    case "unjudged":
      return "站点设置为 Jev 不可用时放行，这个请求没有经过判定。";
    default:
      return "";
  }
}

/** The reason and the action as one sentence, plus the upstream note when the origin failed. */
export function explainRecord(input: ExplainInput): string {
  if (input.trace.v === 0) {
    return `旧格式记录：没有判定依据。${actionOf(input)}`.trim();
  }
  const reason = reasonOf(input);
  const action = actionOf(input);
  const upstream = input.trace.upstream_error
    ? `源站${SOURCE_REASON[input.trace.upstream_error] ?? "出错"}，网关返回 ${input.status ?? "—"}。`
    : "";
  return [reason, action, upstream].filter((part) => part.length > 0).join("");
}

export function jevAnswerTop(jev: JevRecord | null): { access: JevAccess | null; attack: JevAttack | null } {
  return {
    access: topOf<JevAccess>(jev?.access ?? null),
    attack: topOf<JevAttack>(jev?.attack ?? null),
  };
}
