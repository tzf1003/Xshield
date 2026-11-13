// Plain functions behind the request detail page (docs/06 6.4.4 and 6.4.5, docs/07 7.5.2). They read
// the record and return data; the components turn that data into elements. Every string that came
// from a record stays a string, and the components render it as text nodes only.

import type {
  DecisionPath,
  EntryPass,
  GatewayProblem,
  JevAccess,
  JevAttack,
  JevFailure,
  JevRecord,
  JevState,
  Outcome,
  RecentAccess,
  RequestRow,
  ResponseExposure,
  Trace,
  TraceResponse,
  TraceSession,
  TraceSource,
  TraceTiming,
  TraceValue,
  ValueKind,
} from "../../api/types.ts";
import {
  type AlignedValue,
  alignRecent,
  alignValues,
  sameName,
  seenAsAligned,
} from "../../lib/align.ts";
import {
  apiFromWords,
  apiValueLocations,
  byMapNote,
  isNameValue,
  unknownTitle,
} from "../../lib/api-name.ts";
import { topOf } from "../../lib/explain.ts";
import { lostReasons } from "../../lib/health.ts";
import { clip, fmtBytes, fmtElapsed, fmtInt, FUNCTION_KEY_MAX, pct } from "../../lib/format.ts";
import {
  isRequestId,
  isSessionLabel,
  requestIdMillis,
  shortRequestId,
  shortSession,
} from "../../lib/ids.ts";
import {
  ACCESS_LABEL,
  ATTACK_LABEL,
  FAILURE_INFO,
  FUNCTION_VIEW,
  SKIP_LABEL,
  UPSTREAM_LABEL,
} from "../../lib/vocab.ts";

export const REDACTED = "<redacted>";

/** The Jev state limit (docs/07 7.5.1). */
export const STATE_LIMIT_BYTES = 8 * 1024;

/** Records are kept for seven days (docs/06 6.7.2). */
export const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
export const DAY_MS = 24 * 60 * 60 * 1000;

/** The built-in redaction words (docs/07 7.4.4). */
export const BUILTIN_SECRET_WORDS: readonly string[] = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "otp",
  "credential",
  "authorization",
  "cvv",
];

/** Field names that look like personal data, for the "add as redaction word" action (docs/07 7.9.10). */
export const SENSITIVE_FIELD_WORDS: readonly string[] = [
  "ssn",
  "idcard",
  "id_card",
  "passport",
  "cardnum",
  "card_number",
  "cvc",
  "iban",
  "bankaccount",
];

// ------------------------------------------------------------------ the Jev state

export type ParsedState =
  | { status: "absent" }
  | { status: "invalid"; text: string }
  | { status: "ok"; state: JevState; text: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJevState(value: unknown): value is JevState {
  if (!isRecord(value)) return false;
  const { request, session, recent } = value;
  return (
    isRecord(request) &&
    Array.isArray(request.values) &&
    isRecord(session) &&
    Array.isArray(session.entries_passed) &&
    Array.isArray(recent)
  );
}

/** `jev.state` is the exact JSON text Jev received (docs/07 7.5.1); a parse failure is an error state. */
export function parseState(text: string | null): ParsedState {
  if (text === null) return { status: "absent" };
  try {
    const value: unknown = JSON.parse(text);
    return isJevState(value) ? { status: "ok", state: value, text } : { status: "invalid", text };
  } catch {
    return { status: "invalid", text };
  }
}

export type Alignment = { aligned: true; sent: AlignedValue[] } | { aligned: false };

/**
 * The check of docs/07 7.5.2: the non-inert trace values and the state's values pair up by index. Each
 * pair must have the same location (a name the trace cut to 256 bytes still matches the state's full name,
 * see `sameName`), and the state's `seen_as` must match the sources in order (see `seenAsAligned`). The
 * state's recent and entry lists may not be longer than the trace's. When it fails, the views show the
 * state alone and no source links.
 */
export function alignState(state: JevState, trace: Trace): Alignment {
  const sent = alignValues(trace.values ?? []);
  const theirs = state.request.values;
  if (sent.length !== theirs.length) return { aligned: false };
  const trimmed = trace.trimmed === true;
  const same = sent.every((item, index) => {
    const stateValue = theirs[index];
    return (
      stateValue !== undefined &&
      sameName(stateValue.at, item.value.at) &&
      seenAsAligned(stateValue.seen_as, item.value.sources, trimmed)
    );
  });
  if (!same) return { aligned: false };
  const recentCount = trace.session?.recent?.length ?? 0;
  const entryCount = trace.session?.entries_passed?.length ?? 0;
  if (state.recent.length > recentCount) return { aligned: false };
  if (state.session.entries_passed.length > entryCount) return { aligned: false };
  return { aligned: true, sent };
}

/** One value the way Jev received it: from the trace when aligned, from the state otherwise. */
export type SentRow = {
  jevIndex: number;
  /** Position in `trace.values`; null when the row comes from the state alone. */
  traceIndex: number | null;
  at: string;
  /** The original length in bytes of `at`, when the trace cut the location (a 已裁剪 row). */
  atLen: number | null;
  kind: ValueKind;
  value: string;
  seen: boolean;
  verified: boolean;
  /** Original length of a redacted or clipped value, from the trace. */
  len: number | null;
  clipped: boolean;
  /** The sources the trace gives (aligned rows only). */
  sources: TraceSource[];
  /** The `seen_as` text of the state (state-only rows). */
  seenAs: string[];
  /** The class of the value, from the object map or a field name; null when there is none. */
  object: string | null;
  /** Where the class came from; null when the origin is not known (a state-only row). */
  objectFrom: "map" | "name" | null;
};

function rowFromTrace(jevIndex: number, traceIndex: number, value: TraceValue): SentRow {
  return {
    jevIndex,
    traceIndex,
    at: value.at,
    atLen: value.at_len ?? null,
    kind: value.kind,
    value: value.value,
    seen: value.seen,
    verified: value.verified,
    len: value.len ?? null,
    clipped: value.clipped === true,
    sources: value.sources,
    seenAs: [],
    object: value.object ?? null,
    objectFrom: value.object === undefined ? null : value.object_from === "map" ? "map" : "name",
  };
}

/**
 * The values Jev received. Aligned: the trace's non-inert values, in order, with their sources.
 * Not aligned but parsed: the state alone. Without a state (a broken one): the trace's values.
 */
export function sentRows(
  trace: Trace,
  state: JevState | null,
  alignment: Alignment | null,
): SentRow[] {
  if (alignment?.aligned) {
    return alignment.sent.map((item) => rowFromTrace(item.jevIndex, item.traceIndex, item.value));
  }
  if (state !== null) {
    return state.request.values.map((item, jevIndex) => ({
      jevIndex,
      traceIndex: null,
      at: item.at,
      atLen: null,
      kind: item.kind ?? "reference",
      value: item.value,
      seen: item.seen_as.length > 0,
      verified: item.verified === true,
      len: null,
      clipped: false,
      sources: [],
      seenAs: item.seen_as,
      object: item.object ?? null,
      objectFrom: null,
    }));
  }
  return alignValues(trace.values ?? []).map((item) =>
    rowFromTrace(item.jevIndex, item.traceIndex, item.value),
  );
}

/**
 * The note above the values table: the record was trimmed to fit 16 KiB (`trimmed`), or the request was
 * not read in full (`values_truncated`). Null when the values are complete. A cleared record has no rows,
 * so its note is the only thing the table shows.
 */
export function valuesNotice(trace: Trace): string | null {
  const cleared =
    trace.trimmed === true && trace.values_truncated === true && (trace.values ?? []).length === 0;
  const notes: string[] = [];
  if (trace.trimmed === true) {
    notes.push(
      cleared
        ? "已裁剪：为满足 16 KiB 上限，这条记录的值被清空"
        : "已裁剪：为满足 16 KiB 上限，这条记录的部分内容被去掉了",
    );
  }
  if (trace.values_truncated === true && !cleared) {
    notes.push("请求体不是结构化数据，或含有文件部分（文件内容不拆值），拆出的值没有覆盖全部内容");
  }
  return notes.length === 0 ? null : `${notes.join("。")}。`;
}

// ------------------------------------------------------------------ the session tab

/** Recent accesses newest first; the gateway keeps them in the order it saw them. */
export function newestFirst(items: RecentAccess[]): RecentAccess[] {
  return [...items].sort((a, b) => (b.at_millis ?? 0) - (a.at_millis ?? 0));
}

/**
 * The two session lists as the session tab shows them. Both are null when the record made no Jev call:
 * the gateway writes them for Jev records only, so a missing list means "not kept", not "empty".
 */
export function sessionLists(session: TraceSession): {
  entries: EntryPass[] | null;
  recent: RecentAccess[] | null;
} {
  const entries = session.entries_passed ?? null;
  const recent = session.recent ?? null;
  return { entries, recent: recent === null ? null : newestFirst(recent) };
}

export type SessionView = {
  entries: EntryPass[];
  recent: RecentAccess[];
  /** True when the state alone is shown, so no row links to a request. */
  fallback: boolean;
};

/** The session entries and recent accesses, aligned with the state when the check passes (docs/07 7.5.2). */
export function sessionView(
  trace: Trace,
  state: JevState | null,
  alignment: Alignment | null,
): SessionView {
  const traceEntries = trace.session?.entries_passed ?? [];
  const traceRecent = trace.session?.recent ?? [];
  if (state === null) return { entries: traceEntries, recent: traceRecent, fallback: false };
  if (alignment?.aligned) {
    return {
      entries: traceEntries.slice(0, state.session.entries_passed.length),
      recent: alignRecent(state.recent.length, traceRecent),
      fallback: false,
    };
  }
  return {
    entries: state.session.entries_passed.map((path) => ({
      path,
      at_millis: null,
      request_id: null,
    })),
    recent: state.recent.map((item) => ({
      method: item.method,
      path: item.path,
      status: item.status,
      request_id: null,
      at_millis: null,
    })),
    fallback: true,
  };
}

// ------------------------------------------------------------------ reading hints (docs/06 6.5.3, 6.6.2)

export type Reading = {
  mark: "✓" | "–" | "!" | "✕";
  tone: "ok" | "none" | "warn" | "bad";
  text: string;
};

/**
 * The reading of a value, from the trace's flags only. These are the gateway's own records, not
 * Jev's reasoning (docs/06 6.5.1, 6.6.2).
 */
export function readingOf(value: {
  kind: ValueKind;
  seen: boolean;
  verified: boolean;
  inert?: boolean;
}): Reading {
  if (value.verified) return { mark: "✓", tone: "ok", text: "已核验" };
  if (value.kind === "route") return { mark: "–", tone: "none", text: "路由词" };
  if (value.kind === "input") return { mark: "–", tone: "none", text: "输入内容，不需要见过" };
  if (value.inert === true) return { mark: "–", tone: "none", text: "惰性值，不触发判定" };
  if (value.seen) return { mark: "!", tone: "warn", text: "见过，但不是同类对象" };
  return { mark: "✕", tone: "bad", text: "从未见过" };
}

/** A value that still needs evidence: a reference that Jev has to judge (its card opens by default). */
export function needsEvidence(row: { kind: ValueKind; verified: boolean }): boolean {
  return !row.verified && row.kind === "reference";
}

export type SecretMatch = { word: string; builtin: boolean };

/** The redaction word that a value's field name or location carries (docs/07 7.4.4). */
export function secretMatchOf(value: TraceValue, extra: readonly string[]): SecretMatch | null {
  const name = `${value.key ?? ""} ${value.at}`.toLowerCase();
  const builtin = BUILTIN_SECRET_WORDS.find((word) => name.includes(word));
  if (builtin !== undefined) return { word: builtin, builtin: true };
  const own = extra.find((word) => word.length > 0 && name.includes(word.toLowerCase()));
  return own === undefined ? null : { word: own, builtin: false };
}

/** A field name that looks like personal data and went to Jev unredacted (docs/07 7.9.10). */
export function sensitiveFieldOf(trace: Trace): string | null {
  for (const value of trace.values ?? []) {
    if (value.inert || value.kind !== "input" || value.value === REDACTED || value.key === null)
      continue;
    const key = value.key.toLowerCase();
    const word = SENSITIVE_FIELD_WORDS.find((item) => key.includes(item));
    if (word !== undefined) return word;
  }
  return null;
}

/**
 * Count of the values by role, for the summary lines. A value that is the interface name counts as
 * inert: it is shown as a name and is not checked (design 4.2).
 */
export function valueCounts(
  values: TraceValue[],
  names: readonly string[] = [],
): {
  total: number;
  sent: number;
  inert: number;
  unverified: number;
} {
  const isInert = (value: TraceValue) => value.inert || isNameValue(value, names);
  const sent = values.filter((value) => !isInert(value)).length;
  return {
    total: values.length,
    sent,
    inert: values.length - sent,
    unverified: values.filter((value) => !isInert(value) && !value.verified).length,
  };
}

// ------------------------------------------------------------------ Jev answer

/** Jev's answers in words: "越权 DENY 86% · 无攻击 BENIGN 99%". */
export function answerLine(jev: JevRecord): string {
  const parts: string[] = [];
  const access = topOf<JevAccess>(jev.access);
  if (access !== null && jev.access) {
    parts.push(`${ACCESS_LABEL[access]} ${access} ${pct(jev.access[access])}`);
  }
  const attack = topOf<JevAttack>(jev.attack);
  if (attack !== null && jev.attack) {
    parts.push(`${ATTACK_LABEL[attack]} ${attack} ${pct(jev.attack[attack])}`);
  }
  return parts.join(" · ");
}

/** What the gateway did with Jev's conclusion (docs/06 6.4.5): the gateway's action, not Jev's answer. */
export function gatewayText(
  outcome: Outcome,
  status: number | null,
  path: DecisionPath,
  failure: JevFailure | null,
): string {
  switch (outcome) {
    case "allowed":
      return "放行，转发给源站";
    case "would_block":
      return "本站点在观察模式：本应拦截，请求已照常转发";
    case "unjudged":
      return "Jev 不可用，按站点设置放行";
    case "blocked":
      // A spent call limit and a state that does not fit are refused whatever the site says (docs/02).
      if (failure === "JEV_CALL_LIMIT") {
        return `调用次数达到上限，不论站点设置，已拦截，返回 ${status ?? "—"}`;
      }
      if (failure === "JEV_STATE_TOO_LARGE") {
        return `上下文过大，不论站点设置，已拦截，返回 ${status ?? "—"}`;
      }
      return path === "jev_unavailable"
        ? `Jev 不可用，按站点设置拦截，返回 ${status ?? "—"}`
        : `已拦截，返回 ${status ?? "—"}`;
  }
}

/** Whether a timeout came from the site's setting or the deployment default; null when unknown. */
export function timeoutSource(timeoutMs: number, defaultMs: number | null): string | null {
  if (defaultMs === null) return null;
  return timeoutMs === defaultMs ? "默认" : "站点设置";
}

/** The byte size of the state text, as the gateway counted it (UTF-8). */
export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length;
}

// ------------------------------------------------------------------ the decision pipeline (docs/06 6.4.4)

export type StepLink =
  | { kind: "jev"; text: string }
  | { kind: "request"; id: string; text: string }
  | { kind: "session"; label: string; text: string };

export type PipelineStep = {
  id: string;
  name: string;
  /** ✓ when the step ran, – when its condition did not hold or it did not run. */
  done: boolean;
  reason: string;
  /** Milliseconds shown at the right: only Jev and the origin have a time. */
  ms: number | null;
  /** The step that settled the conclusion: drawn bold, with the outcome at the right. */
  decisive: boolean;
  links: StepLink[];
  notes: string[];
  /** A note that needs attention, shown with ▲ beside its text (docs/06 6.4.4). */
  attention: string | null;
  /** The step could not decide (an unreadable interface name): shown with ! instead of – (design 4.2). */
  warn: boolean;
};

type StepInit = Pick<PipelineStep, "id" | "name" | "done" | "reason"> & Partial<PipelineStep>;

/**
 * The function step after the session (docs/06 6.4.4, docs/07 7.4.3): a request that reaches an administrator's function,
 * or one the function table does not list. It says what the table decided. It does not decide the outcome, which the
 * judge's step still does. Null when the trace has no function, so a record without one reads as before.
 */
function functionStep(trace: Trace): StepInit | null {
  const fn = trace.function;
  if (fn === undefined) return null;
  const sentences: string[] = [];
  let warn = false;
  // The keys are compared whole and cut only for the sentence, so two keys that share their first characters stay apart.
  if (fn.attempt === "over_privilege") {
    const entry = fn.entry ?? fn.key;
    const shown = clip(entry, FUNCTION_KEY_MAX);
    sentences.push(
      fn.key === entry
        ? FUNCTION_VIEW.detail.attempt(shown)
        : FUNCTION_VIEW.detail.attemptRouted(clip(fn.key, FUNCTION_KEY_MAX), shown),
    );
    warn = true;
  } else if (fn.entry !== undefined) {
    sentences.push(FUNCTION_VIEW.detail.admin(clip(fn.entry, FUNCTION_KEY_MAX)));
  }
  if (fn.known === false) {
    sentences.push(FUNCTION_VIEW.detail.unknown(clip(fn.key, FUNCTION_KEY_MAX)));
    warn = true;
  }
  if (sentences.length === 0) return null;
  return {
    id: "function",
    name: FUNCTION_VIEW.detail.step,
    done: true,
    reason: sentences.join("；"),
    warn,
  };
}

/**
 * The interface-name step after the site (design 4.2): ✓ with the rule's name, – without a rule (the
 * path is the name), ! with the reason when the name could not be read.
 */
function interfaceStep(summary: RequestRow): PipelineStep {
  const base = {
    id: "api",
    name: "接口名",
    decisive: false,
    links: [],
    notes: [],
    attention: null,
    ms: null,
    warn: false,
  };
  const api = summary.api;
  if (api === null) return { ...base, done: false, reason: "没有规则，用 URL 路径" };
  if ("unknown" in api) {
    return { ...base, done: false, warn: true, reason: unknownTitle(api) };
  }
  return {
    ...base,
    done: true,
    reason: `规则 ${summary.path} → ${api.name}（${apiFromWords(api)}）`,
  };
}

function sessionDetail(trace: Trace): string {
  const parts: string[] = [];
  const age = trace.session?.age_seconds;
  if (age !== undefined) parts.push(`已 ${fmtElapsed(age)}`);
  const known = trace.session?.known_values;
  if (known !== undefined) parts.push(`已见 ${fmtInt(known)} 个值`);
  return parts.length > 0 ? `（${parts.join("，")}）` : "";
}

function modeOf(outcome: Outcome, path: DecisionPath): string | null {
  if (outcome === "would_block") return "观察模式";
  if (
    outcome === "blocked" &&
    (path === "jev_deny" || path === "no_session" || path === "jev_unavailable")
  ) {
    return "拦截模式";
  }
  return null;
}

function executionStep(summary: RequestRow, trace: Trace): PipelineStep {
  const status = summary.status;
  let reason: string;
  switch (summary.outcome) {
    case "allowed":
      reason = `放行 → 转发给源站${status !== null ? `，返回 ${status}` : ""}`;
      break;
    case "would_block":
      reason = "本应拦截（观察模式）→ 照常转发";
      break;
    case "unjudged":
      reason = "未经判定 → 转发给源站";
      break;
    case "blocked":
      reason = `拦截 → 返回 ${status ?? "—"}`;
      break;
  }
  if (trace.upstream_error) reason += `，源站${UPSTREAM_LABEL[trace.upstream_error]}`;
  return {
    id: "execute",
    name: "执行",
    done: true,
    reason,
    ms: summary.outcome === "blocked" ? null : (trace.timing?.origin_ms ?? null),
    decisive: false,
    links: [],
    notes: [],
    attention: null,
    warn: false,
  };
}

const EXPOSURE_KIND_LABEL: Record<ResponseExposure["attributes"][number]["kind"], string> = {
  phone: "手机号",
  email: "邮箱",
  id_card: "身份证号",
};

/**
 * The note for a suspected attribute-level over-exposure (W6, 7.9.17): which kinds of contact detail
 * another user's object carried. It names kinds, never values, and says the request was not stopped.
 */
export function exposureNote(exposure: ResponseExposure | null | undefined): string | null {
  if (!exposure) return null;
  const kinds = [...new Set(exposure.attributes.map((item) => EXPOSURE_KIND_LABEL[item.kind]))];
  if (kinds.length === 0) return null;
  return `疑似属性越权，仅告警未拦截：响应里有不属于本会话的用户的${kinds.join("、")}`;
}

/** The attention line of the learning step: what the response did beyond teaching the session. */
export function learningAttention(response: TraceResponse): string | null {
  const notes = [
    response.after_would_block ? wouldBlockNote(response) : null,
    exposureNote(response.exposure),
  ].filter((note): note is string => note !== null);
  return notes.length > 0 ? notes.join("；") : null;
}

/**
 * A response to a request that observe mode would have refused. Records written before observe mode
 * stopped learning from those responses (docs/07 section 7.4.6) were read and kept, so they say so.
 */
function wouldBlockNote(response: TraceResponse): string {
  return response.observed === "skipped"
    ? "本应拦截请求的响应没有进入上下文"
    : "本应拦截请求的响应也进入了上下文（旧版本的记录）";
}

function learningStep(summary: RequestRow, trace: Trace): PipelineStep | null {
  const response = trace.response;
  if (!response) return null;
  const links: StepLink[] = [];
  if (response.issued_session && isSessionLabel(response.issued_session)) {
    links.push({
      kind: "session",
      label: response.issued_session,
      text: `签发会话 ${shortSession(response.issued_session)}…`,
    });
  }
  const notes: string[] = [];
  if (response.entry_passed) notes.push(`会话第一次经过入口 ${trace.entry ?? summary.path}`);
  let reason: string;
  let done: boolean;
  if (response.observed === "skipped") {
    done = false;
    reason = `未观察：${response.skip ? SKIP_LABEL[response.skip] : "原因未记录"}`;
  } else {
    done = true;
    const kind = response.observed === "json" ? "JSON" : "HTML";
    reason = `${kind} 响应 ${fmtBytes(response.bytes)}：取出 ${fmtInt(response.values)} 个值，新增 ${fmtInt(response.new_values)} 个`;
  }
  return {
    id: "learn",
    name: "学习",
    done,
    reason,
    ms: null,
    decisive: false,
    links,
    notes,
    attention: learningAttention(response),
    warn: false,
  };
}

/**
 * The judgement steps of one record, in the order of docs/06 6.4.4. A step that settled the
 * conclusion is marked decisive, and the steps after it are not listed. A record in the old format
 * has only the site and the execution.
 */
export function pipelineSteps(
  summary: RequestRow,
  trace: Trace,
  jev: JevRecord | null,
): PipelineStep[] {
  const steps: PipelineStep[] = [];
  const add = (init: StepInit): void => {
    steps.push({
      ms: null,
      decisive: false,
      links: [],
      notes: [],
      attention: null,
      warn: false,
      ...init,
    });
  };
  const finish = (): PipelineStep[] => {
    steps.push(executionStep(summary, trace));
    const learned = learningStep(summary, trace);
    if (learned) steps.push(learned);
    return steps;
  };
  const path = summary.decision_path;

  const mode = modeOf(summary.outcome, path);
  const version = summary.site_version !== null ? ` · 配置 v${summary.site_version}` : "";
  add({
    id: "site",
    name: "站点",
    done: summary.site !== null,
    decisive: path === "unknown_site",
    reason:
      summary.site === null
        ? `Host ${summary.host} 不属于任何站点`
        : `${summary.site}（Host ${summary.host}）${version}${mode ? ` · ${mode}` : ""}`,
  });
  if (trace.v === 0 || path === "unknown_site") return finish();
  add(interfaceStep(summary));

  if (path === "bypass") {
    add({
      id: "bypass",
      name: "绕过",
      done: true,
      decisive: true,
      reason: `命中 ${trace.bypass ?? "绕过规则"}，直接转发`,
    });
    return finish();
  }
  add({ id: "bypass", name: "绕过", done: true, reason: "未命中" });

  if (path === "body_not_inspectable") {
    add({
      id: "body",
      name: "请求体",
      done: true,
      decisive: true,
      reason: "超过 48 KiB 判定上限或没有 Content-Length，无法判定",
    });
    return finish();
  }

  if (summary.context === "address") {
    add({ id: "session", name: "会话", done: true, reason: "未登录请求，按客户端地址计上下文" });
  } else if (summary.session === "") {
    add({ id: "session", name: "会话", done: false, reason: "没有会话凭证" });
  } else {
    add({
      id: "session",
      name: "会话",
      done: true,
      reason: `会话 ${shortSession(summary.session)}…${sessionDetail(trace)}`,
    });
  }

  const functions = functionStep(trace);
  if (functions !== null) add(functions);
  add({
    id: "entry",
    name: "入口",
    done: true,
    decisive: path === "no_session",
    reason: trace.entry ? `命中 ${trace.entry}` : "未命中",
  });
  if (path === "no_session") return finish();

  const values = trace.values ?? [];
  const names = apiValueLocations(summary.api);
  const counts = valueCounts(values, names);
  add({
    id: "values",
    name: "请求值",
    done: true,
    reason:
      counts.total === 0
        ? "请求里没有可拆出的值"
        : `${counts.total} 个：${counts.inert} 个惰性，${counts.sent} 个需核验${counts.unverified > 0 ? `，${counts.unverified} 个未核验` : ""}`,
  });

  if (path === "fast_allow") {
    const checked = values.filter((value) => !value.inert && !isNameValue(value, names));
    add({
      id: "fast",
      name: "快速放行",
      done: true,
      decisive: true,
      reason:
        counts.sent > 0
          ? `${counts.sent} 个需核验的值都已核验${byMapNote(checked)}，没有调用 Jev`
          : "请求里没有需要核验的值，没有调用 Jev",
    });
    return finish();
  }
  add({
    id: "fast",
    name: "快速放行",
    done: false,
    reason:
      counts.unverified > 0 ? `不满足：${counts.unverified} 未核验` : "不满足：没有需核验的值",
  });

  if (path === "cached_allow") {
    add({
      id: "cache",
      name: "缓存",
      done: true,
      decisive: true,
      reason: "同一会话此前的相同请求已由 Jev 放行，在缓存时长内直接复用",
      links:
        trace.cache_source && isRequestId(trace.cache_source)
          ? [
              {
                kind: "request",
                id: trace.cache_source,
                text: `来源 ${shortRequestId(trace.cache_source)}`,
              },
            ]
          : [],
    });
    return finish();
  }
  add({ id: "cache", name: "缓存", done: false, reason: "没有可复用的放行" });

  const jevDecides = path === "jev_allow" || path === "jev_deny" || path === "jev_unavailable";
  if (jev === null) {
    add({
      id: "jev",
      name: "Jev",
      done: false,
      decisive: path === "jev_unavailable",
      reason: "没有调用 Jev",
    });
  } else if (jev.failure === "JEV_CALL_LIMIT" || jev.failure === "JEV_STATE_TOO_LARGE") {
    add({
      id: "jev",
      name: "Jev",
      done: false,
      decisive: jevDecides,
      reason: `没有发出调用：${FAILURE_INFO[jev.failure].short}`,
    });
  } else if (jev.failure !== null) {
    const info = FAILURE_INFO[jev.failure];
    add({
      id: "jev",
      name: "Jev",
      done: true,
      decisive: jevDecides,
      reason: `${info.short}（${info.desc}）`,
      ms: jev.millis,
      links: [{ kind: "jev", text: "查看 Jev 上下文" }],
    });
  } else {
    add({
      id: "jev",
      name: "Jev",
      done: true,
      decisive: jevDecides,
      reason: `${answerLine(jev)} · 超时 ${fmtInt(jev.timeout_ms)} ms`,
      ms: jev.millis,
      links: [{ kind: "jev", text: "查看 Jev 上下文" }],
    });
  }
  return finish();
}

export type Waterfall = {
  total: number;
  judge: number;
  origin: number;
  other: number;
  /** Jev's share of the judging time, drawn inside the judge segment. */
  jev: number | null;
  /** The width the segments are measured against. */
  scale: number;
};

/** The timing bar: judging, origin and the rest of the total (docs/06 6.4.4). Null without timing. */
export function waterfallOf(
  timing: TraceTiming | undefined,
  jevMs: number | null,
): Waterfall | null {
  const total = timing?.total_ms;
  if (typeof total !== "number" || total <= 0) return null;
  const judge = typeof timing?.judge_ms === "number" ? timing.judge_ms : null;
  const origin = typeof timing?.origin_ms === "number" ? timing.origin_ms : null;
  if (judge === null && origin === null) return null;
  const judgeMs = judge ?? 0;
  const originMs = origin ?? 0;
  const scale = Math.max(total, judgeMs + originMs, 1);
  return {
    total,
    judge: judgeMs,
    origin: originMs,
    other: Math.max(0, scale - judgeMs - originMs),
    jev: jevMs === null ? null : Math.min(jevMs, judgeMs),
    scale,
  };
}

// ------------------------------------------------------------------ requests that are not found

/** Log gaps the status reports, for the not-found reason (docs/06 6.7.2). */
export function logGaps(
  problems: GatewayProblem[],
): Array<Extract<GatewayProblem, { kind: "log_gap" }>> {
  return problems.filter(
    (problem): problem is Extract<GatewayProblem, { kind: "log_gap" }> =>
      problem.kind === "log_gap",
  );
}

function localDay(ms: number): string {
  const date = new Date(ms);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getMonth() + 1} 月 ${date.getDate()} 日 ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** The reason an ID is not found, read from the time inside the ID (docs/06 6.7.2). */
export function missingReason(
  requestId: string,
  now: number,
  gaps: Array<Extract<GatewayProblem, { kind: "log_gap" }>>,
): string {
  const millis = requestIdMillis(requestId);
  if (millis === null) return "这不是本系统生成的请求 ID 格式（req_ 加 32 位十六进制）。";
  if (millis > now + 60_000) return "ID 时间异常，可能不是本系统生成的。";
  if (now - millis > RETENTION_MS) return `生成于 ${localDay(millis)}，已超过 7 天保留期。`;
  // Only a gap that lost decision records explains a missing ID; bypass drops do not (docs/06 6.7.2).
  const gap = gaps.find(
    (item) =>
      millis >= item.from_ms && millis <= item.to_ms && item.dropped + item.write_errors > 0,
  );
  if (gap)
    return `当时 ${gap.edge} 丢失了 ${fmtInt(gap.dropped + gap.write_errors)} 条记录（${lostReasons(gap)}），这段时间的请求可能查不到。`;
  return "可能来自其他环境的网关。";
}
