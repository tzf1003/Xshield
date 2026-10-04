import { type ReasonTone, type ReasonTuple, reasonData } from "./request-reasons-data.ts";

export type { ReasonTone };

/**
 * Request-level reason codes in plain Chinese: a short label, what the system observed, and what
 * to do next. The data (`request-reasons-data.ts`) covers every code the gateway, core and worker
 * sources emit; tests/request-reasons.test.ts scans those sources and fails on an unmapped one.
 * A code that is not in the table is shown exactly as received, marked as not described.
 */
export type ReasonDescription = Readonly<{
  code: string;
  /** False for a code this build has no description for (or a missing code). */
  known: boolean;
  tone: ReasonTone;
  label: string;
  explain: string;
  next: string;
}>;

const table: ReadonlyMap<string, ReasonTuple> = new Map(Object.entries(reasonData));

export const UNDESCRIBED_EXPLAIN = "控制台尚未收录该原因码的说明，请按原始代码核对。";
export const UNDESCRIBED_NEXT = "对照服务端审计事件与 docs/11 的原因码约定，必要时联系平台管理员。";

export function isKnownReason(code: string | null | undefined): boolean {
  return typeof code === "string" && table.has(code);
}

export function describeReason(code: string | null | undefined): ReasonDescription {
  if (code === null || code === undefined || code === "") {
    return {
      code: "",
      known: false,
      tone: "unknown",
      label: "未记录原因",
      explain: "该记录没有携带原因码。",
      next: "结合阶段结果与事件时间线判断。",
    };
  }
  const tuple = table.get(code);
  if (!tuple) {
    return {
      code,
      known: false,
      tone: "unknown",
      label: code,
      explain: UNDESCRIBED_EXPLAIN,
      next: UNDESCRIBED_NEXT,
    };
  }
  const [tone, label, explain, next] = tuple;
  return { code, known: true, tone, label, explain, next };
}

/** Every code with a description, for tests and the reason legend. */
export function describedReasonCodes(): readonly string[] {
  return [...table.keys()];
}
