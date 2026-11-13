// Aligns what Jev saw (`state`) with what the trace recorded (docs/07 7.5.2 and 7.5.3). The state
// itself is never changed, so the alignment is a view over two parallel structures.

import type { RecentAccess, TraceSource, TraceValue } from "../api/types.ts";

/** The longest location or key name the trace keeps, in bytes (docs/07 7.4.3). */
export const TRACE_NAME_BYTES_MAX = 256;

/** The UTF-8 size of one code point. */
function utf8Size(code: number): number {
  if (code < 0x80) return 1;
  if (code < 0x800) return 2;
  if (code < 0x10000) return 3;
  return 4;
}

/**
 * `text` cut to at most `max` UTF-8 bytes, on a character boundary: the rule the judge uses for names
 * (`cut` in xshield-judge's trace). The longest prefix that fits is kept.
 */
export function clipBytes(text: string, max: number): string {
  let bytes = 0;
  let end = 0;
  for (const char of text) {
    const size = utf8Size(char.codePointAt(0) ?? 0);
    if (bytes + size > max) break;
    bytes += size;
    end += char.length;
  }
  return text.slice(0, end);
}

/**
 * Whether a state's location and a trace's location are the same name. The trace cuts a name longer than
 * the limit, so both sides are cut the same way before they are compared.
 */
export function sameName(stateAt: string, traceAt: string): boolean {
  return clipBytes(stateAt, TRACE_NAME_BYTES_MAX) === clipBytes(traceAt, TRACE_NAME_BYTES_MAX);
}

export type AlignedValue = { jevIndex: number; traceIndex: number; value: TraceValue };

/** `state.request.values[i]` is the i-th non-inert trace value, in extraction order. */
export function alignValues(traceValues: TraceValue[]): AlignedValue[] {
  const aligned: AlignedValue[] = [];
  let jevIndex = 0;
  traceValues.forEach((value, traceIndex) => {
    if (value.inert) return;
    aligned.push({ jevIndex, traceIndex, value });
    jevIndex += 1;
  });
  return aligned;
}

/** `state.recent` is the tail of `trace.session.recent`; the state holds fewer when trimmed. */
export function alignRecent(
  stateRecentCount: number,
  traceRecent: RecentAccess[] | null | undefined,
): RecentAccess[] {
  const all = traceRecent ?? [];
  const count = Math.min(stateRecentCount, all.length);
  return all.slice(all.length - count);
}

/** The `seen_as` text the gateway writes for one source: `field @ request` (xshield-judge's engine). */
export function seenAsText(source: TraceSource): string {
  return `${source.field} @ ${source.request}`;
}

/**
 * docs/07 7.5.2: `seen_as` is a prefix of the sources, compared entry by entry. A trimmed trace may keep
 * fewer sources (trim levels 3 and 4), so a shorter list passes only then. A swapped order never passes,
 * because each index must carry the text of its own source.
 */
export function seenAsAligned(seenAs: string[], sources: TraceSource[], trimmed: boolean): boolean {
  if (seenAs.length > sources.length) return false;
  if (!trimmed && seenAs.length !== sources.length) return false;
  return seenAs.every((text, index) => {
    const source = sources[index];
    return source !== undefined && text === seenAsText(source);
  });
}

/** The note shown above the Jev view when `trim` is not zero (docs/06 6.4.5). */
export function trimNote(trim: number): string | null {
  if (trim <= 0) return null;
  if (trim === 1) return "为满足 8 KiB 上限，最近访问从 10 条减到 3 条";
  if (trim === 2) return "为满足 8 KiB 上限，最近访问已全部去掉";
  if (trim === 3) return "为满足 8 KiB 上限，每个值只保留 1 个来源";
  return "为满足 8 KiB 上限，入口列表被去掉，路径截到 256 字符，这个值不列来源";
}

/** The note for a record whose state was cut into batches (docs/07 7.5.1 and 7.5.2); null for one call. */
export function batchNote(batches: number | undefined, batch: number | undefined): string | null {
  if (batches === undefined || batches < 2) return null;
  return `第 ${batch ?? 1} 批，共 ${batches} 批：这次请求分成 ${batches} 批送判，本批的 state 只含其中一部分值，来源链接不可用`;
}

/** The notice for a request whose judgement left values or pieces out (docs/02 2.5); null when none were. */
export function leftOutNote(leftOut: number | undefined): string | null {
  if (leftOut === undefined || leftOut < 1) return null;
  return `攻击判定不完整：有 ${leftOut} 个值或片段没有送判（分批超过 16 批的上限），结论只依据送出的部分`;
}

export type ValueHint = { tone: "ok" | "bad" | "warn" | "none"; text: string };

/** The reading shown next to each value in the structured view (docs/06 6.4.5). */
export function valueHint(value: {
  kind?: string;
  seen_as: string[];
  verified?: boolean;
}): ValueHint {
  if (value.kind === "route") return { tone: "none", text: "路由词" };
  if (value.verified) return { tone: "ok", text: "已核验" };
  if (value.seen_as.length === 0) {
    if (value.kind === "input") return { tone: "none", text: "表单输入" };
    return { tone: "bad", text: "从未见过" };
  }
  return { tone: "warn", text: "见过但不是同类对象" };
}
