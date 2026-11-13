// Aligns what Jev saw (`state`) with what the trace recorded (docs/07 7.5.2 and 7.5.3). The state
// itself is never changed, so the alignment is a view over two parallel structures.

import type { JevStateValue, RecentAccess, TraceSource, TraceValue } from "../api/types.ts";

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

/** A value the judge cut into pieces: how many pieces Jev received, and which one a state-only row is. */
export type SplitInfo = { pieces: number; piece: number | null };

export type AlignedValue = {
  jevIndex: number;
  traceIndex: number;
  value: TraceValue;
  /** Set when the value went to Jev in pieces: its sources are not compared, so none are shown (docs/07 7.5.2). */
  split: SplitInfo | null;
};

/** `state.request.values[i]` is the i-th non-inert trace value, in extraction order. */
export function alignValues(traceValues: TraceValue[]): AlignedValue[] {
  const aligned: AlignedValue[] = [];
  let jevIndex = 0;
  traceValues.forEach((value, traceIndex) => {
    if (value.inert) return;
    aligned.push({ jevIndex, traceIndex, value, split: null });
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

/**
 * The `seen_as` text the gateway writes for one source (engine.rs `seen_text`): `field @ request`, then the
 * object class in brackets when the map gives one, then the tier and its reliability when the map gives a tier.
 */
export function seenAsText(source: TraceSource): string {
  const base = `${source.field} @ ${source.request}`;
  const withObject = typeof source.object === "string" ? `${base} [${source.object}]` : base;
  if (typeof source.tier !== "string" || typeof source.reliability !== "string") return withObject;
  return `${withObject} (tier ${source.tier}, reliability ${source.reliability})`;
}

/** The longest `seen_as` text the judge keeps before it cuts it (state.rs `TEXT_CHARS_MAX`). */
export const SEEN_AS_CHARS_MAX = 256;

/** `text` cut the way the judge cuts a `seen_as` entry (state.rs `clip`): `max` characters and `...` when longer. */
export function clipChars(text: string, max: number): string {
  const chars = [...text];
  return chars.length > max ? `${chars.slice(0, max).join("")}...` : text;
}

/** The `seen_as` text the state holds for one source: `seenAsText` after the judge's cut. */
export function seenAsShown(source: TraceSource): string {
  return clipChars(seenAsText(source), SEEN_AS_CHARS_MAX);
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
    // The judge cuts a long entry (state.rs `clip`), so the same cut is made before the comparison.
    return source !== undefined && text === seenAsShown(source);
  });
}

type Part = { piece: number; total: number };

/** The `part` of a state value: `k/n` with 1 <= k <= n. Undefined for a whole value, "bad" when malformed. */
function partOf(value: JevStateValue): Part | undefined | "bad" {
  if (value.part === undefined) return undefined;
  const match = /^(\d+)\/(\d+)$/.exec(value.part);
  if (match === null) return "bad";
  const piece = Number(match[1]);
  const total = Number(match[2]);
  return piece >= 1 && total >= 1 && piece <= total ? { piece, total } : "bad";
}

/** One value as the trace counts it: a whole value, or the run of pieces the judge cut it into. */
export type StateEntry = { stateIndex: number; pieces: number; first: JevStateValue };

/**
 * The state's values grouped the way the trace counts them: each run of pieces (`part` 1/n to n/n, all at
 * the same location) is one value. Null when a run is broken, so the record cannot be aligned (docs/02 2.2).
 */
export function stateEntries(values: JevStateValue[]): StateEntry[] | null {
  const entries: StateEntry[] = [];
  let index = 0;
  while (index < values.length) {
    const first = values[index];
    if (first === undefined) return null;
    const part = partOf(first);
    if (part === "bad") return null;
    if (part === undefined || part.total === 1) {
      entries.push({ stateIndex: index, pieces: 1, first });
      index += 1;
      continue;
    }
    if (part.piece !== 1) return null;
    for (let piece = 2; piece <= part.total; piece += 1) {
      const next = values[index + piece - 1];
      const nextPart = next === undefined ? undefined : partOf(next);
      if (
        next === undefined ||
        typeof nextPart !== "object" ||
        nextPart.piece !== piece ||
        nextPart.total !== part.total ||
        next.at !== first.at
      ) {
        return null;
      }
    }
    entries.push({ stateIndex: index, pieces: part.total, first });
    index += part.total;
  }
  return entries;
}

/** The split of a state value that is one piece of a longer value; null for a whole or a malformed value. */
export function splitOf(value: JevStateValue): SplitInfo | null {
  const part = partOf(value);
  if (part === undefined || part === "bad" || part.total === 1) return null;
  return { pieces: part.total, piece: part.piece };
}

/** The header label of a split value's card. */
export function splitBadge(split: SplitInfo): string {
  return split.piece === null ? `切成 ${split.pieces} 片` : `第 ${split.piece}/${split.pieces} 片`;
}

/** The note in a split value's card: its sources are not compared, so none are listed (docs/07 7.5.2). */
export function splitNote(split: SplitInfo): string {
  return split.piece === null
    ? `这个值太长，切成 ${split.pieces} 片送判。片段不带来源，所以来源不比对，也不列出来源。`
    : `这是切成 ${split.pieces} 片中的第 ${split.piece} 片。片段不带来源，所以来源不比对。`;
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
