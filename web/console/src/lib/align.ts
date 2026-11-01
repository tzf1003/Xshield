// Aligns what Jev saw (`state`) with what the trace recorded (docs/07 7.5.2 and 7.5.3). The state
// itself is never changed, so the alignment is a view over two parallel structures.

import type { EntryPass, RecentAccess, TraceSource, TraceValue } from "../api/types.ts";

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

/** `state.session.entries_passed[k]` is `trace.session.entries_passed[k]`. */
export function alignEntries(traceEntries: EntryPass[] | null | undefined): EntryPass[] {
  return traceEntries ?? [];
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

export type TrimLevel = {
  level: number;
  recent: number;
  sources: number;
  valueChars: number;
};

/** The trim table of docs/07 7.5.3, in the order the gateway tries them. */
export const TRIM_LEVELS: TrimLevel[] = [
  { level: 0, recent: 10, sources: 3, valueChars: 512 },
  { level: 1, recent: 3, sources: 3, valueChars: 512 },
  { level: 2, recent: 0, sources: 3, valueChars: 512 },
  { level: 3, recent: 0, sources: 1, valueChars: 512 },
  { level: 4, recent: 0, sources: 1, valueChars: 128 },
];

/** The note shown above the Jev view when `trim` is not zero (docs/06 6.4.5). */
export function trimNote(trim: number): string | null {
  if (trim <= 0) return null;
  if (trim === 1) return "为满足 8 KiB 上限，最近访问从 10 条减到 3 条";
  if (trim === 2) return "为满足 8 KiB 上限，最近访问已全部去掉";
  if (trim === 3) return "为满足 8 KiB 上限，每个值只保留 1 个来源";
  return "为满足 8 KiB 上限，长值只保留前 128 个字符";
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
