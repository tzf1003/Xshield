import type { Watermark } from "../api-contract.ts";

/**
 * The four index states every investigation page distinguishes. "complete" never means the
 * index has no gap for other log sources: the watermark only covers the configured journal.
 */
export type CompletenessKind = "complete" | "pending" | "gap" | "not_indexed";

export type CompletenessObservation = Readonly<{
  /** Which read this observation belongs to, for example 摘要 / 事件 / 列表. */
  label: string;
  asOf: string | null;
  watermark: Watermark | null;
  /** Server-stated scope of the watermark, when the response carries one. */
  scope?: string;
}>;

export type CompletenessInput = Readonly<{
  hasGaps: boolean;
  pendingSegments: number;
  /** The lookup found nothing in the index (not the same as "does not exist"). */
  notFound?: boolean;
  observations: readonly CompletenessObservation[];
}>;

export function completenessKind(input: CompletenessInput): CompletenessKind {
  if (input.notFound) return "not_indexed";
  if (input.hasGaps) return "gap";
  if (input.pendingSegments > 0) return "pending";
  return "complete";
}

/** `索引存在缺口 · 2 个待发布段`, `未观察到索引缺口 · 0 个待发布段`, ... */
export function completenessHeadline(kind: CompletenessKind, input: CompletenessInput): string {
  const pending = `${input.pendingSegments} 个待发布段`;
  switch (kind) {
    case "not_indexed":
      return `当前索引未命中 · ${pending}`;
    case "gap":
      return `索引存在缺口 · ${pending}`;
    case "pending":
      return `索引仍在同步 · ${pending}`;
    case "complete":
      return `未观察到索引缺口 · ${pending}`;
  }
}

/** Whether the result may be missing facts that exist but are not published yet. */
export function mayBeIncomplete(kind: CompletenessKind): boolean {
  return kind === "gap" || kind === "pending";
}

export function formatWatermark(watermark: Watermark | null): string {
  return watermark ? `${watermark.producer_boot_id} / ${watermark.producer_sequence}` : "尚不可用";
}

export const WATERMARK_CAVEAT = "水位仅代表配置的日志源，独立 Outbox 可能仍待发布。";

/** `configured_journal` and friends, in words. */
export function watermarkScopeLabel(scope: string | undefined): string {
  if (scope === undefined || scope === "configured_journal") return "配置的日志源";
  return scope;
}
