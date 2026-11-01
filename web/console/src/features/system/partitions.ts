// The daily partitions of the decision log (docs/07 7.8.2). A partition is named for its UTC day, and the
// control plane keeps yesterday through seven days ahead, so today and two future days are the minimum
// the gateways can write into. These helpers read the names, and decide the two storage warnings of
// docs/06 6.4.11. Pure functions.

import type { Partition } from "../../api/types.ts";
import { utcDay } from "./clock.ts";

export const DAY_MS = 86_400_000;

const NAME = /^decision_log_p(\d{4})(\d{2})(\d{2})$/;

export type PartitionRow = Partition & {
  /** UTC midnight the partition covers; null for a name this page does not recognise. */
  day: number | null;
  /** Days from today: 0 is today, 1 tomorrow, negative is the past. */
  ahead: number | null;
};

/** UTC midnight of the day a partition covers, read from its name (`decision_log_pYYYYMMDD`). */
export function partitionDay(name: string): number | null {
  const match = NAME.exec(name);
  if (!match) return null;
  const ms = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  return Number.isFinite(ms) ? ms : null;
}

/** UTC midnight of the day `now` falls in. */
export function utcMidnight(now: number): number {
  const date = new Date(now);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

/** The partitions in name order, each with its day and how far ahead it is. */
export function withDays(partitions: Partition[], now: number): PartitionRow[] {
  const today = utcMidnight(now);
  return partitions
    .map((partition) => {
      const day = partitionDay(partition.name);
      const ahead = day === null ? null : Math.round((day - today) / DAY_MS);
      return { ...partition, day, ahead };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** The status word of a partition: 今天, 明天, `n 天后`, `n 天前`. */
export function aheadText(ahead: number | null): string {
  if (ahead === null) return "—";
  if (ahead === 0) return "今天";
  if (ahead === 1) return "明天";
  if (ahead > 1) return `${ahead} 天后`;
  return `${-ahead} 天前`;
}

export type StorageWarning = { tone: "bad" | "warn"; text: string };

/**
 * The storage warnings: no partition for today, or fewer than two days of partitions ahead. Either one
 * means that gateway writes will fail once the control plane has been down long enough (docs/07 7.8.2).
 */
export function storageWarnings(rows: PartitionRow[], now: number): StorageWarning[] {
  const warnings: StorageWarning[] = [];
  if (!rows.some((row) => row.ahead === 0)) {
    warnings.push({
      tone: "bad",
      text: `今天（UTC ${utcDay(now)}）没有日志分区，网关的写入会失败。控制面每小时维护分区，请检查控制面是否在运行。`,
    });
  }
  const aheads = rows.map((row) => row.ahead).filter((ahead): ahead is number => ahead !== null);
  const furthest = aheads.length > 0 ? Math.max(...aheads) : null;
  if (furthest === null || furthest < 2) {
    warnings.push({
      tone: "warn",
      text:
        furthest === null || furthest <= 0
          ? "没有提前建好的未来分区。控制面停机期间，网关的写入会失败。"
          : `未来分区只到 ${furthest} 天后，不足 2 天。控制面停机超过这段时间，网关的写入会失败。`,
    });
  }
  return warnings;
}
