// The state of the "需要处理" list, read by both places that show it: the bell of the top bar, which every
// page has, and the one-line summary on the overview (docs/06 6.3.2, 6.4.2). Both call this hook. The
// queries they use share their keys, so each answer is read once however many places show it.

import { useSites, useStatus, useSystemModels } from "../../api/queries.ts";
import { useNowBucket } from "../../app/scope.ts";
import {
  type AttentionCounts,
  type AttentionItem,
  attentionCounts,
  buildAttention,
} from "./attention.ts";
import { useAttentionReads } from "./attention-reads.ts";

/** How often the list re-reads the model configuration (design 3.6). */
const MODEL_RECHECK_MS = 30_000;

/** A read that failed, so the rows that depend on it are missing from the list. */
export type AttentionNotice = {
  key: "sites" | "reads" | "models";
  text: string;
  retry: () => void;
};

export type NeedsAttention = {
  /** The gateway status has not loaded yet, so nothing can be said. */
  loading: boolean;
  /** The gateway status could not be read, so no row can be judged. */
  failed: boolean;
  error: unknown;
  retryStatus: () => void;
  /** The rows that need handling, most serious first. */
  items: AttentionItem[];
  counts: AttentionCounts;
  /** A read that decides whether a row exists is still loading. */
  checking: boolean;
  notices: AttentionNotice[];
  /** When the gateway status was last read, for "最后检查". */
  lastCheck: number;
};

export function useNeedsAttention(): NeedsAttention {
  const status = useStatus();
  const sites = useSites();
  // A gateway that falls behind the console's Jev configuration shows up here within a minute (design 3.6).
  const models = useSystemModels(() => MODEL_RECHECK_MS);
  const now = useNowBucket();
  const list = sites.data?.sites ?? [];
  const reads = useAttentionReads(list);

  const items = status.data
    ? buildAttention({
        status: status.data,
        sites: list,
        now,
        onJevUnavailable: reads.onJevUnavailable,
        insights: reads.insights,
        evidence: reads.evidence,
        jevModels: models.data?.jev ?? null,
        agentModels: models.data?.agent ?? null,
      })
    : [];

  const notices: AttentionNotice[] = [];
  if (sites.isError) {
    notices.push({
      key: "sites",
      text: "站点数据读取失败，站点的调优建议和观察提醒暂时不列出。",
      retry: () => void sites.refetch(),
    });
  } else if (reads.failed) {
    notices.push({
      key: "reads",
      text: "部分站点的详情读取失败，未经判定就放行的提醒暂时不列出。",
      retry: reads.retry,
    });
  }
  if (models.isError) {
    notices.push({
      key: "models",
      text: "模型配置读取失败，网关配置和学习代理的提醒暂时不列出。",
      retry: () => void models.refetch(),
    });
  }

  return {
    loading: status.isPending,
    failed: !status.isPending && !status.data,
    error: status.error,
    retryStatus: () => void status.refetch(),
    items,
    counts: attentionCounts(items),
    checking: sites.isPending || reads.pending || models.isPending,
    notices,
    lastCheck: status.dataUpdatedAt,
  };
}
