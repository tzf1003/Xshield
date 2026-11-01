// The "需要处理" list of the overview (docs/06 6.4.2). It is built from GET /api/status (gateway
// problems and the Jev health), the site summaries (observation-mode misses and tuning suggestions)
// and the scope the page shows. The gateway sentences come from lib/health.ts, so this list and the
// top-bar light use the same words. Pure functions, no React.

import type { GatewayProblem, SiteSummary, StatusResponse } from "../../api/types.ts";
import type { GlobalSearch, RequestsSearch, SiteTab, SystemTab } from "../../app/search-schema.ts";
import { fmtInt } from "../../lib/format.ts";
import { problemText } from "../../lib/health.ts";
import { isSiteName } from "../../lib/ids.ts";
import { FAILURE_INFO, HEALTH_LABEL } from "../../lib/vocab.ts";
import { hm } from "./clock.ts";

export type Level = "serious" | "warn" | "info";

/** Where an action leads. A site target is only built from a name that passes isSiteName. */
export type Target =
  | { kind: "system"; tab: SystemTab }
  | { kind: "site"; name: string; tab: SiteTab; group?: string }
  | { kind: "requests"; search: RequestsSearch }
  | { kind: "jev" };

export type Action = { label: string; target: Target };

export type AttentionItem = { key: string; level: Level; text: string; actions: Action[] };

export type AttentionInput = {
  status: StatusResponse;
  sites: SiteSummary[];
  scope: GlobalSearch;
  now: number;
};

const RANK: Record<Level, number> = { serious: 0, warn: 1, info: 2 };
const DAY_MS = 86_400_000;
/** A window a link carries is never narrower than this, so it stays valid after a refresh. */
const MIN_WINDOW_MS = 60_000;

function toSystem(tab: SystemTab): Target {
  return { kind: "system", tab };
}

function siteActions(name: string, tab: SiteTab, label: string): Action[] {
  return isSiteName(name) ? [{ label, target: { kind: "site", name, tab } }] : [];
}

function gatewayItems(status: StatusResponse): AttentionItem[] {
  const { light, edges, problems } = status.gateway;
  const items: AttentionItem[] = [];
  if (light === "down") {
    items.push({
      key: "gateway-offline",
      level: "serious",
      text:
        edges.total === 0
          ? "还没有网关上报过心跳，网关上线后这里会显示状态"
          : `没有在线的网关：${fmtInt(edges.total)} 个实例在 24 小时内上报过心跳，现在都已离线`,
      actions: [{ label: "查看系统", target: toSystem("edges") }],
    });
  }
  problems.forEach((problem, index) => {
    items.push(...problemItems(problem, `problem-${index}`));
  });
  return items;
}

function problemItems(problem: GatewayProblem, key: string): AttentionItem[] {
  switch (problem.kind) {
    case "site_load_failed":
      return [
        {
          key,
          level: "serious",
          text: problemText(problem),
          actions: siteActions(problem.site, "config", "打开配置"),
        },
      ];
    case "version_behind":
      return [
        {
          key,
          level: "serious",
          text: problemText(problem),
          actions: [{ label: "查看系统", target: toSystem("edges") }],
        },
      ];
    case "log_gap":
      return logGapItems(problem, key);
    case "queue_pressure":
      return [
        {
          key,
          level: "warn",
          text: problemText(problem),
          actions: [{ label: "查看系统", target: toSystem("edges") }],
        },
      ];
    case "partition_missing":
      return [
        {
          key,
          level: "warn",
          text: problemText(problem),
          actions: [{ label: "查看存储", target: toSystem("storage") }],
        },
      ];
    case "heartbeat_late":
      return [
        {
          key,
          level: "warn",
          text: problemText(problem),
          actions: [{ label: "查看系统", target: toSystem("edges") }],
        },
      ];
  }
}

/**
 * A log gap is two different things: decision records that were not written (queue full or a write
 * error), which can make requests unfindable, and bypass records dropped under queue pressure, which
 * cost nothing. The first is serious; the second is a note (docs/06 6.4.2).
 */
function logGapItems(
  problem: Extract<GatewayProblem, { kind: "log_gap" }>,
  key: string,
): AttentionItem[] {
  const items: AttentionItem[] = [];
  const lost = problem.dropped + problem.write_errors;
  if (lost > 0) {
    const reasons: string[] = [];
    if (problem.dropped > 0) reasons.push(`队列满 ${fmtInt(problem.dropped)}`);
    if (problem.write_errors > 0) reasons.push(`写入失败 ${fmtInt(problem.write_errors)}`);
    const since = problem.from_ms;
    const until = Math.max(problem.to_ms, problem.from_ms + MIN_WINDOW_MS);
    items.push({
      key,
      level: "serious",
      text: `${problem.edge} ${hm(problem.from_ms)}–${hm(problem.to_ms)} 有 ${fmtInt(lost)} 条判定记录未写入（${reasons.join("、")}），这段时间的请求可能查不到`,
      actions: [
        {
          label: "查看缺口期间的请求",
          target: { kind: "requests", search: { range: "custom", since, until } },
        },
        { label: "查看缺口", target: toSystem("storage") },
      ],
    });
  }
  if (problem.dropped_bypass > 0) {
    items.push({
      key: `${key}-bypass`,
      level: "info",
      text: `${problem.edge} 在队列压力下丢弃了 ${fmtInt(problem.dropped_bypass)} 条绕过记录（静态资源），判定记录不受影响`,
      actions: [{ label: "查看系统", target: toSystem("edges") }],
    });
  }
  return items;
}

/** The failures of the last five minutes, most frequent first, with the short names of docs/06 6.6.4. */
function failureParts(
  failures: StatusResponse["jev"]["failures"],
): Array<{ short: string; count: number }> {
  const parts: Array<{ short: string; count: number }> = [];
  for (const [code, count] of Object.entries(failures)) {
    if (!count) continue;
    const info = (FAILURE_INFO as Partial<Record<string, { short: string }>>)[code];
    parts.push({ short: info?.short ?? code, count });
  }
  return parts.sort((a, b) => b.count - a.count);
}

function jevItems(jev: StatusResponse["jev"]): AttentionItem[] {
  if (jev.health !== "down" && jev.health !== "degraded") return [];
  const parts = failureParts(jev.failures);
  const failed = parts.reduce((sum, part) => sum + part.count, 0);
  const detail =
    failed > 0
      ? `最近 ${fmtInt(jev.window_minutes)} 分钟失败 ${fmtInt(failed)} 次（${parts
          .map((part) => `${part.short} ${fmtInt(part.count)}`)
          .join("、")}）`
      : `最近 ${fmtInt(jev.window_minutes)} 分钟 ${fmtInt(jev.calls)} 次调用，成功 ${fmtInt(jev.ok)} 次`;
  return [
    {
      key: "jev",
      level: jev.health === "down" ? "serious" : "warn",
      text: `Jev ${HEALTH_LABEL[jev.health].name}：${detail}`,
      actions: [{ label: "查看 Jev", target: { kind: "jev" } }],
    },
  ];
}

function siteItems(sites: SiteSummary[], scope: GlobalSearch, now: number): AttentionItem[] {
  const items: AttentionItem[] = [];
  for (const site of sites) {
    const linkable = isSiteName(site.name);
    if (site.mode === "observe" && site.would_block_24h > 0) {
      const since = site.observing_since_millis;
      const days = since === null ? null : Math.max(0, Math.floor((now - since) / DAY_MS));
      const head =
        days === null
          ? site.name
          : days === 0
            ? `${site.name} 今天开始观察`
            : `${site.name} 观察中 ${fmtInt(days)} 天`;
      items.push({
        key: `observe-${site.name}`,
        level: "warn",
        text: `${head}：最近 24 小时本应拦截 ${fmtInt(site.would_block_24h)} 条`,
        actions: linkable
          ? [
              {
                label: "查看",
                target: {
                  kind: "requests",
                  search: { ...scope, site: site.name, chip: "would_block" },
                },
              },
              { label: "就绪检查", target: { kind: "site", name: site.name, tab: "insights" } },
            ]
          : [],
      });
    }
    if (site.suggestions > 0) {
      items.push({
        key: `suggest-${site.name}`,
        level: "info",
        text: `${site.name} 有 ${fmtInt(site.suggestions)} 条调优建议`,
        actions: linkable
          ? [{ label: "查看建议", target: { kind: "site", name: site.name, tab: "insights" } }]
          : [],
      });
    }
  }
  return items;
}

/** Everything that needs handling, most serious first. An empty list means nothing does. */
export function buildAttention(input: AttentionInput): AttentionItem[] {
  const items = [
    ...gatewayItems(input.status),
    ...jevItems(input.status.jev),
    ...siteItems(input.sites, input.scope, input.now),
  ];
  return items.sort((a, b) => RANK[a.level] - RANK[b.level]);
}
