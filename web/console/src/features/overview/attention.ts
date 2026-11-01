// The "需要处理" list of the overview (docs/06 6.4.2). The gateway rows and the Jev row come from
// GET /api/status; the site rows come from the site list: observation misses, open suggestions,
// unjudged requests, and Jev timeouts or call-limit hits at 1% of a site's Jev calls. Two sentences
// need more than the list carries, and NeedsAttention reads them (attention-reads.ts): the
// on_jev_unavailable of a site with unjudged requests, and the breakdowns of a site's misses and
// suggestions. The gateway sentences come from lib/health.ts, so this list and the top-bar light use
// the same words. Pure functions, no React.

import type {
  DecisionPath,
  GatewayProblem,
  Insights,
  OnJevUnavailable,
  SiteSummary,
  StatusResponse,
  Suggestion,
  SuggestionKind,
} from "../../api/types.ts";
import type { ChipId, RequestsSearch, SiteTab, SystemTab } from "../../app/search-schema.ts";
import { fmtInt } from "../../lib/format.ts";
import { problemText } from "../../lib/health.ts";
import { isSiteName } from "../../lib/ids.ts";
import { DECISION_INFO, FAILURE_INFO, HEALTH_LABEL, SUGGESTION_INFO } from "../../lib/vocab.ts";
import { hm } from "./clock.ts";

export type Level = "serious" | "warn" | "info";

/** Where an action leads. A site target is only offered for a name that passes isSiteName. */
export type Target =
  | { kind: "system"; tab: SystemTab }
  | { kind: "site"; name: string; tab: SiteTab; group?: "advanced" }
  | { kind: "requests"; search: RequestsSearch }
  | { kind: "jev" };

export type Action = { label: string; target: Target };

export type AttentionItem = { key: string; level: Level; text: string; actions: Action[] };

export type AttentionInput = {
  status: StatusResponse;
  sites: SiteSummary[];
  /** The current time, for how long a site has observed. */
  now: number;
  /** on_jev_unavailable of each site with unjudged requests whose detail has loaded. Missing means deny. */
  onJevUnavailable: ReadonlyMap<string, OnJevUnavailable>;
  /** Insights of the sites whose rows show a breakdown. A site without them is listed without it. */
  insights: ReadonlyMap<string, Insights>;
};

const RANK: Record<Level, number> = { serious: 0, warn: 1, info: 2 };
const DAY_MS = 86_400_000;
/** A window a link carries is never narrower than this, so it stays valid after a refresh. */
const MIN_WINDOW_MS = 60_000;
/** The order the suggestion kinds are listed in, as on the site's insights tab. */
const SUGGESTION_ORDER: SuggestionKind[] = [
  "entry_candidate",
  "bypass_candidate",
  "upload_candidate",
  "raise_jev_timeout",
  "raise_call_limit",
  "secret_field_candidate",
  "hot_would_block",
];

/** docs/06 6.4.2: a timeout or a call-limit hit counts when it is 1% of the site's Jev calls or more. */
function atLeastOnePercent(count: number, calls: number): boolean {
  return calls > 0 && count * 100 >= calls;
}

const toSystem = (tab: SystemTab): Target => ({ kind: "system", tab });
const toSite = (name: string, tab: SiteTab, group?: "advanced"): Target => ({
  kind: "site",
  name,
  tab,
  group,
});

/** The request list of one site over the last 24 hours: the window the site's own counts use. */
const siteRequests = (name: string, chip: ChipId): Target => ({
  kind: "requests",
  search: { site: name, range: "24h", chip },
});

/** The actions of a site row. A name that would not make a valid link gets none. */
function siteActions(name: string, actions: Array<[label: string, target: Target]>): Action[] {
  return isSiteName(name) ? actions.map(([label, target]) => ({ label, target })) : [];
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
          actions: siteActions(problem.site, [["打开配置", toSite(problem.site, "config")]]),
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
    // An offline instance is a warning too, like a late heartbeat; the status lights list it in full.
    case "edge_offline":
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
        { label: "查看缺口", target: toSystem("storage") },
        {
          label: "查看这段请求",
          target: { kind: "requests", search: { range: "custom", since, until } },
        },
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

/** "Jev 拒绝 11、无会话 3", most first; null unless the parts add up to the site's count. */
function missBreakdown(
  byPath: Partial<Record<DecisionPath, number>> | undefined,
  total: number,
): string | null {
  if (byPath === undefined) return null;
  // Only the paths this console knows are named; an unknown key from the server is not a sentence.
  const parts = (Object.keys(DECISION_INFO) as DecisionPath[])
    .map((path) => ({ path, count: byPath[path] ?? 0 }))
    .filter((part) => part.count > 0)
    .sort((a, b) => b.count - a.count);
  const sum = parts.reduce((acc, part) => acc + part.count, 0);
  if (parts.length === 0 || sum !== total) return null;
  return parts.map((part) => `${DECISION_INFO[part.path].name} ${fmtInt(part.count)}`).join("、");
}

/** "登记入口 1、加入绕过 1"; null unless the suggestions listed add up to the site's count. */
function suggestionBreakdown(suggestions: Suggestion[] | undefined, total: number): string | null {
  if (suggestions === undefined || suggestions.length !== total) return null;
  const parts = SUGGESTION_ORDER.map((kind) => ({
    kind,
    count: suggestions.filter((item) => item.kind === kind).length,
  })).filter((part) => part.count > 0);
  if (parts.length === 0) return null;
  return parts.map((part) => `${SUGGESTION_INFO[part.kind]} ${fmtInt(part.count)}`).join("、");
}

function observeItem(
  site: SiteSummary,
  now: number,
  insight: Insights | undefined,
): AttentionItem | null {
  if (site.mode !== "observe" || site.would_block_24h <= 0) return null;
  const since = site.observing_since_millis;
  const days = since === null ? null : Math.max(0, Math.floor((now - since) / DAY_MS));
  const head =
    days === null
      ? site.name
      : days === 0
        ? `${site.name} 今天开始观察`
        : `${site.name} 观察中 ${fmtInt(days)} 天`;
  const breakdown = missBreakdown(insight?.readiness?.would_block, site.would_block_24h);
  return {
    key: `observe-${site.name}`,
    level: "warn",
    text: `${head}：本应拦截 ${fmtInt(site.would_block_24h)} 条${breakdown === null ? "" : `（${breakdown}）`}`,
    actions: siteActions(site.name, [
      ["查看", siteRequests(site.name, "would_block")],
      ["就绪检查", toSite(site.name, "insights")],
    ]),
  };
}

function unjudgedItem(
  site: SiteSummary,
  onJev: OnJevUnavailable | undefined,
): AttentionItem | null {
  if (site.unjudged_24h <= 0 || onJev !== "allow") return null;
  return {
    key: `unjudged-${site.name}`,
    level: "warn",
    text: `${site.name} 有 ${fmtInt(site.unjudged_24h)} 个请求未经判定就放行了`,
    actions: siteActions(site.name, [["查看", siteRequests(site.name, "unjudged")]]),
  };
}

function suggestionItem(site: SiteSummary, insight: Insights | undefined): AttentionItem | null {
  if (site.suggestions <= 0) return null;
  const breakdown = suggestionBreakdown(insight?.suggestions, site.suggestions);
  return {
    key: `suggest-${site.name}`,
    level: "info",
    text: `${site.name} 有 ${fmtInt(site.suggestions)} 条调优建议${breakdown === null ? "" : `：${breakdown}`}`,
    actions: siteActions(site.name, [["查看建议", toSite(site.name, "insights")]]),
  };
}

/** The evidence line: Jev timeouts or call-limit hits that reach 1% of the site's Jev calls. */
function evidenceItem(site: SiteSummary): AttentionItem | null {
  const calls = site.jev_calls_24h;
  const timeouts = atLeastOnePercent(site.jev_timeouts_24h, calls);
  const limits = atLeastOnePercent(site.call_limits_24h, calls);
  if (!timeouts && !limits) return null;
  const parts: string[] = [];
  if (timeouts) parts.push(`Jev 超时 ${fmtInt(site.jev_timeouts_24h)} 次`);
  if (limits) parts.push(`触发调用上限 ${fmtInt(site.call_limits_24h)} 次`);
  return {
    key: `evidence-${site.name}`,
    level: "info",
    text: `${site.name} ${parts.join("、")} / ${fmtInt(calls)} 次调用`,
    actions: siteActions(site.name, [["查看证据", toSite(site.name, "config", "advanced")]]),
  };
}

function siteItems(site: SiteSummary, input: AttentionInput): AttentionItem[] {
  const insight = input.insights.get(site.name);
  return [
    observeItem(site, input.now, insight),
    unjudgedItem(site, input.onJevUnavailable.get(site.name)),
    suggestionItem(site, insight),
    evidenceItem(site),
  ].filter((item): item is AttentionItem => item !== null);
}

/** Everything that needs handling, most serious first. An empty list means nothing does. */
export function buildAttention(input: AttentionInput): AttentionItem[] {
  const items = [
    ...gatewayItems(input.status),
    ...jevItems(input.status.jev),
    ...input.sites.flatMap((site) => siteItems(site, input)),
  ];
  return items.sort((a, b) => RANK[a.level] - RANK[b.level]);
}
