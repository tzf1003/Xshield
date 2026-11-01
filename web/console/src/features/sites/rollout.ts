// What the gateways say about a saved version (docs/07 7.9.13, docs/06 6.4.9): the header, the list row
// and the banner after a save all read the same rules, so they cannot disagree.

import type { EdgeRollout, Rollout } from "../../api/types.ts";
import { errorText } from "../../lib/vocab.ts";

/** After this long without every gateway loading a saved version, the gap is reported (docs/06 6.4.9). */
export const LOAD_WAIT_MS = 30_000;

export type RolloutTone = "ok" | "wait" | "warn" | "bad" | "none";

export type RolloutLine = { tone: "info" | "wait" | "warn" | "bad"; text: string };

export type RolloutView = {
  tone: RolloutTone;
  /** "● v13 已生效", "1/2 个网关已生效", "没有在线的网关，…", or the first load error. */
  headline: string;
  /** One line per gateway that needs a word: offline, failed, or still on an older version. */
  lines: RolloutLine[];
  loaded: number;
  online: number;
  /** Online gateways that have not loaded this version and did not fail. */
  lagging: EdgeRollout[];
};

const SHORT_LOAD_ERRORS: Record<string, string> = {
  SITE_CONFIG_ORIGIN_INVALID: "源站地址格式不正确",
  SITE_CONFIG_SESSION_INVALID: "会话凭证格式不正确",
  SITE_CONFIG_ENTRIES_INVALID: "入口规则格式不正确",
  SITE_CONFIG_BYPASS_INVALID: "绕过规则格式不正确",
  SITE_CONFIG_HOSTS_INVALID: "Host 格式不正确",
  SITE_CONFIG_NAME_INVALID: "站点名格式不正确",
  SITE_CONFIG_ADVANCED_INVALID: "高级判定参数有误",
  SITE_HOST_TAKEN: "Host 已属于其他站点",
};

/** The error of a gateway in a few words, for the list; the full text is in errorText. */
export function shortLoadError(code: string): string {
  return SHORT_LOAD_ERRORS[code] ?? errorText(code);
}

/** True when the version was saved more than LOAD_WAIT_MS ago. */
export function isStale(updatedAt: string, now: number): boolean {
  const saved = Date.parse(updatedAt);
  return Number.isFinite(saved) && now - saved > LOAD_WAIT_MS;
}

export function rolloutView(rollout: Rollout, updatedAt: string, now: number): RolloutView {
  const version = rollout.version;
  const count = rollout.edges_online;
  const loaded = rollout.edges_loaded;
  const online = rollout.edges.filter((edge) => edge.online);
  const offlineLines: RolloutLine[] = rollout.edges
    .filter((edge) => !edge.online)
    .map((edge) => ({ tone: "info", text: `${edge.edge} 离线` }));
  if (count === 0 || online.length === 0) {
    return {
      tone: "none",
      headline: "没有在线的网关，配置已保存，网关上线后加载",
      lines: offlineLines,
      loaded,
      online: count,
      lagging: [],
    };
  }
  const failed = online.filter((edge) => edge.error !== null);
  const first = failed[0];
  if (first && first.error !== null) {
    const failedLines: RolloutLine[] = failed.map((edge) => ({
      tone: "bad",
      text: `${edge.edge} 加载失败：${errorText(edge.error ?? undefined)}`,
    }));
    return {
      tone: "bad",
      headline: `✕ 加载失败：${shortLoadError(first.error)}`,
      lines: [...failedLines, ...offlineLines],
      loaded,
      online: count,
      lagging: [],
    };
  }
  const lagging = online.filter((edge) => (edge.loaded_version ?? 0) < version);
  if (loaded >= count && lagging.length === 0) {
    return {
      tone: "ok",
      headline: `● v${version} 已生效`,
      lines: offlineLines,
      loaded,
      online: count,
      lagging,
    };
  }
  const stale = isStale(updatedAt, now);
  const laggingLines: RolloutLine[] = lagging.map((edge) => ({
    tone: stale ? "warn" : "wait",
    text: `${edge.edge} 还没有加载 v${version}（停在 ${edge.loaded_version === null ? "没有版本" : `v${edge.loaded_version}`}）`,
  }));
  return {
    tone: stale ? "warn" : "wait",
    headline: `${loaded}/${count} 个网关已生效`,
    lines: [...laggingLines, ...offlineLines],
    loaded,
    online: count,
    lagging,
  };
}

/** The one-line version of the status for a list row: "● v12 · 2/2 个网关已生效". */
export function rolloutListText(
  rollout: Rollout,
  updatedAt: string,
  now: number,
): { tone: RolloutTone; text: string } {
  const view = rolloutView(rollout, updatedAt, now);
  if (view.tone === "none") return { tone: "none", text: "没有在线的网关" };
  if (view.tone === "bad") return { tone: "bad", text: view.headline };
  const mark = view.tone === "ok" ? "●" : "◌";
  return {
    tone: view.tone,
    text: `${mark} v${rollout.version} · ${view.loaded}/${view.online} 个网关已生效`,
  };
}
