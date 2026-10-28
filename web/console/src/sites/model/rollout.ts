import type { SitePolicyConfig, SiteRevision, SiteRollout, SiteRouteConfig } from "../../api.ts";
import { type RolloutReportRequest, reportTime } from "../../rollout-report.ts";

/** `MAX_OBSERVE_WINDOW_SECONDS`: the longest observe window a save may request. */
export const MAX_OBSERVE_WINDOW_SECONDS = 30 * 24 * 3600;
/** `EXPIRY_WARNING_SECONDS`: how long before the deadline the console warns. */
export const EXPIRY_WARNING_SECONDS = 24 * 3600;
/** The window a new observe rollout starts with (docs/32 32.4: at least seven days). */
export const DEFAULT_OBSERVE_SECONDS = 7 * 24 * 3600;

export type RolloutPhase = "enforce" | "observing" | "expiring" | "expired";

/**
 * Where a rollout stands at `nowUnix`, as the edge decides it: observing until the deadline,
 * enforced from that second on without any configuration change.
 */
export function rolloutPhase(rollout: SiteRollout | undefined, nowUnix: number): RolloutPhase {
  if (!rollout) return "enforce";
  const left = rollout.observe_until_unix - nowUnix;
  if (left <= 0) return "expired";
  return left <= EXPIRY_WARNING_SECONDS ? "expiring" : "observing";
}

/** Blocks whose edge effects observe never skips (`plain_pass_through` in rollout.rs). */
const effectBlocks = [
  "request_crypto",
  "response_crypto",
  "auth_binding",
  "auth_revoke",
  "sensor_html",
  "page_actions",
  "resource_grant",
  "query_pagination",
  "share_issue",
  "auth_refresh",
  "auth_context_switch",
] as const satisfies readonly (keyof SiteRouteConfig)[];

/**
 * Whether observe can forward a refusal on this route (`SiteRollout::observes` without the
 * window and the per-route enforcement): not PUBLIC, read-only, and a plain pass-through.
 */
export function routeObservable(route: SiteRouteConfig): boolean {
  return (
    route.security_entry !== "public" &&
    route.method === "GET" &&
    route.response_mode === "" &&
    effectBlocks.every((key) => route[key] === null || route[key] === undefined)
  );
}

/** The routes an observe rollout would cover, in policy order. */
export const observableRoutes = (policy: SitePolicyConfig) => policy.routes.filter(routeObservable);

/** A fresh observe block: seven days from now, labelled with the start date. */
export function startObserve(nowUnix: number): SiteRollout {
  const day = new Date(nowUnix * 1000).toISOString().slice(0, 10).replaceAll("-", "");
  return {
    mode: "observe",
    observe_until_unix: nowUnix + DEFAULT_OBSERVE_SECONDS,
    revision: `rollout-${day}`,
  };
}

/** What a save would refuse (`SiteRollout::validate` and `validate_window`), as messages. */
export function rolloutProblems(
  rollout: SiteRollout | undefined,
  routes: readonly SiteRouteConfig[],
  nowUnix: number,
): { field: string; text: string }[] {
  if (!rollout) return [];
  const found: { field: string; text: string }[] = [];
  const until = rollout.observe_until_unix;
  if (!Number.isInteger(until) || until <= nowUnix) {
    found.push({
      field: "rollout.observe_until_unix",
      text: "观察截止时间必须在未来；已过期的观察只能改回强制。",
    });
  } else if (until - nowUnix > MAX_OBSERVE_WINDOW_SECONDS) {
    found.push({ field: "rollout.observe_until_unix", text: "观察截止时间最多在 30 天以内。" });
  }
  if (rollout.revision === "") {
    found.push({ field: "rollout.revision", text: "请填写观察标签。" });
  } else if (rollout.revision.length > 128 || !/^[A-Za-z0-9._-]+$/.test(rollout.revision)) {
    found.push({
      field: "rollout.revision",
      text: "观察标签只能包含字母、数字和 . _ -，最长 128 个字符。",
    });
  }
  const known = new Set(routes.map((route) => route.operation_id));
  const enforced = rollout.enforced_operations ?? [];
  const missing = enforced.filter((operation) => !known.has(operation));
  if (missing.length > 0) {
    found.push({
      field: "rollout.enforced_operations",
      text: `单独强制的路由不存在：${missing.join("、")}。`,
    });
  }
  if (new Set(enforced).size !== enforced.length) {
    found.push({ field: "rollout.enforced_operations", text: "单独强制的路由不能重复。" });
  }
  return found;
}

/** The rollout label a stored revision carries, read tolerantly (null when it enforces). */
function storedRolloutRevision(revision: SiteRevision): string | null {
  const policy = revision.config.policy as Record<string, unknown> | undefined;
  const rollout = policy?.rollout as Record<string, unknown> | undefined;
  return rollout?.mode === "observe" && typeof rollout.revision === "string"
    ? rollout.revision
    : null;
}

/**
 * The window an exit report covers: from the first stored revision that carried this rollout
 * label (no earlier than the longest window allows) to the deadline, or to now while it still
 * observes. Null before the window has a second in it.
 */
export function reportWindow(
  rollout: SiteRollout,
  revisions: readonly SiteRevision[],
  nowUnix: number,
): RolloutReportRequest | null {
  const created = revisions
    .filter((revision) => storedRolloutRevision(revision) === rollout.revision)
    .map((revision) => Math.floor(Date.parse(revision.created_at) / 1000))
    .filter(Number.isFinite);
  const earliest = rollout.observe_until_unix - MAX_OBSERVE_WINDOW_SECONDS;
  const start = Math.max(earliest, created.length > 0 ? Math.min(...created) : earliest);
  const end = Math.min(Math.floor(nowUnix), rollout.observe_until_unix);
  if (end <= start) return null;
  return { revision: rollout.revision, start: reportTime(start), end: reportTime(end) };
}
