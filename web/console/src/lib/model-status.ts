// What the model cards say about the state of a configuration (design agent-model-ui 2.1 and 3.6): the status line
// of each card, when the card polls, and which gateways count as not loaded in the overview. Pure functions, no
// React, so the unit tests can pin the wording and the timing.

import type {
  AgentModelsState,
  AgentUsage,
  JevModelsState,
  ModelFailure,
  ModelLoad,
} from "../api/types.ts";
import { fmtInt } from "./format.ts";
import { MODEL_LOAD_ERROR_TEXT, MODEL_TEXT, OBJECT_AGENT_TEXT } from "./vocab.ts";

/** A saved version has this long to reach the gateways before it counts as not loaded (design 2.5, 3.6). */
export const LOAD_GRACE_MS = 60_000;
/** How often a card re-reads the configuration while a version is on its way to the gateways. */
export const LOAD_POLL_MS = 5_000;
/** How often a card re-reads while a gateway is still behind after the grace period, so a late load shows without a reload. */
export const LOAD_RECHECK_MS = 30_000;

export type StatusLine = {
  tone: "ok" | "warn" | "neutral";
  icon: "●" | "▲" | "–" | "○";
  text: string;
};

/** Whether an RFC 3339 time is inside the grace period. A time that is missing counts as not recent. */
function recent(iso: string | null, now: number): boolean {
  if (iso === null) return false;
  const at = Date.parse(iso);
  return !Number.isNaN(at) && now - at < LOAD_GRACE_MS;
}

/** Gateways that run an older console version, or that refused the one they were sent. Online ones only. */
function behindOf(jev: JevModelsState, version: number): ModelLoad[] {
  return jev.loaded.filter(
    (load) => load.online && (load.error !== null || (load.version ?? 0) < version),
  );
}

/** The Jev card's line: how many gateways run the console version, or what holds one back. */
export function jevStatusLine(jev: JevModelsState, now: number): StatusLine {
  if (jev.source === null) return { tone: "neutral", icon: "–", text: MODEL_TEXT.unset };
  const online = jev.loaded.filter((load) => load.online);
  if (jev.source === "env") {
    return online.length === 0
      ? { tone: "neutral", icon: "–", text: MODEL_TEXT.onlineNone }
      : { tone: "ok", icon: "●", text: MODEL_TEXT.loadEnv(online.length) };
  }
  if (online.length === 0) return { tone: "neutral", icon: "–", text: MODEL_TEXT.onlineNone };
  const version = jev.version;
  const behind = behindOf(jev, version);
  if (behind.length === 0) {
    return {
      tone: "ok",
      icon: "●",
      text: MODEL_TEXT.loadedOf(online.length, online.length, version),
    };
  }
  const first = behind.find((load) => load.error !== null) ?? behind[0];
  if (first === undefined) return { tone: "neutral", icon: "–", text: MODEL_TEXT.onlineNone };
  if (first.error === null && recent(jev.updated_at, now)) {
    return { tone: "neutral", icon: "○", text: MODEL_TEXT.loadWaiting(version) };
  }
  const base = MODEL_TEXT.loadBehind(first.edge, first.version);
  const reason = first.error === null ? null : (MODEL_LOAD_ERROR_TEXT[first.error] ?? first.error);
  return { tone: "warn", icon: "▲", text: reason === null ? base : `${base}：${reason}` };
}

/** The card re-reads the configuration only while a saved version is still on its way to some gateway. */
export function jevWaitingForLoad(jev: JevModelsState | undefined, now: number): boolean {
  if (jev === undefined || jev.source !== "console" || jev.version < 1) return false;
  if (!recent(jev.updated_at, now)) return false;
  return behindOf(jev, jev.version).some((load) => load.error === null);
}

/** Whether an online gateway still runs an older version, grace period or not: the card re-reads at LOAD_RECHECK_MS. */
export function jevBehind(jev: JevModelsState | undefined): boolean {
  if (jev === undefined || jev.source !== "console" || jev.version < 1) return false;
  return behindOf(jev, jev.version).length > 0;
}

/** The gateways the overview lists: online, behind the console version, for more than the grace period. */
export function jevNotLoaded(jev: JevModelsState, now: number): ModelLoad[] {
  const version = jev.version;
  if (jev.source !== "console" || version < 1 || jev.updated_at === null) return [];
  const at = Date.parse(jev.updated_at);
  if (Number.isNaN(at) || now - at <= LOAD_GRACE_MS) return [];
  return behindOf(jev, version);
}

/** The gateways that are not loaded, named, with the reason each one gives (design 3.6). */
export function notLoadedSummary(loads: ModelLoad[]): { edges: string; reason: string } {
  const reasons = new Set(
    loads.map((load) =>
      load.error === null
        ? MODEL_TEXT.edgeNoLoadReason
        : (MODEL_LOAD_ERROR_TEXT[load.error] ?? load.error),
    ),
  );
  return {
    edges: loads.map((load) => load.edge).join("、"),
    reason: [...reasons].join("、"),
  };
}

/**
 * The agent card's line from its latest calls (design 2.1): configured or not, no call yet, the newest answer, or
 * the failures in a row with the reason the newest one ended with.
 */
export function agentStatusLine(agent: AgentModelsState): StatusLine {
  if (!agent.configured) return { tone: "neutral", icon: "–", text: MODEL_TEXT.unset };
  const [newest] = agent.recent_failures;
  if (newest === undefined) return { tone: "neutral", icon: "–", text: MODEL_TEXT.agentNoCalls };
  if (newest === null) return { tone: "ok", icon: "●", text: MODEL_TEXT.agentLastOk };
  return {
    tone: "warn",
    icon: "▲",
    text: MODEL_TEXT.agentFailing(failingStreak(agent.recent_failures), agentFailureWord(newest)),
  };
}

/** How many of the newest calls failed in a row, counting from the newest. */
export function failingStreak(outcomes: (ModelFailure | null)[]): number {
  const answered = outcomes.indexOf(null);
  return answered === -1 ? outcomes.length : answered;
}

/** A learning call's failure code in words; a code the console does not know is kept in brackets. */
export function agentFailureWord(code: ModelFailure): string {
  const words: Record<string, string> = OBJECT_AGENT_TEXT.failure;
  return words[code] ?? `回答不可用（${code}）`;
}

/** Today's line under the agent card: the calls, the answers, the failures with the reason most of them had, and the sites on. */
export function agentTodayLine(usage: AgentUsage): string {
  const failed =
    usage.top_failure === null
      ? fmtInt(usage.failed)
      : `${fmtInt(usage.failed)}${MODEL_TEXT.todayTopFailure(agentFailureWord(usage.top_failure))}`;
  return MODEL_TEXT.todayCounts(
    fmtInt(usage.calls),
    fmtInt(usage.ok),
    failed,
    fmtInt(usage.enabled_sites),
  );
}
