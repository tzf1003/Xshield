// The learning agent's rules for the object map's screens (console design 3.1 to 3.5): when an answer disagrees with
// the rules, when a run may start, when a position may be asked again, which filter a choice of the source menu means,
// and how the times and counts read. The screens render these results. Nothing here touches the page, so the tests
// run the functions as they are.

import { ApiError } from "../../../api/client.ts";
import type {
  ObjectAgent,
  ObjectAgentFilter,
  ObjectLearningState,
  ObjectSource,
} from "../../../api/types.ts";
import { OBJECT_AGENT_TEXT } from "../../../lib/vocab.ts";

/** A hand-started run waits this long after the last one: the gateway's rule, which the console shows before the click. */
export const RUN_COOLDOWN_MS = 5 * 60_000;

const WEEK_MS = 7 * 24 * 3_600_000;

/** Whether the agent named another kind than the rules did. Such a position is ambiguous until someone decides. */
export function disagrees(agent: ObjectAgent): boolean {
  return agent.rule_choice !== null && agent.choice !== null && agent.rule_choice !== agent.choice;
}

/** Whether the day's calls have used up the site's limit. A limit of 0 keeps the agent on and makes no calls. */
export function budgetUsed(today: { used: number; limit: number }): boolean {
  return today.used >= today.limit;
}

/** Why a learning run cannot start now, or null when it can (console design 3.2). */
export function runBlock(state: ObjectLearningState, now: number): "running" | "cooldown" | null {
  if (state.running) return "running";
  const last = state.last;
  if (last !== null && last.trigger === "manual" && now - Date.parse(last.at) < RUN_COOLDOWN_MS) {
    return "cooldown";
  }
  return null;
}

/** Why a position cannot be asked again now, or null when it can (console design 3.4). */
export function askBlock(
  agentOn: boolean,
  today: { used: number; limit: number },
): "off" | "budget" | null {
  if (!agentOn) return "off";
  return budgetUsed(today) ? "budget" : null;
}

/** The source menu's choices: every source, one source, or one of the agent's two filters. */
export type SourceChoice = "all" | ObjectSource | ObjectAgentFilter;

/** The choice that a URL's source and agent filters show. */
export function choiceOf(
  source: ObjectSource | undefined,
  agent: ObjectAgentFilter | undefined,
): SourceChoice {
  return agent ?? source ?? "all";
}

/** The URL's source and agent filters for a choice: the agent's filters and a source never apply together. */
export function filtersOf(choice: SourceChoice): {
  source: ObjectSource | undefined;
  agent: ObjectAgentFilter | undefined;
} {
  if (choice === "all") return { source: undefined, agent: undefined };
  if (choice === "waiting" || choice === "failed") return { source: undefined, agent: choice };
  return { source: choice, agent: undefined };
}

/** A failure code in words; a code the console does not know is kept as itself, in brackets. */
export function failureWord(code: string): string {
  const words: Record<string, string> = OBJECT_AGENT_TEXT.failure;
  return words[code] ?? `回答不可用（${code}）`;
}

/**
 * Why a run or a question was refused, in words: the server's code when the console knows it, the code itself when it
 * does not, and the given fallback when the request never reached the server.
 */
export function refusalWord(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    const words: Record<string, string> = OBJECT_AGENT_TEXT.runError;
    return words[error.message] ?? error.message;
  }
  return fallback;
}

/** How many automatic changes of one kind happened in the last week: the settings' counts. */
export function weekCount(
  events: readonly { kind: string; at: string }[],
  kind: string,
  now: number,
): number {
  return events.filter((event) => event.kind === kind && now - Date.parse(event.at) < WEEK_MS)
    .length;
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}

/** A time as `MM-DD HH:mm` on the console's clock, or a dash for a time that does not read. */
export function stampOf(iso: string | null): string {
  if (iso === null) return "—";
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return "—";
  return `${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

/** A run's duration in seconds, at least one; a dash for a run that has not finished. */
export function durationOf(ms: number | null): string {
  return ms === null ? "—" : `${Math.max(1, Math.round(ms / 1000))} 秒`;
}
