import { type ModelCallListPlan, validateModelCallListPlan } from "../api.ts";
import {
  type CausalityPlan,
  type SearchFilter,
  type SearchPlan,
  validateCausalityPlan,
  validateSearchPlan,
} from "../search.ts";
import { type Condition, conditionToFilter } from "./filter-fields.ts";
import type { UtcWindow } from "../ui/time-range.ts";

/**
 * Plan builders. Each one assembles the plain object the API expects and hands it to the
 * allowlisted validator, which is the single gate: it throws a safe `CONTROL_*_INVALID` error for
 * anything the server would refuse, so no page ever sends an unvalidated plan.
 */

// ---------------------------------------------------------------------------------------------
// Request stream: structured search with the fixed filter event_type = request.completed
// ---------------------------------------------------------------------------------------------

/**
 * Terminal events carry these outcomes (worker `PayloadSummary::parse`): `request.completed` is
 * ALLOW or DENY; only `request.aborted` can be UNKNOWN. Search has no OR, so aborted requests are
 * a separate view rather than a fourth chip.
 */
export type StreamOutcome = "all" | "DENY" | "ALLOW" | "UNKNOWN";
export type StreamTerminal = "request.completed" | "request.aborted";

export const STREAM_PAGE_SIZE = 25;

export type StreamFilters = Readonly<{
  terminal: StreamTerminal;
  outcome: StreamOutcome;
  operationId: string;
  reasonCode: string;
  traceId: string;
  subjectRef: string;
}>;

export const emptyStreamFilters: StreamFilters = {
  terminal: "request.completed",
  outcome: "all",
  operationId: "",
  reasonCode: "",
  traceId: "",
  subjectRef: "",
};

/** The outcomes a terminal event type can carry, for the chips. */
export function outcomesFor(terminal: StreamTerminal): readonly StreamOutcome[] {
  return terminal === "request.completed"
    ? ["all", "DENY", "ALLOW"]
    : ["all", "DENY", "ALLOW", "UNKNOWN"];
}

export function buildStreamPlan(window: UtcWindow, filters: StreamFilters): SearchPlan {
  const list: unknown[] = [{ kind: "text", field: "event_type", value: filters.terminal }];
  if (filters.outcome !== "all") list.push({ kind: "outcome", value: filters.outcome });
  if (filters.operationId !== "") {
    list.push({ kind: "text", field: "operation_id", value: filters.operationId });
  }
  if (filters.reasonCode !== "") {
    list.push({ kind: "text", field: "reason_code", value: filters.reasonCode });
  }
  if (filters.traceId !== "") list.push({ kind: "trace_id", value: filters.traceId });
  if (filters.subjectRef !== "") list.push({ kind: "subject_ref", value: filters.subjectRef });
  return validateSearchPlan({
    schema_version: 3,
    ...window,
    filters: list,
    sort: "occurred_at_desc",
    limit: STREAM_PAGE_SIZE,
  });
}

/** Number of optional filters applied on top of the terminal type and outcome. */
export function extraFilterCount(filters: StreamFilters): number {
  return [filters.operationId, filters.reasonCode, filters.traceId, filters.subjectRef].filter(
    (value) => value !== "",
  ).length;
}

// ---------------------------------------------------------------------------------------------
// Structured search page
// ---------------------------------------------------------------------------------------------

export const PAGE_SIZES = [10, 25, 50, 100, 200, 500, 1000] as const;

export function buildSearchPlan(input: {
  window: UtcWindow;
  conditions: readonly Pick<Condition, "field" | "value">[];
  sort: SearchPlan["sort"];
  limit: number;
}): SearchPlan {
  return validateSearchPlan({
    schema_version: 3,
    ...input.window,
    filters: input.conditions.map(conditionToFilter),
    sort: input.sort,
    limit: input.limit,
  });
}

/**
 * A plan for display. A subject reference is a low-entropy identifier that the server only ever
 * sees as a keyed digest, so the console does not repeat it on screen either.
 */
export function displayPlan(plan: SearchPlan): SearchPlan {
  return {
    ...plan,
    filters: plan.filters.map(
      (filter): SearchFilter =>
        filter.kind === "subject_ref" ? { kind: "subject_ref", value: "[已隐藏]" } : filter,
    ),
  };
}

/** Stable text for query keys: the plan as submitted, subject reference included. */
export function planKey(plan: SearchPlan): string {
  return JSON.stringify(plan);
}

// ---------------------------------------------------------------------------------------------
// Model-call list
// ---------------------------------------------------------------------------------------------

export const MODEL_PAGE_SIZES = [10, 25, 50, 100] as const;

export function buildModelListPlan(window: UtcWindow, limit: number): ModelCallListPlan {
  return validateModelCallListPlan({ ...window, limit });
}

// ---------------------------------------------------------------------------------------------
// Causality
// ---------------------------------------------------------------------------------------------

export type CausalityDirection = CausalityPlan["direction"];
export const DEFAULT_CAUSALITY_DEPTH = 2;
export const DEFAULT_CAUSALITY_NODES = 16;

export function buildCausalityPlan(input: {
  window: UtcWindow;
  eventId: string;
  direction: CausalityDirection;
  maxDepth: number;
  maxNodes: number;
}): CausalityPlan {
  return validateCausalityPlan({
    schema_version: 3,
    ...input.window,
    event_id: input.eventId,
    direction: input.direction,
    max_depth: input.maxDepth,
    max_nodes: input.maxNodes,
  });
}
