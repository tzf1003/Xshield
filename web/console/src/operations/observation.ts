/**
 * How one observation of the workbench snapshot is shown. The server reports every source as
 * `{observed_at, source_state, reason_code, value}`; this turns it into one word, a tone and the
 * instant the word describes. Pure, no DOM, unit-tested (tests/operations-model.test.ts).
 *
 * Honesty rules, enforced here so no page can break them:
 *  - only a recognised value from an `available` source is ever shown as healthy, degraded or
 *    unavailable; anything else is "not observed" or "unrecognised", never a guess;
 *  - a source that was not observed has no observation time (the server stamps such rows with the
 *    snapshot time, which would read as "observed just now");
 *  - the upstream value is the last persisted health read, not a probe made for this snapshot, so
 *    it keeps its own (possibly old) time and is marked `stored`.
 */
import type { WorkbenchObservation } from "../api.ts";
import { operationReason } from "../ui/operation-reasons.ts";
import type { PillTone } from "../ui/StatePill";

export type ObservationKind = "edge" | "upstream" | "audit";

export type ObservationState =
  | "healthy"
  | "degraded"
  | "unavailable"
  /** A value or stored state outside the closed vocabulary. */
  | "unrecognized"
  /** Nothing was observed: not configured, never read, not answered or not authorized. */
  | "unobserved";

export type ObservationView = Readonly<{
  state: ObservationState;
  label: string;
  tone: PillTone;
  /** The instant the label describes; `null` when nothing was observed. */
  observedAt: string | null;
  /** The value is a stored earlier observation (the upstream health read), not a live probe. */
  stored: boolean;
  reasonCode: string;
  /** What the reason code means, for the tooltip and the detail line. */
  reasonText: string;
  /** The raw value the server sent when it is not one of the known states. */
  raw: string | null;
}>;

const values: Readonly<Record<string, Readonly<{ label: string; tone: PillTone }>>> = {
  healthy: { label: "健康", tone: "allow" },
  degraded: { label: "降级", tone: "observe" },
  unavailable: { label: "不可用", tone: "deny" },
};

/** Stored observations whose state could not be read still happened at their own time. */
const storedButUnrecognized = new Set(["WORKBENCH_UPSTREAM_STATE_UNKNOWN"]);

const unobservedLabels: Readonly<Record<WorkbenchObservation<string>["source_state"], string>> = {
  available: "未观察",
  partial: "部分观察",
  unavailable: "未观察",
  not_authorized: "无权读取",
};

export function observationView(
  observation: WorkbenchObservation<string>,
  kind: ObservationKind,
): ObservationView {
  const reason = operationReason(observation.reason_code);
  const reasonText = reason?.text ?? "服务端返回了控制台尚未识别的原因码。";
  const base = {
    reasonCode: observation.reason_code,
    reasonText,
  };
  const value = observation.value;
  if (observation.source_state === "available" && value !== null) {
    const known = Object.hasOwn(values, value) ? values[value] : undefined;
    return {
      ...base,
      state: known ? (value as ObservationState) : "unrecognized",
      label: known ? known.label : "无法识别",
      tone: known ? known.tone : "unknown",
      observedAt: observation.observed_at,
      stored: kind === "upstream",
      raw: known ? null : value,
    };
  }
  if (storedButUnrecognized.has(observation.reason_code)) {
    return {
      ...base,
      state: "unrecognized",
      label: reason?.label ?? "无法识别",
      tone: "unknown",
      observedAt: observation.observed_at,
      stored: true,
      raw: null,
    };
  }
  return {
    ...base,
    state: "unobserved",
    label:
      observation.source_state === "not_authorized"
        ? unobservedLabels.not_authorized
        : (reason?.label ?? unobservedLabels[observation.source_state]),
    tone: "unknown",
    observedAt: null,
    stored: false,
    raw: null,
  };
}
