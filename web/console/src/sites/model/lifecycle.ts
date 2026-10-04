import { reasonText } from "../../ui/reason-codes.ts";
import {
  type ApplyStateValue,
  type ConfigStatusValue,
  type SiteDisplayState,
  siteDisplayState,
} from "../../ui/state-model.ts";

export type LifecycleKey = "draft" | "validated" | "approval" | "applying" | "live";
export type StepStatus = "wait" | "process" | "finish" | "error";

export type LifecycleStep = Readonly<{
  key: LifecycleKey;
  title: string;
  status: StepStatus;
  note: string;
}>;

export type LifecycleInput = Readonly<{
  apply_state: ApplyStateValue | null;
  requires_approval: boolean | null;
  status: ConfigStatusValue | null;
  reason_code: string | null;
  desired_revision: number | null;
  active_revision: number | null;
}>;

export type Lifecycle = Readonly<{
  state: SiteDisplayState | null;
  steps: readonly LifecycleStep[];
  /** What the edge is serving versus what is staged, in one sentence. */
  edgeSummary: string;
  /** The step a failure stopped at, with the human reason; `null` unless the state is failed. */
  failure: Readonly<{ at: LifecycleKey; text: string; action: string; code: string }> | null;
}>;

/** Reasons recorded when the configuration itself is refused; everything else failed at the edge. */
const validationFailures = new Set([
  "CONTROL_SITE_POLICY_INVALID",
  "CONTROL_SITE_CONFIG_REQUEST_INVALID",
  "CONTROL_SITE_UPSTREAM_INVALID",
  "CONTROL_SITE_SSRF_BLOCKED",
  "CONTROL_SITE_PORT_UNAVAILABLE",
]);

const order: readonly LifecycleKey[] = ["draft", "validated", "approval", "applying", "live"];

export function edgeSummary(input: Pick<LifecycleInput, "desired_revision" | "active_revision">) {
  const { desired_revision: desired, active_revision: active } = input;
  if (desired === null) return "尚未读取到修订信息。";
  if (active === null) return `edge 目前没有服务该站点；暂存的是 r${desired}。`;
  return desired === active
    ? `edge 正在服务 r${active}，与最新修订一致。`
    : `edge 正在服务 r${active}；暂存的 r${desired} 尚未生效。`;
}

/**
 * Turns the server's `apply_state`, the approval flag, the configured status and the revisions
 * into the five steps an operator follows: 草稿 → 已校验 → 待审批 → 应用中 → 已生效.
 * Any saved revision has passed the server's validation (a write that fails it is rejected),
 * so 已校验 holds as soon as a revision exists. A failure stops at the step that failed.
 */
export function deriveLifecycle(input: LifecycleInput): Lifecycle {
  const state = siteDisplayState({
    apply_state: input.apply_state,
    requires_approval: input.requires_approval,
    status: input.status,
  });
  const paused = input.status === "paused" || input.apply_state === "paused";
  const title: Record<LifecycleKey, string> = {
    draft: "草稿",
    validated: "已校验",
    approval: "待审批",
    applying: "应用中",
    live: paused ? "已暂停" : "已生效",
  };
  const summary = edgeSummary(input);
  const make = (
    statuses: readonly StepStatus[],
    notes: Partial<Record<LifecycleKey, string>> = {},
  ): LifecycleStep[] =>
    order.map((key, index) => ({
      key,
      title: title[key],
      status: statuses[index] ?? "wait",
      note: notes[key] ?? "",
    }));

  if (state === null) {
    return {
      state,
      steps: make([], { draft: "尚未读取状态" }),
      edgeSummary: summary,
      failure: null,
    };
  }
  switch (state) {
    case "draft":
      return {
        state,
        steps: make(["process"], { draft: "已保存，不会发布到 edge" }),
        edgeSummary: summary,
        failure: null,
      };
    case "awaiting_approval":
      return {
        state,
        steps: make(["finish", "finish", "process"], {
          draft: "已保存",
          validated: "服务端已校验",
          approval: "等待另一位审批人",
        }),
        edgeSummary: summary,
        failure: null,
      };
    case "pending":
      return {
        state,
        steps: make(["finish", "finish", "finish", "process"], {
          approval: "无需审批或已批准",
          applying: "等待 edge 确认",
        }),
        edgeSummary: summary,
        failure: null,
      };
    case "active":
      return {
        state,
        steps: make(["finish", "finish", "finish", "finish", "finish"], {
          approval: "无需审批或已批准",
          live: "edge 已确认",
        }),
        edgeSummary: summary,
        failure: null,
      };
    case "paused":
      return {
        state,
        steps: make(["finish", "finish", "finish", "finish", "finish"], {
          approval: "无需审批或已批准",
          live: "edge 不对外服务",
        }),
        edgeSummary: summary,
        failure: null,
      };
    case "failed": {
      const reason = reasonText(input.reason_code);
      const at: LifecycleKey = validationFailures.has(reason.code) ? "validated" : "applying";
      const failedIndex = order.indexOf(at);
      const statuses: StepStatus[] = order.map((_, index) =>
        index < failedIndex ? "finish" : index === failedIndex ? "error" : "wait",
      );
      return {
        state,
        steps: make(statuses, { [at]: reason.text }),
        edgeSummary: summary,
        failure: { at, text: reason.text, action: reason.action, code: reason.code },
      };
    }
  }
}
