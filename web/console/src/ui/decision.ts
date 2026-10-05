import { outcomeName } from "./request-vocab.ts";

/**
 * How a decision or stage outcome is presented. Colour is never the only carrier: every state also
 * has an icon and a word, and "no decision recorded" and "waiting for the terminal event" are
 * states of their own rather than a blank.
 */
export type DecisionTone = "allow" | "deny" | "error" | "observe" | "unknown" | "info";
export type DecisionIcon =
  | "allow"
  | "deny"
  | "error"
  | "observe"
  | "unknown"
  | "skipped"
  | "cancelled"
  | "missing"
  | "pending";

export type DecisionView = Readonly<{
  tone: DecisionTone;
  icon: DecisionIcon;
  label: string;
  /** The raw value as received, shown in a monospace suffix when asked for. */
  code: string | null;
}>;

export function describeDecision(
  value: string | null | undefined,
  options: { pending?: boolean } = {},
): DecisionView {
  if (options.pending) {
    return { tone: "info", icon: "pending", label: "等待终态", code: null };
  }
  if (value === null || value === undefined || value === "") {
    return { tone: "unknown", icon: "missing", label: "未记录", code: null };
  }
  switch (value) {
    case "ALLOW":
      return { tone: "allow", icon: "allow", label: "放行", code: value };
    case "PASS":
      return { tone: "allow", icon: "allow", label: "通过", code: value };
    case "DENY":
      return { tone: "deny", icon: "deny", label: "拒绝", code: value };
    case "ERROR":
      return { tone: "error", icon: "error", label: "错误", code: value };
    case "OBSERVE":
      return { tone: "observe", icon: "observe", label: "观察", code: value };
    case "UNKNOWN":
      return { tone: "unknown", icon: "unknown", label: "未知", code: value };
    case "SKIPPED":
      return { tone: "unknown", icon: "skipped", label: "已跳过", code: value };
    case "CANCELLED":
      return { tone: "unknown", icon: "cancelled", label: "已取消", code: value };
    default:
      return { tone: "unknown", icon: "unknown", label: outcomeName(value).label, code: value };
  }
}
