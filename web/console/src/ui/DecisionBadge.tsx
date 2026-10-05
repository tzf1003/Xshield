import {
  CheckCircleFilled,
  ClockCircleOutlined,
  CloseCircleFilled,
  EyeOutlined,
  MinusCircleOutlined,
  MinusOutlined,
  QuestionCircleFilled,
  StopOutlined,
  WarningFilled,
} from "@ant-design/icons";
import type { ReactNode } from "react";
import { type DecisionIcon, describeDecision } from "./decision.ts";
import "./kit.css";

const icons: Record<DecisionIcon, ReactNode> = {
  allow: <CheckCircleFilled aria-hidden="true" />,
  deny: <CloseCircleFilled aria-hidden="true" />,
  error: <WarningFilled aria-hidden="true" />,
  observe: <EyeOutlined aria-hidden="true" />,
  unknown: <QuestionCircleFilled aria-hidden="true" />,
  skipped: <MinusCircleOutlined aria-hidden="true" />,
  cancelled: <StopOutlined aria-hidden="true" />,
  missing: <MinusOutlined aria-hidden="true" />,
  pending: <ClockCircleOutlined aria-hidden="true" />,
};

type Props = {
  /** ALLOW, DENY, OBSERVE, UNKNOWN, ERROR, or a stage outcome such as PASS / SKIPPED. */
  decision: string | null | undefined;
  /** The terminal event has not been observed yet: shown as its own state, not as a blank. */
  pending?: boolean;
  size?: "md" | "lg";
  /** Append the raw value (`DENY`) in monospace. */
  showCode?: boolean;
};

/**
 * A decision as colour + icon + text. The word always carries the meaning; colour only reinforces
 * it, and "no decision recorded" is shown as such rather than guessed.
 */
export function DecisionBadge({ decision, pending = false, size = "md", showCode = false }: Props) {
  const view = describeDecision(decision, { pending });
  return (
    <span
      className={`xs-decision xs-decision--${view.tone}${size === "lg" ? " xs-decision--lg" : ""}`}
    >
      {icons[view.icon]}
      <span>{view.label}</span>
      {showCode && view.code ? <span className="xs-decision-code mono">{view.code}</span> : null}
    </span>
  );
}
