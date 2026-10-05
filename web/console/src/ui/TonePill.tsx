import {
  CheckCircleFilled,
  ClockCircleOutlined,
  CloseCircleFilled,
  QuestionCircleFilled,
} from "@ant-design/icons";
import type { ReactNode } from "react";
import "./kit.css";

export type PillTone = "allow" | "deny" | "observe" | "unknown";

const icons: Record<PillTone, ReactNode> = {
  allow: <CheckCircleFilled aria-hidden="true" />,
  deny: <CloseCircleFilled aria-hidden="true" />,
  observe: <ClockCircleOutlined aria-hidden="true" />,
  unknown: <QuestionCircleFilled aria-hidden="true" />,
};

/**
 * A state as colour + icon + word, with the raw stored value beside it. Colour only reinforces
 * the word, so the state survives forced colours and colour-blindness.
 */
export function TonePill({
  tone,
  children,
  code,
}: {
  tone: PillTone;
  children: ReactNode;
  /** The value as stored, in monospace. */
  code?: string;
}) {
  return (
    <span className={`xs-decision xs-decision--${tone}`}>
      {icons[tone]}
      <span>{children}</span>
      {code ? <span className="xs-decision-code mono">{code}</span> : null}
    </span>
  );
}
