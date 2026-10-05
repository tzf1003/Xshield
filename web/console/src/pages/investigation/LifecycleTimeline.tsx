import {
  CheckCircleFilled,
  ClockCircleOutlined,
  CloseCircleFilled,
  QuestionCircleFilled,
} from "@ant-design/icons";
import { Collapse, Timeline } from "antd";
import type { ReactNode } from "react";
import type { PillTone } from "../../ui/TonePill";
import "./investigation.css";
import "./lifecycle.css";

export type LifecycleItem = {
  key: string;
  tone: PillTone;
  /** The clickable header, for example `#3 · model.responded · success`. */
  title: string;
  /** When it happened, shown on the right of the header. */
  time: ReactNode;
  /** The facts that open under the header. */
  body: ReactNode;
};

const dots: Record<PillTone, { color: "green" | "red" | "gray" | "blue"; icon: ReactNode }> = {
  allow: { color: "green", icon: <CheckCircleFilled aria-hidden="true" /> },
  deny: { color: "red", icon: <CloseCircleFilled aria-hidden="true" /> },
  observe: { color: "blue", icon: <ClockCircleOutlined aria-hidden="true" /> },
  unknown: { color: "gray", icon: <QuestionCircleFilled aria-hidden="true" /> },
};

/**
 * Lifecycle events of one model call or agent run, oldest first as the server recorded them.
 * Each event is collapsed to its sequence, type and state; the facts open on demand, so a long
 * lifecycle stays readable and nothing is hidden from the keyboard.
 */
export function LifecycleTimeline({
  items,
  label,
}: {
  items: readonly LifecycleItem[];
  label: string;
}) {
  return (
    <section aria-label={label} className="xs-lifecycle">
      <Timeline
        items={items.map((item) => ({
          key: item.key,
          color: dots[item.tone].color,
          icon: dots[item.tone].icon,
          content: (
            <Collapse
              ghost
              size="small"
              items={[
                {
                  key: item.key,
                  label: <span className="mono">{item.title}</span>,
                  extra: item.time,
                  children: item.body,
                },
              ]}
            />
          ),
        }))}
      />
    </section>
  );
}
