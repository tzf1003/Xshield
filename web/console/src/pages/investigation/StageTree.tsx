import {
  CheckCircleFilled,
  CloseCircleFilled,
  MinusCircleFilled,
  QuestionCircleFilled,
  WarningFilled,
} from "@ant-design/icons";
import { Timeline } from "antd";
import type { ReactNode } from "react";
import type { Stage } from "../../api.ts";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { ReasonCode } from "../../ui/ReasonCode";
import { confidenceStateName, proofKindName, stageName } from "../../ui/request-vocab.ts";
import { formatDuration } from "../../ui/time-range.ts";
import "./investigation.css";
import "./request-detail.css";

type Props = {
  stages: readonly Stage[];
  /** The stage whose evidence is highlighted on the right. */
  selected: string | null;
  onSelect: (stage: Stage) => void;
};

type Dot = { color: "green" | "red" | "gray"; icon: ReactNode };
const unknownDot: Dot = { color: "gray", icon: <QuestionCircleFilled aria-hidden="true" /> };
const dots: Record<string, Dot> = {
  PASS: { color: "green", icon: <CheckCircleFilled aria-hidden="true" /> },
  DENY: { color: "red", icon: <CloseCircleFilled aria-hidden="true" /> },
  ERROR: { color: "red", icon: <WarningFilled aria-hidden="true" /> },
  SKIPPED: { color: "gray", icon: <MinusCircleFilled aria-hidden="true" /> },
  CANCELLED: { color: "gray", icon: <MinusCircleFilled aria-hidden="true" /> },
  UNKNOWN: unknownDot,
};

/**
 * The observed stages of one request, in the order their first event was recorded. Only stages
 * that left an event appear: a stage that never ran and recorded no reason has no row, and a
 * skipped stage says why. Selecting one points the right-hand tabs at its evidence.
 */
export function StageTree({ stages, selected, onSelect }: Props) {
  if (stages.length === 0) {
    return <p className="xs-foot">摘要中没有已观察到的阶段。</p>;
  }
  return (
    <Timeline
      className="xs-stages"
      items={stages.map((stage) => {
        const dot = dots[stage.outcome] ?? unknownDot;
        const name = stageName(stage.stage);
        const skipped = stage.outcome === "SKIPPED";
        return {
          key: stage.stage,
          color: dot.color,
          icon: dot.icon,
          content: (
            <button
              type="button"
              className={`xs-stage${selected === stage.stage ? " is-selected" : ""}`}
              aria-pressed={selected === stage.stage}
              onClick={() => onSelect(stage)}
            >
              <span className="xs-stage-head">
                <strong>{name.label}</strong>
                {name.known ? <span className="xs-sub mono">{stage.stage}</span> : null}
                <DecisionBadge decision={stage.outcome} />
              </span>
              <span className="xs-stage-reason">
                {skipped ? "未执行：" : ""}
                <ReasonCode code={stage.reason_code} variant="inline" copyable={false} />
              </span>
              <span className="xs-stage-meta">
                <span>耗时 {formatDuration(stage.duration_us)}</span>
                <span>{proofKindName(stage.proof_kind).label}</span>
                <span>
                  置信度：
                  {stage.confidence === null
                    ? confidenceStateName(stage.confidence_status).label
                    : stage.confidence}
                </span>
                <span>
                  {stage.event_count} 个事件 · 序号 {stage.first_request_seq}
                  {stage.last_request_seq !== stage.first_request_seq
                    ? `–${stage.last_request_seq}`
                    : ""}
                </span>
              </span>
            </button>
          ),
        };
      })}
    />
  );
}
