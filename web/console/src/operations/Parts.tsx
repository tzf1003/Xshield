import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  MinusCircleOutlined,
  QuestionCircleOutlined,
} from "@ant-design/icons";
import { Alert } from "antd";
import type { ReactNode } from "react";
import type { WorkbenchObservation } from "../api.ts";
import { TimeStamp } from "../ui/TimeStamp";
import { type ObservationKind, type ObservationState, observationView } from "./observation.ts";
import "../ui/ui.css";
import "./operations.css";

const icons: Record<ObservationState, ReactNode> = {
  healthy: <CheckCircleOutlined />,
  degraded: <ExclamationCircleOutlined />,
  unavailable: <CloseCircleOutlined />,
  unrecognized: <QuestionCircleOutlined />,
  unobserved: <MinusCircleOutlined />,
};

/**
 * One source of the workbench snapshot as a pill: icon, word and colour say the same thing, the
 * reason and its stable code are the tooltip. A stored observation (the upstream health read)
 * carries its own age beside it, so an old value never passes for a live one.
 */
export function ObservationPill({
  observation,
  kind,
}: {
  observation: WorkbenchObservation<string>;
  kind: ObservationKind;
}) {
  const view = observationView(observation, kind);
  return (
    <span className="xs-op-observation">
      <span
        className={`xs-pill xs-pill--${view.tone} xs-pill--sm`}
        title={`${view.reasonText}（${view.reasonCode}）`}
      >
        <span className="xs-pill-icon" aria-hidden="true">
          {icons[view.state]}
        </span>
        <span>{view.label}</span>
        {view.raw && <code className="xs-pill-raw mono">{view.raw}</code>}
      </span>
      {view.stored && view.observedAt && (
        <small className="xs-op-age">
          上次观察 <TimeStamp value={view.observedAt} compact />
        </small>
      )}
    </span>
  );
}

/**
 * Hidden navigation is not authorization, and a refused read is not a failure of the page: this
 * says which role the server asks for, quietly, instead of an error banner.
 */
export function RoleHint({ title, children }: { title: string; children?: ReactNode }) {
  return <Alert type="info" showIcon title={title} description={children} />;
}
