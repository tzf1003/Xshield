import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  EditOutlined,
  ExclamationCircleOutlined,
  MinusCircleOutlined,
  PauseCircleOutlined,
  QuestionCircleOutlined,
  SafetyCertificateOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import type { ReactNode } from "react";
import { type HealthValue, healthValue, type SiteDisplayState } from "./state-model.ts";
import "./ui.css";

/** The palette tones of src/theme/tokens.ts: every pill has a colour, an icon and a word. */
export type PillTone = "allow" | "deny" | "observe" | "info" | "unknown";

type Spec = Readonly<{ tone: PillTone; icon: ReactNode; label: string; hint: string }>;

export const applyStateSpec: Record<SiteDisplayState, Spec> = {
  draft: {
    tone: "unknown",
    icon: <EditOutlined />,
    label: "草稿",
    hint: "草稿不会发布到 edge。",
  },
  pending: {
    tone: "info",
    icon: <SyncOutlined />,
    label: "待应用",
    hint: "已请求应用，等待 edge 确认；edge 仍在使用上一份已确认的配置。",
  },
  awaiting_approval: {
    tone: "observe",
    icon: <SafetyCertificateOutlined />,
    label: "待审批",
    hint: "变更需要独立审批；在此之前 edge 使用上一份已批准的配置。",
  },
  active: {
    tone: "allow",
    icon: <CheckCircleOutlined />,
    label: "已生效",
    hint: "edge 已确认并正在使用该配置。",
  },
  failed: {
    tone: "deny",
    icon: <CloseCircleOutlined />,
    label: "应用失败",
    hint: "edge 没有确认这份配置；它仍在使用上一份已确认的配置。",
  },
  paused: {
    tone: "unknown",
    icon: <PauseCircleOutlined />,
    label: "已暂停",
    hint: "站点已暂停，edge 不对外提供服务。",
  },
};

export const healthStateSpec: Record<HealthValue, Spec> = {
  healthy: { tone: "allow", icon: <CheckCircleOutlined />, label: "健康", hint: "探测通过。" },
  degraded: {
    tone: "observe",
    icon: <ExclamationCircleOutlined />,
    label: "降级",
    hint: "探测有响应，但与期望不符。",
  },
  unavailable: {
    tone: "deny",
    icon: <CloseCircleOutlined />,
    label: "不可用",
    hint: "探测失败或被拒绝。",
  },
  unconfigured: {
    tone: "unknown",
    icon: <MinusCircleOutlined />,
    label: "未配置",
    hint: "没有配置该项观察来源。",
  },
  unknown: {
    tone: "unknown",
    icon: <QuestionCircleOutlined />,
    label: "未知",
    hint: "服务端没有给出可识别的状态。",
  },
};

const unreadSpec: Spec = {
  tone: "unknown",
  icon: <ClockCircleOutlined />,
  label: "未读取",
  hint: "尚未从服务端读取状态。",
};

type Props =
  | { kind: "apply"; state: SiteDisplayState | null; size?: "sm" | "md" }
  | { kind: "health"; value: unknown; size?: "sm" | "md"; showRaw?: boolean };

/**
 * Apply states (draft, pending, awaiting approval, active, failed, paused) and observed health
 * (healthy, degraded, unavailable, unconfigured, unknown). Colour never carries the meaning
 * alone: the icon and the Chinese label say the same thing.
 */
export function StatePill(props: Props) {
  const spec =
    props.kind === "apply"
      ? props.state === null
        ? unreadSpec
        : applyStateSpec[props.state]
      : healthStateSpec[healthValue(props.value)];
  const raw =
    props.kind === "health" && props.showRaw && typeof props.value === "string"
      ? props.value
      : null;
  return (
    <span
      className={`xs-pill xs-pill--${spec.tone}${props.size === "sm" ? " xs-pill--sm" : ""}`}
      title={spec.hint}
    >
      <span className="xs-pill-icon" aria-hidden="true">
        {spec.icon}
      </span>
      <span>{spec.label}</span>
      {raw && <code className="xs-pill-raw mono">{raw}</code>}
    </span>
  );
}
