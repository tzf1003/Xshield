import { CheckCircleFilled, InfoCircleFilled, WarningFilled } from "@ant-design/icons";
import type { ReactNode } from "react";
import {
  type CompletenessInput,
  completenessHeadline,
  completenessKind,
  formatWatermark,
  mayBeIncomplete,
  WATERMARK_CAVEAT,
  watermarkScopeLabel,
} from "./completeness.ts";
import { formatLocal } from "./time-range.ts";
import "./ui.css";

type Props = {
  input: CompletenessInput;
  /** Accessible name of the status region, for example 搜索索引状态. */
  label: string;
  /** Page-specific verdict shown above the index state, for example 生命周期完整. */
  verdict?: string;
  /** Extra sentence for this page (what the result does not prove). */
  note?: ReactNode;
};

/**
 * The single index-completeness notice. Complete / pending / gap / not-indexed are different
 * states, an empty result is not a complete one, and the watermark (which only covers the
 * configured journal) sits in a collapsible so the caveat is always one click away.
 */
export function CompletenessBanner({ input, label, verdict, note }: Props) {
  const kind = completenessKind(input);
  const headline = completenessHeadline(kind, input);
  const Icon =
    kind === "complete"
      ? CheckCircleFilled
      : kind === "not_indexed"
        ? InfoCircleFilled
        : WarningFilled;
  return (
    <div className={`xs-banner xs-banner--${kind}`} role="status" aria-label={label}>
      <Icon className="xs-banner-icon" aria-hidden="true" />
      <div className="xs-banner-body">
        {verdict ? <strong>{verdict}</strong> : null}
        <strong>{headline}</strong>
        <p>
          {mayBeIncomplete(kind) ? "当前结果可能不完整；" : ""}
          {WATERMARK_CAVEAT}
        </p>
        {note ? <p>{note}</p> : null}
        <details>
          <summary>查看水位</summary>
          {input.observations.map((observation) => (
            <dl key={observation.label}>
              <dt>{observation.label}观察时间</dt>
              <dd className="mono">
                {observation.asOf
                  ? `${formatLocal(observation.asOf, "microsecond")}（${observation.asOf}）`
                  : "尚未读取"}
              </dd>
              <dt>{observation.label}水位</dt>
              <dd className="mono">{formatWatermark(observation.watermark)}</dd>
              <dt>水位范围</dt>
              <dd>{watermarkScopeLabel(observation.scope)}</dd>
            </dl>
          ))}
          <dl>
            <dt>索引缺口</dt>
            <dd>{input.hasGaps ? "存在" : "未观察到"}</dd>
            <dt>待发布段</dt>
            <dd>{input.pendingSegments}</dd>
          </dl>
        </details>
      </div>
    </div>
  );
}
