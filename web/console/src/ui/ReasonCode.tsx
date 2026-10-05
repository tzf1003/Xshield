import { Tooltip } from "antd";
import { CopyButton } from "./CopyButton";
import { describeReason } from "./request-reasons.ts";
import "./ui.css";

type Props = {
  code: string | null | undefined;
  /**
   * `stacked`: label over code (table cells). `inline`: label then code. `full`: also the
   * explanation and the recommended next step (banners and drawers).
   */
  variant?: "stacked" | "inline" | "full";
  /** Keep the copy control out of the tab order (dense tables). */
  quietCopy?: boolean;
  /** Omit the copy control, for example inside a button where nesting a button is invalid. */
  copyable?: boolean;
};

/**
 * A reason code in words, with the raw code kept in monospace next to a copy button. A code the
 * dictionary does not know is shown as received and marked as not described.
 */
export function ReasonCode({
  code,
  variant = "stacked",
  quietCopy = false,
  copyable = true,
}: Props) {
  const reason = describeReason(code);
  const className = `xs-reason xs-reason--${reason.tone}${variant === "inline" ? " xs-reason--inline" : ""}`;
  if (reason.code === "") {
    return <span className="xs-reason-label muted">{reason.label}</span>;
  }
  const label = (
    <span className="xs-reason-label">{reason.known ? reason.label : "未收录的原因码"}</span>
  );
  const raw = (
    <span className="xs-reason-code">
      <code className="mono">{reason.code}</code>
      {copyable ? <CopyButton value={reason.code} tabbable={!quietCopy} /> : null}
    </span>
  );
  if (variant === "full") {
    return (
      <span className={className}>
        {label}
        {raw}
        <span className="xs-reason-full">
          <p>{reason.explain}</p>
          <p>
            <strong>建议：</strong>
            {reason.next}
          </p>
        </span>
      </span>
    );
  }
  return (
    <span className={className}>
      <Tooltip
        title={
          <span className="xs-tip">
            <span>{reason.explain}</span>
            <span>建议：{reason.next}</span>
          </span>
        }
      >
        {label}
      </Tooltip>
      {raw}
    </span>
  );
}
