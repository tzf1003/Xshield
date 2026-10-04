import { Tooltip } from "antd";
import {
  formatLocal,
  formatUtc,
  isoToMs,
  localOffsetLabel,
  microsToIso,
  type TimePrecision,
} from "./time-range.ts";
import "./ui.css";

type Props = {
  /**
   * RFC 3339 UTC text (search, ledger, model wire shapes) or Unix microseconds (the request
   * timeline wire shape). Anything else renders as "时间不可用".
   */
  value: string | number | null | undefined;
  precision?: TimePrecision;
  /** Show only the UTC text (detail panes that spell both out). */
  utc?: boolean;
};

/** The ISO text for either wire shape, or null when it is not a valid instant. */
export function toIso(value: string | number | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  const iso = typeof value === "number" ? microsToIso(value) : value;
  return isoToMs(iso) === null ? null : iso;
}

/**
 * A moment in the browser's local time, with the exact UTC value on hover. The `datetime`
 * attribute carries the untouched UTC text, so nothing is lost to rounding.
 */
export function TimeStamp({ value, precision = "second", utc = false }: Props) {
  const iso = toIso(value);
  if (iso === null) return <span className="xs-time muted">时间不可用</span>;
  const ms = isoToMs(iso) ?? 0;
  const local = formatLocal(iso, precision);
  const universal = formatUtc(iso, "microsecond");
  return (
    <Tooltip
      title={
        <span className="xs-tip">
          <span>{universal}</span>
          <span>
            本地 {formatLocal(iso, "microsecond")}（{localOffsetLabel(ms)}）
          </span>
        </span>
      }
    >
      <time className="xs-time" dateTime={iso}>
        {utc ? formatUtc(iso, precision) : local}
      </time>
    </Tooltip>
  );
}
