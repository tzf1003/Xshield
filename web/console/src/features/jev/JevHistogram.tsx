// A histogram card of the Jev page (docs/06 6.4.6, 6.5.4). Bars are drawn with CSS rather than SVG so
// the labels keep their size in a narrow card, and the threshold lines sit exactly on bucket edges.
// Every chart offers the same numbers as a table ("以表格查看"), so no reading depends on the bars.

import { type ReactNode, useId, useState } from "react";
import { fmtInt } from "../../lib/format.ts";
import { Card } from "../../ui/Page.tsx";

export type HistMarker = { at: number; text: string; strong?: boolean };
export type HistTick = { at: number; text: string };

/** The "以表格查看" switch in a card's header. */
export function TableToggle({
  open,
  controls,
  onToggle,
}: {
  open: boolean;
  controls: string;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      className="linkbtn"
      aria-pressed={open}
      aria-controls={controls}
      onClick={onToggle}
    >
      {open ? "以图查看" : "以表格查看"}
    </button>
  );
}

type Props = {
  title: string;
  counts: number[];
  /** The name of bucket `index`, for hover text and the table. */
  labelAt: (index: number) => string;
  /** Axis labels; `at` is a position in bucket units (0 = left edge, counts.length = right edge). */
  ticks: HistTick[];
  markers?: HistMarker[];
  /** What the chart says, for screen readers, since the bars alone do not. */
  summary: string;
  footnote?: ReactNode;
  dimmed?: boolean;
};

export function JevHistogram({
  title,
  counts,
  labelAt,
  ticks,
  markers = [],
  summary,
  footnote,
  dimmed = false,
}: Props) {
  const [asTable, setAsTable] = useState(false);
  const tableId = useId();
  const max = counts.reduce((top, count) => Math.max(top, count), 0);
  const buckets = counts.length;
  const at = (position: number): string => `${Math.min(100, (position / buckets) * 100)}%`;

  return (
    <Card
      title={title}
      aside={
        <TableToggle open={asTable} controls={tableId} onToggle={() => setAsTable((v) => !v)} />
      }
      className={dimmed ? "jev-hist-card dimmed" : "jev-hist-card"}
    >
      {asTable ? (
        <table id={tableId} className="tbl jev-hist-table" aria-label={`${title}（表格）`}>
          <thead>
            <tr>
              <th scope="col">区间</th>
              <th scope="col" className="num">
                次数
              </th>
            </tr>
          </thead>
          <tbody>
            {counts.map((count, index) => {
              const label = labelAt(index);
              return (
                <tr key={label}>
                  <td>{label}</td>
                  <td className="num tnum">{fmtInt(count)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div id={tableId} className="jev-hist" role="img" aria-label={summary}>
          <div className="jev-hist-plot">
            {counts.map((count, index) => {
              const label = labelAt(index);
              const height = count > 0 && max > 0 ? `${Math.max(2, (count / max) * 100)}%` : "0";
              return (
                <div key={label} className="jev-hist-col" title={`${label}：${fmtInt(count)} 次`}>
                  <span className="jev-hist-bar" style={{ height }} />
                </div>
              );
            })}
            {markers.map((marker) => {
              const classes = ["jev-hist-mark"];
              if (marker.strong) classes.push("strong");
              // Near the right edge the label goes to the left of its line, so it stays in the card.
              if (marker.at / buckets > 0.6) classes.push("flip");
              return (
                <div
                  key={`${marker.at}-${marker.text}`}
                  className={classes.join(" ")}
                  style={{ left: at(marker.at) }}
                >
                  <span className="jev-hist-mark-text">{marker.text}</span>
                </div>
              );
            })}
          </div>
          <div className="jev-hist-axis" aria-hidden="true">
            {ticks.map((tick) => (
              <span
                key={`${tick.at}-${tick.text}`}
                className={
                  tick.at <= 0
                    ? "jev-hist-tick start"
                    : tick.at >= buckets
                      ? "jev-hist-tick end"
                      : "jev-hist-tick"
                }
                style={{ left: at(tick.at) }}
              >
                {tick.text}
              </span>
            ))}
          </div>
        </div>
      )}
      {footnote ? <div className="jev-hist-foot small muted">{footnote}</div> : null}
    </Card>
  );
}
