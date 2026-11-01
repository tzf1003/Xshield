// The learned values of a session as a running total (docs/06 6.4.7): a line that rises as the session
// learns. Each sampled point is a hover target that names the request it belongs to, its time and the
// total at that request. The figure beside it carries the same number as text.

import { useMemo } from "react";
import type { TimelineRow } from "../../api/types.ts";
import { fmtClock, fmtInt } from "../../lib/format.ts";
import { runningTotal, sampleIndices } from "./sessions-model.ts";

const WIDTH = 300;
const HEIGHT = 36;
const MAX_POINTS = 240;

export function TimelineSpark({ rows }: { rows: TimelineRow[] }) {
  const totals = useMemo(() => runningTotal(rows), [rows]);
  const top = totals[totals.length - 1] ?? 0;
  if (rows.length < 2 || top === 0) return null;

  const indices = sampleIndices(rows.length, MAX_POINTS);
  const span = rows.length - 1;
  const slot = WIDTH / indices.length;
  const x = (index: number) => (index / span) * WIDTH;
  const y = (value: number) => HEIGHT - 3 - (value / top) * (HEIGHT - 6);
  const points = indices
    .map((index) => `${x(index).toFixed(1)},${y(totals[index] ?? 0).toFixed(1)}`)
    .join(" ");
  const label = `已见值随时间增长，共 ${fmtInt(top)}`;

  return (
    <svg
      className="sx-spark"
      viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      <title>{label}</title>
      <polyline className="spark-line" points={points} vectorEffect="non-scaling-stroke" />
      {indices.map((index) => {
        const row = rows[index];
        if (row === undefined) return null;
        return (
          <rect
            key={row.request_id}
            x={Math.max(0, x(index) - slot / 2)}
            y={0}
            width={slot}
            height={HEIGHT}
          >
            <title>
              {`${fmtClock(row.at_millis).slice(0, 8)} ${row.method} ${row.path} · 已见 ${fmtInt(totals[index] ?? 0)}`}
            </title>
          </rect>
        );
      })}
    </svg>
  );
}
