// The six metric cards of the overview (docs/06 6.4.2): the figures of the scope, the change from the
// window before it, and a twelve-point trend. Each card opens the request list filtered to its figure.

import { useSummary } from "../../api/queries.ts";
import { type Scope, scopeQuery } from "../../app/scope.ts";
import { fmtInt, fmtMs } from "../../lib/format.ts";
import { Sparkline } from "../../ui/Charts.tsx";
import { ErrorBar, Loading, Tile } from "../../ui/Page.tsx";

const SKELETON = [1, 2, 3, 4, 5, 6];

/** The change from the window before, as a phrase; null when there is nothing to compare with. */
function changeText(now: number, before: number | undefined): string | null {
  if (before === undefined) return null;
  if (before === 0) return now === 0 ? "与上一时段持平" : null;
  const delta = Math.round(((now - before) / before) * 100);
  if (delta === 0) return "与上一时段持平";
  return `较上一时段 ${delta > 0 ? "+" : "−"}${Math.abs(delta)}%`;
}

function joined(parts: Array<string | null>): string {
  return parts.filter((part): part is string => part !== null).join(" · ");
}

export function SummaryTiles({ scope }: { scope: Scope }) {
  const summary = useSummary(scopeQuery(scope));
  const data = summary.data;

  if (!data) {
    if (summary.isError) {
      return <ErrorBar error={summary.error} onRetry={() => void summary.refetch()} />;
    }
    return (
      <div className="tiles">
        {SKELETON.map((item) => (
          <div className="tile" key={item}>
            <Loading height={44} />
          </div>
        ))}
      </div>
    );
  }

  const before = data.previous ?? undefined;
  const share =
    data.judged > 0 ? `占已判定 ${((data.jev_calls / data.judged) * 100).toFixed(1)}%` : null;

  return (
    <>
      <div className="tiles">
        <Tile
          label="已判定请求"
          value={fmtInt(data.judged)}
          sub={joined(["不含绕过和未知站点", changeText(data.judged, before?.judged)])}
          to="/requests"
          search={{ chip: "judged" }}
        >
          <Sparkline values={data.spark.judged} />
        </Tile>
        <Tile
          label="拦截"
          value={fmtInt(data.blocked)}
          sub={changeText(data.blocked, before?.blocked)}
          to="/requests"
          search={{ chip: "blocked" }}
        >
          <Sparkline values={data.spark.blocked} />
        </Tile>
        <Tile
          label="本应拦截"
          value={fmtInt(data.would_block)}
          sub={changeText(data.would_block, before?.would_block)}
          to="/requests"
          search={{ chip: "would_block" }}
        >
          <Sparkline values={data.spark.would_block} />
        </Tile>
        <Tile
          label="未经判定"
          value={fmtInt(data.unjudged)}
          sub={changeText(data.unjudged, before?.unjudged)}
          to="/requests"
          search={{ chip: "unjudged" }}
        >
          <Sparkline values={data.spark.unjudged} />
        </Tile>
        <Tile
          label="Jev 调用"
          value={fmtInt(data.jev_calls)}
          sub={joined([share, changeText(data.jev_calls, before?.jev_calls)])}
          to="/requests"
          search={{ chip: "jev" }}
        >
          <Sparkline values={data.spark.jev_calls} />
        </Tile>
        <Tile
          label="Jev 耗时 p95"
          value={fmtMs(data.jev_p95_ms)}
          sub={`超时 ${fmtInt(data.jev_timeouts)} 次`}
          to="/jev"
        >
          <Sparkline values={data.spark.jev_p95_ms} />
        </Tile>
      </div>
      {data.complete ? null : <p className="ov-note">按前 {fmtInt(data.scanned)} 条记录计算</p>}
    </>
  );
}
