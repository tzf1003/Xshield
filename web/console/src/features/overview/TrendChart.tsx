// The hourly chart of the overview (docs/06 6.4.2): one stacked column per bucket in three groups. A
// segment opens the request list for that slot and those decision paths; a hover card lists the count
// of every path; "以表格查看" shows the same numbers as a table. The shared StackedBars has no per-path
// hover and no click targets, so the columns are drawn here with the same s1/s2/s3 colours.

import { Link } from "@tanstack/react-router";
import { type ReactNode, useMemo, useState } from "react";
import { useTimeseries } from "../../api/queries.ts";
import { type Scope, scopeQuery } from "../../app/scope.ts";
import type { RequestsSearch } from "../../app/search-schema.ts";
import { fmtInt } from "../../lib/format.ts";
import { RANGE_LABEL } from "../../lib/vocab.ts";
import { Legend } from "../../ui/Charts.tsx";
import { Card, Empty, ErrorBar, Loading } from "../../ui/Page.tsx";
import { slotLabel } from "./clock.ts";
import { TREND_GROUPS, type TrendColumn, type TrendGroup, trendColumns } from "./trend.ts";

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;
const PLOT_PX = 160;
/** A link's window starts this far after the scope's start, so it stays inside retention. */
const MARGIN_MS = 60_000;

/** The request list for one slot of the chart and the decision paths of one group. */
function slotSearch(scope: Scope, at: number, bucketMs: number, group: TrendGroup): RequestsSearch {
  const since = Math.max(at, scope.since + MARGIN_MS);
  const until = Math.max(since + MARGIN_MS, Math.min(at + bucketMs, scope.until));
  return {
    ...(scope.site ? { site: scope.site } : {}),
    range: "custom",
    since,
    until,
    q: `decision:${group.paths.join(",")}`,
  };
}

export function TrendCard({ scope }: { scope: Scope }) {
  const [asTable, setAsTable] = useState(false);
  const series = useTimeseries(scopeQuery(scope));
  const data = series.data;
  const columns = useMemo(() => (data ? trendColumns(data.buckets) : []), [data]);
  const bucketMs = data?.bucket_ms ?? HOUR_MS;
  const total = columns.reduce((sum, column) => sum + column.total, 0);
  const hasOther = columns.some((column) =>
    column.groups.some((entry) => entry.group.key === "other" && entry.total > 0),
  );
  const groups = TREND_GROUPS.filter((group) => group.key !== "other" || hasOther);
  const multiDay = scope.until - scope.since > DAY_MS;
  const windowName = scope.range === "custom" ? "这段时间" : `最近 ${RANGE_LABEL[scope.range]}`;
  const title =
    bucketMs === HOUR_MS
      ? "每小时请求（不含绕过）"
      : `每 ${Math.round(bucketMs / 60_000)} 分钟请求（不含绕过）`;

  let body: ReactNode;
  if (series.isPending) {
    body = <Loading height={PLOT_PX} />;
  } else if (!data) {
    body = <ErrorBar error={series.error} onRetry={() => void series.refetch()} />;
  } else if (total === 0) {
    body = (
      <Empty title={`${windowName}没有请求。`}>
        <div className="ov-empty-links">
          <Link to="/system">查看网关状态</Link>
          {scope.range === "7d" ? null : (
            <Link to="/" search={{ ...(scope.site ? { site: scope.site } : {}), range: "7d" }}>
              扩大到 7 天
            </Link>
          )}
        </div>
      </Empty>
    );
  } else if (asTable) {
    body = <TrendTable columns={columns} groups={groups} multiDay={multiDay} />;
  } else {
    body = (
      <TrendBars
        columns={columns}
        groups={groups}
        scope={scope}
        bucketMs={bucketMs}
        multiDay={multiDay}
      />
    );
  }

  return (
    <Card
      title={title}
      aside={
        <button
          type="button"
          className="linkbtn"
          aria-pressed={asTable}
          onClick={() => setAsTable((value) => !value)}
        >
          以表格查看
        </button>
      }
    >
      {body}
      {data && !data.complete ? (
        <p className="ov-note">按前 {fmtInt(data.scanned)} 条记录计算</p>
      ) : null}
    </Card>
  );
}

function TrendBars({
  columns,
  groups,
  scope,
  bucketMs,
  multiDay,
}: {
  columns: TrendColumn[];
  groups: TrendGroup[];
  scope: Scope;
  bucketMs: number;
  multiDay: boolean;
}) {
  const peak = Math.max(1, ...columns.map((column) => column.total));
  const first = columns[0];
  const last = columns[columns.length - 1];
  return (
    <div className="ov-trend">
      <Legend items={groups.map((group) => ({ name: group.name, cls: group.cls }))} />
      <section className="ov-trend-plot" aria-label="每小时请求，按判定路径分组">
        {columns.map((column) => (
          <div className="ov-trend-col" key={column.at}>
            {column.groups.map((entry) =>
              entry.total > 0 ? (
                <Link
                  key={entry.group.key}
                  to="/requests"
                  search={slotSearch(scope, column.at, bucketMs, entry.group)}
                  className={`ov-seg ov-seg-${entry.group.cls}`}
                  style={{ height: Math.max(2, Math.round((entry.total / peak) * PLOT_PX)) }}
                  aria-label={`${slotLabel(column.at, multiDay)} ${entry.group.name} ${fmtInt(entry.total)} 次，查看这段请求`}
                />
              ) : null,
            )}
            <span className="ov-tip" aria-hidden="true">
              <strong>
                {slotLabel(column.at, multiDay)} · 合计 {fmtInt(column.total)} 次
              </strong>
              {column.groups.flatMap((entry) =>
                entry.detail.map((item) => (
                  <span key={`${entry.group.key}-${item.name}`}>
                    {item.name} {fmtInt(item.count)}
                  </span>
                )),
              )}
            </span>
          </div>
        ))}
      </section>
      <div className="ov-trend-axis">
        <span>{first ? slotLabel(first.at, multiDay) : ""}</span>
        <span>{last ? slotLabel(last.at, multiDay) : ""}</span>
      </div>
    </div>
  );
}

function TrendTable({
  columns,
  groups,
  multiDay,
}: {
  columns: TrendColumn[];
  groups: TrendGroup[];
  multiDay: boolean;
}) {
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <caption className="sr-only">每小时请求数，按判定路径分组</caption>
        <thead>
          <tr>
            <th scope="col">时段</th>
            {groups.map((group) => (
              <th scope="col" className="num" key={group.key}>
                {group.name}
              </th>
            ))}
            <th scope="col" className="num">
              合计
            </th>
          </tr>
        </thead>
        <tbody>
          {columns.map((column) => (
            <tr key={column.at}>
              <th scope="row" className="ov-rowhead">
                {slotLabel(column.at, multiDay)}
              </th>
              {groups.map((group) => {
                const entry = column.groups.find((item) => item.group.key === group.key);
                return (
                  <td className="num tnum" key={group.key}>
                    {fmtInt(entry?.total ?? 0)}
                  </td>
                );
              })}
              <td className="num tnum">{fmtInt(column.total)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
