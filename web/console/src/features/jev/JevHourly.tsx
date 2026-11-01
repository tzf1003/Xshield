// The hourly answers of the Jev page (docs/06 6.4.6): one stacked bar per hour with three groups,
// Jev allowed (通过), Jev denied (拒绝) and unavailable (不可用). These are Jev's answers; whether the
// gateway let the request through is in the request list's outcome column.

import { useId, useState } from "react";
import type { JevStats } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { Legend, type Series, StackedBars } from "../../ui/Charts.tsx";
import { Card, Empty } from "../../ui/Page.tsx";
import { TableToggle } from "./JevHistogram.tsx";
import { hourLabel } from "./jev-model.ts";

const SERIES: Series[] = [
  { name: "通过", cls: "s1" },
  { name: "拒绝", cls: "s2" },
  { name: "不可用", cls: "neutral" },
];

type Hour = JevStats["hourly"][number];

export function JevHourly({
  hourly,
  withDate,
  dimmed,
  emptyTitle,
}: {
  hourly: Hour[];
  withDate: boolean;
  dimmed: boolean;
  emptyTitle: string;
}) {
  const [asTable, setAsTable] = useState(false);
  const tableId = useId();
  const total = hourly.reduce((sum, hour) => sum + hour.allow + hour.deny + hour.unavailable, 0);

  return (
    <Card
      title="结论与失败（按小时）"
      aside={
        <TableToggle open={asTable} controls={tableId} onToggle={() => setAsTable((v) => !v)} />
      }
      className={dimmed ? "jev-hourly-card dimmed" : "jev-hourly-card"}
    >
      {total === 0 ? (
        <Empty title={emptyTitle} />
      ) : asTable ? (
        <table id={tableId} className="tbl" aria-label="按小时的 Jev 结论（表格）">
          <thead>
            <tr>
              <th scope="col">时段</th>
              <th scope="col" className="num">
                通过
              </th>
              <th scope="col" className="num">
                拒绝
              </th>
              <th scope="col" className="num">
                不可用
              </th>
            </tr>
          </thead>
          <tbody>
            {hourly.map((hour) => {
              const label = hourLabel(hour.at_millis, withDate);
              return (
                <tr key={hour.at_millis}>
                  <td>{label}</td>
                  <td className="num tnum">{fmtInt(hour.allow)}</td>
                  <td className="num tnum">{fmtInt(hour.deny)}</td>
                  <td className="num tnum">{fmtInt(hour.unavailable)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <div id={tableId} className="stack jev-hourly">
          <Legend items={SERIES} />
          <div className="jev-hourly-chart">
            <StackedBars
              label={`按小时的 Jev 结论：${hourly.length} 个时段，共 ${fmtInt(total)} 次调用`}
              rows={hourly.map((hour) => ({
                label: hourLabel(hour.at_millis, withDate),
                values: [hour.allow, hour.deny, hour.unavailable],
              }))}
              series={SERIES}
              height={170}
            />
          </div>
        </div>
      )}
    </Card>
  );
}
