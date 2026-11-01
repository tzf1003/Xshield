// The "日志存储" tab (docs/06 6.4.11): the daily partitions with their range, rows and size; the earliest
// record, the retention and the PostgreSQL version; and the gaps the gateways reported (docs/07 7.7.4).

import type { LogGap, SystemInfo } from "../../api/types.ts";
import { fmtBytes, fmtInt, fmtLocalDateTime } from "../../lib/format.ts";
import { Card, Empty, Notice } from "../../ui/Page.tsx";
import { hm, shortDateTime, utcDay } from "./clock.ts";
import { aheadText, DAY_MS, storageWarnings, withDays } from "./partitions.ts";

const GAP_REASON: Record<LogGap["reason"], string> = {
  queue_full: "队列满",
  write_error: "写入失败",
};

export function StoragePanel({ system, now }: { system: SystemInfo; now: number }) {
  const storage = system.storage;
  const rows = withDays(storage.partitions, now);
  const warnings = storageWarnings(rows, now);
  const totals = rows.reduce(
    (sum, row) => ({ rows: sum.rows + row.rows, bytes: sum.bytes + row.bytes }),
    { rows: 0, bytes: 0 },
  );
  const gaps = [...storage.gaps].sort((a, b) => b.from_millis - a.from_millis);

  return (
    <>
      {warnings.map((warning) => (
        <Notice key={warning.text} tone={warning.tone}>
          {warning.text}
        </Notice>
      ))}
      <Card title="判定日志">
        <dl className="kv">
          <dt>最早记录</dt>
          <dd>
            {storage.earliest_millis === null
              ? "还没有记录"
              : fmtLocalDateTime(storage.earliest_millis)}
          </dd>
          <dt>保留期</dt>
          <dd>{`${fmtInt(storage.retention_days)} 天（代码默认值）`}</dd>
          <dt>分区</dt>
          <dd>{`${fmtInt(rows.length)} 个，共 ${fmtInt(totals.rows)} 行，${fmtBytes(totals.bytes)}`}</dd>
          <dt>PostgreSQL</dt>
          <dd className="mono">{system.postgres}</dd>
        </dl>
        {rows.length === 0 ? (
          <Empty title="还没有日志分区。" />
        ) : (
          <div className="tbl-wrap">
            <table className="tbl">
              <caption className="sr-only">日志分区</caption>
              <thead>
                <tr>
                  <th scope="col">分区</th>
                  <th scope="col">范围（UTC）</th>
                  <th scope="col">状态</th>
                  <th scope="col" className="num">
                    行数
                  </th>
                  <th scope="col" className="num">
                    大小
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.name}>
                    <td className="mono small">{row.name}</td>
                    <td className="tnum small">
                      {row.day === null
                        ? "—"
                        : `${utcDay(row.day)} 00:00 — ${utcDay(row.day + DAY_MS)} 00:00`}
                    </td>
                    <td>{aheadText(row.ahead)}</td>
                    <td className="num tnum">{fmtInt(row.rows)}</td>
                    <td className="num tnum">{fmtBytes(row.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <div className="sys-section">
        <Card title="日志缺口" aside="最近 24 小时">
          {gaps.length === 0 ? (
            <Empty title="最近 24 小时没有日志缺口。" />
          ) : (
            <div className="tbl-wrap">
              <table className="tbl">
                <caption className="sr-only">日志缺口</caption>
                <thead>
                  <tr>
                    <th scope="col">起止时间</th>
                    <th scope="col">实例</th>
                    <th scope="col" className="num">
                      丢失的判定记录
                    </th>
                    <th scope="col">原因</th>
                  </tr>
                </thead>
                <tbody>
                  {gaps.map((gap) => (
                    <tr key={`${gap.edge}-${gap.from_millis}-${gap.reason}`}>
                      <td className="tnum">
                        {shortDateTime(gap.from_millis)} – {hm(gap.to_millis)}
                      </td>
                      <td>{gap.edge}</td>
                      <td className="num tnum">{fmtInt(gap.rows)}</td>
                      <td>{GAP_REASON[gap.reason]}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="small muted sys-hint">缺口来自网关的心跳，网关重启后清空。</p>
        </Card>
      </div>
    </>
  );
}
