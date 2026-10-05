import type { ReactNode } from "react";
import type { AuditHealthResponse } from "./api";

function time(value: string | number) {
  const date = new Date(typeof value === "number" ? Math.floor(value / 1000) : value);
  return Number.isFinite(date.valueOf())
    ? `${date
        .toISOString()
        .replace("T", " ")
        .replace(/\.\d+Z$/, "")} UTC`
    : "时间不可用";
}
export function Rows({ entries }: { entries: [string, ReactNode][] }) {
  return (
    <dl>
      {entries.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
/** Displays one explicit, audited configuration journal publication snapshot.
 * This is an observation surface, so it never refreshes itself or presents the
 * counters as a business decision, an Outbox report, or service-wide health. */
export function AuditHealthPanel({
  response,
  busy,
  onRefresh,
}: {
  response: AuditHealthResponse | null;
  busy: boolean;
  onRefresh: () => void;
}) {
  return (
    <>
      <section className="panel audit-health-intro" aria-label="审计发布状态说明">
        <h2>配置日志发布观察</h2>
        <p className="footnote">
          此处仅观察一个配置 audit journal 到其索引目标的封存段发布状态。它不代表业务准入、全部
          Outbox 状态或系统整体健康。
        </p>
        <button onClick={onRefresh} disabled={busy}>
          {busy ? "读取中…" : response ? "手动刷新发布状态" : "读取发布状态"}
        </button>
        <p className="footnote">
          每次读取均由服务端单独重新鉴权并写入管理审计；控制台不会自动轮询。
        </p>
      </section>
      {response && (
        <>
          <div
            className={`notice ${response.has_gaps || response.pending_segments > 0 || response.unsealed_segments > 0 ? "warning" : ""}`}
            role="status"
            aria-label="审计发布状态"
          >
            <div>
              <strong>
                {response.has_gaps ? "发布观察到缺口" : "未观察到发布缺口"} ·{" "}
                {response.pending_segments} 个待发布段
              </strong>
              <p>
                连续水位只覆盖配置 journal
                的已确认封存段；后续孤岛、未封存数据和其他发布路径须分别判断。
              </p>
            </div>
          </div>
          <section
            className="panel audit-health-result"
            aria-label="审计发布状态结果"
            aria-busy={busy}
          >
            <div className="panel-heading">
              <h2>发布快照</h2>
              <span className="mono">{response.request_id}</span>
            </div>
            <div className="detail-body">
              <Rows
                entries={[
                  ["观察时间", <span className="mono">{time(response.as_of)}</span>],
                  ["索引目标", <span className="mono">{response.target_id}</span>],
                  ["目标表", <span className="mono">{response.table}</span>],
                  ["元数据保留", `${response.metadata_retention_days} 天`],
                  ["关闭段", response.closed_segments.toLocaleString()],
                  ["关闭段字节", response.closed_segment_bytes.toLocaleString()],
                  ["已发布段", response.published_segments.toLocaleString()],
                  ["待发布段", response.pending_segments.toLocaleString()],
                  ["未封存段", response.unsealed_segments.toLocaleString()],
                  ["发布缺口", response.has_gaps ? "存在" : "未观察到"],
                  [
                    "连续索引水位",
                    response.index_watermark ? (
                      <span className="mono">
                        {response.index_watermark.producer_boot_id} /{" "}
                        {response.index_watermark.producer_sequence}
                      </span>
                    ) : (
                      "尚无连续已发布封存段"
                    ),
                  ],
                ]}
              />
            </div>
          </section>
        </>
      )}
    </>
  );
}
