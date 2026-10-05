import type { Kpi } from "../../operations/kpis.ts";
import { TimeStamp } from "../../ui/TimeStamp";

/**
 * Four numbers, each with its source and the time it describes. A source that could not answer
 * shows "—" and why; it is never rendered as 0.
 */
export function KpiStrip({ kpis }: { kpis: readonly Kpi[] }) {
  return (
    <ul className="xs-wb-kpis" aria-label="关键指标">
      {kpis.map((kpi) => (
        <li key={kpi.key} className={`xs-wb-kpi is-${kpi.tone}`}>
          <span className="xs-wb-kpi-label">{kpi.label}</span>
          <strong className="xs-wb-kpi-value">
            {kpi.value ?? (
              <>
                <span aria-hidden="true">—</span>
                <span className="xs-visually-hidden">无数据</span>
              </>
            )}
          </strong>
          <p className="xs-wb-kpi-detail">{kpi.detail}</p>
          <small className="xs-wb-kpi-source">
            来源：{kpi.source}
            {kpi.asOf ? (
              <>
                {" "}
                · 观察于 <TimeStamp value={kpi.asOf} compact />
              </>
            ) : kpi.receivedAt ? (
              <>
                {" "}
                · 读取于 <TimeStamp value={kpi.receivedAt} compact />
                （浏览器时间）
              </>
            ) : null}
          </small>
        </li>
      ))}
    </ul>
  );
}
