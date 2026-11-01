// The impact of a draft on the last 24 hours (docs/06 6.4.9 save dialog, docs/07 7.9.10): one row per kind of
// change, with its count, the three biggest paths and an example request, and the warnings listed apart.

import type { ImpactChange, ImpactPreview } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { IMPACT_INFO, WARNING_TEXT } from "../../lib/vocab.ts";
import { RequestLink } from "../../ui/RequestRef.tsx";

const DETAIL_LABELS: Record<string, string> = {
  old_ms: "原超时",
  new_ms: "新超时",
  old_limit: "原上限",
  new_limit: "新上限",
  peak: "最高",
};

/** The fields a change carries besides its count, in words. Unknown shapes are left out. */
function detailLines(change: ImpactChange): string[] {
  const detail = change.detail;
  if (!detail) return [];
  const lines: string[] = [];
  for (const [key, label] of Object.entries(DETAIL_LABELS)) {
    const value = detail[key];
    if (typeof value === "number") lines.push(`${label} ${fmtInt(value)}`);
  }
  const fields = detail.fields;
  if (Array.isArray(fields) && fields.length > 0) {
    const names = fields.map((item) => (Array.isArray(item) ? String(item[0]) : String(item)));
    lines.push(`涉及字段 ${names.slice(0, 10).join("、")}`);
  }
  return lines;
}

function ChangeRow({ change }: { change: ImpactChange }) {
  const top = (change.top ?? []).slice(0, 3);
  return (
    <details className="impact-item">
      <summary className="impact-row">
        <span>{IMPACT_INFO[change.kind]}</span>
        <span className="tnum">
          {fmtInt(change.count)}
          {change.would_block !== undefined ? ` · 其中本应拦截 ${fmtInt(change.would_block)}` : ""}
        </span>
      </summary>
      <div className="impact-more small">
        {top.length > 0 ? (
          <ul className="impact-top">
            {top.map(([method, path, count]) => (
              <li key={`${method} ${path}`}>
                <span className="mono">{method}</span> <span className="mono">{path}</span>{" "}
                {fmtInt(count)}
              </li>
            ))}
          </ul>
        ) : null}
        {detailLines(change).map((line) => (
          <div key={line}>{line}</div>
        ))}
        {change.sample ? (
          <div>
            示例请求 <RequestLink id={change.sample} />
          </div>
        ) : null}
      </div>
    </details>
  );
}

export function ImpactView({ preview }: { preview: ImpactPreview }) {
  return (
    <div className="impact" aria-live="polite">
      <div className="small muted">
        影响（最近 {fmtInt(preview.window_hours)} 小时，{fmtInt(preview.rows)} 条记录
        {preview.complete ? "" : `；按前 ${fmtInt(preview.rows)} 条记录计算`}）
      </div>
      {preview.changes.length === 0 ? (
        <div className="small">没有会改变判定的请求。</div>
      ) : (
        preview.changes.map((change) => <ChangeRow key={change.kind} change={change} />)
      )}
      {preview.warnings.map((warning) => (
        <div key={warning} className="field-warn">
          ▲ {WARNING_TEXT[warning] ?? warning}
        </div>
      ))}
    </div>
  );
}
