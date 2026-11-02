// The impact of a draft on the last 24 hours (docs/06 6.4.9 save dialog, docs/07 7.9.10, design 6): one row per kind of
// change, with its count, the three biggest paths and an example request, and the warnings listed apart. The new kinds
// of design 6 read as sentences with their numbers; the notes beside them say where the history can only estimate.

import type { ImpactChange, ImpactPreview } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { IMPACT_INFO, IMPACT_NOTE, OBJECT_KIND_LABEL, WARNING_TEXT } from "../../lib/vocab.ts";
import { RequestLink } from "../../ui/RequestRef.tsx";

const DETAIL_LABELS: Record<string, string> = {
  old_ms: "原超时",
  new_ms: "新超时",
  old_limit: "原上限",
  new_limit: "新上限",
  peak: "最高",
};

/** Whether a save needs the example check: an enforce site that gets fast allows (design 3.2 and 6). */
export function hasNewFastAllow(preview: ImpactPreview): boolean {
  return preview.changes.some((change) => change.kind === "new_fast_allow" && change.count > 0);
}

function numberOf(change: ImpactChange, key: string): number | undefined {
  const value = change.detail?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function textOf(change: ImpactChange, key: string): string | undefined {
  const value = change.detail?.[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function classWord(kind: string | undefined): string | undefined {
  return kind === undefined ? undefined : (OBJECT_KIND_LABEL[kind] ?? kind);
}

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

/** The sentence of a kind of design 6 (`null` for the kinds that keep the label and the count), and its notes. */
function sentenceOf(change: ImpactChange): { text: string; notes: string[] } | null {
  const n = fmtInt(change.count);
  const approximate = change.detail?.approximate === true ? [IMPACT_NOTE.approximate] : [];
  switch (change.kind) {
    case "api_split": {
      // A header is not kept in the history, so the split cannot be counted before the change is saved.
      if (textOf(change, "source") === "header") {
        return { text: "这条路径下的请求将按接口分别判定", notes: [IMPACT_NOTE.afterSave] };
      }
      const apis = numberOf(change, "apis");
      const split = apis === undefined ? "按接口分别判定" : `按 ${fmtInt(apis)} 个接口分别判定`;
      return { text: `这条路径下 ${n} 个请求将${split}`, notes: [] };
    }
    case "entry_unreachable": {
      const entry = textOf(change, "entry") ?? change.top?.[0]?.[1];
      const head = entry === undefined ? "这个入口" : `入口 ${entry}`;
      return {
        text: `${head} 将不再命中任何请求（${n} 个原本放行的无会话请求将需要会话）`,
        notes: [],
      };
    }
    case "new_fast_allow":
      return { text: `${n} 次 Jev 调用会变成快速放行`, notes: approximate };
    case "back_to_jev": {
      const named = classWord(textOf(change, "name_kind"));
      const real = classWord(textOf(change, "object_kind"));
      const why =
        named !== undefined && real !== undefined
          ? [`这些请求原本靠名字把${real}编号当成了${named}编号`]
          : [];
      return { text: `${n} 次快速放行会改回调用 Jev`, notes: [...approximate, ...why] };
    }
    case "cache_by_api":
      return {
        text: "同一会话里参数相同的不同接口不再共用放行结论",
        notes: [IMPACT_NOTE.notCounted],
      };
    default:
      return null;
  }
}

function ChangeRow({ change }: { change: ImpactChange }) {
  const top = (change.top ?? []).slice(0, 3);
  const sentence = sentenceOf(change);
  return (
    <details className="impact-item">
      <summary className="impact-row">
        {sentence === null ? (
          <span>{IMPACT_INFO[change.kind]}</span>
        ) : (
          <span>
            {IMPACT_INFO[change.kind]}：{sentence.text}
            {sentence.notes.map((note) => (
              <span key={note}>
                <br />
                <span className="small muted">{note}</span>
              </span>
            ))}
          </span>
        )}
        {sentence === null ? (
          <span className="tnum">
            {fmtInt(change.count)}
            {change.would_block !== undefined
              ? ` · 其中本应拦截 ${fmtInt(change.would_block)}`
              : ""}
          </span>
        ) : null}
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
