// The readiness checklist before a site switches to enforce mode, and its summary on the overview and
// insights tabs (docs/06 6.4.10 flow D, docs/07 7.9.11). It states facts only; it sets no threshold.

import type { DecisionPath, Readiness } from "../../api/types.ts";
import { fmtInt, fmtLocalDateTime, fmtMs } from "../../lib/format.ts";
import { DECISION_INFO, HEALTH_LABEL } from "../../lib/vocab.ts";

export type ReadyMark = "✓" | "▲" | "–";
type Row = { key: string; mark: ReadyMark; text: string };

/** "4 天 3 小时", or "5 小时" when less than a day has passed. */
export function observedText(ms: number): string {
  const hours = Math.max(0, Math.floor(ms / 3_600_000));
  const days = Math.floor(hours / 24);
  return days > 0 ? `${days} 天 ${hours % 24} 小时` : `${hours} 小时`;
}

function ratioText(ratio: number | null): string {
  return ratio === null ? "—" : `${(ratio * 100).toFixed(1)}%`;
}

export function readinessRows(readiness: Readiness, now: number): Row[] {
  const rows: Row[] = [];
  const since = readiness.observing_since_millis;
  rows.push(
    since === null
      ? { key: "observing", mark: "–", text: "当前是拦截模式，没有观察期" }
      : {
          key: "observing",
          mark: "✓",
          text: `已观察 ${observedText(now - since)}（自 ${fmtLocalDateTime(since)} 起）`,
        },
  );
  const counts = Object.entries(readiness.would_block) as Array<[DecisionPath, number | undefined]>;
  const total = counts.reduce((sum, [, count]) => sum + (count ?? 0), 0);
  const breakdown = counts
    .filter(([, count]) => (count ?? 0) > 0)
    .map(([path, count]) => `${DECISION_INFO[path].name} ${fmtInt(count ?? 0)}`)
    .join(" · ");
  rows.push(
    total === 0
      ? { key: "would", mark: "✓", text: "本应拦截 0 条" }
      : { key: "would", mark: "▲", text: `本应拦截 ${fmtInt(total)} 条：${breakdown}` },
  );
  rows.push(
    readiness.open_suggestions > 0
      ? { key: "suggestions", mark: "▲", text: `待处理建议 ${fmtInt(readiness.open_suggestions)} 条` }
      : { key: "suggestions", mark: "✓", text: "没有待处理建议" },
  );
  const health = HEALTH_LABEL[readiness.jev_health].name;
  rows.push(
    readiness.jev_health === "ok"
      ? {
          key: "jev",
          mark: "✓",
          text: `Jev ${health}（p95 ${fmtMs(readiness.jev_p95_ms)}，超时 ${ratioText(readiness.jev_timeout_ratio)}）`,
        }
      : { key: "jev", mark: "▲", text: `Jev ${health}（p95 ${fmtMs(readiness.jev_p95_ms)}）` },
  );
  rows.push(
    readiness.after_would_block_refs > 0
      ? {
          key: "learned",
          mark: "▲",
          text: `由本应拦截请求学到的值被后续请求引用 ${fmtInt(readiness.after_would_block_refs)} 次（切换后这些请求也可能被拦截）`,
        }
      : { key: "learned", mark: "✓", text: "由本应拦截请求学到的值没有被后续请求引用" },
  );
  rows.push(
    readiness.on_jev_unavailable === "deny"
      ? { key: "unavailable", mark: "✓", text: "Jev 不可用时：拒绝" }
      : {
          key: "unavailable",
          mark: "▲",
          text: "Jev 不可用时：放行（这些请求不经判定直接转发，记录标为“未经判定”）",
        },
  );
  return rows;
}

const MARK_WORD: Record<ReadyMark, string> = { "✓": "正常", "▲": "需要注意", "–": "不适用" };
const MARK_CLASS: Record<ReadyMark, string> = { "✓": "hint-ok", "▲": "hint-warn", "–": "hint-none" };

export function ReadinessList({ readiness, now }: { readiness: Readiness | null; now: number }) {
  if (readiness === null) return <div className="small muted">暂无就绪检查数据</div>;
  return (
    <ul className="ready site-ready" aria-label="就绪检查">
      {readinessRows(readiness, now).map((row) => (
        <li key={row.key} className="ready-row">
          <span className={MARK_CLASS[row.mark]}>
            <span aria-hidden="true">{row.mark}</span>
            <span className="sr-only">{MARK_WORD[row.mark]}</span>
          </span>
          <span>{row.text}</span>
        </li>
      ))}
    </ul>
  );
}
