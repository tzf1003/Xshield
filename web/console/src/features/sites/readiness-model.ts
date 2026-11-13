// The readiness checklist's rows as text and marks (docs/06 6.4.10 flow D, docs/07 7.9.11). Readiness.tsx draws them; the
// rows are a function of the readiness document and the clock, so they are kept apart from the component and tested here.

import type { DecisionPath, Readiness } from "../../api/types.ts";
import { fmtInt, fmtLocalDateTime, fmtMs } from "../../lib/format.ts";
import { DECISION_INFO, FUNCTION_VIEW, HEALTH_LABEL, OBJECT_JUDGEMENT } from "../../lib/vocab.ts";

export type ReadyMark = "✓" | "▲" | "–";
/** `listChip` names the request-list chip that the row's own link opens (docs/06 line 627). */
export type Row = { key: string; mark: ReadyMark; text: string; listChip?: "would_block" };

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
      : {
          key: "would",
          mark: "▲",
          text: `本应拦截 ${fmtInt(total)} 条：${breakdown}`,
          listChip: "would_block",
        },
  );
  rows.push(
    readiness.attempts > 0
      ? {
          key: "attempts",
          mark: "▲",
          text: OBJECT_JUDGEMENT.readiness.attempts(fmtInt(readiness.attempts)),
        }
      : { key: "attempts", mark: "✓", text: OBJECT_JUDGEMENT.readiness.attemptsNone },
  );
  // The function table's two counts, when the table guards something (docs/07 7.9.11). Unknown functions are counted only
  // when the site asks about them.
  if (readiness.functions !== null) {
    const functions = readiness.functions;
    rows.push(
      functions.attempts > 0
        ? {
            key: "functions-attempts",
            mark: "▲",
            text: FUNCTION_VIEW.readiness.attempts(fmtInt(functions.attempts)),
          }
        : { key: "functions-attempts", mark: "✓", text: FUNCTION_VIEW.readiness.attemptsNone },
    );
    if (functions.unknown !== null) {
      rows.push(
        functions.unknown > 0
          ? {
              key: "functions-unknown",
              mark: "▲",
              text: FUNCTION_VIEW.readiness.unknown(fmtInt(functions.unknown)),
            }
          : { key: "functions-unknown", mark: "✓", text: FUNCTION_VIEW.readiness.unknownNone },
      );
    }
  }
  rows.push(
    readiness.open_suggestions > 0
      ? {
          key: "suggestions",
          mark: "▲",
          text: `待处理建议 ${fmtInt(readiness.open_suggestions)} 条`,
        }
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
          text: "Jev 不可用时：放行（这些请求不经判定直接转发，记录标为“未经判定”；调用次数达到上限的请求仍然拒绝）",
        },
  );
  return rows;
}
