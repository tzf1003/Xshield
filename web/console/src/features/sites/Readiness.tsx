// The readiness checklist before a site switches to enforce mode, and its summary on the overview and
// insights tabs (docs/06 6.4.10 flow D, docs/07 7.9.11). It states facts only; it sets no threshold.

import { Link } from "@tanstack/react-router";
import type { Readiness } from "../../api/types.ts";
import { type ReadyMark, readinessRows } from "./readiness-model.ts";

export { observedText } from "./readiness-model.ts";

const MARK_WORD: Record<ReadyMark, string> = { "✓": "正常", "▲": "需要注意", "–": "不适用" };

export function ReadinessList({
  readiness,
  now,
  site,
}: {
  readiness: Readiness | null;
  now: number;
  site: string;
}) {
  if (readiness === null) return <div className="small muted">暂无就绪检查数据</div>;
  return (
    <ul className="ready site-ready" aria-label="就绪检查">
      {readinessRows(readiness, now).map((row) => (
        <li key={row.key} className="ready-row">
          {/* The mark is a shape and a word, never only a colour (docs/06 6.8.2). */}
          <span>
            <span aria-hidden="true">{row.mark}</span>
            <span className="sr-only">{MARK_WORD[row.mark]}</span>
          </span>
          <span>{row.text}</span>
          {row.listChip ? (
            <Link className="ready-link" to="/requests" search={{ site, chip: row.listChip }}>
              逐条查看 <span aria-hidden="true">→</span>
            </Link>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
