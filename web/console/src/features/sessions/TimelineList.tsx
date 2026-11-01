// The requests of one session in time order (docs/06 6.4.7). Each row links to the request record and
// shows its time, method, path, status, decision, outcome, Jev state, the annotations (issued session,
// first entry, learned from a would-block response) and the values it taught. A gap row separates
// requests more than five minutes apart. The request named by `at` is scrolled to and highlighted once
// it is loaded, loading further pages if it is not yet; j and k move between rows.

import { Link } from "@tanstack/react-router";
import { type ReactNode, useEffect, useMemo, useRef } from "react";
import type { TimelineRow } from "../../api/types.ts";
import { useKeys } from "../../app/keys.ts";
import { keepScope } from "../../app/scope.ts";
import { fmtClock, fmtElapsed, fmtInt } from "../../lib/format.ts";
import { isRequestId, shortSession } from "../../lib/ids.ts";
import { DecisionTag, JevCell, OutcomeTag } from "../../ui/Badges.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { withGaps } from "./sessions-model.ts";

/** The element id of a request's row, which `at` scrolls to. */
export function rowDomId(requestId: string): string {
  return `tl-${requestId}`;
}

const LEARN_BAR_PX = 56;

type Props = {
  label: string;
  rows: TimelineRow[];
  at: string | undefined;
  hasNext: boolean;
  loadingMore: boolean;
  onMore: () => void;
};

export function TimelineList({ label, rows, at, hasNext, loadingMore, onMore }: Props) {
  const items = useMemo(() => withGaps(rows), [rows]);
  const maxLearned = rows.reduce((max, row) => Math.max(max, row.learned ?? 0), 1);
  const handled = useRef<string | null>(null);

  // Scroll to the named request once it is on the page, and keep loading pages until it is. Each page
  // that arrives flips `loadingMore`, which runs this check again against the new rows.
  useEffect(() => {
    if (at === undefined || !isRequestId(at) || handled.current === at) return;
    const node = document.getElementById(rowDomId(at));
    if (node !== null) {
      handled.current = at;
      node.scrollIntoView({ block: "center" });
      return;
    }
    if (hasNext && !loadingMore) onMore();
  }, [at, hasNext, loadingMore, onMore]);

  useKeys({
    j: () => moveFocus(1),
    k: () => moveFocus(-1),
  });

  return (
    <ol className="sx-timeline" aria-label="会话里的请求">
      {items.map((item) =>
        item.kind === "gap" ? (
          <li key={item.key} className="tl-gap">
            ⋯ {fmtElapsed(item.ms / 1000)}无请求
          </li>
        ) : (
          <li key={item.key} className="sx-item">
            <TimelineLine
              row={item.row}
              label={label}
              current={at === item.row.request_id}
              maxLearned={maxLearned}
            />
          </li>
        ),
      )}
    </ol>
  );
}

/** Moves the focus to the next or previous request row, from wherever the focus is. */
function moveFocus(delta: number): void {
  const nodes = Array.from(document.querySelectorAll<HTMLElement>("[data-tl-row]"));
  if (nodes.length === 0) return;
  const active = document.activeElement;
  const current = active instanceof HTMLElement ? nodes.indexOf(active) : -1;
  const next =
    current < 0
      ? delta > 0
        ? 0
        : nodes.length - 1
      : Math.min(nodes.length - 1, Math.max(0, current + delta));
  const target = nodes[next];
  target?.focus();
  target?.scrollIntoView({ block: "nearest" });
}

function TimelineLine({
  row,
  label,
  current,
  maxLearned,
}: {
  row: TimelineRow;
  label: string;
  current: boolean;
  maxLearned: number;
}) {
  const tags: Array<{ key: string; text: string }> = [];
  if (row.issued_session !== null) {
    tags.push(
      row.issued_session === label
        ? { key: "issued", text: "◆ 签发本会话" }
        : { key: "issued", text: `◆ 签发新会话 ${shortSession(row.issued_session)}` },
    );
  }
  if (row.entry_passed) tags.push({ key: "entry", text: "⇢ 首次经过入口" });
  if (row.after_would_block) tags.push({ key: "learned", text: "▲ 本应拦截学习" });

  const learned = row.learned;
  const barWidth =
    learned === null || learned === 0
      ? 0
      : Math.max(2, Math.round((learned / maxLearned) * LEARN_BAR_PX));

  const body: ReactNode = (
    <>
      <span className="tnum sx-time">{fmtClock(row.at_millis)}</span>
      <span className="mono sx-method">{row.method}</span>
      <span className="mono sx-path" title={row.path}>
        <SafeText text={row.path} />
      </span>
      <span className="tnum sx-status">{row.status ?? "—"}</span>
      <span className="sx-decision">
        <DecisionTag path={row.decision_path} />
      </span>
      <span className="sx-outcome">
        <OutcomeTag outcome={row.outcome} />
      </span>
      <span className="sx-jev">
        <JevCell jev={row.jev} />
      </span>
      <span className="sx-tags tl-tags">
        {tags.map((tag) => (
          <span key={tag.key}>{tag.text}</span>
        ))}
      </span>
      <span className="sx-learn learn">
        {learned === null ? (
          <span className="dim">—</span>
        ) : (
          <>
            <i style={{ width: barWidth }} aria-hidden="true" />
            学到 {fmtInt(learned)}
          </>
        )}
      </span>
    </>
  );

  const className = current ? "sx-row hl" : "sx-row";
  if (!isRequestId(row.request_id)) {
    return (
      <div className={className} data-tl-row>
        {body}
      </div>
    );
  }
  return (
    <Link
      to="/requests/$requestId"
      params={{ requestId: row.request_id }}
      search={keepScope}
      id={rowDomId(row.request_id)}
      className={className}
      data-tl-row
    >
      {body}
    </Link>
  );
}
