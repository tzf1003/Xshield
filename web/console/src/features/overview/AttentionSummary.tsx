// The overview's line for the "需要处理" list (docs/06 6.4.2). The rows are in the bell of the top bar, which every
// page has. Here the overview says in one line whether anything needs handling, so the page still answers
// "现在正常吗" within thirty seconds.

import type { ReactNode } from "react";
import { fmtInt } from "../../lib/format.ts";
import { Loading, Notice } from "../../ui/Page.tsx";
import type { AttentionCounts } from "./attention.ts";
import { useNeedsAttention } from "./attention-state.ts";
import { hms } from "./clock.ts";
import "./overview.css";

/** The mark of the line: the worst level listed, or the ringed i when only hints show. */
function markFor(counts: AttentionCounts): { glyph: string; cls: string } {
  if (counts.alert === 0) return { glyph: "i", cls: "lvl-info ov-mark-ring" };
  return counts.serious ? { glyph: "■", cls: "lvl-serious" } : { glyph: "▲", cls: "lvl-warn" };
}

export function AttentionSummary() {
  const attention = useNeedsAttention();
  if (attention.loading) return <Loading height={36} />;
  if (attention.failed) {
    return <Notice tone="warn">需要处理的事项读取失败，点顶栏的铃铛可以重试。</Notice>;
  }

  const { alert, hint } = attention.counts;
  let line: ReactNode = null;
  if (attention.items.length > 0) {
    const mark = markFor(attention.counts);
    const words =
      alert > 0
        ? `需要处理 ${fmtInt(alert)} 项${hint > 0 ? `，另有 ${fmtInt(hint)} 条提示` : ""}`
        : `${fmtInt(hint)} 条提示`;
    line = (
      <div className="ov-attn-line">
        <span aria-hidden="true" className={mark.cls}>
          {mark.glyph}
        </span>
        {words}，点顶栏的铃铛查看
      </div>
    );
  } else if (attention.checking) {
    line = <Loading height={36} />;
  } else if (attention.notices.length === 0) {
    line = (
      <div className="ov-attn-line">
        <span aria-hidden="true" className="ov-ok-mark">
          ●
        </span>{" "}
        一切正常 <span className="small muted">· 最后检查 {hms(attention.lastCheck)}</span>
      </div>
    );
  }

  return (
    <>
      {attention.notices.length > 0 ? (
        <Notice tone="warn">部分需要处理的事项读取失败，点顶栏的铃铛查看。</Notice>
      ) : null}
      {line}
    </>
  );
}
