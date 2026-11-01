// The "需要处理" card of the overview (docs/06 6.4.2). The items come from attention.ts, most serious
// first, and each carries its own links. With nothing to handle it says so, with the last check time,
// but only once every read that could add a row has answered; a read that failed is said in a notice.

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useSites, useStatus } from "../../api/queries.ts";
import { useNowBucket } from "../../app/scope.ts";
import { Card, ErrorBar, Loading, Notice } from "../../ui/Page.tsx";
import { type Action, type AttentionItem, buildAttention, type Level } from "./attention.ts";
import { useAttentionReads } from "./attention-reads.ts";
import { hms } from "./clock.ts";

const LEVEL: Record<Level, { glyph: string; word: string; cls: string }> = {
  serious: { glyph: "■", word: "严重", cls: "lvl-serious" },
  warn: { glyph: "▲", word: "警告", cls: "lvl-warn" },
  // docs/06 6.5.3 reserves the filled dot for "正常", so a hint takes a neutral mark.
  info: { glyph: "›", word: "提示", cls: "lvl-info" },
};

function ActionLink({ action }: { action: Action }) {
  const { label, target } = action;
  switch (target.kind) {
    case "system":
      return (
        <Link className="btn ov-btn" to="/system" search={{ tab: target.tab }}>
          {label}
        </Link>
      );
    case "site":
      return (
        <Link
          className="btn ov-btn"
          to="/sites/$name"
          params={{ name: target.name }}
          search={{ tab: target.tab }}
        >
          {label}
        </Link>
      );
    case "requests":
      return (
        <Link className="btn ov-btn" to="/requests" search={target.search}>
          {label}
        </Link>
      );
    case "jev":
      return (
        <Link className="btn ov-btn" to="/jev">
          {label}
        </Link>
      );
  }
}

function AttentionRow({ item }: { item: AttentionItem }) {
  const level = LEVEL[item.level];
  return (
    <li className="attn-row ov-attn-row">
      <span className="ov-level">
        {/* The status colour goes on the mark only; the word stays in ink (docs/06 6.5.3). */}
        <span aria-hidden="true" className={level.cls}>
          {level.glyph}
        </span>{" "}
        {level.word}
      </span>
      <span className="text">{item.text}</span>
      {item.actions.length > 0 ? (
        <span className="ov-actions">
          {item.actions.map((action) => (
            <ActionLink key={action.label} action={action} />
          ))}
        </span>
      ) : null}
    </li>
  );
}

export function NeedsAttention() {
  const status = useStatus();
  const sites = useSites();
  const now = useNowBucket();
  const list = sites.data?.sites ?? [];
  const reads = useAttentionReads(list);

  let body: ReactNode = null;
  if (status.isPending) {
    body = <Loading height={44} />;
  } else if (!status.data) {
    body = <ErrorBar error={status.error} onRetry={() => void status.refetch()} />;
  } else {
    const items = buildAttention({
      status: status.data,
      sites: list,
      now,
      onJevUnavailable: reads.onJevUnavailable,
      insights: reads.insights,
    });
    if (items.length > 0) {
      body = (
        <ul className="attn ov-attn" aria-label="需要处理">
          {items.map((item) => (
            <AttentionRow key={item.key} item={item} />
          ))}
        </ul>
      );
    } else if (sites.isPending || reads.pending) {
      body = <Loading height={44} />;
    } else if (!sites.isError && !reads.failed) {
      body = (
        <div className="all-good ov-all-good">
          <span aria-hidden="true" className="ov-ok-mark">
            ●
          </span>{" "}
          一切正常 <span className="small muted">· 最后检查 {hms(status.dataUpdatedAt)}</span>
        </div>
      );
    }
  }

  return (
    <Card title="需要处理">
      {sites.isError ? (
        <Notice tone="warn">
          站点数据读取失败，站点的调优建议和观察提醒暂时不列出。
          <button type="button" className="linkbtn" onClick={() => void sites.refetch()}>
            重试
          </button>
        </Notice>
      ) : null}
      {!sites.isError && reads.failed ? (
        <Notice tone="warn">
          部分站点的详情读取失败，未经判定就放行的提醒暂时不列出。
          <button type="button" className="linkbtn" onClick={reads.retry}>
            重试
          </button>
        </Notice>
      ) : null}
      {body}
    </Card>
  );
}
