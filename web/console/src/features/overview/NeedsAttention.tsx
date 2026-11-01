// The "需要处理" card of the overview (docs/06 6.4.2). The items come from attention.ts, most serious
// first, and each carries its own links. With nothing to handle it says so, with the last check time.

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useSites, useStatus } from "../../api/queries.ts";
import { useGlobalSearch, useNowBucket } from "../../app/scope.ts";
import { Card, ErrorBar, Loading, Notice } from "../../ui/Page.tsx";
import { type Action, type AttentionItem, buildAttention, type Level } from "./attention.ts";
import { hms } from "./clock.ts";

const LEVEL: Record<Level, { glyph: string; word: string; cls: string }> = {
  serious: { glyph: "■", word: "严重", cls: "lvl-serious" },
  warn: { glyph: "▲", word: "警告", cls: "lvl-warn" },
  info: { glyph: "●", word: "提示", cls: "lvl-info" },
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
          search={target.group ? { tab: target.tab, group: target.group } : { tab: target.tab }}
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
      <span className={`ov-level ${level.cls}`}>
        <span aria-hidden="true">{level.glyph}</span> {level.word}
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
  const scope = useGlobalSearch();
  const now = useNowBucket();

  let body: ReactNode;
  if (status.isPending) {
    body = <Loading height={44} />;
  } else if (!status.data) {
    body = <ErrorBar error={status.error} onRetry={() => void status.refetch()} />;
  } else {
    const items = buildAttention({
      status: status.data,
      sites: sites.data?.sites ?? [],
      scope,
      now,
    });
    body =
      items.length === 0 ? (
        <div className="all-good">
          一切正常 <span className="small muted">· 最后检查 {hms(status.dataUpdatedAt)}</span>
        </div>
      ) : (
        <ul className="attn ov-attn">
          {items.map((item) => (
            <AttentionRow key={item.key} item={item} />
          ))}
        </ul>
      );
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
      {body}
    </Card>
  );
}
