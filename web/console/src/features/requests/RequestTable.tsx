// The request list as a grid (docs/06 6.4.3). Clicking a row selects it and opens the preview; a
// double click or Enter opens the record. Hovering for 150 ms fetches the record in advance.

import { useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Dropdown } from "antd";
import { type RefObject, useRef } from "react";
import { api } from "../../api/client.ts";
import { keys } from "../../api/queries.ts";
import type { RequestRow } from "../../api/types.ts";
import { fmtClock, fmtLocalDateTime, fmtMs, fmtUtc } from "../../lib/format.ts";
import { DecisionTag, JevCell, OutcomeTag } from "../../ui/Badges.tsx";
import { CopyButton, RequestLink } from "../../ui/RequestRef.tsx";
import { SafeText } from "../../ui/SafeText.tsx";

export type ExtraColumn = "session" | "client" | "host" | "version";
export const EXTRA_COLUMNS: ReadonlyArray<{ id: ExtraColumn; label: string }> = [
  { id: "session", label: "会话" },
  { id: "client", label: "客户端" },
  { id: "host", label: "Host" },
  { id: "version", label: "配置版本" },
];

export type RowAction = { key: string; label: string; onSelect: () => void; disabled?: boolean };

type Props = {
  rows: RequestRow[];
  selectedId: string | null;
  showSite: boolean;
  showDate: boolean;
  extras: ExtraColumn[];
  fresh: Set<string>;
  scrollerRef: RefObject<HTMLDivElement | null>;
  onSelect: (id: string) => void;
  onOpen: (id: string) => void;
  actionsFor: (row: RequestRow) => RowAction[];
};

const PREFETCH_MS = 150;

export function RequestTable({
  rows,
  selectedId,
  showSite,
  showDate,
  extras,
  fresh,
  scrollerRef,
  onSelect,
  onOpen,
  actionsFor,
}: Props) {
  const client = useQueryClient();
  const timer = useRef<number | null>(null);

  const prefetch = (id: string) => {
    timer.current = window.setTimeout(() => {
      void client.prefetchQuery({
        queryKey: keys.detail(id),
        queryFn: () => api.requestDetail(id),
        staleTime: Number.POSITIVE_INFINITY,
      });
    }, PREFETCH_MS);
  };
  const cancelPrefetch = () => {
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = null;
  };

  return (
    <div className="tbl-wrap" ref={scrollerRef}>
      <table className="tbl" aria-label="请求列表" aria-rowcount={rows.length}>
        <thead>
          <tr>
            <th scope="col" style={{ width: showDate ? 150 : 110 }}>
              时间
            </th>
            {showSite ? (
              <th scope="col" style={{ width: 90 }}>
                站点
              </th>
            ) : null}
            <th scope="col" style={{ width: 64 }}>
              方法
            </th>
            <th scope="col">路径</th>
            <th scope="col" style={{ width: 56 }}>
              状态
            </th>
            <th scope="col" style={{ width: 118 }}>
              判定
            </th>
            <th scope="col" style={{ width: 96 }}>
              结论
            </th>
            <th scope="col" style={{ width: 110 }}>
              Jev
            </th>
            <th scope="col" style={{ width: 80 }}>
              耗时
            </th>
            {extras.includes("session") ? (
              <th scope="col" style={{ width: 110 }}>
                会话
              </th>
            ) : null}
            {extras.includes("client") ? (
              <th scope="col" style={{ width: 120 }}>
                客户端
              </th>
            ) : null}
            {extras.includes("host") ? (
              <th scope="col" style={{ width: 160 }}>
                Host
              </th>
            ) : null}
            {extras.includes("version") ? (
              <th scope="col" style={{ width: 80 }}>
                配置版本
              </th>
            ) : null}
            <th scope="col" style={{ width: 120 }}>
              请求 ID
            </th>
            <th scope="col" style={{ width: 36 }}>
              <span className="sr-only">操作</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const selected = row.request_id === selectedId;
            const isFresh = fresh.has(row.request_id);
            return (
              <tr
                key={row.request_id}
                id={`row-${row.request_id}`}
                aria-selected={selected}
                className={isFresh ? "row-click fresh" : "row-click"}
                onClick={(event) => {
                  if (!isControlTarget(event.target)) onSelect(row.request_id);
                }}
                onDoubleClick={() => onOpen(row.request_id)}
                onMouseEnter={() => prefetch(row.request_id)}
                onMouseLeave={cancelPrefetch}
              >
                <td className="tnum" title={fmtUtc(row.at_millis)}>
                  {showDate ? fmtLocalDateTime(row.at_millis) : fmtClock(row.at_millis)}
                </td>
                {showSite ? <td>{row.site ?? <span className="dim">—</span>}</td> : null}
                <td className="mono small">{row.method}</td>
                <td style={{ maxWidth: 0 }}>
                  <span className="path" title={row.query ? `${row.path}?${row.query}` : row.path}>
                    <SafeText text={row.path} />
                    {row.query ? <span className="query">{`?${row.query}`}</span> : null}
                  </span>
                </td>
                <td className="tnum num">{row.status ?? "—"}</td>
                <td>
                  <DecisionTag path={row.decision_path} />
                </td>
                <td>
                  <OutcomeTag outcome={row.outcome} />
                </td>
                <td>
                  <JevCell jev={row.jev} />
                </td>
                <td className="tnum num">{fmtMs(row.total_ms)}</td>
                {extras.includes("session") ? (
                  <td>
                    {row.session ? (
                      <Link
                        to="/sessions/$label"
                        params={{ label: row.session }}
                        className="mono small"
                        title={row.session}
                        onClick={(event) => event.stopPropagation()}
                      >
                        {row.session.slice(0, 8)}
                      </Link>
                    ) : (
                      <span className="dim">—</span>
                    )}
                  </td>
                ) : null}
                {extras.includes("client") ? (
                  <td className="mono small">{row.client || <span className="dim">—</span>}</td>
                ) : null}
                {extras.includes("host") ? (
                  <td className="mono small" title={row.host}>
                    <SafeText text={row.host} />
                  </td>
                ) : null}
                {extras.includes("version") ? (
                  <td className="tnum">{row.site_version ?? <span className="dim">—</span>}</td>
                ) : null}
                <td>
                  <span className="row" style={{ gap: 2, flexWrap: "nowrap" }}>
                    <RequestLink id={row.request_id} />
                    <CopyButton text={row.request_id} />
                  </span>
                </td>
                <td>
                  <RowMenu row={row} actions={actionsFor(row)} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** A click on a link, a button or a menu item inside a row acts on that control, not on the row. */
function isControlTarget(target: EventTarget): boolean {
  return target instanceof Element && target.closest("a, button, [role='menuitem']") !== null;
}

function RowMenu({ row, actions }: { row: RequestRow; actions: RowAction[] }) {
  if (actions.length === 0) return null;
  const items = actions.map((action) => ({
    key: action.key,
    label: action.label,
    disabled: action.disabled,
    onClick: action.onSelect,
  }));
  return (
    <Dropdown menu={{ items }} trigger={["click"]} placement="bottomRight">
      <button type="button" className="iconbtn" aria-label={`操作：${row.request_id}`}>
        ⋯
      </button>
    </Dropdown>
  );
}
