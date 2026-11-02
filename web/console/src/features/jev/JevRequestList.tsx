// The list of requests that carry a Jev exchange (docs/06 6.4.6). Cursor paging with a "加载更多"
// button; a row's path opens the request record on its Jev tab. The empty and error states follow
// docs/06 6.7.2 and 6.7.3, and a list that is refreshing keeps its rows and dims them.

import { Link } from "@tanstack/react-router";
import { useMemo } from "react";
import { useRequestPages } from "../../api/queries.ts";
import type { RequestRow } from "../../api/types.ts";
import type { JevChip } from "../../app/search-schema.ts";
import { keepScope, type Scope, useSetSearch } from "../../app/scope.ts";
import { fmtClock, fmtLocalDateTime, fmtMs, fmtUtc, pct } from "../../lib/format.ts";
import { isRequestId } from "../../lib/ids.ts";
import { ACCESS_LABEL, ATTACK_LABEL, FAILURE_INFO } from "../../lib/vocab.ts";
import { OutcomeTag } from "../../ui/Badges.tsx";
import { Empty, ErrorBar } from "../../ui/Page.tsx";
import { RequestLink } from "../../ui/RequestRef.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { conclusionText } from "./jev-model.ts";

/** A row opens the request on its Jev tab (docs/06 6.4.4); the global scope carries along. */
export function toJevTab(previous: Record<string, unknown>) {
  return { ...keepScope(previous), tab: "jev" as const };
}

type Props = {
  query: string;
  scope: Scope;
  chip: JevChip;
  q: string;
  /** The window as the page words it: "最近 24 小时" or "这段时间". */
  windowText: string;
  impossible: boolean;
  noThreshold: boolean;
};

type Column = { key: string; label: string; width?: number | string; num?: boolean };

function columnsFor(): Column[] {
  return [
    { key: "time", label: "时间" },
    { key: "site", label: "站点" },
    // The request takes the width the other columns leave (docs/06 6.4.6); the rest fit their content.
    { key: "request", label: "请求", width: "100%" },
    { key: "conclusion", label: "Jev 结论" },
    { key: "access", label: "访问" },
    { key: "attack", label: "攻击" },
    { key: "confidence", label: "置信度", num: true },
    { key: "elapsed", label: "耗时", num: true },
    { key: "failure", label: "失败" },
    { key: "gateway", label: "网关" },
    { key: "id", label: "请求 ID" },
  ];
}

function Head({ columns }: { columns: Column[] }) {
  return (
    <thead>
      <tr>
        {columns.map((column) => (
          <th
            key={column.key}
            scope="col"
            className={column.num ? "num" : undefined}
            style={column.width === undefined ? undefined : { width: column.width }}
          >
            {column.label}
          </th>
        ))}
      </tr>
    </thead>
  );
}

const SKELETON_ROWS = ["a", "b", "c", "d", "e", "f"];

function SkeletonRows({ columns }: { columns: Column[] }) {
  return (
    <div className="tbl-wrap" aria-busy="true">
      <div className="sr-only" role="status">
        正在加载
      </div>
      <table className="tbl" aria-label="Jev 调用列表">
        <Head columns={columns} />
        <tbody>
          {SKELETON_ROWS.map((row) => (
            <tr key={row}>
              {columns.map((column, cell) => (
                <td key={column.key}>
                  <span
                    className="skeleton"
                    aria-hidden="true"
                    style={{ width: `${55 + ((cell * 13) % 40)}%`, height: 12 }}
                  />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function JevRequestList({
  query,
  scope,
  chip,
  q,
  windowText,
  impossible,
  noThreshold,
}: Props) {
  const pages = useRequestPages(query);
  const setSearch = useSetSearch();
  const rows = useMemo(() => (pages.data?.pages ?? []).flatMap((page) => page.rows), [pages.data]);

  const showDate = scope.until - scope.since > 24 * 60 * 60 * 1000;
  const columns = columnsFor();
  const filtered = chip !== "all" || q.length > 0;
  const widerRange = scope.range !== "7d";
  const expand = () => setSearch({ range: "7d", since: undefined, until: undefined });

  if (impossible) {
    return (
      <Empty title="条件互相排斥，没有结果">
        快捷筛选和条件对同一项要求不同的结论，没有一行能同时满足。清除其中一个再试。
      </Empty>
    );
  }
  if (noThreshold) {
    return (
      <Empty title="没有可以比较的 p95">
        <div>这段时间没有成功的 Jev 调用，算不出 p95。</div>
        <div className="row">
          <button type="button" className="linkbtn" onClick={() => setSearch({ chip: undefined })}>
            清除快捷筛选
          </button>
          {widerRange ? (
            <button type="button" className="linkbtn" onClick={expand}>
              扩大到 7 天
            </button>
          ) : null}
        </div>
      </Empty>
    );
  }
  if (pages.isPending) return <SkeletonRows columns={columns} />;
  if (pages.isError) {
    return <ErrorBar error={pages.error} onRetry={() => void pages.refetch()} />;
  }

  if (rows.length === 0) {
    if (filtered) {
      return (
        <Empty title="没有符合条件的 Jev 调用">
          <div className="row">
            {chip !== "all" ? (
              <button
                type="button"
                className="linkbtn"
                onClick={() => setSearch({ chip: undefined })}
              >
                清除快捷筛选
              </button>
            ) : null}
            {q.length > 0 ? (
              <button type="button" className="linkbtn" onClick={() => setSearch({ q: undefined })}>
                清除条件
              </button>
            ) : null}
            {widerRange ? (
              <button type="button" className="linkbtn" onClick={expand}>
                扩大到 7 天
              </button>
            ) : null}
          </div>
        </Empty>
      );
    }
    return (
      <Empty title={`${windowText}所有请求都快速放行或命中缓存，没有调用 Jev`}>
        <div className="row">
          <Link to="/system" search={keepScope}>
            查看网关状态
          </Link>
          {widerRange ? (
            <button type="button" className="linkbtn" onClick={expand}>
              扩大到 7 天
            </button>
          ) : null}
        </div>
      </Empty>
    );
  }

  return (
    <div className={pages.isFetching && !pages.isFetchingNextPage ? "stack dimmed" : "stack"}>
      <div className="tbl-wrap">
        <table className="tbl" aria-label="Jev 调用列表">
          <Head columns={columns} />
          <tbody>
            {rows.map((row) => (
              <JevRow key={row.request_id} row={row} showDate={showDate} />
            ))}
          </tbody>
        </table>
      </div>
      <div className="tbl-foot">
        <span role="status">已显示 {rows.length} 条</span>
        {pages.hasNextPage ? (
          <button
            type="button"
            className="linkbtn"
            onClick={() => void pages.fetchNextPage()}
            disabled={pages.isFetchingNextPage}
          >
            {pages.isFetchingNextPage ? "正在加载…" : "加载更多"}
          </button>
        ) : null}
      </div>
    </div>
  );
}

function JevRow({ row, showDate }: { row: RequestRow; showDate: boolean }) {
  const jev = row.jev;
  const answered = jev !== null && jev.failure === null;
  const conclusion = conclusionText(row);
  const label = `${row.method} ${row.path}`;

  return (
    <tr>
      <td className="tnum" title={fmtUtc(row.at_millis)}>
        {showDate ? fmtLocalDateTime(row.at_millis) : fmtClock(row.at_millis)}
      </td>
      <td className="keep">
        {row.site === null ? <span className="dim">—</span> : <SafeText text={row.site} />}
      </td>
      <td style={{ maxWidth: 0 }}>
        {isRequestId(row.request_id) ? (
          <Link
            to="/requests/$requestId"
            params={{ requestId: row.request_id }}
            search={toJevTab}
            className="path"
            title={label}
          >
            <SafeText text={label} />
          </Link>
        ) : (
          <span className="path" title={label}>
            <SafeText text={label} />
          </span>
        )}
      </td>
      <td className="keep">{conclusion ?? <span className="dim">—</span>}</td>
      <td className="keep">
        {answered && jev?.access ? ACCESS_LABEL[jev.access] : <span className="dim">—</span>}
      </td>
      <td className="keep">
        {answered && jev?.attack ? ATTACK_LABEL[jev.attack] : <span className="dim">—</span>}
      </td>
      <td className="num tnum">{pct(jev?.confidence)}</td>
      <td className="num tnum">{fmtMs(jev?.ms)}</td>
      <td className="keep">
        {jev?.failure ? (
          <span className="jev-cell fail" title={FAILURE_INFO[jev.failure].desc}>
            {FAILURE_INFO[jev.failure].short}
          </span>
        ) : (
          <span className="dim">—</span>
        )}
      </td>
      <td className="keep">
        <OutcomeTag outcome={row.outcome} />
      </td>
      <td className="keep">
        <RequestLink id={row.request_id} />
      </td>
    </tr>
  );
}
