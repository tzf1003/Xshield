// The session list (docs/06 6.4.7): the sessions of the time window, most recently active first. The
// flag chips narrow the server's answer; the label prefix narrows the rows already loaded. Empty and
// error states follow docs/06 6.7.2 and 6.7.3.

import { Link, useSearch } from "@tanstack/react-router";
import { type ReactNode, useCallback, useMemo } from "react";
import { useSessions } from "../../api/queries.ts";
import { keepScope, scopeQuery, useNowBucket, useScope, useSetSearch } from "../../app/scope.ts";
import { fmtInt } from "../../lib/format.ts";
import { RANGE_LABEL } from "../../lib/vocab.ts";
import { Empty, ErrorBar, Notice, PageHead } from "../../ui/Page.tsx";
import { SessionFilters, type SessionFlag } from "./SessionFilters.tsx";
import { SessionTable, SessionTableSkeleton } from "./SessionTable.tsx";
import { matchesPrefix, normalisePrefix, SESSION_LIMIT } from "./sessions-model.ts";
import "./sessions.css";

export function SessionsPage() {
  const search = useSearch({ from: "/sessions" });
  const setSearch = useSetSearch();
  const scope = useScope();
  const now = useNowBucket();

  const flag = search.flag;
  const q = search.q ?? "";
  const { prefix } = normalisePrefix(q);

  const sessions = useSessions(scopeQuery(scope, { flag }));
  const rows = useMemo(() => sessions.data?.rows ?? [], [sessions.data]);
  const shown = useMemo(
    () => rows.filter((row) => matchesPrefix(row.label, prefix)),
    [rows, prefix],
  );

  const setFlag = useCallback(
    (next: SessionFlag | undefined) => setSearch({ flag: next }),
    [setSearch],
  );
  const setQ = useCallback(
    (text: string) => setSearch({ q: text.length > 0 ? text : undefined }, true),
    [setSearch],
  );
  const expand = () => setSearch({ range: "7d", since: undefined, until: undefined });

  const rangeText = scope.range === "custom" ? "这段时间" : `最近 ${RANGE_LABEL[scope.range]}`;
  const rangeLabel =
    scope.range === "custom" ? "自定义时间范围" : `最近 ${RANGE_LABEL[scope.range]}`;
  const widerRange = scope.range !== "7d";
  const filtered = flag !== undefined || q.length > 0;

  let body: ReactNode;
  if (sessions.isPending) {
    body = <SessionTableSkeleton />;
  } else if (sessions.isError) {
    body = <ErrorBar error={sessions.error} onRetry={() => void sessions.refetch()} />;
  } else if (rows.length === 0) {
    body = filtered ? (
      <Empty title="筛选后没有结果">
        <div className="row">
          {flag !== undefined ? (
            <button type="button" className="linkbtn" onClick={() => setFlag(undefined)}>
              清除快捷筛选
            </button>
          ) : null}
          {q.length > 0 ? (
            <button type="button" className="linkbtn" onClick={() => setQ("")}>
              清除前缀
            </button>
          ) : null}
          {widerRange ? (
            <button type="button" className="linkbtn" onClick={expand}>
              扩大到 7 天
            </button>
          ) : null}
        </div>
      </Empty>
    ) : (
      <Empty title={`${rangeText}没有会话`}>
        <div>会话由登录请求签发；没有登录的流量不产生会话。</div>
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
  } else if (shown.length === 0) {
    body = (
      <Empty title={`没有标签以 “${prefix}” 开头的会话`}>
        <div className="row">
          <button type="button" className="linkbtn" onClick={() => setQ("")}>
            清除前缀
          </button>
        </div>
      </Empty>
    );
  } else {
    body = (
      <div className={sessions.isFetching ? "stack dimmed" : "stack"}>
        <SessionTable rows={shown} now={now} />
        <div className="tbl-foot">
          <span role="status">
            显示 {fmtInt(shown.length)} 个会话
            {prefix.length > 0 ? `（共 ${fmtInt(rows.length)} 个）` : ""}
          </span>
        </div>
      </div>
    );
  }

  return (
    <>
      <PageHead title="会话" sub={`${scope.site ?? "全部站点"} · ${rangeLabel}`} />
      <SessionFilters flag={flag} q={q} onFlag={setFlag} onQ={setQ} />
      {rows.length >= SESSION_LIMIT ? (
        <Notice tone="info">
          只显示最近活动的 {SESSION_LIMIT} 个会话；缩小时间范围可以看到更早的会话。
        </Notice>
      ) : null}
      {body}
    </>
  );
}
