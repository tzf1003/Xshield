// The timeline of one session (docs/06 6.4.7): a summary of the session, its learned values over time,
// and its requests in order. The "只看" selector re-queries the server; `at` scrolls to a request and
// highlights it. A label that cannot be a session, or a session the gateway no longer has, reads as
// "这个会话在当前时间范围内没有记录" (docs/06 6.7.2).

import { Link, useParams, useSearch } from "@tanstack/react-router";
import { type ReactNode, useCallback, useMemo } from "react";
import { ApiError, qs } from "../../api/client.ts";
import { useSite, useTimeline } from "../../api/queries.ts";
import type { SessionCredential, TimelineRow } from "../../api/types.ts";
import { keepScope, useScope, useSetSearch } from "../../app/scope.ts";
import { fmtClock, fmtElapsed, fmtInt } from "../../lib/format.ts";
import { isRequestId, isSessionLabel, shortRequestId } from "../../lib/ids.ts";
import { Card, Empty, ErrorBar, Notice, PageHead } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { TIMELINE_ONLY } from "./sessions-model.ts";
import { TimelineList } from "./TimelineList.tsx";
import { TimelineSpark } from "./TimelineSpark.tsx";
import "./sessions.css";

export function SessionTimelinePage() {
  const { label } = useParams({ from: "/sessions/$label" });
  if (!isSessionLabel(label)) return <SessionMissing />;
  return <Timeline key={label} label={label} />;
}

/** "这个会话在当前时间范围内没有记录" (docs/06 6.7.2), with the way back to the list. */
function SessionMissing() {
  return (
    <>
      <PageHead
        title="会话时间线"
        crumbs={
          <Link to="/sessions" search={keepScope}>
            ← 会话
          </Link>
        }
      />
      <Empty title="这个会话在当前时间范围内没有记录">
        会话在 24 小时无活动后过期，网关重启后也会清空。
      </Empty>
    </>
  );
}

function credentialOf(session: SessionCredential | undefined): string | null {
  if (session?.header) return `请求头 ${session.header}`;
  if (session?.cookie) return `Cookie ${session.cookie}`;
  return null;
}

function Timeline({ label }: { label: string }) {
  const search = useSearch({ from: "/sessions/$label" });
  const setSearch = useSetSearch();
  const scope = useScope();

  const only = search.only ?? "judged";
  const at = search.at;

  const timeline = useTimeline(label, qs({ site: scope.site, only }));
  const rows = useMemo(
    () => (timeline.data?.pages ?? []).flatMap((page) => page.rows),
    [timeline.data],
  );
  const summary = timeline.data?.pages[0]?.summary;
  const site = useSite(summary?.site ?? null);
  const loadMore = useCallback(() => void timeline.fetchNextPage(), [timeline.fetchNextPage]);

  const missing =
    timeline.isError && timeline.error instanceof ApiError && timeline.error.status === 404;
  const issuer: TimelineRow | undefined =
    summary?.issued_by === null || summary?.issued_by === undefined
      ? undefined
      : rows.find((row) => row.request_id === summary.issued_by);
  const atMissing =
    at !== undefined &&
    isRequestId(at) &&
    timeline.isSuccess &&
    !timeline.hasNextPage &&
    !rows.some((row) => row.request_id === at);
  const credential = credentialOf(site.data?.spec.session);

  let issuedBy: ReactNode = <span className="dim">签发它的请求不在保留期内</span>;
  if (summary?.issued_by) {
    if (issuer !== undefined && isRequestId(issuer.request_id)) {
      issuedBy = (
        <Link
          to="/requests/$requestId"
          params={{ requestId: issuer.request_id }}
          search={keepScope}
        >
          {issuer.method} <SafeText text={issuer.path} /> ↗
        </Link>
      );
    } else if (isRequestId(summary.issued_by)) {
      issuedBy = (
        <Link
          to="/requests/$requestId"
          params={{ requestId: summary.issued_by }}
          search={keepScope}
        >
          请求 {shortRequestId(summary.issued_by)} ↗
        </Link>
      );
    }
  }

  return (
    <>
      <PageHead
        title="会话时间线"
        sub={<span className="mono">{label}</span>}
        crumbs={
          <Link to="/sessions" search={keepScope}>
            ← 会话
          </Link>
        }
        actions={
          <select
            className="native-input sx-only"
            value={only}
            onChange={(event) =>
              setSearch({ only: event.target.value === "judged" ? undefined : event.target.value })
            }
            aria-label="只看"
          >
            {TIMELINE_ONLY.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        }
      />

      {missing ? (
        <Empty title="这个会话在当前时间范围内没有记录">
          会话在 24 小时无活动后过期，网关重启后也会清空。
        </Empty>
      ) : timeline.isError ? (
        <ErrorBar error={timeline.error} onRetry={() => void timeline.refetch()} />
      ) : null}

      {summary !== undefined ? (
        <Card className="sx-summary">
          <div className="sx-meta">
            <SafeText text={summary.site ?? "—"} />
            {credential !== null ? <> · {credential}</> : null}
            {" · "}
            <span className="tnum">
              {fmtClock(summary.first_at_millis).slice(0, 8)} –{" "}
              {fmtClock(summary.last_at_millis).slice(0, 8)}
            </span>
            （{fmtElapsed(Math.max(0, summary.last_at_millis - summary.first_at_millis) / 1000)}）
          </div>
          <div className="sx-meta">
            签发于 {issuedBy} · 请求 {fmtInt(summary.requests)} · Jev 调用{" "}
            {fmtInt(summary.jev_calls)} · 本应拦截 {fmtInt(summary.would_block)}
          </div>
          <div className="sx-learned">
            <span className="muted">已见值</span>
            <TimelineSpark rows={rows} />
            <span className="tnum sx-learned-total">
              {fmtInt(rows.reduce((sum, row) => sum + (row.learned ?? 0), 0))}
            </span>
            <span className="small dim">
              累计学到的值，随时间增长
              {timeline.hasNextPage || only !== "judged"
                ? "（只计算已加载且符合“只看”的请求）"
                : ""}
            </span>
          </div>
          <div className="toolbar-note">绕过请求不识别会话，不在这里显示。</div>
        </Card>
      ) : null}

      {timeline.isPending ? (
        <div className="sx-skeleton" aria-busy="true">
          <div className="sr-only" role="status">
            正在加载
          </div>
          {["a", "b", "c", "d", "e", "f"].map((key) => (
            <span key={key} className="skeleton" aria-hidden="true" style={{ height: 28 }} />
          ))}
        </div>
      ) : rows.length === 0 && !missing && !timeline.isError ? (
        only === "judged" ? (
          <Empty title="这个会话在当前时间范围内没有记录">
            会话在 24 小时无活动后过期，网关重启后也会清空。
          </Empty>
        ) : (
          <Empty title="这个会话里没有符合条件的请求">
            <div className="row">
              <button
                type="button"
                className="linkbtn"
                onClick={() => setSearch({ only: undefined })}
              >
                清除“只看”
              </button>
            </div>
          </Empty>
        )
      ) : rows.length > 0 ? (
        <>
          {atMissing && at !== undefined ? (
            <Notice tone="warn">
              找不到请求 {shortRequestId(at)}。它不在这个会话里，或被“只看”筛选去掉了。
            </Notice>
          ) : null}
          <TimelineList
            label={label}
            rows={rows}
            at={at}
            hasNext={timeline.hasNextPage}
            loadingMore={timeline.isFetchingNextPage}
            onMore={loadMore}
          />
          <div className="tbl-foot">
            <span role="status">已显示 {fmtInt(rows.length)} 条请求</span>
            {timeline.hasNextPage ? (
              <button
                type="button"
                className="linkbtn"
                onClick={loadMore}
                disabled={timeline.isFetchingNextPage}
              >
                {timeline.isFetchingNextPage ? "正在加载…" : "加载更多"}
              </button>
            ) : null}
          </div>
        </>
      ) : null}
    </>
  );
}
