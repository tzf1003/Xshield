// The head of the request detail (docs/06 6.4.4): the request line with its verdict, the query string
// with its redacted pairs, the one-sentence reason, the times and places, and the neighbours in the
// same session.

import { Link } from "@tanstack/react-router";
import type { DetailSearch } from "../../app/search-schema.ts";
import { keepScope } from "../../app/scope.ts";
import type { RequestDetail, TraceValue } from "../../api/types.ts";
import { explainRecord } from "../../lib/explain.ts";
import { fmtElapsed, fmtLocalDateTime, fmtMs, fmtUtc } from "../../lib/format.ts";
import { isRequestId, isSessionLabel, isSiteName, shortSession } from "../../lib/ids.ts";
import { CONTEXT_DESC } from "../../lib/vocab.ts";
import { DecisionTag, JevCell, OutcomeTag } from "../../ui/Badges.tsx";
import { CopyButton } from "../../ui/RequestRef.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { REDACTED } from "./detail-model.ts";

/** The search of a neighbour link: the scope and the tab stay, the highlight of this request does not. */
export function neighborSearch(previous: DetailSearch): DetailSearch {
  return { ...keepScope(previous), tab: previous.tab, jev_view: previous.jev_view };
}

/** The search of a session link that opens the timeline on this request (docs/06 6.4.4). */
export function timelineSearch(requestId: string) {
  return (previous: DetailSearch) => ({ ...keepScope(previous), at: requestId });
}

type QueryPair = { at: number; key: string; value: string | null };

/** The query string as pairs, each with its offset: `k=v&k2` (the gateway already redacted the values). */
function splitQuery(query: string): QueryPair[] {
  const pairs: QueryPair[] = [];
  let offset = 0;
  for (const part of query.split("&")) {
    const equals = part.indexOf("=");
    const key = equals === -1 ? part : part.slice(0, equals);
    const value = equals === -1 ? null : part.slice(equals + 1);
    pairs.push({ at: offset, key, value });
    offset += part.length + 1;
  }
  return pairs;
}

function QueryLine({ query, values }: { query: string; values: TraceValue[] }) {
  return (
    <div className="mono small rd-query">
      <span className="dim">?</span>
      {splitQuery(query).map((pair, index) => {
        const traced = values.find((value) => value.at === `query.${pair.key}`);
        const redacted = pair.value === REDACTED;
        return (
          <span key={pair.at} className="rd-querypair">
            {index > 0 ? <span className="dim">&amp;</span> : null}
            <SafeText text={pair.key} />
            {pair.value === null ? null : (
              <>
                <span className="dim">=</span>
                {redacted ? (
                  <span className="redacted">
                    {`🔒 已脱敏${traced?.len !== undefined ? ` · ${traced.len} 字符` : ""}`}
                  </span>
                ) : (
                  <SafeText text={pair.value} />
                )}
              </>
            )}
          </span>
        );
      })}
    </div>
  );
}

export function DetailHead({ detail, requestId }: { detail: RequestDetail; requestId: string }) {
  const { summary, trace, jev, edge, neighbors } = detail;
  const explanation = explainRecord({
    decision_path: summary.decision_path,
    outcome: summary.outcome,
    status: summary.status,
    host: summary.host,
    context: summary.context,
    trace,
    jev,
  });
  const utcClock = fmtUtc(summary.at_millis).split(" ")[1] ?? "";
  const prev = neighbors.prev !== null && isRequestId(neighbors.prev) ? neighbors.prev : null;
  const next = neighbors.next !== null && isRequestId(neighbors.next) ? neighbors.next : null;
  const sessionLabel = isSessionLabel(summary.session) ? summary.session : null;
  const siteName = summary.site !== null && isSiteName(summary.site) ? summary.site : null;
  const version = summary.site_version;
  const judge = trace.timing?.judge_ms ?? null;
  const origin = trace.timing?.origin_ms ?? null;
  const total = trace.timing?.total_ms ?? summary.total_ms;

  return (
    <>
      <nav className="crumbs rd-crumbs" aria-label="请求导航">
        <Link to="/requests" search={keepScope}>
          ← 请求追溯
        </Link>
        <span className="dim" aria-hidden="true">
          ·
        </span>
        {summary.site !== null ? (
          <span className="small">
            <SafeText text={summary.site} />
          </span>
        ) : (
          <span className="small dim">未知站点</span>
        )}
        <span className="mono small rd-reqid" title="请求 ID">
          {requestId}
        </span>
        <CopyButton text={requestId} label="复制 ID" />
        <span className="rd-neighbors">
          {prev !== null ? (
            <Link to="/requests/$requestId" params={{ requestId: prev }} search={neighborSearch} title="上一个请求，快捷键 [">
              ‹ 上一个
            </Link>
          ) : (
            <span className="dim">‹ 上一个</span>
          )}
          {sessionLabel !== null ? (
            <Link to="/sessions/$label" params={{ label: sessionLabel }} search={timelineSearch(requestId)}>
              同一会话
            </Link>
          ) : (
            <span className="dim">同一会话</span>
          )}
          {next !== null ? (
            <Link to="/requests/$requestId" params={{ requestId: next }} search={neighborSearch} title="下一个请求，快捷键 ]">
              下一个 ›
            </Link>
          ) : (
            <span className="dim">下一个 ›</span>
          )}
        </span>
      </nav>

      <section className="detail-head rd-head" aria-label="请求概要">
        <div className="rd-headrow">
          <div className="rd-reqline">
            <span className="mono small rd-method">
              <SafeText text={summary.method} />
            </span>
            <h1 className="detail-line rd-path">
              <SafeText text={summary.path} />
            </h1>
          </div>
          <div className="rd-tags">
            <OutcomeTag outcome={summary.outcome} />
            <DecisionTag path={summary.decision_path} />
            <JevCell jev={summary.jev} />
          </div>
        </div>

        {summary.query !== null ? <QueryLine query={summary.query} values={trace.values ?? []} /> : null}

        <div className="explain">
          <SafeText text={explanation} />
        </div>

        <div className="meta-line rd-meta">
          <span className="tnum">
            {fmtLocalDateTime(summary.at_millis)}（UTC {utcClock}）
          </span>
          <span>状态 {summary.status ?? "—"}</span>
          <span className="tnum">
            {fmtMs(total)}
            {judge !== null || origin !== null
              ? `（判定 ${fmtMs(judge)} · 源站 ${fmtMs(origin)}）`
              : ""}
          </span>
        </div>
        <div className="meta-line rd-meta">
          {siteName !== null && version !== null ? (
            <Link to="/sites/$name" params={{ name: siteName }} search={{ tab: "history", diff: String(version) }}>
              配置 v{version}
            </Link>
          ) : (
            <span>配置 {version !== null ? `v${version}` : "—"}</span>
          )}
          <span>{edge}</span>
          {sessionLabel !== null ? (
            <span>
              <Link to="/sessions/$label" params={{ label: sessionLabel }} search={timelineSearch(requestId)} className="mono">
                会话 {shortSession(sessionLabel)}
              </Link>
              {trace.session ? `（已 ${fmtElapsed(trace.session.age_seconds)}）` : ""}
            </span>
          ) : (
            <span title={summary.context ? CONTEXT_DESC[summary.context] : undefined}>
              {summary.context === "address" ? "按客户端地址" : "无会话"}
            </span>
          )}
          <span>
            客户端 <SafeText text={summary.client} />
          </span>
        </div>
      </section>
    </>
  );
}
