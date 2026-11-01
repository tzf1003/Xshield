// The related rail of the request detail (docs/06 6.4.4): where the values came from, the cache source
// and the session this response issued, the neighbours in the same session, the same path over the
// last 24 hours, and the operations that open the quick rule dialog for this record.

import { Link } from "@tanstack/react-router";
import { qs } from "../../api/client.ts";
import { useRequestCounts } from "../../api/queries.ts";
import type { RequestDetail, Trace, TraceSource } from "../../api/types.ts";
import { keepScope, useNowBucket } from "../../app/scope.ts";
import { serializeFilter } from "../../lib/filter-dsl.ts";
import { fmtInt } from "../../lib/format.ts";
import { isRequestId, isSessionLabel, isSiteName } from "../../lib/ids.ts";
import { isStaticAsset } from "../../lib/quick-rules.ts";
import { DECISION_INFO } from "../../lib/vocab.ts";
import { Card, Loading } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import type { QuickTarget } from "../sites/QuickRuleDialog.tsx";
import { neighborSearch, timelineSearch } from "./DetailHead.tsx";
import { DAY_MS, sensitiveFieldOf } from "./detail-model.ts";
import { CopyAction, LinkedRequest } from "./parts.tsx";

type Props = {
  detail: RequestDetail;
  requestId: string;
  onOperation: (target: QuickTarget) => void;
};

export function RelatedRail({ detail, requestId, onOperation }: Props) {
  const { summary, trace, sources, neighbors } = detail;
  const site = summary.site !== null && isSiteName(summary.site) ? summary.site : null;
  const sessionLabel = isSessionLabel(summary.session) ? summary.session : null;
  const prev = neighbors.prev !== null && isRequestId(neighbors.prev) ? neighbors.prev : null;
  const next = neighbors.next !== null && isRequestId(neighbors.next) ? neighbors.next : null;
  const cache = trace.cache_source ?? null;
  const issued = trace.response?.issued_session ?? null;
  const operations = site === null ? [] : operationsOf(detail, requestId, site);

  return (
    <div className="stack rd-related">
      <SourcesCard trace={trace} sources={sources} />

      {cache !== null || (issued !== null && isSessionLabel(issued)) ? (
        <Card title="这次请求的关联">
          <ul className="rd-list">
            {cache !== null ? (
              <li>
                <span className="small dim">缓存来源 </span>
                {isRequestId(cache) ? (
                  <LinkedRequest id={cache} className="mono">
                    {cache}
                  </LinkedRequest>
                ) : (
                  <SafeText text={cache} />
                )}
              </li>
            ) : null}
            {issued !== null && isSessionLabel(issued) ? (
              <li>
                <span className="small dim">签发的会话 </span>
                <Link
                  to="/sessions/$label"
                  params={{ label: issued }}
                  search={timelineSearch(requestId)}
                  className="mono"
                >
                  打开会话时间线
                </Link>
              </li>
            ) : null}
          </ul>
        </Card>
      ) : null}

      {sessionLabel !== null ? (
        <Card title="同一会话">
          <div className="row">
            {prev !== null ? (
              <Link
                to="/requests/$requestId"
                params={{ requestId: prev }}
                search={neighborSearch}
                title="上一个请求，快捷键 ["
              >
                ‹ 前一个
              </Link>
            ) : (
              <span className="dim">‹ 前一个</span>
            )}
            {next !== null ? (
              <Link
                to="/requests/$requestId"
                params={{ requestId: next }}
                search={neighborSearch}
                title="下一个请求，快捷键 ]"
              >
                后一个 ›
              </Link>
            ) : (
              <span className="dim">后一个 ›</span>
            )}
          </div>
        </Card>
      ) : null}

      <SamePathCard path={summary.path} site={site} />

      <Card title="操作">
        <div className="stack rd-ops">
          {operations.map((operation) => (
            <button
              key={operation.key}
              type="button"
              className="linkbtn"
              onClick={() => onOperation(operation.target)}
            >
              {operation.label}
            </button>
          ))}
          {site !== null ? (
            <Link to="/sites/$name" params={{ name: site }} search={{ tab: "config" }}>
              在配置中打开
            </Link>
          ) : null}
          <CopyAction text={window.location.href} label="复制链接" />
        </div>
      </Card>
    </div>
  );
}

/** Every distinct source request the values came from, each with its method, path and decision path. */
function SourcesCard({ trace, sources }: { trace: Trace; sources: RequestDetail["sources"] }) {
  const distinct = new Map<string, TraceSource>();
  for (const value of trace.values ?? []) {
    for (const source of value.sources) {
      const key = source.request_id ?? `text:${source.request}`;
      if (!distinct.has(key)) distinct.set(key, source);
    }
  }
  const list = [...distinct];
  return (
    <Card title="值的来源">
      {list.length === 0 ? (
        <div className="small dim">这次请求的值没有来源。</div>
      ) : (
        <ul className="rd-list">
          {list.map(([key, source]) => {
            const id =
              source.request_id !== null && isRequestId(source.request_id)
                ? source.request_id
                : null;
            const summary = id === null ? undefined : sources[id];
            return (
              <li key={key}>
                {id === null ? (
                  <span className="srcchip" title="这条来源没有记录请求 ID">
                    <SafeText text={source.request} />
                  </span>
                ) : summary === undefined ? (
                  <span className="srcchip dim" title="来源请求已过保留期">
                    <SafeText text={source.request} /> · 已过保留期
                  </span>
                ) : (
                  <LinkedRequest id={id} className="mono">
                    <SafeText text={`${summary.method} ${summary.path}`} />
                  </LinkedRequest>
                )}
                {summary === undefined ? null : (
                  <span className="small dim"> · {DECISION_INFO[summary.decision_path].name}</span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}

/** How the same path went over the last 24 hours, counted over every request, bypass included. */
function SamePathCard({ path, site }: { path: string; site: string | null }) {
  const now = useNowBucket();
  const filter: Record<string, string> = site === null ? { path } : { path, site };
  const counts = useRequestCounts(
    qs({ ...filter, since_millis: now - DAY_MS, until_millis: now, scope: "all" }),
  );
  const data = counts.data;
  const allowed =
    data === undefined
      ? null
      : Math.max(0, data.judged - data.blocked - data.would_block - data.unjudged);
  const text = serializeFilter(filter);

  return (
    <Card title="同路径 24 小时">
      <div className="mono small rd-path">
        <SafeText text={path} />
      </div>
      {counts.isPending ? <Loading height={48} /> : null}
      {counts.isError ? <div className="small dim">计数暂时读不到。</div> : null}
      {data !== undefined && allowed !== null ? (
        <>
          <dl className="kv">
            <dt>拦截</dt>
            <dd className="tnum">{fmtInt(data.blocked)}</dd>
            <dt>本应拦截</dt>
            <dd className="tnum">{fmtInt(data.would_block)}</dd>
            <dt>未经判定</dt>
            <dd className="tnum">{fmtInt(data.unjudged)}</dd>
            <dt>放行</dt>
            <dd className="tnum">{fmtInt(allowed)}</dd>
          </dl>
          {data.complete ? null : (
            <div className="small dim">
              扫描未完整，已扫描 {fmtInt(data.scanned)} 行，计数可能偏低。
            </div>
          )}
        </>
      ) : null}
      <Link
        to="/requests"
        search={(previous) => ({
          ...keepScope(previous),
          range: "24h" as const,
          since: undefined,
          until: undefined,
          q: text,
          scope: "all" as const,
        })}
      >
        查看这条路径的请求
      </Link>
    </Card>
  );
}

type Operation = { key: string; label: string; target: QuickTarget };

/** The operations that fit this record, as in docs/06 6.4.4; each opens the quick rule dialog. */
function operationsOf(detail: RequestDetail, requestId: string, site: string): Operation[] {
  const { summary, trace, jev } = detail;
  const operations: Operation[] = [];
  if (summary.session === "") {
    operations.push({
      key: "entry",
      label: "登记为入口…",
      target: { kind: "entry", site, path: summary.path, requestId },
    });
  }
  if (
    summary.status === 413 ||
    summary.decision_path === "body_not_inspectable" ||
    isStaticAsset(summary.path)
  ) {
    operations.push({
      key: "bypass",
      label: "加入绕过…",
      target: { kind: "bypass", site, path: summary.path, requestId },
    });
  }
  if (jev?.failure === "JEV_TIMEOUT") {
    operations.push({
      key: "timeout",
      label: "调整 Jev 超时…",
      target: { kind: "timeout", site, requestId },
    });
  }
  if (jev?.failure === "JEV_CALL_LIMIT") {
    operations.push({
      key: "call_limit",
      label: "调整调用上限…",
      target: { kind: "call_limit", site, requestId },
    });
  }
  const field = sensitiveFieldOf(trace);
  if (field !== null) {
    operations.push({
      key: "secret",
      label: "加为脱敏词…",
      target: { kind: "secret", site, field, requestId },
    });
  }
  return operations;
}
