// The session tab (docs/06 6.4.4): how old the session was when the request came, how many values it had
// seen, the entries it passed, and the recent accesses (kept on Jev records only), each with a link to
// its request. The same summary sits in the Jev tab beside the request's cards.

import { Link } from "@tanstack/react-router";
import type { EntryPass, RecentAccess, RequestDetail, Trace } from "../../api/types.ts";
import { fmtElapsed, fmtInt, fmtLocalDateTime } from "../../lib/format.ts";
import { isSessionLabel, shortSession } from "../../lib/ids.ts";
import { Card, Empty } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { timelineSearch } from "./DetailHead.tsx";
import { keyed, LinkedRequest } from "./parts.tsx";

/** Recent accesses newest first; the gateway keeps them in the order it saw them. */
export function newestFirst(items: RecentAccess[]): RecentAccess[] {
  return [...items].sort((a, b) => (b.at_millis ?? 0) - (a.at_millis ?? 0));
}

export function SessionTab({ detail, requestId }: { detail: RequestDetail; requestId: string }) {
  const { summary, trace } = detail;
  const session = trace.session;
  if (!session) {
    return (
      <Card title="会话上下文">
        <Empty title="这条记录没有会话上下文">无会话或绕过的请求没有会话上下文。</Empty>
      </Card>
    );
  }
  return (
    <Card title="会话上下文">
      <SessionSummary
        trace={trace}
        entries={session.entries_passed}
        recent={newestFirst(session.recent)}
        sessionLabel={summary.session}
        requestId={requestId}
        timeline
      />
    </Card>
  );
}

export function SessionSummary({
  trace,
  entries,
  recent,
  sessionLabel,
  requestId,
  timeline = false,
}: {
  trace: Trace;
  entries: EntryPass[];
  recent: RecentAccess[];
  sessionLabel: string;
  requestId: string;
  timeline?: boolean;
}) {
  const session = trace.session;
  const issued = trace.response?.issued_session ?? null;
  const label = isSessionLabel(sessionLabel) ? sessionLabel : null;
  return (
    <div className="stack rd-session">
      <dl className="kv">
        <dt>入口</dt>
        <dd>{trace.entry ? <SafeText text={`命中 ${trace.entry}`} /> : "未命中"}</dd>
        {session ? (
          <>
            <dt>已存在</dt>
            <dd>{fmtElapsed(session.age_seconds)}</dd>
            <dt>已见值</dt>
            <dd className="tnum">{fmtInt(session.known_values)} 个</dd>
          </>
        ) : null}
      </dl>

      <div>
        <div className="field-label">经过的入口</div>
        {entries.length === 0 ? (
          <div className="small dim">没有记录经过的入口</div>
        ) : (
          <ul className="rd-list">
            {keyed(entries, (entry) => `${entry.path}|${entry.request_id ?? ""}`).map(({ key, item }) => (
              <li key={key}>
                <LinkedRequest id={item.request_id} className="mono">
                  <SafeText text={item.path} />
                </LinkedRequest>
                {item.at_millis !== null ? (
                  <span className="small dim tnum"> · {fmtLocalDateTime(item.at_millis)}</span>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <div className="field-label">最近访问 {fmtInt(recent.length)} 条（新 → 旧）</div>
        {recent.length === 0 ? (
          <div className="small dim">最近访问只在调用 Jev 的记录里保存；完整顺序见会话时间线。</div>
        ) : (
          <ul className="rd-list">
            {keyed(recent, (item) => `${item.method} ${item.path}|${item.at_millis ?? ""}|${item.request_id ?? ""}`).map(
              ({ key, item }) => (
                <li key={key}>
                  <LinkedRequest id={item.request_id} className="mono">
                    <SafeText text={`${item.method} ${item.path}`} />
                  </LinkedRequest>{" "}
                  <span className="small dim tnum">{item.status ?? "—"}</span>
                </li>
              ),
            )}
          </ul>
        )}
      </div>

      {issued !== null && isSessionLabel(issued) ? (
        <div className="small">
          这次响应签发了会话{" "}
          <Link to="/sessions/$label" params={{ label: issued }} search={timelineSearch(requestId)} className="mono">
            {shortSession(issued)}…
          </Link>
        </div>
      ) : null}

      {timeline && label !== null ? (
        <div>
          <Link to="/sessions/$label" params={{ label }} search={timelineSearch(requestId)}>
            打开会话时间线（定位到本请求）
          </Link>
        </div>
      ) : null}
    </div>
  );
}
