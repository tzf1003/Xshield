// The session tab (docs/06 6.4.4): how old the session was when the request came, how many values it had
// seen, the entries it passed, and the recent accesses (kept on Jev records only), each with a link to
// its request. The same summary sits in the Jev tab beside the request's cards.

import { Link } from "@tanstack/react-router";
import type {
  EntryPass,
  RecentAccess,
  RequestDetail,
  Trace,
  TraceSession,
} from "../../api/types.ts";
import { fmtElapsed, fmtInt, fmtLocalDateTime } from "../../lib/format.ts";
import { isSessionLabel, shortRequestId, shortSession } from "../../lib/ids.ts";
import { LOGIN_ROW_TEXT, LOGIN_UNBOUND_TEXT, OBJECT_JUDGEMENT } from "../../lib/vocab.ts";
import { Card, Empty } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { sessionLists } from "./detail-model.ts";
import { timelineSearch } from "./DetailHead.tsx";
import { keyed, LinkedRequest } from "./parts.tsx";

/** The values a JSON login response held for its credential (docs/01 section 1.7). Shown whatever the
 *  record's session is: an entry request without a credential carries the address's context, so a
 *  login has a session in the record and still held values. */
function HeldValues({ trace }: { trace: Trace }) {
  const held = trace.response?.pending_values;
  if (held === undefined) return null;
  return (
    <div className="small">
      {LOGIN_ROW_TEXT.held}：{fmtInt(held)} 个值，等待凭证开始会话时绑定，5 分钟内有效。
    </div>
  );
}

export function SessionTab({ detail, requestId }: { detail: RequestDetail; requestId: string }) {
  const { summary, trace } = detail;
  const session = trace.session;
  if (!session) {
    return (
      <Card title="会话上下文">
        <HeldValues trace={trace} />
        <Empty title="这条记录没有会话上下文">无会话或绕过的请求没有会话上下文。</Empty>
      </Card>
    );
  }
  const lists = sessionLists(session);
  return (
    <Card title="会话上下文">
      <HeldValues trace={trace} />
      <SessionSummary
        trace={trace}
        entries={lists.entries}
        recent={lists.recent}
        sessionLabel={summary.session}
        requestId={requestId}
        timeline
      />
    </Card>
  );
}

/** Who the session was when the decision was made, in words: the user and the organization as labels of keyed
 *  hashes, the role as its label (docs/07 7.9.15). Empty when the site declared no identity for the session. */
function identityWords(identity: TraceSession["identity"]): string[] {
  if (identity === undefined) return [];
  const parts: string[] = [];
  if (identity.user !== undefined)
    parts.push(`${OBJECT_JUDGEMENT.identity.user.name} ${identity.user}`);
  if (identity.org !== undefined)
    parts.push(`${OBJECT_JUDGEMENT.identity.org.name} ${identity.org}`);
  if (identity.role !== undefined)
    parts.push(`${OBJECT_JUDGEMENT.identity.role.name} ${identity.role}`);
  return parts;
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
  /** The entries the session passed; null when the record made no Jev call, so none were kept. */
  entries: EntryPass[] | null;
  /** The recent accesses, newest first; null when the record made no Jev call. */
  recent: RecentAccess[] | null;
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
            {identityWords(session.identity).length === 0 ? null : (
              <>
                <dt title={OBJECT_JUDGEMENT.identityRow}>{OBJECT_JUDGEMENT.identityRow}</dt>
                <dd className="mono">
                  <SafeText text={identityWords(session.identity).join(" · ")} />
                </dd>
              </>
            )}
            {session.login_request_id ? (
              <>
                <dt>{LOGIN_ROW_TEXT.request}</dt>
                <dd className="mono">
                  <LinkedRequest id={session.login_request_id} className="mono">
                    {shortRequestId(session.login_request_id)}
                  </LinkedRequest>
                </dd>
              </>
            ) : null}
            {session.login_unbound === undefined ? null : (
              <>
                <dt>{LOGIN_ROW_TEXT.unbound}</dt>
                <dd>
                  {LOGIN_UNBOUND_TEXT[session.login_unbound].name}
                  <div className="small dim">{LOGIN_UNBOUND_TEXT[session.login_unbound].desc}</div>
                </dd>
              </>
            )}
          </>
        ) : null}
      </dl>

      <div>
        <div className="field-label">经过的入口</div>
        {entries === null ? (
          <div className="small dim">
            经过的入口只在调用 Jev 的记录里保存；完整顺序见会话时间线。
          </div>
        ) : entries.length === 0 ? (
          <div className="small dim">没有记录经过的入口</div>
        ) : (
          <ul className="rd-list">
            {keyed(entries, (entry) => `${entry.path}|${entry.request_id ?? ""}`).map(
              ({ key, item }) => (
                <li key={key}>
                  <LinkedRequest id={item.request_id} className="mono">
                    <SafeText text={item.path} />
                  </LinkedRequest>
                  {item.at_millis !== null ? (
                    <span className="small dim tnum"> · {fmtLocalDateTime(item.at_millis)}</span>
                  ) : null}
                </li>
              ),
            )}
          </ul>
        )}
      </div>

      <div>
        <div className="field-label">
          {recent === null ? "最近访问" : `最近访问 ${fmtInt(recent.length)} 条（新 → 旧）`}
        </div>
        {recent === null ? (
          <div className="small dim">最近访问只在调用 Jev 的记录里保存；完整顺序见会话时间线。</div>
        ) : recent.length === 0 ? (
          <div className="small dim">没有最近访问</div>
        ) : (
          <ul className="rd-list">
            {keyed(
              recent,
              (item) =>
                `${item.method} ${item.path}|${item.at_millis ?? ""}|${item.request_id ?? ""}`,
            ).map(({ key, item }) => (
              <li key={key}>
                <LinkedRequest id={item.request_id} className="mono">
                  <SafeText text={`${item.method} ${item.path}`} />
                </LinkedRequest>{" "}
                <span className="small dim tnum">{item.status ?? "—"}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {issued !== null && isSessionLabel(issued) ? (
        <div className="small">
          这次响应签发了会话{" "}
          <Link
            to="/sessions/$label"
            params={{ label: issued }}
            search={timelineSearch(requestId)}
            className="mono"
          >
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
