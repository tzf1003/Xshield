// The Jev tab of the request detail (docs/06 6.4.5): the answer area first, then one of four views of
// what Jev received (structured cards, JSON tree, raw text, instruction version). A request that never
// called Jev says why instead, and a failed call says what the gateway did about it.

import { Link } from "@tanstack/react-router";
import { Segmented } from "antd";
import { type KeyboardEvent, useRef, useState } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { useJevStatus, usePrompt } from "../../api/queries.ts";
import type { JevPrompt, RequestDetail } from "../../api/types.ts";
import { useSetSearch } from "../../app/scope.ts";
import type { JevDoc, JevView } from "../../app/search-schema.ts";
import { batchNote, leftOutNote } from "../../lib/align.ts";
import { isSiteName } from "../../lib/ids.ts";
import { Card, Empty, Notice } from "../../ui/Page.tsx";
import {
  type Alignment,
  type ParsedState,
  alignState,
  parseState,
  sentRows,
  sessionView,
  utf8Bytes,
} from "./detail-model.ts";
import { JevAnswerArea } from "./JevAnswerArea.tsx";
import { JevStructured } from "./JevCards.tsx";
import { JevJson, JevRaw, PromptView } from "./JevViews.tsx";
import { CopyAction, LinkedRequest } from "./parts.tsx";

const VIEWS: Array<{ label: string; value: JevView }> = [
  { label: "结构化", value: "structured" },
  { label: "JSON", value: "json" },
  { label: "原文", value: "raw" },
  { label: "指令", value: "prompt" },
];

type Props = {
  detail: RequestDetail;
  requestId: string;
  view: JevView;
  doc: JevDoc;
  hl: number | undefined;
};

export function JevInspector({ detail, requestId, view, doc, hl }: Props) {
  const { summary, trace, jev, sources } = detail;
  const setSearch = useSetSearch();
  const status = useJevStatus();
  const prompt = usePrompt(jev?.prompt ?? null);
  const [query, setQuery] = useState("");
  const [position, setPosition] = useState<{ index: number; total: number } | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);

  if (jev === null) return <NoCall detail={detail} />;

  const parsed: ParsedState = parseState(jev.state);
  const state = parsed.status === "ok" ? parsed.state : null;
  // A state cut into batches holds only one batch's values, so no source link can be checked against the trace.
  const alignment: Alignment | null =
    state === null ? null : (jev.batches ?? 1) > 1 ? { aligned: false } : alignState(state, trace);
  const batched = batchNote(jev.batches, jev.batch);
  const leftOut = leftOutNote(jev.left_out);
  const rows = sentRows(trace, state, alignment);
  const session = sessionView(trace, state, alignment);
  const body =
    state !== null && prompt.data !== undefined
      ? { model: jev.model, state, questions: prompt.data.questions }
      : null;
  const bodyText = body === null ? null : JSON.stringify(body, null, 2);
  const bodyNote = bodyNoteOf(parsed, prompt);
  const stateNote = jev.state === null ? noStateText(jev.failure) : null;
  const limitLink = jev.failure === "JEV_CALL_LIMIT" || jev.failure === "JEV_STATE_TOO_LARGE";
  const siteName = summary.site !== null && isSiteName(summary.site) ? summary.site : null;

  function jump(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key !== "Enter") return;
    event.preventDefault();
    const marks = panel.current
      ? Array.from(panel.current.querySelectorAll<HTMLElement>("mark.hit"))
      : [];
    if (marks.length === 0) {
      setPosition({ index: -1, total: 0 });
      return;
    }
    const step = event.shiftKey ? -1 : 1;
    const index = position === null ? 0 : (position.index + step + marks.length) % marks.length;
    setPosition({ index, total: marks.length });
    marks[index]?.scrollIntoView({ block: "center" });
  }

  return (
    <div className="stack rd-jev">
      <JevAnswerArea
        jev={jev}
        outcome={summary.outcome}
        status={summary.status}
        path={summary.decision_path}
        defaultTimeout={status.data?.config?.default_timeout_ms ?? null}
        stateBytes={jev.state === null ? null : utf8Bytes(jev.state)}
        onPrompt={() => setSearch({ jev_view: "prompt" })}
      />

      <div className="row rd-viewtools">
        <Segmented
          size="small"
          value={view}
          options={VIEWS}
          onChange={(value) => setSearch({ jev_view: String(value) })}
        />
        <input
          type="search"
          className="native-input rd-search"
          placeholder="在上下文中搜索"
          aria-label="在上下文中搜索"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setPosition(null);
          }}
          onKeyDown={jump}
        />
        {position === null ? null : (
          <span className="small dim tnum" role="status">
            {position.total === 0 ? "没有匹配" : `${position.index + 1} / ${position.total}`}
          </span>
        )}
        {jev.state !== null ? <CopyAction text={jev.state} label="复制 state" /> : null}
        {bodyText !== null ? <CopyAction text={bodyText} label="复制完整请求体" /> : null}
      </div>

      {batched !== null ? <Notice tone="info">{batched}</Notice> : null}
      {leftOut !== null ? <Notice tone="warn">{leftOut}</Notice> : null}

      {stateNote !== null ? (
        <Notice tone="info">
          {stateNote}
          {limitLink && siteName !== null ? (
            <>
              {" "}
              <Link
                to="/sites/$name"
                params={{ name: siteName }}
                search={{ tab: "config", group: "advanced" }}
              >
                在站点的高级判定参数里查看
              </Link>
            </>
          ) : null}
        </Notice>
      ) : null}

      <div ref={panel} className="stack">
        {view === "structured" ? (
          <JevStructured
            rows={rows}
            session={session}
            trace={trace}
            sessionLabel={summary.session}
            requestId={requestId}
            summaries={sources}
            query={query}
            hl={hl}
          />
        ) : null}
        {view === "json" ? (
          <JevJson
            doc={doc}
            parsed={parsed}
            body={body}
            bodyNote={bodyNote}
            response={jev.response}
            query={query}
          />
        ) : null}
        {view === "raw" ? (
          <JevRaw
            doc={doc}
            parsed={parsed}
            body={body}
            bodyNote={bodyNote}
            response={jev.response}
            query={query}
          />
        ) : null}
        {view === "prompt" ? (
          <PromptView jev={jev} prompt={prompt} current={status.data?.config?.prompt ?? null} />
        ) : null}
      </div>
    </div>
  );
}

function bodyNoteOf(parsed: ParsedState, prompt: UseQueryResult<JevPrompt, Error>): string {
  if (parsed.status !== "ok") return "这次调用没有可还原的 state，所以没有完整请求体。";
  if (prompt.isError) return "指令全文读取失败，无法还原完整请求体。";
  return "正在读取指令全文，用来还原完整请求体。";
}

/** Why the call left no state, for a record that has a Jev entry but no call text. */
function noStateText(failure: string | null): string {
  if (failure === "JEV_CALL_LIMIT") return "调用次数达到上限，这次没有发出调用，所以没有 state。";
  if (failure === "JEV_STATE_TOO_LARGE")
    return "分批（最多 16 批）后仍装不下，这次没有发出调用，所以没有 state。";
  return "这次调用没有 state。";
}

/** A request that never reached Jev: the reason comes from its decision path (docs/06 6.4.5). */
function NoCall({ detail }: { detail: RequestDetail }) {
  const { summary, trace } = detail;
  const siteName = summary.site !== null && isSiteName(summary.site) ? summary.site : null;
  const cacheSource = trace.cache_source ?? null;
  return (
    <Card title="Jev 上下文 · 未调用">
      <Empty title="这次请求没有调用 Jev">
        <div className="small">{noCallReason(summary.decision_path)}</div>
        {summary.decision_path === "cached_allow" && cacheSource !== null ? (
          <div className="small">
            缓存来源：<LinkedRequest id={cacheSource}>{cacheSource}</LinkedRequest>
          </div>
        ) : null}
        {summary.decision_path === "jev_unavailable" && siteName !== null ? (
          <div className="small">
            <Link
              to="/sites/$name"
              params={{ name: siteName }}
              search={{ tab: "config", group: "advanced" }}
            >
              在站点的高级判定参数里查看
            </Link>
          </div>
        ) : null}
      </Empty>
    </Card>
  );
}

function noCallReason(path: RequestDetail["summary"]["decision_path"]): string {
  switch (path) {
    case "fast_allow":
      return "快速放行：需核验的值都已核验，所以没有调用 Jev。";
    case "cached_allow":
      return "缓存放行：同一会话里相同的请求刚由 Jev 放行，在缓存时长内直接复用，没有再调用。";
    case "no_session":
      return "无会话：没有会话凭证，路径也不是入口，网关不调用 Jev。";
    case "bypass":
      return "绕过：命中绕过规则，不判定，直接转发。";
    case "body_not_inspectable":
      return "请求体不可判定：超过 48 KiB 或没有 Content-Length，返回 413，不调用 Jev。";
    case "unknown_site":
      return "未知站点：Host 不属于任何站点，返回 404，不调用 Jev。";
    case "jev_unavailable":
      return "这次没有发出调用：调用次数达到上限或上下文过大，记录里没有调用的详情。";
    case "jev_allow":
    case "jev_deny":
      return "这条记录没有 Jev 调用的详情。";
  }
}
