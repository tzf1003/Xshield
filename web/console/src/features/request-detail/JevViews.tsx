// The other three views of the Jev tab (docs/06 6.4.5): the JSON tree, the raw text of what was sent,
// and the instruction version. Both document views share one switch: the state Jev received, the request
// body rebuilt from it (a restored value, whose key order may differ), and the raw provider response.

import type { UseQueryResult } from "@tanstack/react-query";
import { Segmented } from "antd";
import { useState } from "react";
import type { JevPrompt, JevRecord } from "../../api/types.ts";
import { useSetSearch } from "../../app/scope.ts";
import type { JevDoc } from "../../app/search-schema.ts";
import { fmtBytes, fmtLocalDateTime, fmtInt } from "../../lib/format.ts";
import { Empty, ErrorBar, Loading, Notice } from "../../ui/Page.tsx";
import { JsonTree } from "../../ui/JsonTree.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { type ParsedState, utf8Bytes } from "./detail-model.ts";

const DOC_OPTIONS = [
  { label: "state", value: "state" },
  { label: "完整请求体（还原）", value: "body" },
  { label: "原始响应", value: "response" },
];

function DocSwitch({ doc }: { doc: JevDoc }) {
  const setSearch = useSetSearch();
  return (
    <Segmented
      size="small"
      value={doc}
      options={DOC_OPTIONS}
      onChange={(value) => setSearch({ jev_doc: String(value) })}
    />
  );
}

type Tree = "default" | "all" | "none";

/** The response text as JSON when it parses, so it can be shown as a tree. */
function parseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

type DocProps = {
  doc: JevDoc;
  parsed: ParsedState;
  body: Record<string, unknown> | null;
  bodyNote: string;
  response: string | null;
  query: string;
};

export function JevJson({ doc, parsed, body, bodyNote, response, query }: DocProps) {
  const [tree, setTree] = useState<Tree>("default");
  const depth = tree === "all" ? 99 : tree === "none" ? 0 : 2;
  return (
    <div className="stack">
      <div className="row rd-viewtools">
        <DocSwitch doc={doc} />
        <button type="button" className="linkbtn" onClick={() => setTree("all")}>
          全部展开
        </button>
        <button type="button" className="linkbtn" onClick={() => setTree("none")}>
          全部折叠
        </button>
        <button type="button" className="linkbtn" onClick={() => setTree("default")}>
          恢复默认
        </button>
      </div>
      {doc === "state" ? (
        parsed.status === "ok" ? (
          <JsonTree key={`state-${tree}`} value={parsed.state} openDepth={depth} query={query} />
        ) : parsed.status === "invalid" ? (
          <>
            <Notice tone="bad">
              这次调用的 state 不是合法的 JSON，无法展开。原文视图仍显示原始文本。
            </Notice>
            <pre className="codeblock">
              <SafeText text={parsed.text} query={query} />
            </pre>
          </>
        ) : (
          <Empty title="这次调用没有 state" />
        )
      ) : null}
      {doc === "body" ? (
        body !== null ? (
          <JsonTree key={`body-${tree}`} value={body} openDepth={depth} query={query} />
        ) : (
          <Notice tone="info">{bodyNote}</Notice>
        )
      ) : null}
      {doc === "response" ? (
        <ResponseView response={response} query={query} tree={tree} depth={depth} />
      ) : null}
    </div>
  );
}

function ResponseView({
  response,
  query,
  tree,
  depth,
}: {
  response: string | null;
  query: string;
  tree: Tree;
  depth: number;
}) {
  if (response === null) {
    return <Empty title="没有原始响应">超时、连接失败或没有发出调用时，没有响应。</Empty>;
  }
  const parsed = parseJson(response);
  if (parsed.ok) {
    return (
      <JsonTree key={`response-${tree}`} value={parsed.value} openDepth={depth} query={query} />
    );
  }
  return (
    <pre className="codeblock">
      <SafeText text={response} query={query} />
    </pre>
  );
}

/** The response indented per level when it is JSON; null when it is not (it stays as it came). */
function indentedResponse(response: string | null): string | null {
  if (response === null) return null;
  const parsed = parseJson(response);
  return parsed.ok ? JSON.stringify(parsed.value, null, 2) : null;
}

/**
 * The raw text of what was sent (docs/06 6.4.5). The original is one line as Jev received it; the
 * format box indents it per level and numbers the lines; the wrap box turns wrapping off; the byte
 * count is of the text on screen.
 */
export function JevRaw({ doc, parsed, body, bodyNote, response, query }: DocProps) {
  const [formatted, setFormatted] = useState(false);
  const [wrap, setWrap] = useState(true);

  const original =
    doc === "state"
      ? parsed.status === "absent"
        ? null
        : parsed.text
      : doc === "body"
        ? body !== null
          ? JSON.stringify(body)
          : null
        : response;
  const indented =
    doc === "state"
      ? parsed.status === "ok"
        ? JSON.stringify(parsed.state, null, 2)
        : null
      : doc === "body"
        ? body !== null
          ? JSON.stringify(body, null, 2)
          : null
        : indentedResponse(response);
  const shown = formatted && indented !== null ? indented : original;
  const lines: string[] = shown === null ? [] : shown.split("\n");

  return (
    <div className="stack">
      <div className="row rd-viewtools">
        <DocSwitch doc={doc} />
        <label className="check small">
          <input
            type="checkbox"
            checked={formatted}
            onChange={(event) => setFormatted(event.target.checked)}
          />
          格式化显示
        </label>
        <label className="check small">
          <input
            type="checkbox"
            checked={wrap}
            onChange={(event) => setWrap(event.target.checked)}
          />
          自动换行
        </label>
        {shown !== null ? (
          <span className="small dim tnum">{fmtBytes(utf8Bytes(shown))}</span>
        ) : null}
      </div>
      {doc === "body" && body === null ? <Notice tone="info">{bodyNote}</Notice> : null}
      {doc === "response" && response === null ? (
        <Empty title="没有原始响应">超时、连接失败或没有发出调用时，没有响应。</Empty>
      ) : null}
      {shown !== null && !(doc === "response" && response === null) ? (
        formatted && indented !== null ? (
          <pre className={wrap ? "codeblock code-numbered" : "codeblock code-numbered nowrap"}>
            {lines.map((line, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: the lines are a fixed list of one text
              <span className="code-line" key={index}>
                <span className="code-no" aria-hidden="true">
                  {index + 1}
                </span>
                <SafeText text={line} query={query} />
              </span>
            ))}
          </pre>
        ) : (
          <pre className={wrap ? "codeblock" : "codeblock nowrap"}>
            <SafeText text={shown} query={query} />
          </pre>
        )
      ) : null}
    </div>
  );
}

export function PromptView({
  jev,
  prompt,
  current,
}: {
  jev: JevRecord;
  prompt: UseQueryResult<JevPrompt, Error>;
  current: string | null;
}) {
  const data = prompt.data;
  return (
    <div className="stack">
      {current !== null && current !== jev.prompt ? (
        <Notice tone="warn">这次调用用的是旧版指令（当前 {current}）。</Notice>
      ) : null}
      {prompt.isPending ? <Loading height={120} /> : null}
      {prompt.isError ? (
        <ErrorBar error={prompt.error} onRetry={() => void prompt.refetch()} />
      ) : null}
      {data !== undefined ? (
        <>
          <QuestionBlock title="访问有依据吗" question={data.questions.access} />
          <QuestionBlock title="内容是攻击吗" question={data.questions.attack} />
          <div className="small dim">
            指令版本 <span className="mono">{data.id}</span> · 首次出现{" "}
            {formatFirstSeen(data.first_seen)}
            {data.calls !== undefined ? ` · 被 ${fmtInt(data.calls)} 次调用使用` : ""}
          </div>
        </>
      ) : null}
    </div>
  );
}

function formatFirstSeen(value: string): string {
  const millis = Date.parse(value);
  return Number.isNaN(millis) ? value : fmtLocalDateTime(millis);
}

function QuestionBlock({
  title,
  question,
}: {
  title: string;
  question: JevPrompt["questions"]["access"];
}) {
  return (
    <section className="struct-sec">
      <h2 className="struct-title">{title}</h2>
      <div className="small">
        <SafeText text={question.instructions} />
      </div>
      <dl className="kv rd-criteria">
        {Object.entries(question.criteria).map(([option, meaning]) => (
          <div key={option} className="rd-criterion">
            <dt className="mono">{option}</dt>
            <dd>
              <SafeText text={meaning} />
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
