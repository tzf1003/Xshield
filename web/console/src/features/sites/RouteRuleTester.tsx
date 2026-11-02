// The rule tester (console-design-objects-routes 2): a path, or a whole HTTP request pasted in, is read in the
// browser. Credentials are hidden before anything is shown, and nothing is uploaded or stored. The interface
// name, the logical path and the judgement are shown; a path typed alone is judged by its URL path, as the
// gateway judges a path without a name. PatternTester shares this reading.

import { useState } from "react";
import type { ApiInfo, RouteRule } from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { type Hidden, isUnknownApi, splitSource, testRequest } from "../../lib/logical-path.ts";
import { judgePath, type PathVerdict } from "../../lib/patterns.ts";
import {
  ROUTE_SOURCE_LABEL,
  ROUTE_TEST_FAILURE,
  ROUTE_TESTER_HELP,
  ROUTE_TESTER_NO_CREDENTIAL,
  ROUTE_TESTER_UNKNOWN_JUDGE,
  UNKNOWN_API_LABEL,
  UNKNOWN_REASON_TEXT,
} from "../../lib/vocab.ts";
import { SafeText } from "../../ui/SafeText.tsx";

/** The rules and lists a judgement is checked against: the draft's, and the saved ones for "草稿新增". */
export type TestBasis = {
  routes: readonly RouteRule[];
  entries: readonly string[];
  bypass: readonly string[];
  savedEntries: readonly string[];
  savedBypass: readonly string[];
};

export type TestView =
  | { kind: "failure"; text: string }
  | {
      kind: "ok";
      /** The interface name, or why it is unknown. Null for a path typed alone. */
      name: string | null;
      /** The logical path the judgement used. Null for a path typed alone and for an unknown name. */
      logical: string | null;
      verdict: string;
      /** The credentials hidden in a pasted request. Null for a path typed alone. */
      hidden: string | null;
    };

type RouteKind = keyof typeof ROUTE_SOURCE_LABEL;

function isRouteKind(kind: string): kind is RouteKind {
  return Object.hasOwn(ROUTE_SOURCE_LABEL, kind);
}

/** One location in words: `请求头 X-Service-Id`, or `URL 路径` for the path itself. */
function sourceText(source: string): string {
  if (source === "path") return "URL 路径";
  const { kind, name } = splitSource(source);
  const label = isRouteKind(kind) ? ROUTE_SOURCE_LABEL[kind] : kind;
  return name.length > 0 ? `${label} ${name}` : label;
}

function nameText(api: ApiInfo | null): string | null {
  if (api === null) return null;
  if (isUnknownApi(api)) {
    const where = api.source === undefined ? "" : `，来源 ${sourceText(api.source)}`;
    return `${UNKNOWN_API_LABEL}（${UNKNOWN_REASON_TEXT[api.unknown]}${where}）`;
  }
  const segments = api.from.map((source, index) => `第 ${index + 1} 段：${sourceText(source)}`);
  return `${api.name}（${segments.join("，")}）`;
}

function hiddenText(hidden: Hidden): string {
  if (hidden.count === 0) return ROUTE_TESTER_NO_CREDENTIAL;
  return `已隐藏 ${fmtInt(hidden.count)} 个凭证值（${hidden.names.join("、")}）`;
}

function judgeText(verdict: PathVerdict, basis: TestBasis): string {
  switch (verdict.kind) {
    case "bypass": {
      const fresh = basis.savedBypass.includes(verdict.rule) ? "" : "（草稿新增）";
      return `命中绕过 ${verdict.rule}：不判定，直接转发${fresh}`;
    }
    case "entry": {
      const fresh = basis.savedEntries.includes(verdict.rule) ? "" : "（草稿新增）";
      return `命中入口 ${verdict.rule}${fresh}`;
    }
    case "needs_session":
      return "需要会话：没有命中入口或绕过，没有会话凭证的请求会被记为无会话";
    case "invalid_spelling":
      return "网关不会把这种写法的路径匹配到任何入口或绕过（路径含 ; // %2e %2f 等写法）";
  }
}

/** What the tester shows for what was typed: nothing, a failure, or the reading and the judgement. */
export function testView(input: string, basis: TestBasis): TestView | null {
  const outcome = testRequest(input, basis.routes);
  if (outcome.kind === "empty") return null;
  if (outcome.kind === "invalid") {
    return { kind: "failure", text: ROUTE_TEST_FAILURE[outcome.reason] };
  }
  const entries = [...basis.entries];
  const bypass = [...basis.bypass];
  if (outcome.method === null) {
    const verdict = judgePath(outcome.request.path, entries, bypass);
    return {
      kind: "ok",
      name: null,
      logical: null,
      verdict: judgeText(verdict, basis),
      hidden: null,
    };
  }
  const hidden = hiddenText(outcome.hidden);
  const api = outcome.logical.api;
  if (isUnknownApi(api)) {
    return {
      kind: "ok",
      name: nameText(api),
      logical: null,
      verdict: `${UNKNOWN_API_LABEL}：${ROUTE_TESTER_UNKNOWN_JUDGE}`,
      hidden,
    };
  }
  const logical = outcome.logical.logical_path;
  const verdict = judgePath(logical, entries, bypass);
  return {
    kind: "ok",
    name: nameText(api),
    logical,
    verdict: judgeText(verdict, basis),
    hidden,
  };
}

/** The lines of a tester's result. Text from requests and rules is shown as text only. */
export function TestLines({ view, placeholder }: { view: TestView | null; placeholder: string }) {
  if (view === null) return <span>{placeholder}</span>;
  if (view.kind === "failure") return <span className="field-error">{view.text}</span>;
  return (
    <div className="stack-tight">
      {view.name === null ? null : (
        <div>
          <span className="muted">接口名 </span>
          <SafeText text={view.name} />
        </div>
      )}
      {view.logical === null ? null : (
        <div>
          <span className="muted">逻辑路径 </span>
          <span className="mono">
            <SafeText text={view.logical} />
          </span>
        </div>
      )}
      <div>
        <SafeText text={view.verdict} />
      </div>
      {view.hidden === null ? null : <div className="small muted">{view.hidden}</div>}
    </div>
  );
}

export function RouteRuleTester(basis: TestBasis) {
  const [text, setText] = useState("");
  const view = testView(text, basis);
  return (
    <div className="stack-tight route-tester">
      <label className="field-label" htmlFor="site-route-tester">
        规则测试
      </label>
      <div className="field-help">{ROUTE_TESTER_HELP}</div>
      <textarea
        id="site-route-tester"
        className="native-input mono"
        rows={3}
        value={text}
        placeholder="例如 POST /weixin/wx/mp/wx361163d21a65f679/gateway HTTP/1.1，或只输入一个路径"
        onChange={(event) => setText(event.target.value)}
      />
      <div className="small" role="status" aria-live="polite">
        <TestLines view={view} placeholder="粘贴后显示接口名、逻辑路径和判定" />
      </div>
    </div>
  );
}
