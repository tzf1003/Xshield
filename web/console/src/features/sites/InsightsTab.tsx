// The tuning suggestions of a site (docs/06 6.4.9, docs/07 7.9.11): each one says what the change is and why. A
// change can be added to the draft, or applied at once through the save dialog. Ignoring a suggestion is kept
// in this browser only. While the site observes, the readiness checklist sits above the list.

import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useInsights } from "../../api/queries.ts";
import type {
  SiteDetail,
  SiteSpec,
  Suggestion,
  SuggestionAction,
  SuggestionKind,
} from "../../api/types.ts";
import { fmtInt } from "../../lib/format.ts";
import { PARAM_INFO, SUGGESTION_INFO } from "../../lib/vocab.ts";
import { Card, Empty, ErrorBar, Loading } from "../../ui/Page.tsx";
import { RequestLink } from "../../ui/RequestRef.tsx";
import { ReadinessList } from "./Readiness.tsx";
import { actionLines, applyAction } from "./spec-model.ts";
import { readIgnored, writeIgnored } from "./site-storage.ts";

type Props = {
  site: SiteDetail;
  /** The draft, or the saved configuration when there is none: a change applies on top of it. */
  working: SiteSpec;
  now: number;
  onAdd: (spec: SiteSpec) => void;
  onApply: (spec: SiteSpec) => void;
};

const KIND_ORDER: SuggestionKind[] = [
  "entry_candidate",
  "bypass_candidate",
  "upload_candidate",
  "raise_jev_timeout",
  "raise_call_limit",
  "secret_field_candidate",
  "hot_would_block",
];

const UPLOAD_NOTE = "绕过后该接口不做越权判定，只在确实需要上传大文件时使用。";

/** What the change costs, in the words of the parameter it changes (the "?" help of docs/06 6.4.9). */
function costNote(suggestion: Suggestion, option: SuggestionAction | undefined): string | null {
  switch (suggestion.kind) {
    case "upload_candidate":
      return UPLOAD_NOTE;
    case "raise_jev_timeout":
      return PARAM_INFO.jev_timeout_ms.cost;
    case "raise_call_limit":
      return option?.set_advanced?.address_calls_per_minute !== undefined
        ? PARAM_INFO.address_calls_per_minute.cost
        : PARAM_INFO.session_calls_per_minute.cost;
    case "secret_field_candidate":
      return PARAM_INFO.secret_fields.cost;
    default:
      return null;
  }
}

type CardProps = {
  siteName: string;
  suggestion: Suggestion;
  working: SiteSpec;
  choice: number;
  onChoice: (index: number) => void;
  onAdd: (spec: SiteSpec) => void;
  onApply: (spec: SiteSpec) => void;
  onIgnore: (id: string) => void;
};

function SuggestionCard({
  siteName,
  suggestion,
  working,
  choice,
  onChoice,
  onAdd,
  onApply,
  onIgnore,
}: CardProps) {
  const options = suggestion.actions;
  const selected = options[choice] ?? options[0];
  const note = costNote(suggestion, selected);
  const target =
    suggestion.path === null
      ? ""
      : `${suggestion.method ? `${suggestion.method} ` : ""}${suggestion.path}`;

  return (
    <article className="sugg">
      <div className="sugg-h">
        <span>{SUGGESTION_INFO[suggestion.kind]}</span>
        {target ? <span className="mono">{target}</span> : null}
        <span className="sugg-meta">{fmtInt(suggestion.count)} 次</span>
      </div>
      <div className="sugg-body">{suggestion.reason}</div>
      {options.length > 1 ? (
        <div className="adv-choice" role="radiogroup" aria-label="改动的写法">
          {options.map((option, index) => (
            <label key={actionLines(option).join("|")} className="adv-radio">
              <input
                type="radio"
                name={`option-${suggestion.id}`}
                checked={index === choice}
                onChange={() => onChoice(index)}
              />
              {option.label === "prefix" ? "前缀" : "精确路径"}
              {option.matches !== undefined ? `（匹配 ${fmtInt(option.matches)} 次）` : null}
            </label>
          ))}
        </div>
      ) : null}
      {selected ? (
        <ul className="changes" aria-label="改动">
          {actionLines(selected).map((line) => (
            <li key={line}>· {line}</li>
          ))}
        </ul>
      ) : null}
      {note ? <div className="field-warn">▲ {note}</div> : null}
      {suggestion.sample ? (
        <div className="small muted">
          示例请求 <RequestLink id={suggestion.sample} />
        </div>
      ) : null}
      <div className="sugg-actions">
        <button type="button" className="linkbtn" onClick={() => onIgnore(suggestion.id)}>
          忽略
        </button>
        {selected ? (
          <>
            <button
              type="button"
              className="btn"
              onClick={() => onAdd(applyAction(working, selected))}
            >
              加入草稿
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={() => onApply(applyAction(working, selected))}
            >
              应用…
            </button>
          </>
        ) : (
          <Link
            to="/requests"
            search={{ site: siteName, chip: "would_block", q: suggestion.path ?? undefined }}
            className="btn"
          >
            查看请求
          </Link>
        )}
      </div>
    </article>
  );
}

export function InsightsTab({ site, working, now, onAdd, onApply }: Props) {
  const insights = useInsights(site.name);
  const [ignored, setIgnored] = useState<string[]>(() => readIgnored(site.name));
  const [showIgnored, setShowIgnored] = useState(false);
  const [picked, setPicked] = useState<Record<string, number>>({});

  if (insights.isPending) return <Loading height={180} />;
  if (insights.isError)
    return <ErrorBar error={insights.error} onRetry={() => void insights.refetch()} />;
  const data = insights.data;
  if (data === undefined) return <Loading height={180} />;

  const ignore = (id: string) => {
    const next = [...ignored, id];
    setIgnored(next);
    writeIgnored(site.name, next);
  };
  const restore = (id: string) => {
    const next = ignored.filter((item) => item !== id);
    setIgnored(next);
    writeIgnored(site.name, next);
  };
  const visible = data.suggestions.filter((item) => !ignored.includes(item.id));
  const hidden = data.suggestions.filter((item) => ignored.includes(item.id));
  const groups = KIND_ORDER.map((kind) => ({
    kind,
    items: visible.filter((item) => item.kind === kind),
  })).filter((group) => group.items.length > 0);

  return (
    <div className="stack">
      {site.mode === "observe" ? (
        <Card title="就绪检查" aside={`最近 ${fmtInt(data.window_hours)} 小时`}>
          <ReadinessList readiness={data.readiness} now={now} site={site.name} />
        </Card>
      ) : null}
      {data.complete ? null : (
        <div className="small muted">统计不完整：按部分记录计算，数字可能偏小。</div>
      )}
      {data.suggestions.length === 0 ? (
        <Empty title="暂时没有建议">
          {site.mode === "observe" ? "观察模式下积累更多请求后再来看。" : null}
        </Empty>
      ) : null}

      {groups.map((group) => (
        <section key={group.kind} className="stack-tight" aria-label={SUGGESTION_INFO[group.kind]}>
          <div className="field-label">
            {SUGGESTION_INFO[group.kind]}（{fmtInt(group.items.length)}）
          </div>
          {group.items.map((suggestion) => (
            <SuggestionCard
              key={suggestion.id}
              siteName={site.name}
              suggestion={suggestion}
              working={working}
              choice={picked[suggestion.id] ?? 0}
              onChoice={(index) =>
                setPicked((previous) => ({ ...previous, [suggestion.id]: index }))
              }
              onAdd={onAdd}
              onApply={onApply}
              onIgnore={ignore}
            />
          ))}
        </section>
      ))}

      {hidden.length > 0 ? (
        <div className="small muted">
          已忽略 {fmtInt(hidden.length)} 条 ·{" "}
          <button
            type="button"
            className="linkbtn"
            onClick={() => setShowIgnored((value) => !value)}
          >
            {showIgnored ? "隐藏" : "显示"}
          </button>
        </div>
      ) : null}
      {showIgnored
        ? hidden.map((item) => (
            <div key={item.id} className="row small">
              <span>
                {SUGGESTION_INFO[item.kind]} {item.path ?? ""}
              </span>
              <button type="button" className="linkbtn" onClick={() => restore(item.id)}>
                恢复
              </button>
            </div>
          ))
        : null}
    </div>
  );
}
