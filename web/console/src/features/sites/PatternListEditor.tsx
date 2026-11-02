// The entry and bypass rule lists of a configuration (docs/06 6.4.9): one rule per row with its 24-hour hits,
// rules checked as they are typed (docs/06 6.6.5), and a warning for prefixes wide enough to matter. Under an
// interface-name rule, a path typed under the rule is completed from the recent records, and an entry the rule
// now hides lists the logical paths it could be written as (console-design-objects-routes 2).

import { useState } from "react";
import type { RouteRule } from "../../api/types.ts";
import { ruleBase, ruleFor, typedUnderRule } from "../../lib/logical-path.ts";
import { fmtInt } from "../../lib/format.ts";
import { parsePattern } from "../../lib/patterns.ts";
import type { FieldIssue } from "../../lib/site-validate.ts";
import { ROUTE_REWRITE_HINT } from "../../lib/vocab.ts";
import { RouteCandidates } from "./RouteCandidates.tsx";
import { addUnique } from "./spec-model.ts";

export type RulePreset = { label: string; rules: readonly string[] };

const MAX_RULES = 64;

function hitText(hits: Record<string, number> | undefined, rule: string): string {
  const count = hits?.[rule];
  if (count === undefined) return "—";
  return count === 0 ? "24 小时未命中" : `24 小时 ${fmtInt(count)} 次`;
}

/** A prefix whose only segment is the first one, such as `/*`: it reaches almost every path. */
function isWidePrefix(rule: string): boolean {
  const parsed = parsePattern(rule);
  return (
    parsed.ok && parsed.value.prefix && parsed.value.literal.split("/").filter(Boolean).length <= 1
  );
}

export function PatternListEditor({
  kind,
  label,
  rules,
  hits,
  issues,
  warnings = [],
  site = null,
  routes = [],
  onChange,
  notice = null,
  presets = [],
}: {
  kind: "entries" | "bypass";
  label: string;
  rules: string[];
  hits: Record<string, number> | undefined;
  issues: FieldIssue[];
  /** Warnings of the draft; a row's warning is the one for its position. */
  warnings?: FieldIssue[];
  /** The site's name, for the recent records; null while the site is created. */
  site?: string | null;
  /** The interface-name rules of the draft. */
  routes?: RouteRule[];
  onChange: (rules: string[]) => void;
  notice?: string | null;
  presets?: RulePreset[];
}) {
  const [text, setText] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const groupIssues = issues.filter((issue) => issue.field === kind);
  const typed = text.trim();
  const typedRule =
    site === null ? null : (routes.find((rule) => typedUnderRule(typed, rule)) ?? null);

  const add = () => {
    const raw = text.trim();
    if (raw.length === 0) return;
    const parsed = parsePattern(raw);
    if (!parsed.ok) {
      setProblem(parsed.reason);
      return;
    }
    if (rules.includes(raw)) {
      setProblem("这条规则已经在列表里");
      return;
    }
    if (rules.length >= MAX_RULES) {
      setProblem(`最多 ${MAX_RULES} 条`);
      return;
    }
    onChange([...rules, raw]);
    setText("");
    setProblem(null);
  };

  return (
    <div className="stack-tight">
      <div className="row between">
        <span className="small muted">
          {label} {rules.length} 条
        </span>
        {presets.length > 0 ? (
          <span className="row">
            {presets.map((preset) => (
              <button
                key={preset.label}
                type="button"
                className="chip"
                onClick={() => onChange(addUnique(rules, preset.rules))}
              >
                {preset.label}
              </button>
            ))}
          </span>
        ) : null}
      </div>
      {groupIssues.map((issue) => (
        <div key={issue.message} className="field-error" role="alert">
          {issue.message}
        </div>
      ))}
      <ul className="rulelist" aria-label={label}>
        {rules.map((rule, index) => {
          const parsed = parsePattern(rule);
          const rowIssue = issues.find((issue) => issue.field === `${kind}[${index}]`);
          const error = parsed.ok ? (rowIssue?.message ?? null) : parsed.reason;
          const wide = kind === "entries" && isWidePrefix(rule);
          const rowWarning = warnings.find((item) => item.field === `${kind}[${index}]`);
          const covering = site === null ? null : ruleFor(routes, rule);
          const coveringBase = covering === null ? null : ruleBase(covering);
          return (
            <li key={rule} className={`rulerow${error ? " err" : ""}`}>
              <span className="mono path">{rule}</span>
              <span className={`hits${hits?.[rule] === 0 ? " dim" : ""}`}>
                {hitText(hits, rule)}
              </span>
              <button
                type="button"
                className="btn"
                aria-label={`删除 ${rule}`}
                onClick={() => onChange(rules.filter((item) => item !== rule))}
              >
                删除
              </button>
              {error ? <div className="field-error rulerow-note">{error}</div> : null}
              {wide && !error ? (
                <div className="field-warn rulerow-note">前缀入口会放大无会话可达的范围</div>
              ) : null}
              {rowWarning && !error ? (
                <div className="field-warn rulerow-note">▲ {rowWarning.message}</div>
              ) : null}
              {site !== null && covering !== null && coveringBase !== null && rowWarning ? (
                <div className="rulerow-note">
                  <span className="small muted">{ROUTE_REWRITE_HINT}</span>
                  <RouteCandidates
                    site={site}
                    rule={covering}
                    prefix={`${coveringBase}/`}
                    onPick={(logical) =>
                      onChange(rules.map((item, position) => (position === index ? logical : item)))
                    }
                  />
                </div>
              ) : null}
            </li>
          );
        })}
      </ul>
      <div className="row">
        <input
          className="native-input mono"
          value={text}
          placeholder={
            kind === "entries" ? "添加入口，例如 /rest/admin/*" : "添加绕过，例如 /static/*"
          }
          aria-label={`添加${label}规则`}
          onChange={(event) => {
            setText(event.target.value);
            setProblem(null);
          }}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
          style={{ flex: 1, minWidth: 0 }}
        />
        <button type="button" className="btn" onClick={add}>
          添加
        </button>
      </div>
      {site !== null && typedRule !== null ? (
        <RouteCandidates
          site={site}
          rule={typedRule}
          prefix={typed}
          onPick={(logical) => {
            setText(logical);
            setProblem(null);
          }}
        />
      ) : null}
      {problem ? (
        <div className="field-error" role="alert">
          {problem}
        </div>
      ) : null}
      {notice ? <div className="field-warn">▲ {notice}</div> : null}
    </div>
  );
}
