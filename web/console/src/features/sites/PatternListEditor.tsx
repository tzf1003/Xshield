// The entry and bypass rule lists of a configuration (docs/06 6.4.9): one rule per row with its 24-hour hits,
// rules checked as they are typed (docs/06 6.6.5), and a warning for prefixes wide enough to matter.

import { useState } from "react";
import type { FieldIssue } from "../../lib/site-validate.ts";
import { parsePattern } from "../../lib/patterns.ts";
import { fmtInt } from "../../lib/format.ts";
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
  return parsed.ok && parsed.value.prefix && parsed.value.literal.split("/").filter(Boolean).length <= 1;
}

export function PatternListEditor({
  kind,
  label,
  rules,
  hits,
  issues,
  onChange,
  notice = null,
  presets = [],
}: {
  kind: "entries" | "bypass";
  label: string;
  rules: string[];
  hits: Record<string, number> | undefined;
  issues: FieldIssue[];
  onChange: (rules: string[]) => void;
  notice?: string | null;
  presets?: RulePreset[];
}) {
  const [text, setText] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const groupIssues = issues.filter((issue) => issue.field === kind);

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
          return (
            <li key={rule} className={`rulerow${error ? " err" : ""}`}>
              <span className="mono path">{rule}</span>
              <span className={`hits${hits?.[rule] === 0 ? " dim" : ""}`}>{hitText(hits, rule)}</span>
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
            </li>
          );
        })}
      </ul>
      <div className="row">
        <input
          className="native-input mono"
          value={text}
          placeholder={kind === "entries" ? "添加入口，例如 /rest/admin/*" : "添加绕过，例如 /static/*"}
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
      {problem ? (
        <div className="field-error" role="alert">
          {problem}
        </div>
      ) : null}
      {notice ? <div className="field-warn">▲ {notice}</div> : null}
    </div>
  );
}
