// The advanced judging parameters of a site (docs/06 6.4.9, docs/07 7.6): each one with its default, the value
// the site uses, the last 24 hours of evidence, the effect of a change, and a suggestion to adopt. Evidence is
// requested only while this group is open (the group mounts only then).

import { useState, type ReactNode } from "react";
import type { Advanced, ImpactChange, SiteSpec } from "../../api/types.ts";
import { useEvidence, useInsights, useSystem } from "../../api/queries.ts";
import { fmtInt, fmtMs } from "../../lib/format.ts";
import type { FieldIssue } from "../../lib/site-validate.ts";
import { IMPACT_INFO, OBJECT_TEXT, PARAM_INFO } from "../../lib/vocab.ts";
import { Histogram } from "../../ui/Charts.tsx";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { SynonymMigrateDialog } from "./objects/SynonymMigrateDialog.tsx";
import { TagInput } from "./TagInput.tsx";
import {
  customAdvanced,
  NUMERIC_ADVANCED,
  type NumericAdvanced,
  withAdvanced,
} from "./spec-model.ts";

type Props = {
  name: string;
  spec: SiteSpec;
  onChange: (next: SiteSpec) => void;
  issues: FieldIssue[];
  warnings: FieldIssue[];
  impact: ImpactChange[];
};

const BUILTIN_SYNONYMS: Array<[string, string]> = [["payment", "card"]];
const SECRET_WORD = /^[a-z0-9_-]{3,32}$/;

/** Drops unset values; an empty advanced block is removed altogether. */
function prune(value: Advanced): Advanced | undefined {
  const out: Advanced = {};
  for (const key of NUMERIC_ADVANCED) {
    const item = value[key];
    if (item !== undefined) out[key] = item;
  }
  if (value.secret_fields && value.secret_fields.length > 0)
    out.secret_fields = value.secret_fields;
  if (value.synonyms && value.synonyms.length > 0) out.synonyms = value.synonyms;
  return Object.keys(out).length > 0 ? out : undefined;
}

let rowSeq = 0;
type PairRow = { id: number; a: string; b: string };
function newRow(a: string, b: string): PairRow {
  rowSeq += 1;
  return { id: rowSeq, a, b };
}

function NumericItem({
  field,
  defaultValue,
  value,
  onCommit,
  problems,
  suggestion,
  children,
}: {
  field: NumericAdvanced;
  defaultValue: number | undefined;
  value: number | undefined;
  onCommit: (next: number | undefined) => void;
  problems: string[];
  suggestion: number | null;
  children?: ReactNode;
}) {
  const info = PARAM_INFO[field];
  const [text, setText] = useState(value === undefined ? "" : String(value));
  const [local, setLocal] = useState<string | null>(null);
  const [seen, setSeen] = useState(value);
  const [helpOpen, setHelpOpen] = useState(false);
  // A value changed from outside (a suggestion adopted, a reset) replaces what the box shows.
  if (seen !== value) {
    setSeen(value);
    setText(value === undefined ? "" : String(value));
    setLocal(null);
  }
  const rangeText = `${info.label}需在 ${info.min}–${info.max} ${info.unit} 之间`;
  const edit = (raw: string) => {
    setText(raw);
    const number = Number(raw);
    if (raw.trim() === "" || !Number.isInteger(number) || number < info.min || number > info.max) {
      setLocal(rangeText);
      return;
    }
    setLocal(null);
    onCommit(number);
  };
  const groupName = `adv-${field}`;
  const message = local ?? problems[0] ?? null;
  return (
    <section className="adv-item" aria-label={info.label}>
      <div className="adv-head">
        <span className="adv-name">{info.label}</span>
        <span className="adv-choice" role="radiogroup" aria-label={`${info.label}的取值`}>
          <label className="adv-radio">
            <input
              type="radio"
              name={groupName}
              checked={value === undefined}
              onChange={() => onCommit(undefined)}
            />
            默认 {fmtInt(defaultValue ?? 0)} {info.unit}（部署设置）
          </label>
          <label className="adv-radio">
            <input
              type="radio"
              name={groupName}
              checked={value !== undefined}
              onChange={() => onCommit(value ?? defaultValue ?? info.min)}
            />
            自定义
          </label>
        </span>
        {value !== undefined ? (
          <input
            type="number"
            className="native-input adv-input tnum"
            min={info.min}
            max={info.max}
            value={text}
            aria-label={`${info.label}（${info.unit}）`}
            aria-invalid={message ? true : undefined}
            onChange={(event) => edit(event.target.value)}
          />
        ) : null}
        <span className="small dim">
          {info.min}–{info.max} {info.unit}
        </span>
        <button
          type="button"
          className="iconbtn"
          aria-expanded={helpOpen}
          aria-label={`${info.label}：调整的代价`}
          onClick={() => setHelpOpen((open) => !open)}
        >
          ?
        </button>
      </div>
      {helpOpen ? <div className="adv-help small">{info.cost}</div> : null}
      {children}
      {suggestion !== null ? (
        <div className="row small">
          <span>
            建议 {fmtInt(suggestion)} {info.unit}
          </span>
          <button type="button" className="linkbtn" onClick={() => onCommit(suggestion)}>
            采用
          </button>
        </div>
      ) : null}
      {message ? (
        <div className="field-error" role="alert">
          {message}
        </div>
      ) : null}
    </section>
  );
}

function SynonymsItem({
  pairs,
  builtins,
  problems,
  onCommit,
  onMigrate,
}: {
  pairs: Array<[string, string]>;
  builtins: Array<[string, string]>;
  problems: string[];
  onCommit: (pairs: Array<[string, string]>) => void;
  onMigrate: () => void;
}) {
  const [rows, setRows] = useState<PairRow[]>(() => pairs.map(([a, b]) => newRow(a, b)));
  const update = (next: PairRow[]) => {
    setRows(next);
    onCommit(next.map((row) => [row.a, row.b]));
  };
  return (
    <section className="adv-item" aria-label={PARAM_INFO.synonyms.label}>
      <div className="adv-head">
        <span className="adv-name">同义词</span>
        {pairs.length > 0 ? (
          <button type="button" className="linkbtn" onClick={onMigrate}>
            {OBJECT_TEXT.fromSynonyms}
          </button>
        ) : null}
      </div>
      <div className="small muted">内置</div>
      <div className="taglist">
        {builtins.map(([a, b]) => (
          <span
            key={`${a}|${b}`}
            className="tag-chip builtin builtin-chip"
            title="内置词，不能删除"
          >
            {a} ↔ {b}
          </span>
        ))}
      </div>
      <div className="small muted" style={{ marginTop: 8 }}>
        本站点
      </div>
      <div className="stack-tight">
        {rows.map((row) => (
          <div key={row.id} className="syn-row">
            <input
              className="native-input mono"
              aria-label="第一个词"
              value={row.a}
              onChange={(event) =>
                update(
                  rows.map((item) =>
                    item.id === row.id ? { ...item, a: event.target.value } : item,
                  ),
                )
              }
            />
            <span aria-hidden="true">↔</span>
            <input
              className="native-input mono"
              aria-label="第二个词"
              value={row.b}
              onChange={(event) =>
                update(
                  rows.map((item) =>
                    item.id === row.id ? { ...item, b: event.target.value } : item,
                  ),
                )
              }
            />
            <button
              type="button"
              className="iconbtn"
              aria-label="删除这组同义词"
              onClick={() => update(rows.filter((item) => item.id !== row.id))}
            >
              ×
            </button>
          </div>
        ))}
        <div>
          <button type="button" className="btn" onClick={() => update([...rows, newRow("", "")])}>
            ＋ 添加一组
          </button>
        </div>
      </div>
      <div className="adv-help small">
        按词根比较，结尾的 s 会被忽略。例：字段 paymentId 的值来自 /api/Cards，就是 payment ↔ card。
      </div>
      <div className="field-warn">
        ▲ 同义词改变核验结果，无法从历史记录预估影响，保存后请观察一段时间
      </div>
      {problems.map((message) => (
        <div key={message} className="field-error" role="alert">
          {message}
        </div>
      ))}
    </section>
  );
}

function changeOf(impact: ImpactChange[], kind: ImpactChange["kind"]): ImpactChange | undefined {
  return impact.find((item) => item.kind === kind);
}

/** The first field names a secret-word change touches, as the server lists them. */
function fieldNames(change: ImpactChange): string[] {
  const fields = change.detail?.fields;
  if (!Array.isArray(fields)) return [];
  return fields.slice(0, 10).map((item) => (Array.isArray(item) ? String(item[0]) : String(item)));
}

/** The effect of a new Jev timeout, read against the timeout it replaces (docs/06 6.4.9). */
function timeoutSentence(change: ImpactChange, next: number, before: number): string {
  const count = fmtInt(change.count);
  return next < before
    ? `改为 ${fmtInt(next)} ms：过去 24 小时有 ${count} 次调用会超时`
    : `改为 ${fmtInt(next)} ms：过去 24 小时有 ${count} 次超时的调用可能不再超时`;
}

export function AdvancedParams({ name, spec, onChange, issues, warnings, impact }: Props) {
  const system = useSystem();
  const evidence = useEvidence(name, true);
  const insights = useInsights(name);
  const [epoch, setEpoch] = useState(0);
  const [migrateOpen, setMigrateOpen] = useState(false);
  const defaults = system.data?.params.site_overridable;
  const advanced = spec.advanced;
  const labels = customAdvanced(advanced);
  const issueFor = (field: string) =>
    issues.filter((issue) => issue.field === field).map((issue) => issue.message);
  const warnFor = (field: string) =>
    warnings.filter((warning) => warning.field === field).map((warning) => warning.message);

  const commit = (patch: Advanced) => {
    onChange(withAdvanced(spec, prune({ ...(advanced ?? {}), ...patch })));
  };

  const suggestions = insights.data?.suggestions ?? [];
  const timeoutSuggestion =
    suggestions.find((item) => item.kind === "raise_jev_timeout")?.actions[0]?.set_advanced
      ?.jev_timeout_ms ?? null;
  const limitAction = suggestions.find((item) => item.kind === "raise_call_limit")?.actions[0]
    ?.set_advanced;
  const ev = evidence.data;
  const timeoutChange = changeOf(impact, "jev_timeout");
  const limitChange = changeOf(impact, "call_limit");
  const cacheChange = changeOf(impact, "cache");
  const secretChange = changeOf(impact, "secret_fields");

  const evidenceBlock = (
    <>
      {evidence.isPending ? <Loading height={28} /> : null}
      {evidence.isError ? (
        <ErrorBar error={evidence.error} onRetry={() => void evidence.refetch()} />
      ) : null}
    </>
  );

  return (
    <div className="stack">
      {/* The evidence of each parameter below comes from the evidence endpoint, read only while this group is open. */}
      <h2 className="adv-title">Jev 证据</h2>
      <div className="row between adv-summary">
        <span>
          {labels.length === 0
            ? "全部使用默认值"
            : `已自定义 ${labels.length} 项：${labels.join("、")}`}
        </span>
        {labels.length > 0 ? (
          <button
            type="button"
            className="linkbtn"
            onClick={() => {
              setEpoch((value) => value + 1);
              onChange(withAdvanced(spec, undefined));
            }}
          >
            全部恢复默认
          </button>
        ) : null}
      </div>

      <NumericItem
        field="jev_timeout_ms"
        defaultValue={defaults?.jev_timeout_ms}
        value={advanced?.jev_timeout_ms}
        problems={issueFor("jev_timeout_ms")}
        suggestion={timeoutSuggestion}
        onCommit={(value) => commit({ jev_timeout_ms: value })}
      >
        {evidenceBlock}
        {ev ? (
          <div className="small dim">
            {ev.jev.calls === 0
              ? "最近 24 小时没有 Jev 调用"
              : `最近 24 小时 p50 ${fmtMs(ev.jev.p50_ms)} · p95 ${fmtMs(ev.jev.p95_ms)} · p99 ${fmtMs(ev.jev.p99_ms)} · 超时 ${fmtInt(ev.jev.timeouts)} 次 / ${fmtInt(ev.jev.calls)} 次`}
          </div>
        ) : null}
        {ev && ev.histogram.length > 0 && ev.histogram_bucket_ms > 0 ? (
          <div className="adv-chart">
            <Histogram
              counts={ev.histogram}
              labelAt={(index) => `${fmtInt(index * ev.histogram_bucket_ms)} ms`}
              label="Jev 耗时分布，最近 24 小时"
              height={96}
              threshold={{
                index: Math.min(
                  ev.histogram.length - 1,
                  Math.floor(
                    (advanced?.jev_timeout_ms ?? defaults?.jev_timeout_ms ?? 0) /
                      ev.histogram_bucket_ms,
                  ),
                ),
                text: `本站点 ${fmtInt(advanced?.jev_timeout_ms ?? defaults?.jev_timeout_ms ?? 0)} ms`,
              }}
            />
            <details className="small">
              <summary>以表格查看</summary>
              <table className="tbl">
                <thead>
                  <tr>
                    <th scope="col">耗时</th>
                    <th scope="col" className="num">
                      调用次数
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {ev.histogram.map((count, index) => {
                    // The start of each bucket is unique, so it serves as the row key.
                    const from = index * ev.histogram_bucket_ms;
                    return (
                      <tr key={from}>
                        <td className="mono">{`${fmtInt(from)} ms`}</td>
                        <td className="num tnum">{fmtInt(count)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </details>
          </div>
        ) : null}
        {timeoutChange && advanced?.jev_timeout_ms !== undefined ? (
          <div className="impact-line small">
            {timeoutSentence(
              timeoutChange,
              advanced.jev_timeout_ms,
              typeof timeoutChange.detail?.old_ms === "number"
                ? timeoutChange.detail.old_ms
                : (defaults?.jev_timeout_ms ?? 0),
            )}
          </div>
        ) : null}
      </NumericItem>

      <NumericItem
        field="session_calls_per_minute"
        defaultValue={defaults?.session_calls_per_minute}
        value={advanced?.session_calls_per_minute}
        problems={issueFor("session_calls_per_minute")}
        suggestion={limitAction?.session_calls_per_minute ?? null}
        onCommit={(value) => commit({ session_calls_per_minute: value })}
      >
        {ev ? (
          <div className="small dim">
            最近 24 小时最高 1 分钟 {fmtInt(ev.call_limit.session_peak)} 次 · 触发上限{" "}
            {fmtInt(ev.call_limit.session_hits)} 次
          </div>
        ) : (
          evidenceBlock
        )}
        {limitChange && advanced?.session_calls_per_minute !== undefined ? (
          <div className="impact-line small">
            {IMPACT_INFO.call_limit}：{fmtInt(limitChange.count)} 次
          </div>
        ) : null}
      </NumericItem>

      <NumericItem
        field="address_calls_per_minute"
        defaultValue={defaults?.address_calls_per_minute}
        value={advanced?.address_calls_per_minute}
        problems={issueFor("address_calls_per_minute")}
        suggestion={limitAction?.address_calls_per_minute ?? null}
        onCommit={(value) => commit({ address_calls_per_minute: value })}
      >
        {ev ? (
          <div className="small dim">
            最近 24 小时最高 1 分钟 {fmtInt(ev.call_limit.address_peak)} 次 · 触发上限{" "}
            {fmtInt(ev.call_limit.address_hits)} 次{ev.call_limit.address_hits > 0 ? " ▲" : ""}
          </div>
        ) : (
          evidenceBlock
        )}
        <div className="adv-help small">
          NAT
          或代理后多个用户共用一个地址时需要调大。触发过上限时先看是不是未登录页面在轮询；那种情况登记入口或绕过通常更合适。
        </div>
      </NumericItem>

      <NumericItem
        field="allow_cache_minutes"
        defaultValue={defaults?.allow_cache_minutes}
        value={advanced?.allow_cache_minutes}
        problems={issueFor("allow_cache_minutes")}
        suggestion={null}
        onCommit={(value) => commit({ allow_cache_minutes: value })}
      >
        {ev ? (
          <div className="small dim">缓存放行 {fmtInt(ev.cache.cached_allows)} 次</div>
        ) : (
          evidenceBlock
        )}
        {advanced?.allow_cache_minutes === 0 ? (
          <div className="field-warn">▲ 0 时每个未核验的请求都会调用 Jev</div>
        ) : null}
        {cacheChange ? (
          <div className="impact-line small">
            {IMPACT_INFO.cache}：{fmtInt(cacheChange.count)} 次
          </div>
        ) : null}
      </NumericItem>

      <section className="adv-item" aria-label={PARAM_INFO.secret_fields.label}>
        <div className="adv-head">
          <span className="adv-name">追加脱敏词</span>
        </div>
        <div className="adv-help small">
          命中的值发给 Jev 和写日志时都写成 &lt;redacted&gt;。被脱敏的值 Jev
          只看到长度，只加纯输入字段（身份证号、银行卡号），不要加对象引用字段。
        </div>
        <TagInput
          id="site-field-secret"
          label="脱敏词"
          values={advanced?.secret_fields ?? []}
          locked={defaults?.secret_fields ?? []}
          lockedLabel="内置"
          lockedTitle="内置词，不能删除"
          ownLabel="本站点"
          max={32}
          placeholder="例如 idcard，按 Enter 添加"
          check={(word) => {
            if (!SECRET_WORD.test(word)) return "3–32 个字符，小写字母、数字、_ 或 -";
            if ((defaults?.secret_fields ?? []).includes(word))
              return "这是内置词，已经在脱敏范围内";
            return null;
          }}
          onChange={(words) => commit({ secret_fields: words })}
          error={issueFor("secret_fields")[0] ?? null}
        />
        {warnFor("secret_fields").map((message) => (
          <div key={message} className="field-warn">
            ▲ {message}
          </div>
        ))}
        {secretChange ? (
          <div className="impact-line small">
            过去 24 小时有 {fmtInt(secretChange.count)} 次 Jev 调用会有值被脱敏
            {fieldNames(secretChange).length > 0
              ? `，涉及字段 ${fieldNames(secretChange).join("、")}`
              : ""}
          </div>
        ) : null}
      </section>

      <SynonymsItem
        key={epoch}
        pairs={advanced?.synonyms ?? []}
        builtins={defaults?.synonyms ?? BUILTIN_SYNONYMS}
        problems={issueFor("synonyms")}
        onCommit={(pairs) => commit({ synonyms: pairs })}
        onMigrate={() => setMigrateOpen(true)}
      />

      {migrateOpen ? (
        <SynonymMigrateDialog
          site={name}
          working={spec}
          onClose={() => setMigrateOpen(false)}
          onApply={(next) => {
            // The groups are gone from the draft: the synonym rows remount to read the new list.
            onChange(next);
            setEpoch((value) => value + 1);
            setMigrateOpen(false);
          }}
        />
      ) : null}
    </div>
  );
}
