// The quick rule dialog (docs/06 6.4.10, flows A to D): one request leads to one change of the site
// configuration. The dialog shows the candidates, the impact on the last 24 hours, and saves a new
// version; it then waits until the gateways have loaded it.

import { Link } from "@tanstack/react-router";
import { Modal, Radio } from "antd";
import { useMemo, useState } from "react";
import { ApiError } from "../../api/client.ts";
import { useEvidence, usePreview, useSaveSite, useSite } from "../../api/queries.ts";
import type { SiteSpec } from "../../api/types.ts";
import { entryCandidates, bypassCandidates } from "../../lib/quick-rules.ts";
import { fmtInt } from "../../lib/format.ts";
import { shortRequestId } from "../../lib/ids.ts";
import { errorText, IMPACT_INFO, PARAM_INFO } from "../../lib/vocab.ts";
import { validateSpec } from "../../lib/site-validate.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";

export type QuickTarget =
  | { kind: "entry"; site: string; path: string; requestId: string | null }
  | { kind: "bypass"; site: string; path: string; requestId: string | null }
  | { kind: "timeout"; site: string; requestId: string | null }
  | { kind: "call_limit"; site: string; requestId: string | null }
  | { kind: "secret"; site: string; field: string; requestId: string | null };

type Props = {
  target: QuickTarget | null;
  onClose: () => void;
};

const TITLES: Record<QuickTarget["kind"], string> = {
  entry: "登记为入口",
  bypass: "加入绕过",
  timeout: "调整 Jev 超时",
  call_limit: "调整调用上限",
  secret: "加为脱敏词",
};

function uniq(values: string[]): string[] {
  return [...new Set(values)];
}

/** Rounds up to the next 500 ms, capped at the setting's maximum. */
function roundTimeout(ms: number): number {
  return Math.min(PARAM_INFO.jev_timeout_ms.max, Math.ceil(ms / 500) * 500);
}

export function QuickRuleDialog({ target, onClose }: Props) {
  if (target === null) return <Modal open={false} onCancel={onClose} footer={null} />;
  return <QuickRuleBody key={`${target.kind}:${target.site}`} target={target} onClose={onClose} />;
}

function QuickRuleBody({ target, onClose }: { target: QuickTarget; onClose: () => void }) {
  const site = useSite(target.site);
  const evidence = useEvidence(
    target.site,
    target.kind === "timeout" || target.kind === "call_limit",
  );
  const save = useSaveSite();
  const [selected, setSelected] = useState(0);
  const [numeric, setNumeric] = useState<number | null>(null);
  const [note, setNote] = useState(
    target.requestId ? `从请求 ${shortRequestId(target.requestId)} ${TITLES[target.kind]}` : "",
  );
  const [savedVersion, setSavedVersion] = useState<number | null>(null);

  const choices = useMemo(() => {
    if (target.kind === "entry") {
      return entryCandidates(target.path).map((candidate) => ({
        label: candidate.label,
        value: candidate.rule,
        note: candidate.note,
      }));
    }
    if (target.kind === "bypass") {
      return bypassCandidates(target.path).map((candidate) => ({
        label: candidate.label,
        value: candidate.rule,
        note: candidate.note,
      }));
    }
    return [];
  }, [target]);

  const suggestion = useMemo(() => {
    const jev = evidence.data?.jev;
    if (target.kind === "timeout") {
      const base = jev?.p99_ms ?? jev?.p95_ms ?? null;
      return base === null ? null : roundTimeout(base * 1.5);
    }
    if (target.kind === "call_limit") {
      const peak = Math.max(
        evidence.data?.call_limit.session_peak ?? 0,
        evidence.data?.call_limit.address_peak ?? 0,
      );
      return peak > 0 ? Math.min(600, Math.ceil(peak * 1.2)) : null;
    }
    return null;
  }, [target.kind, evidence.data]);

  const draft: SiteSpec | null = useMemo(() => {
    const spec = site.data?.spec;
    if (!spec) return null;
    const advanced = spec.advanced ?? {};
    switch (target.kind) {
      case "entry": {
        const rule = choices[selected]?.value ?? target.path;
        return { ...spec, entries: uniq([...spec.entries, rule]) };
      }
      case "bypass": {
        const rule = choices[selected]?.value ?? target.path;
        return { ...spec, bypass: uniq([...(spec.bypass ?? []), rule]) };
      }
      case "timeout":
        return {
          ...spec,
          advanced: {
            ...advanced,
            jev_timeout_ms: numeric ?? suggestion ?? advanced.jev_timeout_ms ?? 2000,
          },
        };
      case "call_limit":
        return {
          ...spec,
          advanced: {
            ...advanced,
            session_calls_per_minute:
              numeric ?? suggestion ?? advanced.session_calls_per_minute ?? 60,
          },
        };
      case "secret":
        return {
          ...spec,
          advanced: {
            ...advanced,
            secret_fields: uniq([...(advanced.secret_fields ?? []), target.field]),
          },
        };
    }
  }, [site.data, target, choices, selected, numeric, suggestion]);

  const issues = draft ? validateSpec(draft) : { errors: [], warnings: [] };
  const preview = usePreview(target.site, issues.errors.length === 0 ? draft : null);
  const siteState = useSite(savedVersion === null ? null : target.site, {
    refetchInterval: savedVersion === null ? false : 1000,
  });
  const loaded = siteState.data?.loaded_version ?? null;
  const effective = savedVersion !== null && loaded !== null && loaded >= savedVersion;

  const change = choices.length > 0 ? (choices[selected]?.value ?? "") : "";
  const impact = preview.data?.changes ?? [];

  const confirm = () => {
    if (!draft || !site.data) return;
    save.mutate(
      {
        name: target.site,
        spec: draft,
        body: { spec: draft, expected_version: site.data.version, note: note.trim() || undefined },
      },
      { onSuccess: (saved) => setSavedVersion(saved.version) },
    );
  };

  const conflict = save.error instanceof ApiError && save.error.code === "VERSION_CONFLICT";

  return (
    <Modal
      open
      onCancel={onClose}
      title={`${TITLES[target.kind]} · ${target.site}`}
      width={680}
      footer={null}
    >
      {site.isPending ? <Loading height={160} /> : null}
      {site.isError ? <ErrorBar error={site.error} /> : null}
      {site.data && draft ? (
        <div className="stack">
          {target.kind === "entry" || target.kind === "bypass" ? (
            <>
              <div className="field-label">候选规则</div>
              <Radio.Group
                value={selected}
                onChange={(event) => setSelected(event.target.value as number)}
                style={{ display: "flex", flexDirection: "column", gap: 6 }}
                options={choices.map((choice, index) => ({
                  value: index,
                  label: (
                    <span>
                      {choice.label} <span className="mono small">{choice.value}</span>
                      {choice.note ? <span className="small dim"> · {choice.note}</span> : null}
                    </span>
                  ),
                }))}
              />
            </>
          ) : null}

          {target.kind === "timeout" || target.kind === "call_limit" ? (
            <div className="field">
              <div className="field-label">
                {target.kind === "timeout" ? "Jev 超时（ms）" : "会话调用上限（次/分钟）"}
              </div>
              <input
                className="native-input"
                type="number"
                min={
                  PARAM_INFO[
                    target.kind === "timeout" ? "jev_timeout_ms" : "session_calls_per_minute"
                  ].min
                }
                max={
                  PARAM_INFO[
                    target.kind === "timeout" ? "jev_timeout_ms" : "session_calls_per_minute"
                  ].max
                }
                value={numeric ?? suggestion ?? ""}
                onChange={(event) =>
                  setNumeric(event.target.value === "" ? null : Number(event.target.value))
                }
                aria-label="新的数值"
                style={{ maxWidth: 180 }}
              />
              <div className="field-help">
                {suggestion !== null
                  ? `建议 ${fmtInt(suggestion)}：${target.kind === "timeout" ? "最近 24 小时 p99 的 1.5 倍，向上取整到 500 ms" : "观察到的每分钟最高调用数加 20%"}。`
                  : "最近 24 小时没有足够的证据给出建议。"}
              </div>
              {target.kind === "timeout" && evidence.data ? (
                <div className="small dim">
                  最近 24 小时 p50 {fmtInt(evidence.data.jev.p50_ms ?? 0)} · p95{" "}
                  {fmtInt(evidence.data.jev.p95_ms ?? 0)} · p99{" "}
                  {fmtInt(evidence.data.jev.p99_ms ?? 0)} ms，超时{" "}
                  {fmtInt(evidence.data.jev.timeouts)} 次
                </div>
              ) : null}
            </div>
          ) : null}

          {target.kind === "secret" ? (
            <div className="notice">
              字段 <span className="mono">{target.field}</span> 之后会被脱敏。Jev
              只能看到它的长度，无法判断它是否越权。只对纯输入字段这样做。
            </div>
          ) : null}

          {target.kind === "entry" || target.kind === "bypass" ? (
            <div className="small">
              改动：{target.kind === "entry" ? "entries" : "bypass"} ＋{" "}
              <span className="mono">{change}</span>
            </div>
          ) : null}

          <div className="impact" aria-live="polite">
            <div className="small muted">
              影响（最近 24 小时，{preview.data ? `${fmtInt(preview.data.rows)} 条记录` : "计算中"}
              ）
            </div>
            {issues.errors.length > 0 ? (
              <div className="field-error">{issues.errors[0]?.message}</div>
            ) : preview.isPending ? (
              <Loading height={28} />
            ) : impact.length === 0 ? (
              <div className="small">没有会改变判定的请求。</div>
            ) : (
              impact.map((item) => (
                <div key={`${item.kind}-${item.count}`} className="impact-row">
                  <span>{IMPACT_INFO[item.kind]}</span>
                  <span className="tnum">{fmtInt(item.count)}</span>
                </div>
              ))
            )}
            {preview.data && preview.data.warnings.length > 0 ? (
              <div className="small">
                {preview.data.warnings.map((warning) => (
                  <div key={warning} className="field-warn">
                    ▲ {warning}
                  </div>
                ))}
              </div>
            ) : null}
          </div>

          {savedVersion === null ? (
            <>
              <label className="field" style={{ margin: 0 }}>
                <span className="field-label">备注（可选）</span>
                <input
                  className="native-input"
                  value={note}
                  maxLength={500}
                  onChange={(event) => setNote(event.target.value)}
                  aria-label="备注"
                />
              </label>
              {save.error ? (
                <div className="field-error" role="alert">
                  {conflict
                    ? errorText("VERSION_CONFLICT")
                    : errorText(save.error instanceof ApiError ? save.error.code : undefined)}
                  {conflict &&
                  save.error instanceof ApiError &&
                  save.error.currentVersion !== undefined
                    ? `（当前 v${save.error.currentVersion}）`
                    : ""}
                </div>
              ) : null}
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <button type="button" className="btn" onClick={onClose}>
                  取消
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  disabled={issues.errors.length > 0 || save.isPending}
                  onClick={confirm}
                >
                  {save.isPending ? "正在保存…" : `保存为 v${(site.data.version ?? 0) + 1}`}
                </button>
              </div>
            </>
          ) : (
            <div className="stack">
              <div className={effective ? "hint-ok" : "muted"} role="status">
                {effective
                  ? `● v${savedVersion} 已生效`
                  : `已保存 v${savedVersion} · 等待网关加载…`}
              </div>
              <div className="row" style={{ justifyContent: "flex-end" }}>
                <Link to="/sites/$name" params={{ name: target.site }} search={{ tab: "history" }}>
                  查看变更历史
                </Link>
                <button type="button" className="btn" onClick={onClose}>
                  关闭
                </button>
              </div>
            </div>
          )}
        </div>
      ) : null}
    </Modal>
  );
}
