// The save dialog (docs/06 6.4.9): what changes, the YAML diff, the impact on the last 24 hours, a note, and
// the save as a new version. On a stale version (409 VERSION_CONFLICT) it shows the newer version's changes and
// can re-apply this draft's changes on top of it; conflicting fields need an explicit choice.

import { Modal, Segmented } from "antd";
import { useEffect, useMemo, useState } from "react";
import { ApiError } from "../../api/client.ts";
import { usePreview, useSaveSite, useSite, useValidate, useVersions } from "../../api/queries.ts";
import type { SiteDetail, SiteSpec } from "../../api/types.ts";
import { canonical, semanticChanges, yamlDiff } from "../../lib/diff.ts";
import { errorText } from "../../lib/vocab.ts";
import { type FieldIssue, validateSpec } from "../../lib/site-validate.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { DiffView } from "./DiffView.tsx";
import { ImpactView } from "./ImpactPreview.tsx";
import { type Choices, rebaseSpec, sameJson, valueText } from "./spec-model.ts";

type Props = {
  site: SiteDetail;
  draft: SiteSpec;
  /** The version the draft was started from; its configuration is the base of a re-apply. */
  baseVersion: number;
  onClose: () => void;
  onSaved: (spec: SiteSpec, version: number) => void;
  onDiscard: () => void;
};

type Rebase = {
  base: SiteSpec;
  mine: SiteSpec;
  latest: SiteSpec;
  latestVersion: number;
  choices: Choices;
};

/** The server's message for a refused configuration; a host clash names the host (docs/06 6.6.5). */
function serverProblem(code: string, field: string | undefined, spec: SiteSpec): string {
  if (code === "SITE_HOST_TAKEN" && field) {
    const index = /^hosts\[(\d+)\]$/.exec(field)?.[1];
    const host = index === undefined ? field : spec.hosts[Number(index)];
    return `Host ${host ?? field} 已属于其他站点`;
  }
  return errorText(code);
}

export function SaveDialog({ site, draft, baseVersion, onClose, onSaved, onDiscard }: Props) {
  const save = useSaveSite();
  const validate = useValidate();
  const latest = useSite(site.name);
  const versions = useVersions(site.name);
  const [note, setNote] = useState("");
  const [view, setView] = useState<"unified" | "split">("unified");
  const [conflict, setConflict] = useState<number | null>(null);
  const [showLatest, setShowLatest] = useState(false);
  const [rebase, setRebase] = useState<Rebase | null>(null);

  const base = versions.data?.versions.find((item) => item.version === baseVersion)?.spec ?? site.spec;
  const rebased = useMemo(
    () => (rebase ? rebaseSpec(rebase.base, rebase.mine, rebase.latest, rebase.choices) : null),
    [rebase],
  );
  const working: SiteSpec = rebased ? rebased.spec : draft;
  const current: SiteSpec = rebase ? rebase.latest : site.spec;
  const expected = rebase ? rebase.latestVersion : site.version;
  const issues = validateSpec(working);
  const localOk = issues.errors.length === 0;
  const preview = usePreview(site.name, localOk ? working : null);

  const validateRemote = validate.mutate;
  useEffect(() => {
    if (localOk) validateRemote(working);
  }, [localOk, validateRemote, working]);

  const remote =
    validate.variables !== undefined && sameJson(validate.variables, working) ? validate.data : undefined;
  const remoteProblem =
    remote && !remote.valid ? serverProblem(remote.error, remote.field, working) : null;
  const changes = semanticChanges(current, working);
  const unchanged = canonical(current) === canonical(working);
  const unresolved = rebased && rebase ? rebased.conflicts.filter((item) => rebase.choices[item.field] === undefined).length : 0;
  const conflictBlocked = conflict !== null && rebase === null;
  const canSave =
    localOk &&
    !unchanged &&
    remote?.valid !== false &&
    !save.isPending &&
    !conflictBlocked &&
    unresolved === 0;
  const saveError = save.error instanceof ApiError && save.error.code === "VERSION_CONFLICT" ? null : save.error;

  const submit = () => {
    save.mutate(
      {
        name: site.name,
        spec: working,
        body: { spec: working, expected_version: expected, note: note.trim() || undefined },
      },
      {
        onSuccess: (saved) => onSaved(working, saved.version),
        onError: (error) => {
          if (error instanceof ApiError && error.code === "VERSION_CONFLICT") {
            setConflict(error.currentVersion ?? latest.data?.version ?? site.version + 1);
            void latest.refetch();
          }
        },
      },
    );
  };

  const startRebase = () => {
    const newer = latest.data;
    if (!newer || conflict === null) return;
    setRebase({
      base: base ?? site.spec,
      mine: draft,
      latest: newer.spec,
      latestVersion: newer.version,
      choices: {},
    });
  };

  const choose = (field: string, choice: "mine" | "theirs") => {
    setRebase((previous) => (previous ? { ...previous, choices: { ...previous.choices, [field]: choice } } : previous));
  };

  const latestChanges = latest.data ? semanticChanges(base, latest.data.spec) : [];
  const theirVersion = conflict ?? site.version;

  return (
    <Modal open onCancel={onClose} title={`保存 ${site.name} 的配置`} width={760} footer={null}>
      <div className="stack">
        {conflict !== null && rebase === null ? (
          <div className="notice bad" role="alert">
            <div>
              配置已被修改（当前 v{theirVersion}）。你的改动基于 v{baseVersion}，保存前需要先处理。
            </div>
            <div className="row" style={{ marginTop: 8 }}>
              <button type="button" className="linkbtn" onClick={() => setShowLatest((value) => !value)}>
                查看 v{theirVersion} 的改动
              </button>
              <button type="button" className="btn" disabled={!latest.data} onClick={startRebase}>
                在 v{theirVersion} 基础上重新应用我的改动
              </button>
              <button type="button" className="linkbtn" onClick={onDiscard}>
                放弃我的改动，载入 v{theirVersion}
              </button>
            </div>
            {showLatest ? (
              <ul className="changes" aria-label={`v${theirVersion} 的改动`} style={{ marginTop: 8 }}>
                {latestChanges.length === 0 ? <li>没有可以列出的改动。</li> : null}
                {latestChanges.map((change) => (
                  <li key={change}>· {change}</li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}

        {rebase !== null && rebased ? (
          <div className="stack-tight">
            <div className="small muted">
              已在 v{rebase.latestVersion} 的基础上重新应用你的改动。
              {rebased.conflicts.length > 0
                ? `下面 ${rebased.conflicts.length} 项两边都改过了，请选择保留哪一个。`
                : "没有冲突。"}
            </div>
            {rebased.conflicts.map((item) => (
              <fieldset key={item.field} className="conflict">
                <legend className="field-label">{item.label}</legend>
                <label className="adv-radio">
                  <input
                    type="radio"
                    name={`conflict-${item.field}`}
                    checked={rebase.choices[item.field] === "mine"}
                    onChange={() => choose(item.field, "mine")}
                  />
                  保留我的：{valueText(item.field, item.mine)}
                </label>
                <label className="adv-radio">
                  <input
                    type="radio"
                    name={`conflict-${item.field}`}
                    checked={rebase.choices[item.field] === "theirs"}
                    onChange={() => choose(item.field, "theirs")}
                  />
                  采用 v{rebase.latestVersion}：{valueText(item.field, item.theirs)}
                </label>
              </fieldset>
            ))}
          </div>
        ) : null}

        <div>
          <div className="field-label">改动</div>
          {unchanged ? (
            <div className="small muted">没有需要保存的改动。</div>
          ) : (
            <ul className="changes" aria-label="改动摘要">
              {changes.map((change) => (
                <li key={change}>· {change}</li>
              ))}
            </ul>
          )}
        </div>

        {issues.errors.length > 0 ? (
          <div>
            {issues.errors.map((item: FieldIssue) => (
              <div key={`${item.field}-${item.message}`} className="field-error" role="alert">
                {item.message}
              </div>
            ))}
          </div>
        ) : null}
        {issues.warnings.map((item) => (
          <div key={`${item.field}-${item.message}`} className="field-warn">
            ▲ {item.message}
          </div>
        ))}

        <details open className="diff-box">
          <summary className="small">差异（YAML 逐行）</summary>
          <div className="row" style={{ margin: "8px 0" }}>
            <Segmented
              value={view}
              options={[
                { label: "合并", value: "unified" },
                { label: "并排", value: "split" },
              ]}
              onChange={(value) => setView(value === "split" ? "split" : "unified")}
            />
          </div>
          <DiffView ops={yamlDiff(current, working)} mode={view} />
        </details>

        {localOk ? (
          preview.isPending ? (
            <Loading height={56} />
          ) : preview.isError ? (
            <ErrorBar error={preview.error} onRetry={() => void preview.refetch()} />
          ) : preview.data ? (
            <ImpactView preview={preview.data} />
          ) : null
        ) : null}

        <div aria-live="polite" className="small">
          {validate.isPending && remote === undefined ? <span className="muted">正在校验…</span> : null}
          {remoteProblem ? (
            <span className="field-error" role="alert">
              {remoteProblem}
            </span>
          ) : null}
          {remote?.valid === true ? <span className="hint-ok">服务端校验通过</span> : null}
        </div>

        <label className="field" style={{ margin: 0 }}>
          <span className="field-label">备注（可选，最多 500 字）</span>
          <input
            className="native-input"
            value={note}
            maxLength={500}
            onChange={(event) => setNote(event.target.value)}
          />
        </label>

        {saveError ? (
          <div className="errbar" role="alert">
            {errorText(saveError instanceof ApiError ? saveError.code : undefined)}
          </div>
        ) : null}

        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>
            取消
          </button>
          <button type="button" className="btn-primary" disabled={!canSave} onClick={submit}>
            {save.isPending ? "正在保存…" : `保存为 v${expected + 1}`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
