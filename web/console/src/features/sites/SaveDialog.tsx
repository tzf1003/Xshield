// The save dialog (docs/06 6.4.9): what changes, the YAML diff, the impact on the last 24 hours, a note, and
// the save as a new version. On a stale version (409 VERSION_CONFLICT) it shows the newer version's changes and
// can re-apply this draft's changes on top of it; conflicting fields need an explicit choice.

import { Modal, Segmented } from "antd";
import { useEffect, useMemo, useState } from "react";
import { ApiError } from "../../api/client.ts";
import { usePreview, useSaveSite, useSite, useValidate, useVersions } from "../../api/queries.ts";
import type { SiteDetail, SiteSpec } from "../../api/types.ts";
import { canonical, semanticChanges, yamlDiff } from "../../lib/diff.ts";
import { type FieldIssue, validateSpec } from "../../lib/site-validate.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { DiffView } from "./DiffView.tsx";
import { hasNewFastAllow, ImpactView } from "./ImpactPreview.tsx";
import { type Choices, rebaseSpec, sameJson, valueText } from "./spec-model.ts";
import { requestProblem, serverProblem } from "./site-messages.ts";

type Props = {
  site: SiteDetail;
  draft: SiteSpec;
  /** The version the draft was started from; its configuration is the base of a re-apply. */
  baseVersion: number;
  /** The note the dialog opens with, e.g. `撤销自动收紧 v18` (console design 2.4). */
  initialNote?: string;
  /** The automatic change this save undoes or re-confirms; the server marks it undone (console design 6 A3). */
  objectEvent?: string;
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

export function SaveDialog({
  site,
  draft,
  baseVersion,
  initialNote,
  objectEvent,
  onClose,
  onSaved,
  onDiscard,
}: Props) {
  const save = useSaveSite();
  const validate = useValidate();
  const latest = useSite(site.name);
  const versions = useVersions(site.name);
  const [note, setNote] = useState(initialNote ?? "");
  const [view, setView] = useState<"unified" | "split">("unified");
  const [conflict, setConflict] = useState<number | null>(null);
  const [showLatest, setShowLatest] = useState(false);
  const [rebase, setRebase] = useState<Rebase | null>(null);
  const [examplesChecked, setExamplesChecked] = useState(false);

  const base =
    versions.data?.versions.find((item) => item.version === baseVersion)?.spec ?? site.spec;
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
    validate.variables !== undefined && sameJson(validate.variables, working)
      ? validate.data
      : undefined;
  const remoteProblem =
    remote && !remote.valid
      ? serverProblem(remote.error, remote.field, working, remote.reason)
      : null;
  const changes = semanticChanges(current, working);
  const unchanged = canonical(current) === canonical(working);
  const unresolved =
    rebased && rebase
      ? rebased.conflicts.filter((item) => rebase.choices[item.field] === undefined).length
      : 0;
  const conflictBlocked = conflict !== null && rebase === null;
  // Design 3.2 and 6: an enforce site that gets fast allows is saved only after the example requests were looked at.
  // While this draft's impact is still on its way (or still the previous draft's), the answer does not count yet.
  const enforce = working.mode === "enforce";
  const fastAllow = preview.data !== undefined && hasNewFastAllow(preview.data);
  const examplesWait =
    enforce && !examplesChecked && (preview.isPending || preview.isPlaceholderData || fastAllow);
  const canSave =
    localOk &&
    !unchanged &&
    remote?.valid !== false &&
    !save.isPending &&
    !conflictBlocked &&
    unresolved === 0 &&
    !examplesWait;
  const saveError =
    save.error instanceof ApiError && save.error.code === "VERSION_CONFLICT" ? null : save.error;

  const submit = () => {
    save.mutate(
      {
        name: site.name,
        spec: working,
        body: {
          spec: working,
          expected_version: expected,
          note: note.trim() || undefined,
          object_event: objectEvent,
        },
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
    setRebase((previous) =>
      previous ? { ...previous, choices: { ...previous.choices, [field]: choice } } : previous,
    );
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
              <button
                type="button"
                className="linkbtn"
                onClick={() => setShowLatest((value) => !value)}
              >
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
              <ul
                className="changes"
                aria-label={`v${theirVersion} 的改动`}
                style={{ marginTop: 8 }}
              >
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
        {localOk && enforce && fastAllow ? (
          <div className="stack-tight">
            <div className="small muted">
              拦截模式下，这些请求会直接放行，不再调用 Jev。保存前请展开上面的示例请求。
            </div>
            <label className="adv-radio">
              <input
                type="checkbox"
                checked={examplesChecked}
                onChange={(event) => setExamplesChecked(event.target.checked)}
              />
              我已查看示例请求
            </label>
          </div>
        ) : null}

        <div aria-live="polite" className="small">
          {validate.isPending && remote === undefined ? (
            <span className="muted">正在校验…</span>
          ) : null}
          {remoteProblem ? (
            <span className="field-error" role="alert">
              {remoteProblem}
            </span>
          ) : null}
          {remote?.valid === true ? <span>✓ 服务端校验通过</span> : null}
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
            {requestProblem(saveError, working)}
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
