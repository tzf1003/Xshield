// Rolling back to an earlier version (docs/06 6.4.9 history, flow E): the difference from the current
// configuration, the impact of the old one on the last 24 hours, and a note. It saves a new version whose
// content is the target's, so the history keeps every step.

import { useQueryClient } from "@tanstack/react-query";
import { Modal } from "antd";
import { useState } from "react";
import { keys, usePreview, useRollback } from "../../api/queries.ts";
import type { SiteDetail, SiteVersion } from "../../api/types.ts";
import { canonical, semanticChanges, yamlDiff } from "../../lib/diff.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { DiffView } from "./DiffView.tsx";
import { ImpactView } from "./ImpactPreview.tsx";
import { requestProblem } from "./site-messages.ts";

/**
 * The version a rollback goes back to. An undo of an automatic change carries that change as `undoes`, and its
 * note is the reason the dialog starts from. The history builds it; the page passes it on unchanged.
 */
export type RollbackTarget = SiteVersion & { undoes?: SiteVersion };

type Props = {
  site: SiteDetail;
  target: RollbackTarget;
  /** Unsaved draft changes: the rollback works on the saved configuration, so it waits for them. */
  dirty: boolean;
  onClose: () => void;
  onDone: (version: number) => void;
};

export function RollbackDialog({ site, target, dirty, onClose, onDone }: Props) {
  const rollback = useRollback();
  const client = useQueryClient();
  const targetSpec = target.spec;
  const preview = usePreview(site.name, targetSpec);
  const [note, setNote] = useState(() => target.undoes?.note ?? "");

  const unchanged = targetSpec !== null && canonical(targetSpec) === canonical(site.spec);
  const ready = targetSpec !== null && !dirty && !rollback.isPending;
  const changes = targetSpec === null ? [] : semanticChanges(site.spec, targetSpec);

  const submit = () => {
    if (targetSpec === null) return;
    rollback.mutate(
      {
        name: site.name,
        toVersion: target.version,
        expectedVersion: site.version,
        note: note.trim() || undefined,
      },
      {
        onSuccess: (saved) => onDone(saved.version),
        // A stale version (409) or a refused target: the current version is read again for the next try.
        onError: () => void client.invalidateQueries({ queryKey: keys.site(site.name) }),
      },
    );
  };

  return (
    <Modal
      open
      onCancel={onClose}
      title={`回滚 ${site.name} 到 v${target.version}`}
      width={760}
      footer={null}
    >
      <div className="stack">
        {dirty ? (
          <div className="notice" role="alert">
            有未保存的改动。请先在配置页保存或放弃，再回滚。
          </div>
        ) : null}
        {targetSpec === null ? (
          <div className="notice bad" role="alert">
            v{target.version} 是删除操作，不能回滚到它。
          </div>
        ) : null}
        {unchanged ? (
          <div className="small muted">
            v{target.version} 的内容与当前版本相同，回滚只会生成一个内容相同的新版本。
          </div>
        ) : null}
        {target.undoes ? (
          <div className="small muted">
            撤销 v{target.undoes.version} 的自动改动：回到 v{target.version} 的内容。备注已填入 v
            {target.undoes.version} 的原因，可以改。
          </div>
        ) : null}

        <div>
          <div className="field-label">
            改动（v{site.version} → v{target.version}）
          </div>
          {changes.length === 0 ? (
            <div className="small muted">没有可以列出的改动。</div>
          ) : (
            <ul className="changes" aria-label="改动摘要">
              {changes.map((change) => (
                <li key={change}>· {change}</li>
              ))}
            </ul>
          )}
        </div>

        {targetSpec !== null ? (
          <details open className="diff-box">
            <summary className="small">差异（YAML 逐行）</summary>
            <DiffView ops={yamlDiff(site.spec, targetSpec)} mode="unified" />
          </details>
        ) : null}

        {targetSpec !== null ? (
          <div>
            <div className="field-label">影响（最近 24 小时）</div>
            {preview.isPending ? (
              <Loading height={56} />
            ) : preview.isError ? (
              <ErrorBar error={preview.error} onRetry={() => void preview.refetch()} />
            ) : preview.data ? (
              <ImpactView preview={preview.data} />
            ) : null}
          </div>
        ) : null}

        <label className="field" style={{ margin: 0 }}>
          <span className="field-label">备注（可选，最多 500 字）</span>
          <input
            className="native-input"
            value={note}
            maxLength={500}
            onChange={(event) => setNote(event.target.value)}
          />
        </label>

        {rollback.isError ? (
          <div className="errbar" role="alert">
            {requestProblem(rollback.error, site.spec)}
          </div>
        ) : null}

        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>
            取消
          </button>
          <button type="button" className="btn-primary" disabled={!ready} onClick={submit}>
            {rollback.isPending
              ? "正在回滚…"
              : `回滚，生成 v${site.version + 1}（内容同 v${target.version}）`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
