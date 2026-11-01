// Switching a site between observe and enforce (docs/06 6.4.10 flow D): the readiness checklist and the impact of
// the switch on the last 24 hours. Switching to enforce asks for a confirmation while requests would have been
// blocked; the checklist states facts and sets no threshold. Either direction saves a new version of the saved
// configuration, so it waits while the draft has unsaved changes.

import { Modal } from "antd";
import { useState } from "react";
import { useInsights, usePreview, useSaveSite } from "../../api/queries.ts";
import type { SiteDetail, SiteMode, SiteSpec } from "../../api/types.ts";
import { useNowBucket } from "../../app/scope.ts";
import { fmtInt } from "../../lib/format.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { ImpactView } from "./ImpactPreview.tsx";
import { ReadinessList } from "./Readiness.tsx";
import { requestProblem } from "./site-messages.ts";

type Props = {
  site: SiteDetail;
  /** Unsaved draft changes: the switch works on the saved configuration, so it waits for them. */
  dirty: boolean;
  onClose: () => void;
  onSaved: (version: number) => void;
};

export function ModeSwitchDialog({ site, dirty, onClose, onSaved }: Props) {
  const target: SiteMode = site.mode === "enforce" ? "observe" : "enforce";
  const toEnforce = target === "enforce";
  const next: SiteSpec = { ...site.spec, mode: target };
  const insights = useInsights(site.name);
  const preview = usePreview(site.name, next);
  const save = useSaveSite();
  const now = useNowBucket();
  const [confirmed, setConfirmed] = useState(false);

  const readiness = insights.data?.readiness ?? null;
  const wouldBlock = readiness
    ? Object.values(readiness.would_block).reduce((sum, count) => sum + (count ?? 0), 0)
    : 0;
  const needsConfirm = toEnforce && wouldBlock > 0;
  const ready = !dirty && (!needsConfirm || confirmed) && !save.isPending;
  const title = toEnforce ? `把 ${site.name} 切换到拦截模式` : `把 ${site.name} 切回观察模式`;
  const action = toEnforce ? "切换到拦截模式" : "切回观察模式";

  const submit = () => {
    save.mutate(
      {
        name: site.name,
        spec: next,
        body: {
          spec: next,
          expected_version: site.version,
          note: toEnforce ? "切换到拦截模式" : "切回观察模式",
        },
      },
      { onSuccess: (saved) => onSaved(saved.version) },
    );
  };

  return (
    <Modal open onCancel={onClose} title={title} width={680} footer={null}>
      <div className="stack">
        {dirty ? (
          <div className="notice" role="alert">
            有未保存的改动。请先在配置页保存或放弃，再切换模式。
          </div>
        ) : null}

        {toEnforce ? (
          <div>
            <div className="field-label">
              就绪检查（最近 {fmtInt(insights.data?.window_hours ?? 24)} 小时）
            </div>
            {insights.isPending ? (
              <Loading height={120} />
            ) : insights.isError ? (
              <ErrorBar error={insights.error} onRetry={() => void insights.refetch()} />
            ) : (
              <ReadinessList readiness={readiness} now={now} />
            )}
          </div>
        ) : (
          <div className="small">切回观察后不再拦截任何请求，只记录本应拦截。</div>
        )}

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

        {needsConfirm ? (
          <label className="adv-radio">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(event) => setConfirmed(event.target.checked)}
            />
            我已查看这些请求，确认它们应当被拦截
          </label>
        ) : null}

        {save.isError ? (
          <div className="errbar" role="alert">
            {requestProblem(save.error, next)}
          </div>
        ) : null}

        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button type="button" className="btn" onClick={onClose}>
            取消
          </button>
          <button type="button" className="btn-primary" disabled={!ready} onClick={submit}>
            {save.isPending ? "正在保存…" : `${action}（生成 v${site.version + 1}）`}
          </button>
        </div>
      </div>
    </Modal>
  );
}
