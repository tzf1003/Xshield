import { Button, Skeleton } from "antd";
import { useState } from "react";
import type { SiteRevision } from "../../../../api.ts";
import { standing } from "../../../../sites/outcome.ts";
import { IdChip } from "../../../../ui/IdChip";
import { reasonText } from "../../../../ui/reason-codes.ts";
import { StatePill } from "../../../../ui/StatePill";
import { siteDisplayState } from "../../../../ui/state-model.ts";
import { TimeStamp } from "../../../../ui/TimeStamp";
import { DiffModal } from "../../DiffView";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";
import type { Release } from "./use-release.ts";

/** Who stored a revision, when, and its digest: the facts a reviewer pins an approval to. */
function RevisionMeta({
  revision,
  digest,
}: {
  revision: SiteRevision | null;
  digest?: string | null;
}) {
  const value = revision?.config_digest ?? digest ?? null;
  if (!revision && !value) return null;
  return (
    <dl className="xs-release-meta">
      {revision && (
        <>
          <div>
            <dt>提交人</dt>
            <dd className="xs-wrap">{revision.created_by}</dd>
          </div>
          <div>
            <dt>提交时间</dt>
            <dd>
              <TimeStamp value={revision.created_at} />
            </dd>
          </div>
        </>
      )}
      {value && (
        <div>
          <dt>配置摘要</dt>
          <dd>
            <IdChip value={value} label="配置摘要" maxLength={18} />
          </dd>
        </div>
      )}
    </dl>
  );
}

/**
 * What the edge serves next to what is staged, the one-word state, and (when they differ) the
 * way to the full comparison. Everything here is the server's own report; `observed` time of the
 * read is shown by the page header.
 */
export function StateCard({ ws, release }: { ws: WorkspaceApi; release: Release }) {
  const { view, access } = ws;
  const [diffOpen, setDiffOpen] = useState(false);

  if (!release.known) {
    return (
      <section className="xs-card" aria-label="发布状态">
        <h3>发布状态</h3>
        {access.canObserve ? (
          <Skeleton active paragraph={{ rows: 3 }} />
        ) : (
          <p className="muted">状态及修订读取需要 observer 角色。操作授权仍按当前角色逐次校验。</p>
        )}
      </section>
    );
  }

  const state = siteDisplayState({
    apply_state: view.apply_state,
    requires_approval: view.requires_approval,
    status: view.status,
  });
  const sentence = standing(view, view.status);
  const reason = view.reason_code ? reasonText(view.reason_code) : null;
  const diffCount = release.changes?.length ?? null;

  return (
    <section className="xs-card" aria-label="发布状态">
      <h3>发布状态</h3>
      <div className="xs-release-columns">
        <div className="xs-release-col">
          <h4>edge 正在服务</h4>
          {view.active_revision === null ? (
            <>
              <p className="xs-release-rev xs-release-rev--none">未上线</p>
              <p className="muted">edge 目前没有服务这个站点。</p>
            </>
          ) : (
            <>
              <p className="xs-release-rev mono">r{view.active_revision}</p>
              <p className="muted">
                {view.apply_state === "paused"
                  ? "edge 已确认该修订处于暂停状态，不对外服务。"
                  : "edge 已确认并正在使用这个修订。"}
              </p>
              <RevisionMeta revision={release.serving} />
            </>
          )}
        </div>
        <div className="xs-release-col">
          <h4>已暂存</h4>
          <p className="xs-release-rev">
            <span className="mono">
              {view.desired_revision === null ? "—" : `r${view.desired_revision}`}
            </span>{" "}
            <StatePill kind="apply" state={state} />
          </p>
          {sentence && <p>{sentence}</p>}
          {view.apply_state === "failed" && reason && (
            <p className="xs-failure-note">
              <strong>{reason.text}</strong> 建议：{reason.action}{" "}
              <small className="mono">{reason.code}</small>
            </p>
          )}
          <RevisionMeta revision={release.staged} digest={view.config_digest} />
          {release.pending && diffCount !== null && (
            <Button onClick={() => setDiffOpen(true)}>查看待发布差异（{diffCount} 项）</Button>
          )}
          {release.pending && release.diffNote && <p className="muted">{release.diffNote}</p>}
          {!release.pending && view.desired_revision !== null && (
            <p className="muted">暂存的修订就是 edge 在用的修订，没有待发布的变更。</p>
          )}
        </div>
      </div>
      {release.changes && (
        <DiffModal
          open={diffOpen}
          onClose={() => setDiffOpen(false)}
          title="待发布差异"
          caption={
            release.comparesServed
              ? `对比：edge 在用的 r${view.active_revision} → 暂存的 r${view.desired_revision}。右侧标出每项变更属于哪类审批原因。`
              : `对比：新站点默认值 → 暂存的 r${view.desired_revision}（edge 目前没有服务该站点）。`
          }
          changes={release.changes}
          showRisk={release.comparesServed}
        />
      )}
    </section>
  );
}
