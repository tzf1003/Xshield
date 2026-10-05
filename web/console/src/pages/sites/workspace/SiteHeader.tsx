import { ArrowRightOutlined } from "@ant-design/icons";
import { Steps } from "antd";
import { deriveLifecycle } from "../../../sites/model/lifecycle.ts";
import { IdChip } from "../../../ui/IdChip";
import { StatePill } from "../../../ui/StatePill";
import { TimeStamp } from "../../../ui/TimeStamp";
import type { WorkspaceApi } from "./use-workspace.ts";

/** Steps show their state with an icon and colour; this is the same fact for a screen reader. */
const stepWord = {
  wait: "未开始",
  process: "当前步骤",
  finish: "已完成",
  error: "失败",
} as const;

/** `desired r3 · active r2`: what is staged next to what the edge serves. */
export function revisionPair(desired: number | null, active: number | null): string {
  return `desired ${desired === null ? "—" : `r${desired}`} · active ${active === null ? "—" : `r${active}`}`;
}

/**
 * The site at a glance: where traffic enters and where it goes, the one-word state, what the
 * edge serves versus what is staged, and the lifecycle with the step a failure stopped at.
 */
export function SiteHeader({ ws }: { ws: WorkspaceApi }) {
  const { view } = ws;
  const config = ws.stagedConfig ?? ws.saved;
  const lifecycle = deriveLifecycle({
    apply_state: view.apply_state,
    requires_approval: view.requires_approval,
    status: view.status,
    reason_code: view.reason_code,
    desired_revision: view.desired_revision,
    active_revision: view.active_revision,
  });
  const current = Math.max(
    0,
    lifecycle.steps.findIndex((step) => step.status === "process" || step.status === "error"),
  );
  const known = view.source !== "none";
  return (
    <section className="xs-site-header" aria-label="站点概况">
      <div className="xs-site-header-top">
        {ws.siteId && <IdChip value={ws.siteId} label="站点 ID" />}
        <StatePill kind="apply" state={lifecycle.state} />
        <span className="mono xs-revisions">
          {revisionPair(view.desired_revision, view.active_revision)}
        </span>
      </div>
      {config && (
        <p className="xs-site-flow mono">
          <span>{config.public_origin || "（未填写公网入口）"}</span>
          <ArrowRightOutlined aria-label="转发到" />
          <span>{config.upstream_address || "（未填写源站）"}</span>
          <span className="muted">
            {config.upstream_tls ? " · TLS" : " · 明文"}
            {config.upstream_server_name ? ` · ${config.upstream_server_name}` : ""}
          </span>
        </p>
      )}
      {ws.saved && (
        <p className="xs-site-meta muted">
          监听端口 <span className="mono">{ws.saved.listen_port}</span>
          {ws.configQuery.data?.config && (
            <>
              {" · 最近更新 "}
              <TimeStamp value={ws.configQuery.data.config.updated_at} /> ·{" "}
              {ws.configQuery.data.config.updated_by}
            </>
          )}
        </p>
      )}
      {known && <p className="xs-edge-summary">{lifecycle.edgeSummary}</p>}
      {known && (
        <Steps
          className="xs-lifecycle"
          size="small"
          current={current}
          items={lifecycle.steps.map((step) => ({
            title: (
              <>
                {step.title}
                <span className="xs-visually-hidden">（{stepWord[step.status]}）</span>
              </>
            ),
            content: step.note || undefined,
            status: step.status,
          }))}
        />
      )}
      {lifecycle.failure && (
        <p className="xs-failure-note">
          <strong>{lifecycle.failure.text}</strong> 建议：{lifecycle.failure.action}{" "}
          <small className="mono">{lifecycle.failure.code}</small>
        </p>
      )}
    </section>
  );
}
