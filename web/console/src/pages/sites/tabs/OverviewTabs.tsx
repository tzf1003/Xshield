import { Button, Descriptions } from "antd";
import { useRouter } from "@tanstack/react-router";
import { securityEntryLabel, statusLabel } from "../../../sites/model/config.ts";
import { IdChip } from "../../../ui/IdChip";
import { reasonText } from "../../../ui/reason-codes.ts";
import { StatePill } from "../../../ui/StatePill";
import { siteDisplayState } from "../../../ui/state-model.ts";
import { TimeStamp } from "../../../ui/TimeStamp";
import { revisionPair } from "../workspace/SiteHeader";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";

/** 概览: where the site stands and the one thing to do next. */
export function OverviewTab({ ws }: { ws: WorkspaceApi }) {
  const { view } = ws;
  const config = ws.configQuery.data?.config ?? null;
  const router = useRouter();
  const state = siteDisplayState({
    apply_state: view.apply_state,
    requires_approval: view.requires_approval,
    status: view.status,
  });
  const reason = reasonText(view.reason_code);
  const nextStep =
    state === "awaiting_approval"
      ? "这次变更等待另一位审批人批准：到“发布”页审阅差异。"
      : state === "failed"
        ? `应用失败：${reason.action}`
        : state === "draft"
          ? "草稿不会发布：确认配置后把状态改为“启用”，经审批后上线。"
          : state === "pending"
            ? "等待 edge 确认：稍后刷新；长时间未确认请到“发布”页重试应用。"
            : null;
  return (
    <section className="xs-card" aria-label="站点概览">
      <h3>站点概览</h3>
      <Descriptions
        size="small"
        column={{ xs: 1, md: 2 }}
        items={[
          {
            key: "id",
            label: "站点 ID",
            children: ws.siteId ? <IdChip value={ws.siteId} label="站点 ID" /> : "尚未填写",
          },
          {
            key: "origin",
            label: "公网入口",
            children: <span className="mono xs-wrap">{config?.public_origin ?? "—"}</span>,
          },
          {
            key: "upstream",
            label: "上游",
            children: config ? (
              <span className="mono xs-wrap">
                {config.upstream_address}（{config.upstream_tls ? "TLS" : "明文"}，
                {config.upstream_server_name}）
              </span>
            ) : (
              "—"
            ),
          },
          {
            key: "port",
            label: "监听端口",
            children: <span className="mono">{config?.listen_port ?? "—"}</span>,
          },
          {
            key: "entry",
            label: "安全入口",
            children: config ? securityEntryLabel[config.security_entry] : "—",
          },
          {
            key: "status",
            label: "配置状态",
            children: config
              ? statusLabel[config.status]
              : view.status
                ? statusLabel[view.status]
                : "—",
          },
          { key: "apply", label: "应用状态", children: <StatePill kind="apply" state={state} /> },
          {
            key: "revisions",
            label: "期望 / 活动版本",
            children: (
              <span className="mono">
                {revisionPair(view.desired_revision, view.active_revision)}
              </span>
            ),
          },
          {
            key: "approval",
            label: "审批",
            children: view.requires_approval
              ? "等待独立审批"
              : view.source === "none"
                ? "未读取"
                : "无需审批",
          },
          {
            key: "reason",
            label: "最近结果",
            children: view.reason_code ? <span>{reason.text}</span> : "—",
          },
          {
            key: "digest",
            label: "配置摘要",
            children: view.config_digest ? (
              <IdChip value={view.config_digest} label="配置摘要" maxLength={18} />
            ) : (
              "—"
            ),
          },
          {
            key: "updated",
            label: "最近更新",
            children: config ? (
              <span>
                <TimeStamp value={config.updated_at} /> · {config.updated_by}
              </span>
            ) : (
              "—"
            ),
          },
        ]}
      />
      {nextStep && (
        <p className="xs-next-step">
          <strong>下一步：</strong>
          {nextStep}{" "}
          {ws.siteId && (
            <Button
              size="small"
              onClick={() => void router.navigate({ to: `/sites/${ws.siteId}/releases` } as never)}
            >
              去“发布”
            </Button>
          )}
        </p>
      )}
    </section>
  );
}

/** 审计: the management request behind this view and the way into the investigation pages. */
export function AuditTab({ ws }: { ws: WorkspaceApi }) {
  const router = useRouter();
  const requestId = ws.configQuery.data?.request_id ?? ws.statusQuery.data?.request_id ?? null;
  return (
    <section className="xs-card" aria-label="站点审计">
      <h3>审计与调查</h3>
      <p>
        管理请求 ID：
        {requestId ? <IdChip value={requestId} label="请求 ID" /> : <span className="mono">—</span>}
      </p>
      <p className="muted">
        调查读取按当前管理会话的站点范围授权；每次读取、保存、验证、批准、应用、回滚和删除都会写入服务端审计。
      </p>
      <Button onClick={() => void router.navigate({ to: "/investigation/requests" } as never)}>
        打开调查控制台
      </Button>
    </section>
  );
}
