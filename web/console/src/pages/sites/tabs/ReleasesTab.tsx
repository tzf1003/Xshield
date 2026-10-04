import { Button, Table, type TableColumnsType } from "antd";
import { useMemo } from "react";
import type { SiteRevision } from "../../../api.ts";
import { configFromStored } from "../../../sites/model/config.ts";
import { diffConfigs } from "../../../sites/model/diff.ts";
import { IdChip } from "../../../ui/IdChip";
import { reasonText } from "../../../ui/reason-codes.ts";
import { StatePill } from "../../../ui/StatePill";
import { siteDisplayState } from "../../../ui/state-model.ts";
import { TimeStamp } from "../../../ui/TimeStamp";
import { DiffTable } from "../DiffView";
import { revisionPair } from "../workspace/SiteHeader";
import type { WorkspaceApi } from "../workspace/use-workspace.ts";

/** Revisions, newest first, each compared with the one before it. */
function RevisionHistory({ ws }: { ws: WorkspaceApi }) {
  const revisions = useMemo(
    () => [...ws.revisions].sort((a, b) => b.revision - a.revision),
    [ws.revisions],
  );
  const parsed = useMemo(
    () =>
      new Map(
        revisions.map((item) => [
          item.revision,
          configFromStored(item.config, item.policy_revision),
        ]),
      ),
    [revisions],
  );
  const columns: TableColumnsType<SiteRevision> = [
    {
      title: "修订",
      key: "revision",
      width: 150,
      render: (_, item) => (
        <span>
          <span className="mono">r{item.revision}</span>{" "}
          {item.revision === ws.view.desired_revision && (
            <span className="xs-pill xs-pill--sm xs-pill--info">暂存</span>
          )}
          {item.revision === ws.view.active_revision && (
            <span className="xs-pill xs-pill--sm xs-pill--allow">edge 在用</span>
          )}
        </span>
      ),
    },
    {
      title: "策略版本",
      dataIndex: "policy_revision",
      responsive: ["md"],
      render: (value: string) => <span className="mono">{value}</span>,
    },
    {
      title: "提交人",
      dataIndex: "created_by",
      responsive: ["lg"],
      render: (value: string) => <span className="xs-wrap">{value}</span>,
    },
    {
      title: "时间",
      key: "at",
      render: (_, item) => <TimeStamp value={item.created_at} compact />,
    },
    {
      title: "摘要",
      key: "digest",
      responsive: ["lg"],
      render: (_, item) => <IdChip value={item.config_digest} label="配置摘要" maxLength={14} />,
    },
  ];
  return (
    <section className="xs-card" aria-label="修订历史">
      <h3>修订历史</h3>
      {revisions.length === 0 ? (
        <p className="empty">暂无可读取的修订历史。</p>
      ) : (
        <Table<SiteRevision>
          size="small"
          rowKey="revision"
          columns={columns}
          dataSource={revisions}
          pagination={revisions.length > 10 ? { pageSize: 10, showSizeChanger: false } : false}
          scroll={{ x: 360 }}
          expandable={{
            expandedRowRender: (item) => {
              const before =
                parsed.get(item.revision - 1) ??
                parsed.get(
                  revisions.find((other) => other.revision < item.revision)?.revision ?? -1,
                ) ??
                null;
              const after = parsed.get(item.revision) ?? null;
              if (!after) return <p className="muted">这个修订的内容无法解读。</p>;
              if (!before) return <p className="muted">初始配置，没有更早的修订可比较。</p>;
              return (
                <DiffTable
                  changes={diffConfigs(before, after)}
                  empty="与上一个修订没有字段差异（可能只是重新保存）。"
                />
              );
            },
          }}
        />
      )}
    </section>
  );
}

/**
 * 发布: the current state and the release actions the roles allow. Every action is a frozen
 * write; a role without Observer sees the actions without state and the server decides.
 */
export function ReleasesTab({ ws }: { ws: WorkspaceApi }) {
  const { access, view, locked } = ws;
  const known = view.source !== "none";
  const state = siteDisplayState({
    apply_state: view.apply_state,
    requires_approval: view.requires_approval,
    status: view.status,
  });
  const reason = reasonText(view.reason_code);
  return (
    <section className="xs-releases" aria-label="站点发布">
      <div className="xs-card">
        <h3>发布与回滚</h3>
        {known ? (
          <>
            <p className="xs-release-state">
              当前状态：
              <StatePill kind="apply" state={state} />
              {view.reason_code && <span className="muted"> {reason.text}</span>}
            </p>
            <p>
              <span className="mono">
                {revisionPair(view.desired_revision, view.active_revision)}
              </span>{" "}
              · {view.requires_approval ? "等待独立审批" : "无需审批"}
            </p>
          </>
        ) : (
          !access.canObserve && (
            <p className="muted">
              状态及修订读取需要 observer 角色。操作授权仍按当前角色逐次校验。
            </p>
          )
        )}
        <div className="form-actions xs-release-actions">
          {access.canValidate && (
            <Button
              disabled={locked}
              onClick={() => void ws.run("validate", () => ws.writes.validate.submit({}))}
            >
              验证配置
            </Button>
          )}
          {access.canApprove && (
            <Button
              type="primary"
              disabled={locked || view.requires_approval === false}
              onClick={() =>
                void ws.run("approve", () => ws.writes.approve.submit({ digest: null }))
              }
            >
              批准并应用
            </Button>
          )}
          {access.canApply && (
            <Button
              type="primary"
              disabled={
                locked ||
                view.requires_approval === true ||
                (known && view.desired_revision === null)
              }
              onClick={() => void ws.run("apply", () => ws.writes.apply.submit({}))}
            >
              应用期望版本
            </Button>
          )}
          {access.canApply && (
            <Button
              disabled={locked || (known && view.active_revision === null)}
              onClick={() => void ws.run("rollback", () => ws.writes.rollback.submit({}))}
            >
              回滚上一版本
            </Button>
          )}
        </div>
      </div>
      {access.canObserve && <RevisionHistory ws={ws} />}
      {ws.configQuery.data?.config && (
        <details className="xs-card">
          <summary>edge 配置投影（只读）</summary>
          <pre className="config-preview">
            {JSON.stringify(ws.configQuery.data.config.gateway_config, null, 2)}
          </pre>
        </details>
      )}
    </section>
  );
}
