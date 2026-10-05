import { Table, type TableColumnsType } from "antd";
import { useMemo } from "react";
import type { SiteRevision } from "../../../../api.ts";
import { safeError } from "../../../../security/errors.ts";
import { configFromStored } from "../../../../sites/model/config.ts";
import { diffConfigs } from "../../../../sites/model/diff.ts";
import { restoredFrom } from "../../../../sites/model/release.ts";
import { IdChip } from "../../../../ui/IdChip";
import { ProblemAlert } from "../../../../ui/ProblemAlert";
import { TimeStamp } from "../../../../ui/TimeStamp";
import { DiffTable } from "../../DiffView";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";

/**
 * Revisions, newest first, each compared with the one before it. A revision that repeats an
 * older one's content says so: that is what a rollback leaves behind (it stores the restored
 * configuration as a new revision), and it is how the operator confirms what was restored.
 */
export function RevisionHistory({ ws }: { ws: WorkspaceApi }) {
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
  const repeats = useMemo(() => restoredFrom(revisions), [revisions]);
  const columns: TableColumnsType<SiteRevision> = [
    {
      title: "修订",
      key: "revision",
      width: 190,
      render: (_, item) => {
        const same = repeats.get(item.revision);
        return (
          <div className="xs-revision-cell">
            <span>
              <span className="mono">r{item.revision}</span>{" "}
              {item.revision === ws.view.desired_revision && (
                <span className="xs-pill xs-pill--sm xs-pill--info">暂存</span>
              )}
              {item.revision === ws.view.active_revision && (
                <span className="xs-pill xs-pill--sm xs-pill--allow">edge 在用</span>
              )}
            </span>
            {same !== undefined && (
              <small className="muted" title="可能由回滚产生：内容与更早的修订完全相同">
                内容与 r{same} 相同
              </small>
            )}
          </div>
        );
      },
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
      {ws.revisionsQuery.isError ? (
        <ProblemAlert problem={safeError(ws.revisionsQuery.error)} title="没有读到修订历史" />
      ) : revisions.length === 0 ? (
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
