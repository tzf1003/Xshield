import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { Alert, Button, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { CaseItem } from "../../cases.ts";
import type { HoldRecord } from "../../evidence-holds.ts";
import { useGuardedQuery, usePendingOperations } from "../../security/hooks";
import { useShellActions } from "../../shell/actions";
import { estimateServerNowMs, holdState } from "../../work/holds.ts";
import {
  IdChip,
  labelled,
  LoadState,
  Observed,
  Pager,
  StatePill,
  Time,
  usePager,
} from "../../work/Parts";
import { owners } from "../../work/operations.ts";
import { specs } from "../../work/queries.ts";
import { holdPill } from "../../work/status.ts";
import { useUnresolved } from "../../work/use-write.ts";
import { PendingNotice } from "../../work/WriteDialog";
import { CreateHoldDialog, ReleaseHoldDialog } from "./dialogs";

const releasePath = /^\/control\/v1\/evidence-holds\/(ev_[0-9a-f-]{36})\/release$/;

/**
 * 保留锁 (AuditAdministrator): the case's retention history, newest state first by hold ID, and
 * the two writes. A hold only postpones physical deletion; it grants no read permission.
 */
export function HoldsTab({ caseId, members }: { caseId: string; members: readonly CaseItem[] }) {
  const pager = usePager(`holds:${caseId}`);
  const query = useGuardedQuery(specs.holds(caseId, pager.cursor));
  const shell = useShellActions();
  const [creating, setCreating] = useState(false);
  const [releasing, setReleasing] = useState<string | null>(null);
  const unresolvedCreate = useUnresolved(owners.createHold(caseId));
  const unresolvedReleases = usePendingOperations().filter((operation) =>
    releasePath.test(operation.path),
  );
  const page = query.data;

  const columns: TableColumnsType<HoldRecord> = [
    {
      title: "保留锁",
      key: "id",
      onCell: labelled("保留锁"),
      render: (_, hold) => <IdChip id={hold.hold_id} label="保留锁 ID" />,
    },
    {
      title: "证据",
      key: "artifact",
      onCell: labelled("证据"),
      render: (_, hold) => <IdChip id={hold.artifact_id} label="证据 ID" />,
    },
    {
      title: "状态",
      key: "state",
      onCell: labelled("状态"),
      render: (_, hold) =>
        page ? <StatePill pill={holdPill[holdState(hold, page.as_of)]} /> : null,
    },
    {
      title: "保留至",
      key: "until",
      onCell: labelled("保留至"),
      render: (_, hold) => <Time value={hold.hold_until} />,
    },
    {
      title: "创建",
      key: "created",
      onCell: labelled("创建"),
      render: (_, hold) => (
        <div>
          <div className="xs-w-text">{hold.reason}</div>
          <small className="xs-w-muted">
            {hold.created_by} · <Time value={hold.created_at} />
          </small>
        </div>
      ),
    },
    {
      title: "释放",
      key: "released",
      onCell: labelled("释放"),
      render: (_, hold) =>
        hold.released_at === null ? (
          "未释放"
        ) : (
          <div>
            <div className="xs-w-text">{hold.released_reason}</div>
            <small className="xs-w-muted">
              {hold.released_by} · <Time value={hold.released_at} />
            </small>
          </div>
        ),
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, hold) => (
        <Space wrap>
          <Button
            size="small"
            danger
            disabled={hold.released_at !== null}
            onClick={() => setReleasing(hold.hold_id)}
          >
            释放
          </Button>
          {shell && (
            <Button
              size="small"
              aria-label={`准备历史检索 ${hold.hold_id}`}
              onClick={() =>
                shell.run({
                  type: "search",
                  preset: { kind: "evidence_hold_id", value: hold.hold_id },
                })
              }
            >
              准备历史检索
            </Button>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div className="xs-w-stack">
      <Alert
        type="info"
        showIcon
        title="保留锁只推迟物理删除，不授予读取权限"
        description="证据内容的原始期限、独立审批和到期拒读继续生效；释放可在案件关闭、内容到期后执行。每页是一次独立的审计读取，创建或释放后列表会重新读取。"
      />
      <PendingNotice
        operation={unresolvedCreate}
        label="创建保留锁"
        onOpen={() => setCreating(true)}
      />
      {unresolvedReleases.map((operation) => {
        const holdId = releasePath.exec(operation.path)?.[1];
        return holdId ? (
          <PendingNotice
            key={operation.id}
            operation={operation}
            label="释放保留锁"
            onOpen={() => setReleasing(holdId)}
          />
        ) : null;
      })}
      <div className="xs-w-between xs-w-toolbar">
        {page ? <Observed asOf={page.as_of} requestId={page.request_id} /> : <span />}
        <Space wrap>
          <Button
            icon={<ReloadOutlined aria-hidden="true" />}
            loading={query.isFetching}
            onClick={() => void query.refetch()}
          >
            刷新
          </Button>
          <Button
            type="primary"
            icon={<PlusOutlined aria-hidden="true" />}
            disabled={!page || page.case_status !== "open"}
            title={page && page.case_status !== "open" ? "案件已关闭，不能新建保留锁" : undefined}
            onClick={() => setCreating(true)}
          >
            创建保留锁
          </Button>
        </Space>
      </div>
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {page && (
          <>
            <Table<HoldRecord>
              className="xs-w-table"
              rowKey="hold_id"
              size="middle"
              pagination={false}
              columns={columns}
              dataSource={page.items}
              loading={query.isFetching && !query.isPending}
              locale={{ emptyText: "当前案件没有保留历史。" }}
            />
            <Pager
              pager={pager}
              count={page.items.length}
              nextCursor={page.next_cursor}
              busy={query.isFetching}
            />
          </>
        )}
      </LoadState>
      {creating && page && (
        <CreateHoldDialog
          caseId={caseId}
          members={members}
          serverNow={() => estimateServerNowMs(page.as_of, query.dataUpdatedAt, Date.now())}
          onClose={() => setCreating(false)}
        />
      )}
      {releasing !== null && (
        <ReleaseHoldDialog holdId={releasing} onClose={() => setReleasing(null)} />
      )}
    </div>
  );
}
