import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { Button, Drawer, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { CaseItem } from "../../cases.ts";
import { useGuardedQuery } from "../../security/hooks";
import { ArtifactMeta } from "../../work/ArtifactMeta";
import { owners } from "../../work/operations.ts";
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
import { specs } from "../../work/queries.ts";
import { catalogPill } from "../../work/status.ts";
import { useUnresolved } from "../../work/use-write.ts";
import { PendingNotice } from "../../work/WriteDialog";
import { AddEvidenceDialog, RequestAccessDialog } from "./dialogs";

/** 证据集合: the case's members, with their catalog state, metadata and access shortcuts. */
export function EvidenceTab({
  caseId,
  canWrite,
  canRequest,
}: {
  caseId: string;
  /** Investigator: may associate evidence. */
  canWrite: boolean;
  /** May file an access request (Investigator). */
  canRequest: boolean;
}) {
  const pager = usePager(`items:${caseId}`);
  const query = useGuardedQuery(specs.caseItems(caseId, pager.cursor));
  const [adding, setAdding] = useState(false);
  const [meta, setMeta] = useState<string | null>(null);
  const [requesting, setRequesting] = useState<string | null>(null);
  const unresolvedAdd = useUnresolved(owners.addEvidence(caseId));
  const collection = query.data;
  const open = collection?.case.status === "open";

  const columns: TableColumnsType<CaseItem> = [
    {
      title: "证据",
      key: "artifact",
      onCell: labelled("证据"),
      render: (_, item) => <IdChip id={item.artifact_id} label="证据 ID" />,
    },
    {
      title: "目录状态",
      key: "state",
      onCell: labelled("目录状态"),
      render: (_, item) => <StatePill pill={catalogPill[item.catalog_status]} />,
    },
    { title: "加入者", dataIndex: "added_by", key: "by", onCell: labelled("加入者") },
    {
      title: "加入时间",
      dataIndex: "added_at",
      key: "at",
      onCell: labelled("加入时间"),
      render: (value: string) => <Time value={value} />,
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, item) => (
        <Space wrap>
          <Button size="small" onClick={() => setMeta(item.artifact_id)}>
            元数据
          </Button>
          {canRequest && open && item.catalog_status === "active" && (
            <Button size="small" onClick={() => setRequesting(item.artifact_id)}>
              申请原文访问
            </Button>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div className="xs-w-stack">
      <PendingNotice operation={unresolvedAdd} label="关联证据" onOpen={() => setAdding(true)} />
      <div className="xs-w-between xs-w-toolbar">
        {collection && pager.index > 0 ? (
          <Observed asOf={collection.as_of} requestId={collection.request_id} />
        ) : (
          // The first page is the observation the case header already shows.
          <span />
        )}
        <Space wrap>
          <Button
            icon={<ReloadOutlined aria-hidden="true" />}
            loading={query.isFetching}
            onClick={() => void query.refetch()}
          >
            刷新
          </Button>
          {canWrite && (
            <Button
              type="primary"
              icon={<PlusOutlined aria-hidden="true" />}
              disabled={collection !== undefined && !open}
              title={collection && !open ? "案件已关闭，不能新增关联" : undefined}
              onClick={() => setAdding(true)}
            >
              关联证据
            </Button>
          )}
        </Space>
      </div>
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {collection && (
          <>
            <Table<CaseItem>
              className="xs-w-table"
              rowKey="artifact_id"
              size="middle"
              pagination={false}
              columns={columns}
              dataSource={collection.items}
              loading={query.isFetching && !query.isPending}
              locale={{ emptyText: "当前案件尚无证据引用。" }}
            />
            <Pager
              pager={pager}
              count={collection.items.length}
              nextCursor={collection.next_cursor}
              busy={query.isFetching}
            />
          </>
        )}
      </LoadState>
      <p className="xs-w-muted">
        目录状态只描述证据目录，不证明内容读取权或对象完整性。证据元数据需要 Observer
        角色；原文访问须单独申请并经独立审批。
      </p>
      {adding && <AddEvidenceDialog caseId={caseId} onClose={() => setAdding(false)} />}
      {requesting !== null && (
        <RequestAccessDialog
          caseId={caseId}
          members={collection?.items ?? []}
          initialArtifact={requesting}
          onClose={() => setRequesting(null)}
        />
      )}
      <Drawer
        title="证据元数据"
        open={meta !== null}
        onClose={() => setMeta(null)}
        size={480}
        destroyOnHidden
      >
        {meta !== null && <ArtifactMeta artifactId={meta} />}
      </Drawer>
    </div>
  );
}
