import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { Alert, Button, Drawer, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { CaseItem } from "../../cases.ts";
import type { AccessList } from "../../evidence-access.ts";
import { useGuardedQuery } from "../../security/hooks";
import { AccessDetail } from "../../work/AccessDetail";
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
import { accessPill } from "../../work/status.ts";
import { useUnresolved } from "../../work/use-write.ts";
import { PendingNotice } from "../../work/WriteDialog";
import { RequestAccessDialog } from "./dialogs";

type Row = AccessList["items"][number];

/**
 * 访问申请: this case's original-content access requests. The server lists requests per person,
 * not per case, so the table reads "我的申请" and keeps the rows of this case in the browser.
 */
export function AccessTab({
  caseId,
  caseOpen,
  members,
  canRequest,
}: {
  caseId: string;
  caseOpen: boolean | null;
  members: readonly CaseItem[];
  canRequest: boolean;
}) {
  const pager = usePager(`access:${caseId}`);
  const query = useGuardedQuery(specs.accessList("mine", pager.cursor));
  const [requesting, setRequesting] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const unresolved = useUnresolved(owners.requestAccess(caseId));
  const page = query.data;
  const rows = page ? page.items.filter((item) => item.case_id === caseId) : [];

  const columns: TableColumnsType<Row> = [
    {
      title: "申请",
      key: "id",
      onCell: labelled("申请"),
      render: (_, row) => <IdChip id={row.access_request_id} label="访问申请 ID" />,
    },
    {
      title: "证据",
      key: "artifact",
      onCell: labelled("证据"),
      render: (_, row) => <IdChip id={row.artifact_id} label="证据 ID" />,
    },
    {
      title: "状态",
      key: "status",
      onCell: labelled("状态"),
      render: (_, row) => <StatePill pill={accessPill[row.stored_status]} />,
    },
    {
      title: "申请时间",
      key: "at",
      onCell: labelled("申请时间"),
      render: (_, row) => <Time value={row.requested_at} />,
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, row) => (
        <Button size="small" onClick={() => setDetail(row.access_request_id)}>
          详情
        </Button>
      ),
    },
  ];

  return (
    <div className="xs-w-stack">
      <PendingNotice
        operation={unresolved}
        label="申请原文访问"
        onOpen={() => setRequesting(true)}
      />
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
          {canRequest && (
            <Button
              type="primary"
              icon={<PlusOutlined aria-hidden="true" />}
              disabled={caseOpen === false}
              title={caseOpen === false ? "案件已关闭，不能申请原文访问" : undefined}
              onClick={() => setRequesting(true)}
            >
              申请原文访问
            </Button>
          )}
        </Space>
      </div>
      <Alert
        type="info"
        showIcon
        title="已按本案件筛选"
        description={
          page
            ? `此表来自“我的申请”列表，浏览器只保留属于本案件的行：本页 ${page.items.length} 条申请中有 ${rows.length} 条属于本案件。其余页的申请需翻页读取，每页都是独立的审计读取。`
            : "此表来自“我的申请”列表，浏览器只保留属于本案件的行。"
        }
      />
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {page && (
          <>
            <Table<Row>
              className="xs-w-table"
              rowKey="access_request_id"
              size="middle"
              pagination={false}
              columns={columns}
              dataSource={rows}
              loading={query.isFetching && !query.isPending}
              locale={{
                emptyText:
                  page.items.length > 0
                    ? "本页没有属于本案件的访问申请，可翻页继续查看。"
                    : "没有访问申请。",
              }}
            />
            <Pager
              pager={pager}
              count={page.items.length}
              nextCursor={page.next_cursor}
              busy={query.isFetching}
              noun="条申请"
            />
          </>
        )}
      </LoadState>
      {requesting && (
        <RequestAccessDialog
          caseId={caseId}
          members={members}
          onClose={() => setRequesting(false)}
        />
      )}
      <Drawer
        title="访问申请详情"
        open={detail !== null}
        onClose={() => setDetail(null)}
        size={560}
        destroyOnHidden
      >
        {detail !== null && <AccessDetail accessId={detail} ownership="mine" />}
      </Drawer>
    </div>
  );
}
