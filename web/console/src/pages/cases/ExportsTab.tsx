import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { Alert, Button, Drawer, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { ExportListItem } from "../../exports.ts";
import { useGuardedQuery } from "../../security/hooks";
import { ExportDetail } from "../../work/ExportDetail";
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
import { exportLapsed, exportPill } from "../../work/status.ts";
import { useUnresolved } from "../../work/use-write.ts";
import { PendingNotice } from "../../work/WriteDialog";
import { RequestExportDialog } from "./dialogs";

/**
 * 导出: this case's metadata exports. Like the access table it reads the requester's own list
 * (`GET /control/v1/exports?view=mine`) and keeps the rows of this case in the browser.
 */
export function ExportsTab({ caseId, canRequest }: { caseId: string; canRequest: boolean }) {
  const pager = usePager(`exports:${caseId}`);
  const query = useGuardedQuery(specs.exportList("mine", pager.cursor));
  const [requesting, setRequesting] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const unresolved = useUnresolved(owners.requestExport(caseId));
  const page = query.data;
  const rows = page ? page.items.filter((item) => item.case_id === caseId) : [];
  const asOfMs = page ? Date.parse(page.as_of) : Number.NaN;

  const columns: TableColumnsType<ExportListItem> = [
    {
      title: "导出",
      key: "id",
      onCell: labelled("导出"),
      render: (_, row) => <IdChip id={row.export_id} label="导出 ID" />,
    },
    {
      title: "状态",
      key: "status",
      onCell: labelled("状态"),
      render: (_, row) => <StatePill pill={exportPill(row.status, exportLapsed(row, asOfMs))} />,
    },
    {
      title: "申请时间",
      key: "at",
      onCell: labelled("申请时间"),
      render: (_, row) => <Time value={row.requested_at} />,
    },
    {
      title: "到期",
      key: "expires",
      onCell: labelled("到期"),
      render: (_, row) => <Time value={row.expires_at} />,
    },
    {
      title: "操作",
      key: "actions",
      onCell: labelled("操作"),
      render: (_, row) => (
        <Button size="small" onClick={() => setDetail(row.export_id)}>
          {row.status === "ready" ? "查看并下载" : "详情"}
        </Button>
      ),
    },
  ];

  return (
    <div className="xs-w-stack">
      <PendingNotice operation={unresolved} label="申请导出" onOpen={() => setRequesting(true)} />
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
              onClick={() => setRequesting(true)}
            >
              申请导出
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
            ? `此表来自“我的导出”列表，浏览器只保留属于本案件的行：本页 ${page.items.length} 条导出中有 ${rows.length} 条属于本案件。导出只含案件与证据目录的元数据，批准与下载都需要 MFA 再认证。`
            : "此表来自“我的导出”列表，浏览器只保留属于本案件的行。"
        }
      />
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {page && (
          <>
            <Table<ExportListItem>
              className="xs-w-table"
              rowKey="export_id"
              size="middle"
              pagination={false}
              columns={columns}
              dataSource={rows}
              loading={query.isFetching && !query.isPending}
              locale={{
                emptyText:
                  page.items.length > 0
                    ? "本页没有属于本案件的导出，可翻页继续查看。"
                    : "没有导出申请。",
              }}
            />
            <Pager
              pager={pager}
              count={page.items.length}
              nextCursor={page.next_cursor}
              busy={query.isFetching}
              noun="条导出"
            />
          </>
        )}
      </LoadState>
      {requesting && <RequestExportDialog caseId={caseId} onClose={() => setRequesting(false)} />}
      <Drawer
        title="导出详情"
        open={detail !== null}
        onClose={() => setDetail(null)}
        size={560}
        destroyOnHidden
      >
        {detail !== null && (
          <ExportDetail exportId={detail} ownership="mine" observedAt={page?.as_of} />
        )}
      </Drawer>
    </div>
  );
}
