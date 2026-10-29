import { ReloadOutlined, ThunderboltOutlined } from "@ant-design/icons";
import { App as AntdApp, Alert, Button, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import type { JobResponse } from "../../api.ts";
import type { CaseJobListItem } from "../../case-job-list.ts";
import { useGuardedQuery } from "../../security/hooks";
import { useShellActions } from "../../shell/actions";
import { JobCard } from "../../work/JobCard";
import { owners } from "../../work/operations.ts";
import {
  ErrorNotice,
  IdChip,
  labelled,
  LoadState,
  Observed,
  Pager,
  StatePill,
  Time,
  usePager,
} from "../../work/Parts";
import { domains, specs } from "../../work/queries.ts";
import { jobPill } from "../../work/status.ts";
import { useWrite } from "../../work/use-write.ts";
import { FrozenOperation } from "../../work/WriteDialog";

/**
 * Every job this case has ever produced, read from the durable store directly (not from local
 * state), so it survives a page reload and shows jobs submitted before this page was opened.
 */
function CaseJobHistory({ caseId }: { caseId: string }) {
  const pager = usePager(`case-jobs:${caseId}`);
  const query = useGuardedQuery(specs.caseJobList(caseId, pager.cursor));
  const shell = useShellActions();
  const page = query.data;
  const columns: TableColumnsType<CaseJobListItem> = [
    {
      title: "任务",
      key: "id",
      onCell: labelled("任务"),
      render: (_, row) => <IdChip id={row.job_id} label="任务 ID" />,
    },
    {
      title: "状态",
      key: "status",
      onCell: labelled("状态"),
      render: (_, row) => <StatePill pill={jobPill[row.status]} />,
    },
    {
      title: "检查点",
      key: "checkpoint",
      onCell: labelled("检查点"),
      render: (_, row) => <span className="mono">{row.checkpoint}</span>,
    },
    {
      title: "创建时间",
      key: "created",
      onCell: labelled("创建时间"),
      render: (_, row) => <Time value={row.created_at} />,
    },
    {
      title: "操作",
      key: "open",
      onCell: labelled("操作"),
      render: (_, row) =>
        shell && (
          <Button
            size="small"
            onClick={() =>
              shell.run({ type: "search", preset: { kind: "job_id", value: row.job_id } })
            }
          >
            查看
          </Button>
        ),
    },
  ];
  return (
    <section className="xs-w-card" aria-label="历史任务">
      <div className="xs-w-between xs-w-toolbar">
        <h4>历史任务</h4>
        <Space wrap>
          {page ? <Observed asOf={page.as_of} requestId={page.request_id} /> : <span />}
          <Button
            size="small"
            icon={<ReloadOutlined aria-hidden="true" />}
            loading={query.isFetching}
            onClick={() => void query.refetch()}
          >
            刷新
          </Button>
        </Space>
      </div>
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {page && (
          <>
            <Table<CaseJobListItem>
              className="xs-w-table"
              rowKey="job_id"
              size="middle"
              pagination={false}
              columns={columns}
              dataSource={page.items}
              loading={query.isFetching && !query.isPending}
              locale={{ emptyText: "该案件尚未产生任何任务。" }}
            />
            <Pager
              pager={pager}
              count={page.items.length}
              nextCursor={page.next_cursor}
              busy={query.isFetching}
              noun="条任务"
            />
          </>
        )}
      </LoadState>
    </section>
  );
}

/**
 * 分析任务: a read-only inventory of the case (reference and catalog counts) written to a
 * durable job. It reads no evidence content and calls no model.
 */
export function AnalysisTab({ caseId, canWrite }: { caseId: string; canWrite: boolean }) {
  const { message } = AntdApp.useApp();
  const shell = useShellActions();
  const [latest, setLatest] = useState<JobResponse | null>(null);
  const jobId = latest?.job?.job_id ?? null;
  const reread = useGuardedQuery({ ...specs.job(jobId ?? "job_none"), enabled: false });
  const write = useWrite<{ caseId: string }, JobResponse>(
    {
      label: "案件清单分析",
      path: (vars) => `/control/v1/cases/${vars.caseId}/analyze`,
      run: (client, vars, context) =>
        client.analyzeCase(vars.caseId, context.idempotencyKey, context.signal),
      owner: owners.analyzeCase(caseId),
      invalidate: [domains.cases],
    },
    (response) => {
      setLatest(response);
      message.success("分析任务已受理");
    },
  );
  // A re-read replaces the shown job; before the first re-read the submission's reply is shown.
  const shown = reread.data?.found ? reread.data : latest;
  const job = shown?.job ?? null;

  return (
    <div className="xs-w-stack">
      <section className="xs-w-card" aria-label="案件清单分析">
        <h4>案件清单分析</h4>
        <p className="xs-w-muted">
          只统计当前案件的证据引用数量与目录状态，结果写入耐久任务；不读取证据内容，不调用模型，不产生任何读取资格。
          每次提交都是一次独立的写入，由框架生成幂等键。
        </p>
        {write.operation ? (
          <FrozenOperation
            operation={write.operation}
            busy={write.busy}
            onRetry={() => void write.retry()}
          />
        ) : (
          <Space orientation="vertical" size="small">
            {write.rejection !== null && (
              <Alert type="error" showIcon title="本次请求被拒绝，没有任务被创建" />
            )}
            <Button
              type="primary"
              icon={<ThunderboltOutlined aria-hidden="true" />}
              loading={write.busy}
              disabled={!canWrite}
              title={canWrite ? undefined : "需要 Investigator 角色"}
              onClick={() => void write.submit({ caseId })}
            >
              提交案件清单分析
            </Button>
          </Space>
        )}
      </section>
      {job && shown ? (
        <section className="xs-w-card" aria-label="分析任务状态">
          <div className="xs-w-between">
            <h4>任务状态</h4>
            <Space wrap>
              <Button
                size="small"
                icon={<ReloadOutlined aria-hidden="true" />}
                loading={reread.isFetching}
                onClick={() => void reread.refetch()}
              >
                重新读取任务状态
              </Button>
              {shell && (
                <Button
                  size="small"
                  onClick={() =>
                    shell.run({
                      type: "search",
                      preset: { kind: "job_id", value: job.job_id },
                    })
                  }
                >
                  准备任务历史检索
                </Button>
              )}
            </Space>
          </div>
          {reread.error && <ErrorNotice error={reread.error} />}
          <JobCard job={job} requestId={shown.request_id} />
        </section>
      ) : (
        <p className="xs-w-muted">尚未提交分析任务。</p>
      )}
      <CaseJobHistory caseId={caseId} />
    </div>
  );
}
