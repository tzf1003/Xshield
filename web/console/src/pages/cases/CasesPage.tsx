import { PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { useParams, useSearch } from "@tanstack/react-router";
import { Alert, Button, Input, Modal, Segmented, Space, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import { type CaseFacts, casePattern } from "../../cases.ts";
import { useGuardedQuery } from "../../security/hooks";
import { PageActions } from "../../shell/page-actions";
import { JobCard } from "../../work/JobCard";
import { RouteLink, useGo } from "../../work/nav";
import { owners } from "../../work/operations.ts";
import {
  Field,
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
import { role, useRoles } from "../../work/roles.ts";
import { casePill } from "../../work/status.ts";
import { useUnresolved } from "../../work/use-write.ts";
import { PendingNotice } from "../../work/WriteDialog";
import { WorkRoot } from "../../work/WorkRoot";
import { CreateCaseDialog } from "./dialogs";

type Filter = "all" | "open" | "closed";

const moved: Record<string, { title: string; text: string }> = {
  holds: {
    title: "“证据保留”已并入案件",
    text: "保留锁现在在案件详情的“保留锁”页签中管理：先打开案件（AuditAdministrator 可按案件 ID 打开），再创建、释放或核对保留历史。",
  },
  exports: {
    title: "“调查导出”已并入案件",
    text: "导出申请在案件详情的“导出”页签中提交；待你审批的导出和你的导出申请在“审批中心”。",
  },
};

export function CasesPage() {
  return (
    <WorkRoot>
      <CasesBody />
    </WorkRoot>
  );
}

function CasesBody() {
  const { has } = useRoles();
  const go = useGo();
  const search = useSearch({ strict: false }) as { moved?: string };
  const params = useParams({ strict: false }) as { jobId?: string };
  const investigator = has(role.investigator);
  const pager = usePager("cases");
  const query = useGuardedQuery({ ...specs.caseList(pager.cursor), enabled: investigator });
  const [filter, setFilter] = useState<Filter>("all");
  const [creating, setCreating] = useState(false);
  const unresolved = useUnresolved(owners.createCase());
  const page = query.data;
  const all = page?.items ?? [];
  const open = all.filter((item) => item.status === "open").length;
  const rows = filter === "all" ? all : all.filter((item) => item.status === filter);
  const hint =
    typeof search.moved === "string" && Object.hasOwn(moved, search.moved)
      ? moved[search.moved]
      : undefined;

  const columns: TableColumnsType<CaseFacts> = [
    {
      title: "案件",
      key: "case",
      onCell: labelled("案件"),
      render: (_, item) => (
        <div className="xs-w-case">
          <RouteLink to={`/cases/${item.case_id}`}>
            <span className="xs-w-text">{item.purpose}</span>
          </RouteLink>
          <IdChip id={item.case_id} label="案件 ID" />
        </div>
      ),
    },
    {
      title: "状态",
      key: "status",
      onCell: labelled("状态"),
      render: (_, item) => <StatePill pill={casePill[item.status]} />,
    },
    {
      title: "创建时间",
      key: "created",
      onCell: labelled("创建时间"),
      render: (_, item) => <Time value={item.created_at} />,
    },
  ];

  return (
    <div className="xs-w-stack">
      {investigator && (
        <PageActions>
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
            onClick={() => setCreating(true)}
          >
            新建案件
          </Button>
        </PageActions>
      )}
      {hint && (
        <Alert
          type="info"
          showIcon
          closable={{ onClose: () => go("/cases", { replace: true }) }}
          title={hint.title}
          description={hint.text}
        />
      )}
      <PendingNotice operation={unresolved} label="创建案件" onOpen={() => setCreating(true)} />
      {investigator ? (
        <>
          <div className="xs-w-between xs-w-toolbar">
            <Segmented<Filter>
              aria-label="案件状态筛选"
              value={filter}
              onChange={setFilter}
              options={[
                { label: `全部 ${all.length}`, value: "all" },
                { label: `开放 ${open}`, value: "open" },
                { label: `已关闭 ${all.length - open}`, value: "closed" },
              ]}
            />
            {page && <Observed asOf={page.as_of} requestId={page.request_id} />}
          </div>
          <LoadState
            pending={query.isPending}
            error={query.error}
            onRetry={() => void query.refetch()}
          >
            {page && (
              <>
                <Table<CaseFacts>
                  className="xs-w-table xs-w-clickable"
                  rowKey="case_id"
                  size="middle"
                  pagination={false}
                  columns={columns}
                  dataSource={rows}
                  loading={query.isFetching && !query.isPending}
                  onRow={(item) => ({
                    onClick: (event) => {
                      if ((event.target as HTMLElement).closest("a,button")) return;
                      go(`/cases/${item.case_id}`);
                    },
                  })}
                  locale={{
                    emptyText:
                      all.length === 0
                        ? "当前页没有本人案件。"
                        : `当前页没有${filter === "open" ? "开放" : "已关闭"}案件；筛选只作用于已读取的这一页，可翻页继续查看。`,
                  }}
                />
                <Pager
                  pager={pager}
                  count={all.length}
                  nextCursor={page.next_cursor}
                  busy={query.isFetching}
                  noun="个案件"
                />
              </>
            )}
          </LoadState>
          <p className="xs-w-muted">
            “我的案件”包含本人开放和已关闭的案件，按案件 ID
            降序；每页是一次独立的审计读取，创建或关闭后会重新读取。
          </p>
        </>
      ) : (
        <CaseLookup canHold={has(role.audit)} />
      )}
      {creating && (
        <CreateCaseDialog
          onClose={() => setCreating(false)}
          onCreated={(created) => go(`/cases/${created.case_id}`)}
        />
      )}
      {params.jobId && <JobDialog jobId={params.jobId} onClose={() => go("/cases")} />}
    </div>
  );
}

/** For a role that may manage holds but cannot list cases: open a case by its ID. */
function CaseLookup({ canHold }: { canHold: boolean }) {
  const go = useGo();
  const [value, setValue] = useState("");
  const valid = casePattern.test(value);
  return (
    <section className="xs-w-card" aria-label="按案件 ID 打开">
      <h4>按案件 ID 打开案件</h4>
      <p className="xs-w-muted">
        {canHold
          ? "你的角色可以管理案件的证据保留，但案件列表只对 Investigator 开放。输入案件 ID 打开案件，在“保留锁”页签中管理保留。"
          : "当前角色不能读取案件列表。服务端对每个请求独立授权。"}
      </p>
      {canHold && (
        <form
          className="xs-w-inline"
          onSubmit={(event) => {
            event.preventDefault();
            if (valid) go(`/cases/${value}`);
          }}
        >
          <Field
            id="case-lookup"
            label="案件 ID"
            help="case_ 前缀加小写 UUIDv7"
            error={value.length > 0 && !valid ? "案件 ID 格式无效" : null}
          >
            <Input
              id="case-lookup"
              className="mono"
              value={value}
              placeholder="case_…"
              autoComplete="off"
              spellCheck={false}
              aria-describedby="case-lookup-help"
              onChange={(event) => setValue(event.target.value.trim())}
            />
          </Field>
          <Button
            type="primary"
            htmlType="submit"
            icon={<SearchOutlined aria-hidden="true" />}
            disabled={!valid}
          >
            打开案件
          </Button>
        </form>
      )}
    </section>
  );
}

/** A small status dialog for one analysis job, opened from the command palette. */
function JobDialog({ jobId, onClose }: { jobId: string; onClose: () => void }) {
  const query = useGuardedQuery(specs.job(jobId));
  const job = query.data?.job ?? null;
  return (
    <Modal
      open
      title="案件分析任务"
      onCancel={onClose}
      destroyOnHidden
      footer={
        <Space>
          {job && <RouteLink to={`/cases/${job.case_id}/analysis`}>打开该案件的分析页签</RouteLink>}
          <Button onClick={onClose}>关闭</Button>
        </Space>
      }
    >
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {query.data && job ? (
          <JobCard job={job} requestId={query.data.request_id} />
        ) : (
          <Alert
            type="warning"
            showIcon
            title="当前主体范围内未找到该任务"
            description="未知、他人或跨范围的任务统一显示为未找到，不泄露它是否存在。"
          />
        )}
      </LoadState>
    </Modal>
  );
}
