import { ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { useSearch } from "@tanstack/react-router";
import { Alert, Button, Input, Space, Table, type TableColumnsType } from "antd";
import { type FormEvent, useState } from "react";
import { jobPattern } from "../../api-contract.ts";
import { RoleHint } from "../../operations/Parts";
import { isRoleRefusal } from "../../operations/sources.ts";
import { useGuardedQuery } from "../../security/hooks";
import { useSession } from "../../security/SessionProvider";
import { useShellActions } from "../../shell/actions";
import {
  normalizePaste,
  type PaletteResult,
  paletteSearch,
  recognise,
} from "../../shell/palette-classifier.ts";
import { operationReason } from "../../ui/operation-reasons.ts";
import { JobCard } from "../../work/JobCard";
import { RouteLink, useGo } from "../../work/nav";
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
import { specs } from "../../work/queries.ts";
import type { JobListItem } from "../../job-list.ts";
import { jobPill } from "../../work/status.ts";
import { useRoles } from "../../work/roles.ts";
import { WorkRoot } from "../../work/WorkRoot";
import "../../operations/operations.css";

type Problem = Readonly<{ text: string; options: readonly PaletteResult[] }>;

/**
 * Why a pasted value is not a job ID, in the shell's own words: the command palette's classifier
 * recognises every object ID by its prefix, so a case or request ID pasted here is named and its
 * own page is offered instead (only pages this operator's roles show).
 */
function classify(value: string, roles: readonly string[] | null, siteId: string | null): Problem {
  if (value === "") return { text: "请输入任务 ID（job_ 加小写 UUIDv7）。", options: [] };
  const outcome = paletteSearch(value, roles, siteId);
  const objects = outcome.results.filter((result) => result.group === "object");
  const noun = recognise(value)?.noun;
  if (noun && objects.length > 0) {
    return { text: `这是${noun}，不是任务 ID。可以直接打开它：`, options: objects };
  }
  if (noun) return { text: outcome.notice ?? `这是${noun}，不是任务 ID。`, options: [] };
  if (/^job_/i.test(value)) {
    return {
      text: "任务 ID 的格式不对：应为 job_ 加小写 UUIDv7，例如 job_018f2a3b-4c5d-7000-8000-000000000041。",
      options: [],
    };
  }
  return {
    text: outcome.notice ?? "这不是任务 ID：任务 ID 以 job_ 开头，后接小写 UUIDv7。",
    options: [],
  };
}

/**
 * 我的任务: the caller's own jobs, newest identity first. Each row opens the same by-ID view as
 * the lookup, so the owner-scoped detail read stays the only source of a job's status.
 */
function MyJobs() {
  const pager = usePager("jobs:mine");
  const query = useGuardedQuery(specs.jobList(pager.cursor));
  const go = useGo();
  const page = query.data;
  const columns: TableColumnsType<JobListItem> = [
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
      title: "案件",
      key: "case",
      onCell: labelled("案件"),
      render: (_, row) => <IdChip id={row.case_id} label="案件 ID" />,
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
      render: (_, row) => (
        <Button
          size="small"
          onClick={() => go("/operations/jobs", { search: { job: row.job_id } })}
        >
          查看
        </Button>
      ),
    },
  ];
  return (
    <section className="xs-w-card" aria-label="我的任务">
      <div className="xs-w-between xs-w-toolbar">
        {page ? <Observed asOf={page.as_of} requestId={page.request_id} /> : <span />}
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          loading={query.isFetching}
          onClick={() => void query.refetch()}
        >
          刷新
        </Button>
      </div>
      <LoadState pending={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {page && (
          <>
            <Table<JobListItem>
              className="xs-w-table"
              rowKey="job_id"
              size="middle"
              pagination={false}
              columns={columns}
              dataSource={page.items}
              loading={query.isFetching && !query.isPending}
              locale={{ emptyText: "没有本人提交的任务。" }}
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

function JobsBody() {
  const { roles } = useRoles();
  const { state } = useSession();
  const shell = useShellActions();
  const go = useGo();
  // The route validates `?job=` (route-tree.ts): only a canonical job ID gets here.
  const search = useSearch({ strict: false }) as { job?: string };
  const jobId = search.job ?? null;
  const [draft, setDraft] = useState(jobId ?? "");
  const [problem, setProblem] = useState<Problem | null>(null);
  // Opening an address with `?job=` is the lookup itself: it reads once, then only on request.
  const query = useGuardedQuery(specs.job(jobId ?? "job_none", jobId !== null));
  const investigator = roles === null || roles.includes("investigator");
  const job = query.data?.job ?? null;
  const reason = job ? operationReason(job.reason_code) : null;

  function submit(event: FormEvent) {
    event.preventDefault();
    const value = normalizePaste(draft);
    if (jobPattern.test(value)) {
      setProblem(null);
      setDraft(value);
      if (value === jobId) void query.refetch();
      else go("/operations/jobs", { search: { job: value } });
      return;
    }
    setProblem(classify(value, roles, state.session?.site_id ?? null));
  }

  return (
    <div className="xs-w-stack">
      {!investigator && (
        <RoleHint title="需要 Investigator 角色">
          任务状态只对提交它的 Investigator 可见，服务端会拒绝其他身份的读取。
        </RoleHint>
      )}
      <section className="xs-w-card" aria-label="按任务 ID 查询">
        <form className="xs-op-lookup" onSubmit={submit}>
          <label htmlFor="job-id" className="xs-op-label">
            任务 ID
          </label>
          <Space.Compact className="xs-op-lookup-row">
            <Input
              id="job-id"
              className="mono"
              placeholder="job_…"
              value={draft}
              maxLength={80}
              autoComplete="off"
              spellCheck={false}
              aria-describedby="job-id-help"
              status={problem ? "error" : undefined}
              onChange={(event) => {
                setDraft(event.target.value);
                setProblem(null);
              }}
            />
            <Button type="primary" htmlType="submit" icon={<SearchOutlined aria-hidden="true" />}>
              查询
            </Button>
          </Space.Compact>
          <small id="job-id-help" className="xs-w-muted">
            粘贴 job_ 开头的任务
            ID（来自案件的“分析任务”页签）。只能读取本人提交的任务；每次查询都会被服务端审计。
          </small>
        </form>
        {problem && (
          <Alert
            type="warning"
            showIcon
            title={problem.text}
            description={
              problem.options.length > 0 ? (
                <Space wrap>
                  {problem.options.map((option) =>
                    option.action.type === "navigate" ? (
                      <RouteLink
                        key={option.id}
                        to={option.action.to}
                        search={option.action.search}
                      >
                        {option.label}
                      </RouteLink>
                    ) : shell ? (
                      <Button key={option.id} size="small" onClick={() => shell.run(option.action)}>
                        {option.label}
                      </Button>
                    ) : null,
                  )}
                </Space>
              ) : undefined
            }
          />
        )}
      </section>
      {investigator && <MyJobs />}
      {jobId !== null && (
        <section className="xs-w-card" aria-label="任务状态">
          <div className="xs-w-between">
            <h2 className="xs-op-title">任务状态</h2>
            <Button
              icon={<ReloadOutlined aria-hidden="true" />}
              loading={query.isFetching}
              onClick={() => void query.refetch()}
            >
              重新读取
            </Button>
          </div>
          {query.isError && isRoleRefusal(query.error) ? (
            <RoleHint title="任务状态被服务端拒绝">读取任务需要 Investigator 角色。</RoleHint>
          ) : query.isError ? (
            <ErrorNotice
              error={query.error}
              title="任务状态读取失败"
              action={
                <Button size="small" onClick={() => void query.refetch()}>
                  重试
                </Button>
              }
            />
          ) : (
            <LoadState pending={query.isPending} error={null} onRetry={() => void query.refetch()}>
              {query.data && job ? (
                <div className="xs-w-stack">
                  <JobCard job={job} requestId={query.data.request_id} />
                  <Alert
                    type={reason?.tone === "success" ? "success" : "info"}
                    showIcon
                    title={reason?.label ?? "服务端返回了控制台尚未识别的原因码"}
                    description={
                      <>
                        {reason?.text ?? "原因码保留在上方，供核对。"}{" "}
                        <span className="mono">{job.reason_code}</span>
                      </>
                    }
                  />
                  <RouteLink to={`/cases/${job.case_id}/analysis`}>打开该案件的分析页签</RouteLink>
                </div>
              ) : (
                <Alert
                  type="warning"
                  showIcon
                  title="当前主体范围内未找到该任务"
                  description="只能读取本人在当前范围内提交的任务；未知、他人或跨范围的任务统一显示为未找到，不泄露它是否存在。"
                />
              )}
            </LoadState>
          )}
        </section>
      )}
    </div>
  );
}

/** 后台任务 (`/operations/jobs`): look one job up by its ID; `?job=` makes the lookup an address. */
export function JobsPage() {
  return (
    <WorkRoot>
      <JobsBody />
    </WorkRoot>
  );
}
