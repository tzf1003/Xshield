import { FilterOutlined, ReloadOutlined } from "@ant-design/icons";
import { Button, Input, Popover, Segmented, Switch, Table, type TableColumnsType, Tag } from "antd";
import { useCallback, useState } from "react";
import { ApiError, requestPattern } from "../../api-contract.ts";
import { conditionProblem } from "../../investigation/filter-fields.ts";
import { requestPath, useInvestigationNavigate } from "../../investigation/navigation.ts";
import {
  buildStreamPlan,
  emptyStreamFilters,
  extraFilterCount,
  outcomesFor,
  type StreamFilters,
  type StreamOutcome,
  planKey,
} from "../../investigation/plans.ts";
import { canSearch } from "../../investigation/roles.ts";
import { useCursorPages } from "../../investigation/use-cursor-pages.ts";
import { useRemembered } from "../../investigation/view-memory.ts";
import type { SearchEvent, SearchPlan, SearchResponse } from "../../search.ts";
import { useSession } from "../../security/SessionProvider";
import { normalizePaste } from "../../shell/palette-classifier.ts";
import { PageActions } from "../../shell/page-actions";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { ObjectId } from "../../ui/ObjectId";
import { ReasonCode } from "../../ui/ReasonCode";
import { EmptyState, ErrorState, LoadingState } from "../../ui/states";
import { TimeRangePicker, checkedResolution } from "../../ui/TimeRangePicker";
import { EventTime } from "../../ui/EventTime";
import { isoToMs, formatDuration, formatSpan, type RangeIntent } from "../../ui/time-range.ts";
import { QueryDetails } from "./QueryDetails";
import "./investigation.css";

type StreamDraft = Readonly<{ range: RangeIntent; filters: StreamFilters }>;

const defaultDraft: StreamDraft = {
  range: { kind: "preset", preset: "1h" },
  filters: emptyStreamFilters,
};

/** A subject reference is a low-entropy identifier: it is never kept when the page is left. */
const scrubDraft = (draft: StreamDraft): StreamDraft => ({
  ...draft,
  filters: { ...draft.filters, subjectRef: "" },
});

const outcomeLabels: Record<StreamOutcome, string> = {
  all: "全部",
  DENY: "拒绝",
  ALLOW: "放行",
  UNKNOWN: "未知",
};

type Applied = Readonly<{ plan: SearchPlan; nonce: number }>;

function acceptsWindow(window: { start: string; end: string }): boolean {
  try {
    buildStreamPlan(window, emptyStreamFilters);
    return true;
  } catch {
    return false;
  }
}

function resolveDraft(draft: StreamDraft): SearchPlan {
  const resolution = checkedResolution(draft.range, Date.now(), acceptsWindow);
  if (!resolution.window) throw new ApiError("CONTROL_QUERY_INVALID");
  return buildStreamPlan(resolution.window, draft.filters);
}

/** 请求流: indexed terminal request events, newest first, built on structured search. */
export function RequestStreamPage() {
  const { state } = useSession();
  const allowed = canSearch(state.roles);
  const [draft, setDraft] = useRemembered<StreamDraft>(
    "stream.draft",
    () => defaultDraft,
    scrubDraft,
  );
  const [formError, setFormError] = useState<unknown>(null);
  // The first read happens on open, with the remembered filters, as one audited search.
  const [applied, setApplied] = useState<Applied | null>(() => {
    if (!allowed) return null;
    try {
      return { plan: resolveDraft(draft), nonce: 1 };
    } catch {
      return null;
    }
  });
  const [moreOpen, setMoreOpen] = useState(false);

  const apply = useCallback(
    (next: StreamDraft) => {
      setDraft(next);
      try {
        const plan = resolveDraft(next);
        setFormError(null);
        setApplied((current) => ({ plan, nonce: (current?.nonce ?? 0) + 1 }));
      } catch (error) {
        setFormError(error);
      }
    },
    [setDraft],
  );

  const { filters } = draft;
  const aborted = filters.terminal === "request.aborted";

  return (
    <div className="xs-page">
      <section className="xs-card xs-toolbar" aria-label="请求流筛选">
        <div className="xs-toolbar-row">
          <div className="xs-toolbar-group">
            <span className="xs-toolbar-label" id="stream-outcome-label">
              判定
            </span>
            <Segmented<StreamOutcome>
              aria-labelledby="stream-outcome-label"
              value={filters.outcome}
              disabled={!allowed}
              options={outcomesFor(filters.terminal).map((value) => ({
                value,
                label: outcomeLabels[value],
              }))}
              onChange={(outcome) => apply({ ...draft, filters: { ...filters, outcome } })}
            />
            <Switch
              size="small"
              checked={aborted}
              disabled={!allowed}
              aria-labelledby="stream-aborted-label"
              onChange={(checked) =>
                apply({
                  ...draft,
                  filters: {
                    ...filters,
                    terminal: checked ? "request.aborted" : "request.completed",
                    outcome: filters.outcome === "UNKNOWN" && !checked ? "all" : filters.outcome,
                  },
                })
              }
            />
            <span className="xs-toolbar-note" id="stream-aborted-label">
              改看中止 / 未完成请求（request.aborted）
            </span>
          </div>
          <OpenByRequestId />
        </div>
        <div className="xs-toolbar-row">
          <TimeRangePicker
            value={draft.range}
            accepts={acceptsWindow}
            disabled={!allowed}
            onChange={(range) => {
              const next = { ...draft, range };
              if (range.kind === "custom") setDraft(next);
              else apply(next);
            }}
          />
          <div className="xs-toolbar-actions">
            {draft.range.kind === "custom" ? (
              <Button type="primary" disabled={!allowed} onClick={() => apply(draft)}>
                应用时间范围
              </Button>
            ) : null}
            <Popover
              trigger="click"
              open={moreOpen}
              onOpenChange={setMoreOpen}
              placement="bottomRight"
              title="更多筛选"
              content={
                <MoreFilters
                  filters={filters}
                  onApply={(next) => {
                    setMoreOpen(false);
                    apply({ ...draft, filters: next });
                  }}
                />
              }
            >
              <Button icon={<FilterOutlined aria-hidden="true" />} disabled={!allowed}>
                更多筛选
                {extraFilterCount(filters) > 0 ? `（${extraFilterCount(filters)}）` : ""}
              </Button>
            </Popover>
          </div>
        </div>
        <ActiveFilters filters={filters} onChange={(next) => apply({ ...draft, filters: next })} />
        <p className="xs-toolbar-hint">
          列表是已索引的终态事件（<span className="mono">{filters.terminal}</span>
          ），不是实时流量，可能落后于网关；方法与操作 ID 在请求详情中查看。
        </p>
        <p className="xs-toolbar-hint">
          列表来自结构化检索，需要 Investigator；打开请求详情另需 Observer。两者由服务端分别校验。
        </p>
      </section>
      {formError ? <ErrorState error={formError} title="查询条件未通过校验" /> : null}
      {!allowed ? (
        <section className="xs-card">
          <EmptyState title="当前会话没有 Investigator 角色，无法浏览请求列表">
            请求列表基于结构化检索。你仍可在上方输入请求 ID 打开详情（需要
            Observer）；角色由服务端授予， 此处不会改变任何权限。
          </EmptyState>
        </section>
      ) : applied ? (
        <StreamResults key={applied.nonce} plan={applied.plan} />
      ) : null}
    </div>
  );
}

/** The paste path for a known request ID; the ⌘K palette is the other one. */
function OpenByRequestId() {
  const navigateTo = useInvestigationNavigate();
  const [value, setValue] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  function open() {
    const id = normalizePaste(value);
    if (!requestPattern.test(id)) {
      setProblem("请输入规范的请求 ID（req_ 加小写 UUIDv7）。");
      return;
    }
    setProblem(null);
    navigateTo.go(requestPath(id));
  }
  return (
    <div className="xs-open">
      <Input.Search
        aria-label="按请求 ID 打开"
        placeholder="按请求 ID 打开（req_…）"
        enterButton="打开"
        value={value}
        status={problem ? "error" : undefined}
        maxLength={64}
        autoComplete="off"
        spellCheck={false}
        onChange={(event) => {
          setValue(event.target.value);
          setProblem(null);
        }}
        onSearch={open}
      />
      {problem ? <p className="xs-field-error">{problem}</p> : null}
    </div>
  );
}

function ActiveFilters({
  filters,
  onChange,
}: {
  filters: StreamFilters;
  onChange: (next: StreamFilters) => void;
}) {
  const tags: { key: string; text: string; clear: () => void }[] = [];
  if (filters.operationId)
    tags.push({
      key: "operation",
      text: `操作 ID：${filters.operationId}`,
      clear: () => onChange({ ...filters, operationId: "" }),
    });
  if (filters.reasonCode)
    tags.push({
      key: "reason",
      text: `原因码：${filters.reasonCode}`,
      clear: () => onChange({ ...filters, reasonCode: "" }),
    });
  if (filters.traceId)
    tags.push({
      key: "trace",
      text: `Trace：${filters.traceId}`,
      clear: () => onChange({ ...filters, traceId: "" }),
    });
  if (filters.subjectRef)
    tags.push({
      key: "subject",
      text: "主体引用：已设置（不回显）",
      clear: () => onChange({ ...filters, subjectRef: "" }),
    });
  if (tags.length === 0) return null;
  return (
    <ul className="xs-tags" aria-label="已启用的筛选">
      {tags.map((tag) => (
        <li key={tag.key}>
          <Tag closable={{ "aria-label": `移除筛选：${tag.text}` }} onClose={tag.clear}>
            {tag.text}
          </Tag>
        </li>
      ))}
    </ul>
  );
}

type FieldKey = "operationId" | "reasonCode" | "traceId" | "subjectRef";
const fieldSpec: Record<
  FieldKey,
  {
    label: string;
    field: "operation_id" | "reason_code" | "trace_id" | "subject_ref";
    placeholder: string;
  }
> = {
  operationId: { label: "操作 ID", field: "operation_id", placeholder: "例如 orders.read" },
  reasonCode: {
    label: "原因码",
    field: "reason_code",
    placeholder: "例如 UI_ACTION_NOT_AVAILABLE",
  },
  traceId: { label: "Trace ID", field: "trace_id", placeholder: "32 位小写十六进制" },
  subjectRef: { label: "主体引用", field: "subject_ref", placeholder: "仅精确匹配，不会回显" },
};

function MoreFilters({
  filters,
  onApply,
}: {
  filters: StreamFilters;
  onApply: (next: StreamFilters) => void;
}) {
  const [values, setValues] = useState<Record<FieldKey, string>>({
    operationId: filters.operationId,
    reasonCode: filters.reasonCode,
    traceId: filters.traceId,
    subjectRef: filters.subjectRef,
  });
  const [problems, setProblems] = useState<Partial<Record<FieldKey, string>>>({});

  function submit() {
    const found: Partial<Record<FieldKey, string>> = {};
    const next: Record<FieldKey, string> = { ...values };
    for (const key of Object.keys(fieldSpec) as FieldKey[]) {
      const raw = key === "traceId" ? normalizePaste(values[key]) : values[key].trim();
      next[key] = raw;
      if (raw === "") continue;
      const problem = conditionProblem({ field: fieldSpec[key].field, value: raw });
      if (problem) found[key] = problem;
    }
    setProblems(found);
    if (Object.keys(found).length === 0) onApply({ ...filters, ...next });
  }

  return (
    <form
      className="xs-more"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      {(Object.keys(fieldSpec) as FieldKey[]).map((key) => (
        <div className="xs-more-field" key={key}>
          <label htmlFor={`stream-${key}`}>{fieldSpec[key].label}</label>
          <Input
            id={`stream-${key}`}
            value={values[key]}
            status={problems[key] ? "error" : undefined}
            placeholder={fieldSpec[key].placeholder}
            autoComplete="off"
            spellCheck={false}
            maxLength={key === "subjectRef" ? 256 : 128}
            allowClear
            onChange={(event) => setValues({ ...values, [key]: event.target.value })}
          />
          {problems[key] ? <p className="xs-field-error">{problems[key]}</p> : null}
        </div>
      ))}
      <div className="xs-more-actions">
        <Button
          onClick={() =>
            setValues({ operationId: "", reasonCode: "", traceId: "", subjectRef: "" })
          }
        >
          清空
        </Button>
        <Button type="primary" htmlType="submit">
          应用筛选
        </Button>
      </div>
    </form>
  );
}

function durationText(event: SearchEvent): string {
  return event.duration_us > 0 ? formatDuration(event.duration_us) : "—";
}

function StreamResults({ plan }: { plan: SearchPlan }) {
  const navigateTo = useInvestigationNavigate();
  const stream = useCursorPages<SearchResponse>({
    key: ["investigation", "stream", planKey(plan)],
    fetchPage: (client, cursor, signal) => client.search(plan, cursor, signal),
  });
  const rows = stream.pages.flatMap((page) => page.events);
  const first = stream.pages[0];
  const last = stream.pages.at(-1);

  const columns: TableColumnsType<SearchEvent> = [
    {
      title: "发生时间",
      dataIndex: "occurred_at",
      width: 168,
      render: (value: string) => <EventTime value={value} />,
    },
    {
      title: "判定",
      dataIndex: "outcome",
      width: 96,
      render: (value: string | null) => <DecisionBadge decision={value} />,
    },
    {
      title: "原因",
      dataIndex: "reason_code",
      render: (value: string | null) => <ReasonCode code={value} quietCopy />,
    },
    {
      title: "请求",
      dataIndex: "request_id",
      width: 232,
      render: (value: string | null) =>
        value ? (
          <ObjectId
            value={value}
            short
            quietCopy
            href={requestPath(value)}
            onOpen={() => navigateTo.go(requestPath(value))}
          />
        ) : (
          <span className="muted">未记录</span>
        ),
    },
    {
      title: "耗时",
      dataIndex: "duration_us",
      width: 96,
      align: "right",
      render: (_value: number, event) => durationText(event),
    },
  ];

  const newest = first?.events[0];
  const lagMs =
    first && newest ? (isoToMs(first.as_of) ?? 0) - (isoToMs(newest.occurred_at) ?? 0) : null;

  return (
    <>
      <PageActions>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          disabled={stream.loading}
          onClick={stream.refresh}
        >
          刷新
        </Button>
      </PageActions>
      {stream.firstError ? <ErrorState error={stream.firstError} onRetry={stream.refresh} /> : null}
      {first ? (
        <CompletenessBanner
          label="请求流索引状态"
          input={{
            hasGaps: stream.pages.some((page) => page.has_gaps),
            pendingSegments: Math.max(...stream.pages.map((page) => page.pending_segments)),
            observations: [
              { label: "首页", asOf: first.as_of, watermark: first.index_watermark },
              ...(last && last !== first
                ? [{ label: "末页", asOf: last.as_of, watermark: last.index_watermark }]
                : []),
            ],
          }}
          note={
            newest && lagMs !== null ? (
              <>
                最新终态事件发生于 <EventTime value={newest.occurred_at} />
                ，距索引观察时间 {formatSpan(lagMs)}；之后到达的请求可能尚未发布到索引。
              </>
            ) : null
          }
        />
      ) : null}
      <section className="xs-card" aria-label="请求流结果" aria-busy={stream.loading}>
        {stream.loading ? <LoadingState label="正在读取请求流" /> : null}
        {first ? (
          <>
            <div className="xs-card-head">
              <h2>请求终态</h2>
              <span className="xs-count" aria-live="polite">
                已加载 {rows.length} 条
              </span>
            </div>
            <Table<SearchEvent>
              size="middle"
              rowKey="event_id"
              columns={columns}
              dataSource={rows}
              pagination={false}
              scroll={{ x: 720 }}
              locale={{
                emptyText: (
                  <EmptyState title="该时间范围内没有已索引的请求终态" icon="search">
                    空结果不证明没有流量：事件可能尚未发布、已过保留期或不在当前作用域，请结合上方索引状态判断。
                  </EmptyState>
                ),
              }}
              onRow={(event) => ({
                onClick: () => {
                  if (event.request_id) navigateTo.go(requestPath(event.request_id));
                },
                className: event.request_id ? "xs-row-link" : undefined,
              })}
            />
            <div className="xs-more-bar">
              {stream.moreError ? (
                <ErrorState
                  error={stream.moreError}
                  onRetry={stream.retryMore}
                  retryLabel="重试下一页"
                />
              ) : null}
              <Button disabled={!stream.hasMore || stream.loadingMore} onClick={stream.loadMore}>
                加载更多
              </Button>
              <span className="xs-count" aria-live="polite">
                {stream.loadingMore
                  ? "正在读取下一页…"
                  : stream.hasMore
                    ? "还有后续页，沿用已提交计划"
                    : stream.capped
                      ? "已达到加载上限，请缩小时间范围"
                      : "当前可见结果已读完"}
              </span>
            </div>
            <p className="xs-foot xs-table-foot">
              分页期间的新发布或到期可能改变后续可见记录；游标不是冻结快照。
            </p>
          </>
        ) : null}
      </section>
      {first ? <QueryDetails plan={plan} pages={stream.pages} /> : null}
    </>
  );
}
