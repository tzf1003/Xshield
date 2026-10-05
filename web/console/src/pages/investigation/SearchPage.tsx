import { PlusOutlined, ReloadOutlined, SearchOutlined, TableOutlined } from "@ant-design/icons";
import { useRouterState } from "@tanstack/react-router";
import {
  Button,
  Checkbox,
  Input,
  Popover,
  Select,
  Table,
  type TableColumnsType,
  Tag,
  Tooltip,
} from "antd";
import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "../../api-contract.ts";
import { type EventView, fromSearchEvent } from "../../investigation/event-view.ts";
import {
  type Condition,
  conditionProblem,
  detectField,
  type FilterField,
  fieldDef,
  filterFields,
  MAX_CONDITIONS,
  outcomeValues,
} from "../../investigation/filter-fields.ts";
import { requestPath, useInvestigationNavigate } from "../../investigation/navigation.ts";
import { buildSearchPlan, PAGE_SIZES, planKey } from "../../investigation/plans.ts";
import { canSearch, ROLE_SEARCH_TEXT } from "../../investigation/roles.ts";
import { decodePrefill, type SearchPreset } from "../../investigation/search-preset.ts";
import { useCursorPages } from "../../investigation/use-cursor-pages.ts";
import { useRemembered } from "../../investigation/view-memory.ts";
import type { SearchEvent, SearchPlan, SearchResponse } from "../../search.ts";
import { useSession } from "../../security/SessionProvider";
import { normalizePaste } from "../../shell/palette-classifier.ts";
import { PageActions } from "../../shell/page-actions";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { EventTime } from "../../ui/EventTime";
import { ObjectId } from "../../ui/ObjectId";
import { ReasonCode } from "../../ui/ReasonCode";
import { eventTypeName, stageName } from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState, LoadingState } from "../../ui/states";
import { checkedResolution, TimeRangePicker } from "../../ui/TimeRangePicker";
import { formatDuration, type RangeIntent } from "../../ui/time-range.ts";
import { AddToCaseModal } from "./AddToCaseModal";
import { ArtifactDrawer } from "./ArtifactDrawer";
import { EventDrawer } from "./EventDrawer";
import { QueryDetails } from "./QueryDetails";
import "./investigation.css";
import "./search.css";

const columnOptions = [
  { key: "type", label: "事件类型" },
  { key: "stage", label: "阶段" },
  { key: "outcome", label: "结果" },
  { key: "reason", label: "原因" },
  { key: "request", label: "请求" },
  { key: "trace", label: "Trace" },
  { key: "duration", label: "耗时" },
  { key: "seq", label: "序号" },
  { key: "evidence", label: "证据" },
] as const;

type ColumnKey = (typeof columnOptions)[number]["key"];

const defaultColumns: readonly ColumnKey[] = ["type", "stage", "outcome", "reason", "request"];

type SearchDraft = Readonly<{
  conditions: readonly Condition[];
  range: RangeIntent;
  sort: SearchPlan["sort"];
  limit: number;
  columns: readonly ColumnKey[];
}>;

const defaultDraft: SearchDraft = {
  conditions: [],
  range: { kind: "preset", preset: "24h" },
  sort: "occurred_at_desc",
  limit: 25,
  columns: defaultColumns,
};

/** A subject reference is a low-entropy identifier: it is never kept when the page is left. */
const scrubDraft = (draft: SearchDraft): SearchDraft => ({
  ...draft,
  conditions: draft.conditions.filter((condition) => condition.field !== "subject_ref"),
});

/** What another page hands over is one condition and nothing else: no range, no submission. */
function draftFromPreset(base: SearchDraft, preset: SearchPreset): SearchDraft {
  return {
    ...base,
    conditions: [{ id: 1, field: preset.kind, value: preset.value }],
    range: { kind: "none" },
  };
}

function acceptsWindow(window: { start: string; end: string }): boolean {
  try {
    buildSearchPlan({ window, conditions: [], sort: "occurred_at_desc", limit: 10 });
    return true;
  } catch {
    return false;
  }
}

type Applied = Readonly<{ plan: SearchPlan; nonce: number }>;

/** Counts submit presses for the life of the page bundle, so no two reads share a cache entry. */
let submissions = 0;

const sortOptions: { value: SearchPlan["sort"]; label: string }[] = [
  { value: "occurred_at_desc", label: "最新优先" },
  { value: "occurred_at_asc", label: "最早优先" },
];

function describeCondition(condition: Pick<Condition, "field" | "value">): string {
  const def = fieldDef(condition.field);
  return `${def.label}：${condition.field === "subject_ref" ? "已设置（不回显）" : condition.value}`;
}

/** 结构化检索: allowlisted conditions, an explicit UTC window, nothing runs until you submit. */
export function SearchPage() {
  const { state } = useSession();
  const allowed = canSearch(state.roles);
  const [draft, setDraft] = useRemembered<SearchDraft>(
    "search.draft",
    () => defaultDraft,
    scrubDraft,
  );
  const [applied, setApplied] = useState<Applied | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [rangeNotice, setRangeNotice] = useState<string | null>(null);
  const [arrived, setArrived] = useState<SearchPreset | null>(null);

  // A search handed over by another page arrives as `?prefill=kind:value`. It fills the form once
  // per navigation and never submits: the range is yours to choose.
  const location = useRouterState({ select: (router) => router.location });
  const rawPrefill = (location.search as Record<string, unknown>).prefill;
  const prefill = useMemo(() => decodePrefill(rawPrefill), [rawPrefill]);
  const arrival = `${location.state.__TSR_key ?? location.state.key ?? ""}|${location.href}`;
  const handled = useRef<string | null>(null);
  useLayoutEffect(() => {
    if (handled.current === arrival) return;
    handled.current = arrival;
    if (!prefill) return;
    setDraft((current) => draftFromPreset(current, prefill));
    setApplied(null);
    setFormError(null);
    setRangeNotice(null);
    setArrived(prefill);
  }, [arrival, prefill, setDraft]);

  function edit(next: SearchDraft) {
    setDraft(next);
    // Editing the form retires the submitted plan, its rows and every cursor it produced.
    setApplied(null);
    setFormError(null);
    setRangeNotice(null);
    setArrived(null);
  }

  function submit() {
    const resolution = checkedResolution(draft.range, Date.now(), acceptsWindow);
    setArrived(null);
    if (!resolution.window) {
      setApplied(null);
      if (resolution.problem === "missing" || resolution.problem === "incomplete") {
        setFormError(null);
        setRangeNotice(
          resolution.problem === "missing"
            ? "请先选择时间范围：检索只查询你指定的 UTC 整秒半开窗口。"
            : "请完整填写时间范围的开始与结束时间。",
        );
      } else {
        setRangeNotice(null);
        setFormError(new ApiError("CONTROL_QUERY_INVALID"));
      }
      return;
    }
    try {
      const plan = buildSearchPlan({
        window: resolution.window,
        conditions: draft.conditions,
        sort: draft.sort,
        limit: draft.limit,
      });
      setFormError(null);
      setRangeNotice(null);
      submissions += 1;
      setApplied({ plan, nonce: submissions });
    } catch (error) {
      setApplied(null);
      setRangeNotice(null);
      setFormError(error);
    }
  }

  function addCondition(field: FilterField, value: string) {
    const id = draft.conditions.reduce((highest, item) => Math.max(highest, item.id), 0) + 1;
    edit({ ...draft, conditions: [...draft.conditions, { id, field, value }] });
  }

  const full = draft.conditions.length >= MAX_CONDITIONS;

  return (
    <div className="xs-page">
      <section className="xs-card xs-toolbar" aria-label="检索条件">
        {!allowed ? (
          <p className="xs-field-error" role="status">
            {ROLE_SEARCH_TEXT}当前会话没有 Investigator 角色，下列控件已停用。
          </p>
        ) : null}
        {arrived ? (
          <p className="xs-builder-note" role="status">
            {`已预填目标引用，请确认 UTC 时间窗后提交历史检索。条件「${fieldDef(arrived.kind).label}」已带入，时间范围尚未选择，也没有发起任何查询。`}
          </p>
        ) : null}
        <ConditionBuilder
          disabled={!allowed || full}
          full={full}
          onAdd={addCondition}
          existing={draft.conditions}
        />
        <div className="xs-conditions">
          <div className="xs-conditions-head">
            <span>
              已添加 {draft.conditions.length} / {MAX_CONDITIONS} 个条件
            </span>
            <Tooltip title="条件之间是「且」：同一个事件必须同时满足全部条件。">
              <span className="xs-sub">条件之间为「且」</span>
            </Tooltip>
            {draft.conditions.length > 0 ? (
              <Button
                size="small"
                type="link"
                disabled={!allowed}
                onClick={() => edit({ ...draft, conditions: [] })}
              >
                清空条件
              </Button>
            ) : null}
          </div>
          {draft.conditions.length > 0 ? (
            <ul className="xs-tags" aria-label="已添加的检索条件">
              {draft.conditions.map((condition) => (
                <li key={condition.id}>
                  <Tag
                    closable={
                      allowed
                        ? { "aria-label": `移除条件：${describeCondition(condition)}` }
                        : false
                    }
                    onClose={() =>
                      edit({
                        ...draft,
                        conditions: draft.conditions.filter((item) => item.id !== condition.id),
                      })
                    }
                  >
                    {describeCondition(condition)}
                  </Tag>
                </li>
              ))}
            </ul>
          ) : (
            <p className="xs-builder-note">不添加条件时返回时间范围内的全部已索引事件。</p>
          )}
        </div>
        <div className="xs-toolbar-row">
          <TimeRangePicker
            value={draft.range}
            accepts={acceptsWindow}
            disabled={!allowed}
            onChange={(range) => edit({ ...draft, range })}
          />
        </div>
        {rangeNotice ? (
          <p className="xs-field-error" role="alert">
            {rangeNotice}
          </p>
        ) : null}
        <div className="xs-options">
          <div className="xs-option">
            <label htmlFor="search-sort">事件时间排序</label>
            <Select<SearchPlan["sort"]>
              id="search-sort"
              value={draft.sort}
              options={sortOptions}
              disabled={!allowed}
              onChange={(sort) => edit({ ...draft, sort })}
            />
          </div>
          <div className="xs-option">
            <label htmlFor="search-limit">每页条数</label>
            <Select<number>
              id="search-limit"
              value={draft.limit}
              options={PAGE_SIZES.map((value) => ({ value, label: String(value) }))}
              disabled={!allowed}
              onChange={(limit) => edit({ ...draft, limit })}
            />
          </div>
          <Popover
            trigger="click"
            placement="bottomLeft"
            title="显示的列"
            content={
              <div className="xs-columns">
                <Checkbox.Group
                  value={[...draft.columns]}
                  options={columnOptions.map((option) => ({
                    value: option.key,
                    label: option.label,
                  }))}
                  style={{ display: "grid", gap: 6 }}
                  onChange={(next) => setDraft({ ...draft, columns: next as ColumnKey[] })}
                />
              </div>
            }
          >
            <Button icon={<TableOutlined aria-hidden="true" />}>选择列</Button>
          </Popover>
          <div className="xs-toolbar-actions">
            <Button
              type="primary"
              icon={<SearchOutlined aria-hidden="true" />}
              disabled={!allowed}
              onClick={submit}
            >
              检索事件
            </Button>
            <Button
              disabled={!allowed}
              onClick={() => edit({ ...defaultDraft, columns: draft.columns })}
            >
              重置
            </Button>
          </div>
        </div>
        <p className="xs-toolbar-hint">
          检索只读取已索引的脱敏事件，需要 Investigator；时间为 UTC 整秒半开窗口，最长 31
          天。条件与时间范围的任何修改都会使已有结果和分页游标失效，需重新提交。
        </p>
      </section>
      {formError ? <ErrorState error={formError} title="查询条件未通过校验" /> : null}
      {applied ? (
        <SearchResults
          key={applied.nonce}
          plan={applied.plan}
          submission={applied.nonce}
          columns={draft.columns}
        />
      ) : null}
    </div>
  );
}

type BuilderProps = {
  disabled: boolean;
  full: boolean;
  existing: readonly Condition[];
  onAdd: (field: FilterField, value: string) => void;
};

/** One condition at a time: pick a field (or paste an ID and let the shell recognise it). */
function ConditionBuilder({ disabled, full, existing, onAdd }: BuilderProps) {
  const [field, setField] = useState<FilterField | "auto">("auto");
  const [value, setValue] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const def = field === "auto" ? null : fieldDef(field);
  const detection = field === "auto" ? detectField(value) : null;

  function normalise(target: FilterField, raw: string): string {
    const input = fieldDef(target).input;
    if (input === "id") return normalizePaste(raw);
    if (input === "text" || input === "basis_points") return raw.trim();
    return raw;
  }

  function add() {
    let target: FilterField;
    let alternatives: readonly FilterField[] = [];
    if (field === "auto") {
      const found = detectField(value);
      if (!found) {
        setProblem(
          value.trim() === ""
            ? "请填写条件的值，或粘贴一个规范的 ID。"
            : "无法自动识别该值：请先选择条件字段，或粘贴规范的 ID（小写 UUIDv7 加前缀）。",
        );
        return;
      }
      target = found.field;
      alternatives = found.alternatives;
    } else target = field;
    const text = normalise(target, value);
    const issue = conditionProblem({ field: target, value: text });
    if (issue) {
      setProblem(issue);
      return;
    }
    if (existing.some((item) => item.field === target && item.value === text)) {
      setProblem("该条件已经添加。");
      return;
    }
    onAdd(target, text);
    setValue("");
    setProblem(null);
    setNotice(
      alternatives.length > 1
        ? `该前缀同时用于${alternatives.map((item) => fieldDef(item).label).join("与")}，已按「${fieldDef(target).label}」添加；如需另一种请手动选择字段。`
        : null,
    );
  }

  return (
    <div className="xs-builder">
      <div className="xs-builder-row">
        <label className="xs-visually-hidden" htmlFor="search-field">
          条件字段
        </label>
        <Select<FilterField | "auto">
          id="search-field"
          className="xs-builder-field"
          value={field}
          showSearch
          optionFilterProp="label"
          virtual={false}
          disabled={disabled}
          options={[
            { value: "auto", label: "自动识别（粘贴 ID）" },
            ...filterFields.map((item) => ({ value: item.id, label: item.label })),
          ]}
          onChange={(next) => {
            setField(next);
            setValue("");
            setProblem(null);
            setNotice(null);
          }}
        />
        <label className="xs-visually-hidden" htmlFor="search-value">
          条件值
        </label>
        {def?.input === "outcome" ? (
          <Select<string>
            id="search-value"
            className="xs-builder-value"
            value={value === "" ? undefined : value}
            placeholder="选择结果"
            disabled={disabled}
            options={outcomeValues.map((item) => ({ value: item, label: item }))}
            onChange={(next) => {
              setValue(next);
              setProblem(null);
            }}
          />
        ) : (
          <Input
            id="search-value"
            className="xs-builder-value"
            value={value}
            disabled={disabled}
            status={problem ? "error" : undefined}
            placeholder={def ? def.placeholder : "粘贴 ID，自动识别字段"}
            autoComplete="off"
            spellCheck={false}
            maxLength={def?.input === "subject" ? 256 : 160}
            onChange={(event) => {
              setValue(event.target.value);
              setProblem(null);
              setNotice(null);
            }}
            onPressEnter={add}
          />
        )}
        <Button icon={<PlusOutlined aria-hidden="true" />} disabled={disabled} onClick={add}>
          添加条件
        </Button>
      </div>
      {full ? (
        <p className="xs-builder-note" role="status">
          最多 {MAX_CONDITIONS} 个条件，已达上限；移除一个条件后才能继续添加。
        </p>
      ) : null}
      {problem ? <p className="xs-field-error">{problem}</p> : null}
      {!problem && detection ? (
        <p className="xs-builder-note">
          识别为：{detection.noun}
          {detection.alternatives.length > 1 ? "（该前缀有多种含义，默认取第一种）" : ""}
        </p>
      ) : null}
      {!problem && def ? <p className="xs-builder-note">{def.hint}</p> : null}
      {!problem && def?.needs ? (
        <p className="xs-builder-note">此条件另需 {def.needs} 角色，由服务端校验。</p>
      ) : null}
      {notice ? (
        <p className="xs-builder-note" role="status">
          {notice}
        </p>
      ) : null}
    </div>
  );
}

function durationText(event: SearchEvent): string {
  return event.duration_us > 0 ? formatDuration(event.duration_us) : "—";
}

function SearchResults({
  plan,
  submission,
  columns,
}: {
  plan: SearchPlan;
  /** Counts the submit presses: every press is a new audited read, even for the same plan. */
  submission: number;
  columns: readonly ColumnKey[];
}) {
  const navigateTo = useInvestigationNavigate();
  const { state } = useSession();
  const canAddToCase = canSearch(state.roles);
  const search = useCursorPages<SearchResponse>({
    key: ["investigation", "search", submission, planKey(plan)],
    fetchPage: (client, cursor, signal) => client.search(plan, cursor, signal),
  });
  const rows = search.pages.flatMap((page) => page.events);
  const views = rows.map(fromSearchEvent);
  const first = search.pages[0];
  const last = search.pages.at(-1);
  const [event, setEvent] = useState<EventView | null>(null);
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [caseTarget, setCaseTarget] = useState<string | null>(null);

  const show = (key: ColumnKey) => columns.includes(key);
  const tableColumns: TableColumnsType<SearchEvent> = [
    {
      title: "发生时间",
      dataIndex: "occurred_at",
      width: 168,
      render: (value: string) => <EventTime value={value} />,
    },
    ...(show("type")
      ? [
          {
            title: "事件类型",
            dataIndex: "event_type",
            render: (value: string) => {
              const type = eventTypeName(value);
              return (
                <span className="xs-event-cell">
                  {type.label}
                  {type.known ? <span className="mono">{value}</span> : null}
                </span>
              );
            },
          },
        ]
      : []),
    ...(show("stage")
      ? [
          {
            title: "阶段",
            dataIndex: "stage",
            render: (value: string | null) => (value ? stageName(value).label : "—"),
          },
        ]
      : []),
    ...(show("outcome")
      ? [
          {
            title: "结果",
            dataIndex: "outcome",
            width: 96,
            render: (value: string | null) => <DecisionBadge decision={value} />,
          },
        ]
      : []),
    ...(show("reason")
      ? [
          {
            title: "原因",
            dataIndex: "reason_code",
            render: (value: string | null) => <ReasonCode code={value} quietCopy />,
          },
        ]
      : []),
    ...(show("request")
      ? [
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
        ]
      : []),
    ...(show("trace")
      ? [
          {
            title: "Trace",
            dataIndex: "trace_id",
            width: 200,
            render: (value: string) => <ObjectId value={value} short quietCopy />,
          },
        ]
      : []),
    ...(show("duration")
      ? [
          {
            title: "耗时",
            dataIndex: "duration_us",
            width: 96,
            align: "right" as const,
            render: (_value: number, item: SearchEvent) => durationText(item),
          },
        ]
      : []),
    ...(show("seq")
      ? [
          {
            title: "序号",
            dataIndex: "request_seq",
            width: 80,
            align: "right" as const,
          },
        ]
      : []),
    ...(show("evidence")
      ? [
          {
            title: "证据",
            dataIndex: "evidence_refs",
            width: 80,
            align: "right" as const,
            render: (value: readonly string[]) => value.length,
          },
        ]
      : []),
    {
      title: "操作",
      key: "actions",
      width: 88,
      render: (_value: unknown, item: SearchEvent) => (
        <Button
          size="small"
          aria-label={`查看事件 ${item.event_id}`}
          onClick={(click) => {
            click.stopPropagation();
            setEvent(fromSearchEvent(item));
          }}
        >
          详情
        </Button>
      ),
    },
  ];

  return (
    <>
      <PageActions>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          disabled={search.loading}
          onClick={search.refresh}
        >
          刷新
        </Button>
      </PageActions>
      {search.firstError ? <ErrorState error={search.firstError} onRetry={search.refresh} /> : null}
      {first ? (
        <CompletenessBanner
          label="搜索索引状态"
          input={{
            hasGaps: search.pages.some((page) => page.has_gaps),
            pendingSegments: Math.max(...search.pages.map((page) => page.pending_segments)),
            observations: [
              { label: "首页", asOf: first.as_of, watermark: first.index_watermark },
              ...(last && last !== first
                ? [{ label: "末页", asOf: last.as_of, watermark: last.index_watermark }]
                : []),
            ],
          }}
        />
      ) : null}
      <section className="xs-card" aria-label="搜索事件结果" aria-busy={search.loading}>
        {search.loading ? <LoadingState label="正在检索事件" /> : null}
        {first ? (
          <>
            <div className="xs-card-head">
              <h2>匹配的事件</h2>
              <span className="xs-count" aria-live="polite">
                已加载 {rows.length} 条
              </span>
            </div>
            <Table<SearchEvent>
              size="middle"
              rowKey="event_id"
              columns={tableColumns}
              dataSource={rows}
              pagination={false}
              scroll={{ x: 720 }}
              locale={{
                emptyText: (
                  <EmptyState title="当前条件下没有匹配的已索引事件" icon="search">
                    空结果不证明事件不存在：事件可能尚未发布、已过保留期或不在当前作用域，请结合上方索引状态判断。
                  </EmptyState>
                ),
              }}
              onRow={(item) => ({
                onClick: () => setEvent(fromSearchEvent(item)),
                className: "xs-row-link",
              })}
            />
            <div className="xs-more-bar">
              {search.moreError ? (
                <ErrorState
                  error={search.moreError}
                  onRetry={search.retryMore}
                  retryLabel="重试下一页"
                />
              ) : null}
              <Button disabled={!search.hasMore || search.loadingMore} onClick={search.loadMore}>
                加载更多
              </Button>
              <span className="xs-count" aria-live="polite">
                {search.loadingMore
                  ? "正在读取下一页…"
                  : search.hasMore
                    ? "还有后续页，沿用已提交计划"
                    : search.capped
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
      {first ? <QueryDetails plan={plan} pages={search.pages} label="查看已提交计划" /> : null}
      <EventDrawer
        event={event}
        onClose={() => setEvent(null)}
        related={views}
        onSelectEvent={setEvent}
        onOpenArtifact={setArtifactId}
      />
      <ArtifactDrawer
        artifactId={artifactId}
        onClose={() => setArtifactId(null)}
        canAddToCase={canAddToCase}
        onAddToCase={setCaseTarget}
      />
      <AddToCaseModal artifactId={caseTarget} onClose={() => setCaseTarget(null)} />
    </>
  );
}
