import { ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Collapse, Descriptions, Select, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import { ApiError, modelCallPattern } from "../../api-contract.ts";
import type { ModelCallListItem, ModelCallListPlan, ModelCallListResponse } from "../../api.ts";
import { modelTone, modelWord } from "../../investigation/model-status.ts";
import {
  modelPath,
  requestPath,
  useInvestigationNavigate,
} from "../../investigation/navigation.ts";
import { buildModelListPlan, MODEL_PAGE_SIZES } from "../../investigation/plans.ts";
import { ROLE_OBSERVER_TEXT } from "../../investigation/roles.ts";
import { useCursorPages } from "../../investigation/use-cursor-pages.ts";
import { useRemembered } from "../../investigation/view-memory.ts";
import { PageActions } from "../../shell/page-actions";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { EventTime } from "../../ui/EventTime";
import { ObjectId } from "../../ui/ObjectId";
import { ReasonCode } from "../../ui/ReasonCode";
import { confidenceStateName } from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState, LoadingState } from "../../ui/states";
import { TonePill } from "../../ui/TonePill";
import { checkedResolution, TimeRangePicker } from "../../ui/TimeRangePicker";
import type { RangeIntent } from "../../ui/time-range.ts";
import { IdLookup } from "./IdLookup";
import "./investigation.css";
import "./lifecycle.css";

type ListDraft = Readonly<{ range: RangeIntent; limit: number }>;

const defaultDraft: ListDraft = { range: { kind: "preset", preset: "24h" }, limit: 25 };

function acceptsWindow(window: { start: string; end: string }): boolean {
  try {
    buildModelListPlan(window, 10);
    return true;
  } catch {
    return false;
  }
}

type Applied = Readonly<{ plan: ModelCallListPlan; nonce: number }>;

/** Counts reads for the life of the page bundle, so no two reads share a cache entry. */
let submissions = 0;

/** 模型调用: discover calls in a fixed UTC window, or open one by its ID. */
export function ModelListPage() {
  const navigateTo = useInvestigationNavigate();
  const [draft, setDraft] = useRemembered<ListDraft>("models.draft", () => defaultDraft);
  const [applied, setApplied] = useState<Applied | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [rangeNotice, setRangeNotice] = useState<string | null>(null);

  function edit(next: ListDraft) {
    setDraft(next);
    // Any change retires the rows and every cursor they produced.
    setApplied(null);
    setFormError(null);
    setRangeNotice(null);
  }

  function submit() {
    const resolution = checkedResolution(draft.range, Date.now(), acceptsWindow);
    if (!resolution.window) {
      setApplied(null);
      if (resolution.problem === "missing" || resolution.problem === "incomplete") {
        setFormError(null);
        setRangeNotice("请先选择完整的时间范围。");
      } else {
        setRangeNotice(null);
        setFormError(new ApiError("CONTROL_MODEL_CALLS_REQUEST_INVALID"));
      }
      return;
    }
    try {
      const plan = buildModelListPlan(resolution.window, draft.limit);
      submissions += 1;
      setFormError(null);
      setRangeNotice(null);
      setApplied({ plan, nonce: submissions });
    } catch (error) {
      setApplied(null);
      setFormError(error);
    }
  }

  return (
    <div className="xs-page">
      <section className="xs-card xs-toolbar" aria-label="模型调用列表条件">
        <div className="xs-toolbar-row">
          <TimeRangePicker
            value={draft.range}
            accepts={acceptsWindow}
            onChange={(range) => edit({ ...draft, range })}
          />
          <div className="xs-open">
            <IdLookup
              label="模型调用 ID"
              prefix="mdl_"
              pattern={modelCallPattern}
              buttonText="打开"
              onOpen={(id) => navigateTo.go(modelPath(id))}
            />
            <p className="xs-foot">已知模型调用 ID 时直接打开；打开会重新鉴权并读取详情。</p>
          </div>
        </div>
        {rangeNotice ? (
          <p className="xs-field-error" role="alert">
            {rangeNotice}
          </p>
        ) : null}
        <div className="xs-options">
          <div className="xs-option">
            <label htmlFor="model-limit">每页条数</label>
            <Select<number>
              id="model-limit"
              value={draft.limit}
              options={MODEL_PAGE_SIZES.map((value) => ({ value, label: String(value) }))}
              onChange={(limit) => edit({ ...draft, limit })}
            />
          </div>
          <div className="xs-toolbar-actions">
            <Button type="primary" icon={<SearchOutlined aria-hidden="true" />} onClick={submit}>
              读取模型调用
            </Button>
          </div>
        </div>
        <p className="xs-toolbar-hint">
          UTC 整秒半开时间窗，最多 31 天。结果固定按发生时间、模型调用 ID 从新到旧排列。
        </p>
        <p className="xs-toolbar-hint">
          {ROLE_OBSERVER_TEXT}
          此列表只显示窗口内可见的最新脱敏记录；模型详情和证据元数据仍分别重新鉴权。
        </p>
      </section>
      {formError ? <ErrorState error={formError} title="查询条件未通过校验" /> : null}
      {applied ? (
        <ModelResults key={applied.nonce} plan={applied.plan} submission={applied.nonce} />
      ) : null}
    </div>
  );
}

function ModelResults({ plan, submission }: { plan: ModelCallListPlan; submission: number }) {
  const navigateTo = useInvestigationNavigate();
  const list = useCursorPages<ModelCallListResponse>({
    key: ["investigation", "models", submission, plan.start, plan.end, plan.limit],
    fetchPage: (client, cursor, signal) => client.modelCalls(plan, cursor, signal),
  });
  const rows = list.pages.flatMap((page) => page.items);
  const first = list.pages[0];
  const last = list.pages.at(-1);

  const columns: TableColumnsType<ModelCallListItem> = [
    {
      title: "发生时间",
      dataIndex: "occurred_at",
      width: 168,
      render: (value: string) => <EventTime value={value} precision="millisecond" />,
    },
    {
      title: "模型调用",
      dataIndex: "model_call_id",
      width: 270,
      render: (value: string, item) => (
        <span className="xs-event-cell">
          <ObjectId
            value={value}
            wrap
            href={modelPath(value)}
            onOpen={() => navigateTo.go(modelPath(value))}
          />
          <ObjectId
            value={item.request_id}
            short
            quietCopy
            href={requestPath(item.request_id)}
            onOpen={() => navigateTo.go(requestPath(item.request_id))}
          />
        </span>
      ),
    },
    {
      title: "供应商 / 模型",
      key: "provider",
      render: (_value: unknown, item) => (
        <span className="xs-event-cell">
          {item.provider ?? "历史记录未提供"}
          <span className="mono">{item.provider_model_id ?? "历史记录未提供"}</span>
        </span>
      ),
    },
    {
      title: "内部版本",
      key: "revision",
      render: (_value: unknown, item) => (
        <span className="xs-event-cell">
          <span className="mono">{item.model_revision}</span>
          <span className="mono">{item.prompt_revision}</span>
          {item.question_type}
        </span>
      ),
    },
    {
      title: "窗口内最新状态",
      key: "status",
      render: (_value: unknown, item) => (
        <span className="xs-event-cell">
          <TonePill tone={modelTone(item.latest_status)} code={item.latest_status}>
            {modelWord(item.latest_status)}
          </TonePill>
          <ReasonCode code={item.latest_reason_code} quietCopy />
          <span>置信度：{confidenceStateName(item.latest_confidence_status).label}</span>
        </span>
      ),
    },
  ];

  return (
    <>
      <PageActions>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          disabled={list.loading}
          onClick={list.refresh}
        >
          刷新
        </Button>
      </PageActions>
      {list.firstError ? <ErrorState error={list.firstError} onRetry={list.refresh} /> : null}
      {first ? (
        <CompletenessBanner
          label="模型调用列表索引状态"
          note="列表为空、生命周期是否完整和其他生产者是否追平都须分别判断。"
          input={{
            hasGaps: list.pages.some((page) => page.has_gaps),
            pendingSegments: Math.max(...list.pages.map((page) => page.pending_segments)),
            observations: [
              {
                label: "首页",
                asOf: first.as_of,
                watermark: first.index_watermark,
                scope: first.watermark_scope,
              },
              ...(last && last !== first
                ? [
                    {
                      label: "末页",
                      asOf: last.as_of,
                      watermark: last.index_watermark,
                      scope: last.watermark_scope,
                    },
                  ]
                : []),
            ],
          }}
        />
      ) : null}
      <section className="xs-card" aria-label="模型调用列表结果" aria-busy={list.loading}>
        {list.loading ? <LoadingState label="正在读取模型调用" /> : null}
        {first ? (
          <>
            <div className="xs-card-head">
              <h2>模型调用列表</h2>
              <span className="xs-count" aria-live="polite">
                已加载 {rows.length} 条
              </span>
            </div>
            <Table<ModelCallListItem>
              size="middle"
              rowKey="model_call_id"
              columns={columns}
              dataSource={rows}
              pagination={false}
              scroll={{ x: 880 }}
              locale={{
                emptyText: (
                  <EmptyState title="当前窗口内没有可见调用" icon="search">
                    当前窗口和作用域内没有可见调用；这不推断调用不存在、未发布记录不存在或索引完整。
                  </EmptyState>
                ),
              }}
            />
            <div className="xs-more-bar">
              {list.moreError ? (
                <ErrorState
                  error={list.moreError}
                  onRetry={list.retryMore}
                  retryLabel="重试下一页"
                />
              ) : null}
              <Button disabled={!list.hasMore || list.loadingMore} onClick={list.loadMore}>
                加载更多
              </Button>
              <span className="xs-count" aria-live="polite">
                {list.loadingMore
                  ? "正在读取下一页…"
                  : list.hasMore
                    ? "本页已截断，可继续翻页"
                    : list.capped
                      ? "已达到加载上限，请缩小时间范围"
                      : "当前可见结果已读完"}
              </span>
            </div>
          </>
        ) : null}
      </section>
      {first ? (
        <Collapse
          size="small"
          className="xs-details"
          items={[
            {
              key: "plan",
              label: "已提交列表条件",
              children: (
                <section aria-label="已提交模型调用列表条件" className="xs-plan-region">
                  <Descriptions
                    size="small"
                    bordered
                    column={{ xs: 1, md: 2 }}
                    items={[
                      {
                        key: "start",
                        label: "开始时间",
                        children: <span className="mono">{plan.start}</span>,
                      },
                      {
                        key: "end",
                        label: "结束时间",
                        children: <span className="mono">{plan.end}</span>,
                      },
                      { key: "limit", label: "每页条数", children: plan.limit },
                      ...list.pages.flatMap((page, index) => [
                        {
                          key: `request-${index}`,
                          label: "管理请求 ID",
                          children: <ObjectId value={page.request_id} quietCopy />,
                        },
                        {
                          key: `rows-${index}`,
                          label: "实际扫描行",
                          children:
                            page.scanned_rows === null
                              ? "未知（索引未报告）"
                              : page.scanned_rows.toLocaleString(),
                        },
                        {
                          key: `bytes-${index}`,
                          label: "实际扫描字节",
                          children:
                            page.scanned_bytes === null
                              ? "未知（索引未报告）"
                              : page.scanned_bytes.toLocaleString(),
                        },
                      ]),
                    ]}
                  />
                </section>
              ),
            },
          ]}
        />
      ) : null}
    </>
  );
}
