import { FolderAddOutlined } from "@ant-design/icons";
import { Button, Table, type TableColumnsType, Tag } from "antd";
import type { ReactNode } from "react";
import type {
  EventsResponse,
  EvidenceResponse,
  Manifest,
  Stage,
  SummaryResponse,
} from "../../api.ts";
import type { EventView } from "../../investigation/event-view.ts";
import {
  bindingListPath,
  grantListPath,
  modelPath,
  useInvestigationNavigate,
} from "../../investigation/navigation.ts";
import type { CursorPages } from "../../investigation/use-cursor-pages.ts";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { IdChip } from "../../ui/IdChip";
import { ReasonCode } from "../../ui/ReasonCode";
import {
  captureName,
  confidenceStateName,
  confidenceText,
  eventTypeName,
  proofKindName,
  stageName,
} from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState } from "../../ui/states";
import { TimeStamp } from "../../ui/TimeStamp";
import { formatDuration } from "../../ui/time-range.ts";
import "./investigation.css";
import "./request-detail.css";

/** The words used when the redacted summary simply does not carry a fact. */
export const NOT_IN_SUMMARY = "该信息当前不在脱敏摘要中";

// ---------------------------------------------------------------------------------------------
// 事件时间线
// ---------------------------------------------------------------------------------------------

export function EventsTab({
  events,
  views,
  stageFilter,
  onClearStage,
  onOpen,
}: {
  events: CursorPages<EventsResponse>;
  views: readonly EventView[];
  stageFilter: string | null;
  onClearStage: () => void;
  onOpen: (event: EventView) => void;
}) {
  const shown = stageFilter ? views.filter((view) => view.stage === stageFilter) : views;
  const columns: TableColumnsType<EventView> = [
    { title: "序号", dataIndex: "requestSeq", width: 64 },
    {
      title: "事件",
      key: "event",
      render: (_value, view) => (
        <span className="xs-event-cell">
          <strong>{eventTypeName(view.eventType).label}</strong>
          {view.stage ? <span className="xs-sub">{stageName(view.stage).label}</span> : null}
          <IdChip value={view.eventId} short quietCopy />
        </span>
      ),
    },
    {
      title: "结果",
      dataIndex: "outcome",
      width: 96,
      render: (value: string | null) => <DecisionBadge decision={value} />,
    },
    {
      title: "原因",
      dataIndex: "reasonCode",
      render: (value: string | null) => <ReasonCode code={value} quietCopy />,
    },
    {
      title: "耗时",
      dataIndex: "durationUs",
      width: 88,
      align: "right",
      render: (value: number) => formatDuration(value),
    },
    {
      title: "详情",
      key: "open",
      width: 72,
      render: (_value, view) => (
        <Button size="small" aria-label={`查看事件 ${view.eventId}`} onClick={() => onOpen(view)}>
          详情
        </Button>
      ),
    },
  ];
  return (
    <div>
      {stageFilter ? (
        <div className="xs-tags">
          <Tag closable={{ "aria-label": "清除阶段筛选" }} onClose={onClearStage}>
            仅看阶段：{stageName(stageFilter).label}
          </Tag>
        </div>
      ) : null}
      {events.firstError ? <ErrorState error={events.firstError} onRetry={events.refresh} /> : null}
      <Table<EventView>
        size="middle"
        rowKey="eventId"
        columns={columns}
        dataSource={shown}
        pagination={false}
        loading={events.loading}
        scroll={{ x: 640 }}
        locale={{
          emptyText: events.loading ? (
            "正在读取事件…"
          ) : (
            <EmptyState title="当前页暂无事件">
              请结合索引水位判断完整性；没有事件不证明请求没有发生。
            </EmptyState>
          ),
        }}
        onRow={(view) => ({ onClick: () => onOpen(view), className: "xs-row-link" })}
      />
      <div className="xs-more-bar">
        {events.moreError ? (
          <ErrorState error={events.moreError} onRetry={events.retryMore} retryLabel="重试下一页" />
        ) : null}
        <Button disabled={!events.hasMore || events.loadingMore} onClick={events.loadMore}>
          加载更多
        </Button>
        <span className="xs-count" aria-live="polite">
          已加载 {views.length} 条
          {events.hasMore ? "，还有后续页" : events.capped ? "，已达到加载上限" : "，已读完"}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// 输入与输出 (evidence manifest, metadata only)
// ---------------------------------------------------------------------------------------------

export function EvidenceTab({
  evidence,
  canAddToCase,
  onOpen,
  onAddToCase,
}: {
  evidence: CursorPages<EvidenceResponse>;
  canAddToCase: boolean;
  onOpen: (artifactId: string) => void;
  onAddToCase: (artifactId: string) => void;
}) {
  const rows = evidence.pages.flatMap((page) => page.artifacts);
  const columns: TableColumnsType<Manifest> = [
    {
      title: "证据",
      key: "artifact",
      render: (_value, row) => (
        <span className="xs-event-cell">
          <IdChip value={row.artifact_id} onOpen={() => onOpen(row.artifact_id)} wrap quietCopy />
          <span className="xs-sub mono">{row.kind}</span>
        </span>
      ),
    },
    {
      title: "采集 / 保真度",
      key: "capture",
      render: (_value, row) => (
        <span className="xs-event-cell">
          <span>{captureName(row.capture_status).label}</span>
          <span className="xs-sub">{captureName(row.fidelity).label}</span>
        </span>
      ),
    },
    {
      title: "分级",
      dataIndex: "classification",
      render: (value: string) => captureName(value).label,
    },
    {
      title: "大小",
      dataIndex: "bytes_saved",
      align: "right",
      render: (value: number) => `${value.toLocaleString()} 字节`,
    },
    {
      title: "到期",
      dataIndex: "expires_at",
      render: (value: string) => <TimeStamp value={value} />,
    },
    {
      title: "操作",
      key: "actions",
      render: (_value, row) => (
        <span className="xs-row-actions">
          <Button
            size="small"
            aria-label={`查看元数据 ${row.artifact_id}`}
            onClick={() => onOpen(row.artifact_id)}
          >
            元数据
          </Button>
          {canAddToCase ? (
            <Button
              size="small"
              icon={<FolderAddOutlined aria-hidden="true" />}
              aria-label={`加入案件 ${row.artifact_id}`}
              onClick={() => onAddToCase(row.artifact_id)}
            >
              加入案件
            </Button>
          ) : null}
        </span>
      ),
    },
  ];
  return (
    <div>
      <p className="xs-foot">
        这里只列出证据目录的元数据：采集状态、保真度、分级、大小与期限。内容读取需要独立的访问申请与审批；目录记录不证明读取权，也不证明对象侧完整性。
      </p>
      {evidence.firstError ? (
        <ErrorState error={evidence.firstError} onRetry={evidence.refresh} />
      ) : null}
      <Table<Manifest>
        size="middle"
        rowKey="artifact_id"
        columns={columns}
        dataSource={rows}
        pagination={false}
        loading={evidence.loading}
        scroll={{ x: 720 }}
        locale={{
          emptyText: evidence.loading ? (
            "正在读取证据目录…"
          ) : (
            <EmptyState title="当前页暂无可用证据目录记录">
              未采集、已到期或已删除的证据都不会出现在目录中，这不推断证据从未存在。
            </EmptyState>
          ),
        }}
      />
      <div className="xs-more-bar">
        {evidence.moreError ? (
          <ErrorState
            error={evidence.moreError}
            onRetry={evidence.retryMore}
            retryLabel="重试下一页"
          />
        ) : null}
        <Button disabled={!evidence.hasMore || evidence.loadingMore} onClick={evidence.loadMore}>
          加载更多证据
        </Button>
        <span className="xs-count" aria-live="polite">
          已加载 {rows.length} 条{evidence.hasMore ? "，还有后续页" : "，已读完"}
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// 界面来源 / 资源资格 / 加密转换: stage facts the summary does carry
// ---------------------------------------------------------------------------------------------

export function StageFactsTab({
  stages,
  intro,
  missing,
  extra,
  onShowEvents,
}: {
  stages: readonly Stage[];
  /** What these stages are, in one sentence. */
  intro: string;
  /** Facts the redacted summary does not carry. */
  missing: string;
  extra?: ReactNode;
  onShowEvents: (stage: string) => void;
}) {
  if (stages.length === 0) {
    return (
      <EmptyState title={NOT_IN_SUMMARY} icon="search">
        {intro}此请求的摘要里没有相关阶段的记录；{missing}
      </EmptyState>
    );
  }
  return (
    <div className="xs-stage-facts">
      <p className="xs-foot">
        {intro}
        {missing}
      </p>
      {stages.map((stage) => (
        <section
          className="xs-fact-card"
          key={stage.stage}
          aria-label={stageName(stage.stage).label}
        >
          <div className="xs-card-head">
            <h3>{stageName(stage.stage).label}</h3>
            <DecisionBadge decision={stage.outcome} />
          </div>
          <ReasonCode code={stage.reason_code} variant="full" />
          <dl className="xs-facts">
            <div>
              <dt>证明方式</dt>
              <dd>{proofKindName(stage.proof_kind).label}</dd>
            </div>
            <div>
              <dt>置信度</dt>
              <dd>{confidenceText(stage.confidence, stage.confidence_status)}</dd>
            </div>
            <div>
              <dt>耗时</dt>
              <dd>{formatDuration(stage.duration_us)}</dd>
            </div>
            <div>
              <dt>事件</dt>
              <dd>
                {stage.event_count} 个 · 序号 {stage.first_request_seq}
                {stage.last_request_seq !== stage.first_request_seq
                  ? `–${stage.last_request_seq}`
                  : ""}
              </dd>
            </div>
          </dl>
          <Button size="small" onClick={() => onShowEvents(stage.stage)}>
            在时间线中查看该阶段
          </Button>
        </section>
      ))}
      {extra}
    </div>
  );
}

export function CapabilityHint() {
  const navigateTo = useInvestigationNavigate();
  return (
    <p className="xs-foot">
      已知资格或绑定 ID 时，可到「身份与资格」页核对
      <Button type="link" size="small" onClick={() => navigateTo.go(grantListPath)}>
        资格
      </Button>
      或
      <Button type="link" size="small" onClick={() => navigateTo.go(bindingListPath)}>
        身份绑定
      </Button>
      的账本快照。
    </p>
  );
}

// ---------------------------------------------------------------------------------------------
// 模型判别
// ---------------------------------------------------------------------------------------------

export function ModelTab({
  views,
  stages,
  complete,
  onShowEvents,
}: {
  views: readonly EventView[];
  stages: readonly Stage[];
  /** Every event page has been loaded. */
  complete: boolean;
  onShowEvents: (stage: string) => void;
}) {
  const navigateTo = useInvestigationNavigate();
  const modelStages = stages.filter((stage) => stage.proof_kind === "model");
  const calls = [
    ...new Map(views.filter((v) => v.modelCallId).map((v) => [v.modelCallId, v])).values(),
  ];
  if (modelStages.length === 0 && calls.length === 0) {
    return (
      <EmptyState title={NOT_IN_SUMMARY} icon="search">
        摘要里没有以模型作证明的阶段，已加载的事件也没有模型调用引用
        {complete ? "。" : "（事件尚未读完，后续页可能含有）。"}
        这不推断该请求从未触发模型判别。
      </EmptyState>
    );
  }
  return (
    <div className="xs-stage-facts">
      <p className="xs-foot">
        模型判别只在这里列出调用引用与阶段结果；输入、输出与供应商正文不在脱敏摘要中。置信度只在服务端提供时显示，确定性规则与
        Noul 保持「无置信度」。
      </p>
      {modelStages.map((stage) => (
        <section
          className="xs-fact-card"
          key={stage.stage}
          aria-label={stageName(stage.stage).label}
        >
          <div className="xs-card-head">
            <h3>{stageName(stage.stage).label}</h3>
            <DecisionBadge decision={stage.outcome} />
          </div>
          <ReasonCode code={stage.reason_code} variant="full" />
          <dl className="xs-facts">
            <div>
              <dt>置信度</dt>
              <dd>
                {stage.confidence === null
                  ? confidenceStateName(stage.confidence_status).label
                  : stage.confidence}
              </dd>
            </div>
          </dl>
          <Button size="small" onClick={() => onShowEvents(stage.stage)}>
            在时间线中查看该阶段
          </Button>
        </section>
      ))}
      {calls.length > 0 ? (
        <section className="xs-fact-card" aria-label="模型调用引用">
          <h3>模型调用</h3>
          <ul className="xs-plain-list">
            {calls.map((view) => {
              const id = view.modelCallId;
              if (!id) return null;
              return (
                <li key={id}>
                  <IdChip
                    value={id}
                    wrap
                    href={modelPath(id)}
                    onOpen={() => navigateTo.go(modelPath(id))}
                  />
                  <span className="xs-sub">
                    {view.modelRevision ? `模型版本 ${view.modelRevision} · ` : ""}
                    置信度：{confidenceText(view.confidence, view.confidenceStatus)}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="xs-foot">打开模型调用页会重新读取详情并重新鉴权（需要 Observer）。</p>
        </section>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------------------------

export function AgentTab({ views, complete }: { views: readonly EventView[]; complete: boolean }) {
  const agent = views.filter((view) => view.eventType.startsWith("agent."));
  if (agent.length === 0) {
    return (
      <EmptyState title={NOT_IN_SUMMARY} icon="search">
        摘要里没有 Agent 事件的记录
        {complete ? "。" : "，事件也尚未读完。"}
        Agent 运行 ID 不在脱敏事件摘要中；已知 agt_ ID 时可用 ⌘K 粘贴打开运行详情。
      </EmptyState>
    );
  }
  return (
    <div className="xs-stage-facts">
      <p className="xs-foot">
        以下是该请求已加载事件中的 Agent
        固定生命周期事件。工具参数、结果、提示与权限快照不在脱敏摘要中；Agent 运行 ID
        也不在其中，已知 agt_ ID 时可用 ⌘K 粘贴打开运行详情。
      </p>
      <ul className="xs-plain-list">
        {agent.map((view) => (
          <li key={view.eventId}>
            <strong>{eventTypeName(view.eventType).label}</strong>
            <DecisionBadge decision={view.outcome} />
            <ReasonCode code={view.reasonCode} variant="inline" quietCopy />
          </li>
        ))}
      </ul>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// 审计完整性
// ---------------------------------------------------------------------------------------------

export function AuditTab({
  summary,
  events,
}: {
  summary: SummaryResponse;
  events: CursorPages<EventsResponse>;
}) {
  const facts = summary.summary;
  const last = events.pages.at(-1);
  const loaded = events.pages.flatMap((page) => page.events).length;
  return (
    <div className="xs-stage-facts">
      <CompletenessBanner
        label="审计完整性"
        input={{
          hasGaps: summary.has_gaps || events.pages.some((page) => page.has_gaps),
          pendingSegments: summary.pending_segments,
          observations: [
            { label: "摘要", asOf: summary.as_of, watermark: summary.index_watermark },
            {
              label: "事件",
              asOf: last?.as_of ?? null,
              watermark: last?.index_watermark ?? null,
            },
          ],
        }}
      />
      <dl className="xs-facts">
        <div>
          <dt>摘要状态</dt>
          <dd>
            {summary.completeness === "complete"
              ? "complete：已观察到请求终态"
              : summary.completeness === "pending"
                ? "pending：尚未观察到请求终态"
                : summary.completeness === "pending_index"
                  ? "pending_index：索引待就绪"
                  : "not_found：当前未找到"}
          </dd>
        </div>
        {facts ? (
          <>
            <div>
              <dt>摘要事件数</dt>
              <dd>{facts.event_count}</dd>
            </div>
            <div>
              <dt>已加载事件</dt>
              <dd>
                {loaded} 条{events.hasMore ? "（还有后续页）" : ""}
              </dd>
            </div>
            <div>
              <dt>首个事件</dt>
              <dd>
                <TimeStamp value={facts.first_occurred_at} precision="millisecond" />
              </dd>
            </div>
            <div>
              <dt>最后事件</dt>
              <dd>
                <TimeStamp value={facts.last_occurred_at} precision="millisecond" />
              </dd>
            </div>
          </>
        ) : null}
      </dl>
      <p className="xs-foot">
        「complete」表示观察到了该请求保留的终态，不表示索引没有缺口；摘要与事件分别读取，水位只覆盖配置的日志源，不覆盖其他
        Outbox 生产者。
      </p>
    </div>
  );
}
