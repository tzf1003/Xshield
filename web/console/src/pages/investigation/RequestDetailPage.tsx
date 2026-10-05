import { ReloadOutlined } from "@ant-design/icons";
import { useParams } from "@tanstack/react-router";
import { Button, Descriptions, Tabs, Tag } from "antd";
import { useState } from "react";
import type { EventsResponse, EvidenceResponse, Stage, SummaryResponse } from "../../api.ts";
import { fromAuditEvent } from "../../investigation/event-view.ts";
import type { EventView } from "../../investigation/event-view.ts";
import {
  bindingListPath,
  requestListPath,
  useInvestigationNavigate,
} from "../../investigation/navigation.ts";
import { canSearch } from "../../investigation/roles.ts";
import { useCursorPages } from "../../investigation/use-cursor-pages.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { useSession } from "../../security/SessionProvider";
import { PageActions } from "../../shell/page-actions";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { IdChip } from "../../ui/IdChip";
import { ReasonCode } from "../../ui/ReasonCode";
import { originStateName } from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState, LoadingState } from "../../ui/states";
import { TimeStamp } from "../../ui/TimeStamp";
import { formatDuration } from "../../ui/time-range.ts";
import { AddToCaseModal } from "./AddToCaseModal";
import { ArtifactDrawer } from "./ArtifactDrawer";
import { EventDrawer } from "./EventDrawer";
import {
  AgentTab,
  AuditTab,
  CapabilityHint,
  EventsTab,
  EvidenceTab,
  ModelTab,
  NOT_IN_SUMMARY,
  StageFactsTab,
} from "./RequestTabs";
import { StageTree } from "./StageTree";
import "./investigation.css";
import "./request-detail.css";

type TabKey = "events" | "source" | "capability" | "io" | "crypto" | "model" | "agent" | "audit";

/** Where the evidence of a stage is shown. Everything else is read in the event timeline. */
const stageTabs: Readonly<Record<string, TabKey>> = {
  ui_semantic_match: "source",
  ui_provenance: "source",
  ui_action: "source",
  capability: "capability",
  grant: "capability",
  response_grant: "capability",
  share_grant: "capability",
  crypto_decode: "crypto",
  crypto_encode: "crypto",
  evidence_capture: "io",
  model_eval: "model",
};

const tabOfStage = (stage: string): TabKey => stageTabs[stage] ?? "events";
const stagesOf = (stages: readonly Stage[], tab: TabKey) =>
  stages.filter((stage) => stageTabs[stage.stage] === tab);

/** 请求详情: decision banner, key facts, stage tree and the evidence tabs of one request. */
export function RequestDetailPage() {
  const { requestId } = useParams({ strict: false }) as { requestId?: string };
  if (!requestId) return null;
  return <RequestDetail key={requestId} requestId={requestId} />;
}

function RequestDetail({ requestId }: { requestId: string }) {
  const { state } = useSession();
  const canAddToCase = canSearch(state.roles);
  const [tab, setTab] = useState<TabKey>("events");
  const [visited, setVisited] = useState<ReadonlySet<TabKey>>(new Set<TabKey>(["events"]));
  const [stageFilter, setStageFilter] = useState<string | null>(null);
  const [selectedStage, setSelectedStage] = useState<string | null>(null);
  const [event, setEvent] = useState<EventView | null>(null);
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [caseTarget, setCaseTarget] = useState<string | null>(null);

  // Summary first, then the timeline; the evidence catalogue only when its tab is opened.
  const summary = useGuardedQuery({
    key: ["investigation", "request", requestId, "summary"],
    fetch: (client, signal) => client.summary(requestId, signal),
    staleTime: MANUAL_REFRESH,
  });
  const found = summary.data?.found === true;
  const events = useCursorPages<EventsResponse>({
    key: ["investigation", "request", requestId, "events"],
    fetchPage: (client, cursor, signal) => client.events(requestId, cursor, signal),
    enabled: found,
  });
  const evidence = useCursorPages<EvidenceResponse>({
    key: ["investigation", "request", requestId, "evidence"],
    fetchPage: (client, cursor, signal) => client.evidence(requestId, cursor, signal),
    enabled: found && visited.has("io"),
  });

  const views = events.pages.flatMap((page) =>
    page.events.map((e) => fromAuditEvent(e, requestId)),
  );

  function showTab(next: TabKey) {
    setTab(next);
    setVisited((current) => new Set(current).add(next));
  }
  function showStageEvents(stage: string) {
    setStageFilter(stage);
    showTab("events");
  }
  function selectStage(stage: Stage) {
    setSelectedStage(stage.stage);
    const target = tabOfStage(stage.stage);
    if (target === "events") setStageFilter(stage.stage);
    showTab(target);
  }
  function openEvent(view: EventView) {
    setEvent(view);
  }
  function refresh() {
    void summary.refetch();
    if (found) events.refresh();
    if (visited.has("io")) evidence.refresh();
  }

  const data = summary.data;
  const stages = data?.summary?.stages ?? [];

  return (
    <div className="xs-page">
      <PageActions>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          disabled={summary.isFetching}
          onClick={refresh}
        >
          刷新
        </Button>
      </PageActions>
      {summary.isError ? (
        <ErrorState error={summary.error} onRetry={() => void summary.refetch()} />
      ) : null}
      {summary.isPending && summary.isFetching ? (
        <section className="xs-card">
          <LoadingState label="正在读取请求摘要" />
        </section>
      ) : null}
      {data && !data.summary ? <NotFoundCard response={data} /> : null}
      {data?.summary ? (
        <>
          <DecisionBanner response={data} />
          <KeyFacts response={data} />
        </>
      ) : null}
      {data ? (
        <CompletenessBanner
          label="请求索引状态"
          verdict={
            data.summary
              ? data.summary.terminal
                ? "已观察到请求终态"
                : "尚未观察到请求终态"
              : undefined
          }
          input={{
            hasGaps: data.has_gaps || events.pages.some((page) => page.has_gaps),
            pendingSegments: data.pending_segments,
            notFound: !data.found,
            observations: [
              { label: "摘要", asOf: data.as_of, watermark: data.index_watermark },
              ...(events.pages.length > 0
                ? [
                    {
                      label: "事件",
                      asOf: events.pages.at(-1)?.as_of ?? null,
                      watermark: events.pages.at(-1)?.index_watermark ?? null,
                    },
                  ]
                : []),
            ],
          }}
        />
      ) : null}
      {data?.summary ? (
        <div className="xs-detail-grid">
          <section className="xs-card xs-stage-card" aria-label="阶段">
            <div className="xs-card-head">
              <h2>阶段</h2>
              <span className="xs-count">按首个事件序号排列</span>
            </div>
            <StageTree stages={stages} selected={selectedStage} onSelect={selectStage} />
          </section>
          <section className="xs-card xs-tabs-card" aria-label="调查内容">
            <Tabs
              activeKey={tab}
              onChange={(key) => showTab(key as TabKey)}
              items={[
                {
                  key: "events",
                  label: "事件时间线",
                  children: (
                    <EventsTab
                      events={events}
                      views={views}
                      stageFilter={stageFilter}
                      onClearStage={() => setStageFilter(null)}
                      onOpen={openEvent}
                    />
                  ),
                },
                {
                  key: "source",
                  label: "界面来源",
                  children: (
                    <StageFactsTab
                      stages={stagesOf(stages, "source")}
                      intro="界面来源阶段记录请求是否来自已验证页面上的已批准动作。"
                      missing="页面构建、动作映射与来源动作的具体内容不在脱敏摘要中。"
                      onShowEvents={showStageEvents}
                    />
                  ),
                },
                {
                  key: "capability",
                  label: "资源资格",
                  children: (
                    <StageFactsTab
                      stages={stagesOf(stages, "capability")}
                      intro="资源资格阶段记录请求对资源与操作是否持有精确资格。"
                      missing="资格 ID、资源指纹与约束正文不在脱敏摘要中。"
                      extra={<CapabilityHint />}
                      onShowEvents={showStageEvents}
                    />
                  ),
                },
                {
                  key: "io",
                  label: "输入与输出",
                  children: (
                    <EvidenceTab
                      evidence={evidence}
                      canAddToCase={canAddToCase}
                      onOpen={setArtifactId}
                      onAddToCase={setCaseTarget}
                    />
                  ),
                },
                {
                  key: "crypto",
                  label: "加密转换",
                  children: (
                    <StageFactsTab
                      stages={stagesOf(stages, "crypto")}
                      intro="加密转换阶段记录请求解密与响应加密是否按站点策略完成。"
                      missing="算法、密钥引用、报文 ID 与 nonce 摘要不在脱敏摘要中。"
                      onShowEvents={showStageEvents}
                    />
                  ),
                },
                {
                  key: "model",
                  label: "模型判别",
                  children: (
                    <ModelTab
                      views={views}
                      stages={stages}
                      complete={!events.hasMore}
                      onShowEvents={showStageEvents}
                    />
                  ),
                },
                {
                  key: "agent",
                  label: "Agent",
                  children: <AgentTab views={views} complete={!events.hasMore} />,
                },
                {
                  key: "audit",
                  label: "审计完整性",
                  children: <AuditTab summary={data} events={events} />,
                },
              ]}
            />
          </section>
        </div>
      ) : null}
      <EventDrawer
        event={event}
        onClose={() => setEvent(null)}
        related={views}
        onSelectEvent={openEvent}
        onOpenArtifact={setArtifactId}
        currentRequestId={requestId}
      />
      <ArtifactDrawer
        artifactId={artifactId}
        onClose={() => setArtifactId(null)}
        canAddToCase={canAddToCase}
        onAddToCase={setCaseTarget}
      />
      <AddToCaseModal artifactId={caseTarget} onClose={() => setCaseTarget(null)} />
    </div>
  );
}

function NotFoundCard({ response }: { response: SummaryResponse }) {
  const navigateTo = useInvestigationNavigate();
  const pending = response.completeness === "pending_index";
  return (
    <section className="xs-card">
      <EmptyState
        title={pending ? "索引待就绪" : "当前未找到请求"}
        icon="search"
        action={<Button onClick={() => navigateTo.go(requestListPath)}>回到请求列表</Button>}
      >
        {pending
          ? "待发布记录或索引缺口可能影响查询结果，请稍后点击页面右上角的「刷新」。"
          : "请核对请求 ID 与当前访问范围。未找到不推断请求不存在：它可能已过保留期、尚未发布，或不在当前作用域。"}
        <br />
        <IdChip value={response.source_request_id} wrap />
      </EmptyState>
    </section>
  );
}

function DecisionBanner({ response }: { response: SummaryResponse }) {
  const summary = response.summary;
  if (!summary) return null;
  const pending = !summary.terminal;
  const forwarded = summary.forwarded
    ? "已观察到转发意图（不等于源站已执行）"
    : summary.origin_state === "not_sent"
      ? "未转发到源站"
      : "未观察到转发";
  return (
    <section className="xs-card xs-banner-card" aria-label="判定摘要">
      <div className="xs-decision-line">
        <DecisionBadge decision={summary.decision} pending={pending} size="lg" showCode />
        {pending ? (
          <p className="xs-decision-text">尚未观察到请求终态；索引可能仍在同步，请稍后刷新。</p>
        ) : summary.decision === null ? (
          <p className="xs-decision-text">终态事件没有记录判定，不能据此推断放行或拒绝。</p>
        ) : null}
      </div>
      {summary.reason_code ? (
        <ReasonCode code={summary.reason_code} variant="full" />
      ) : (
        <p className="xs-foot">尚未记录主要原因。</p>
      )}
      <div className="xs-tags xs-fact-tags">
        <Tag>{forwarded}</Tag>
        <Tag>{summary.business_result_confirmed ? "已确认源站响应" : "业务结果未确认"}</Tag>
        {summary.origin_state ? <Tag>{originStateName(summary.origin_state).label}</Tag> : null}
        {summary.status !== null ? <Tag>HTTP {summary.status}</Tag> : null}
      </div>
      {summary.decision === "ALLOW" ? (
        <p className="xs-foot">
          检查范围：{summary.operation_id ?? "未记录"}
          ，以对应策略及阶段记录为准；放行不表示业务执行成功。
        </p>
      ) : null}
      {summary.business_result_confirmed ? (
        <p className="xs-foot">源站响应已确认不等同于业务执行成功。</p>
      ) : null}
    </section>
  );
}

function KeyFacts({ response }: { response: SummaryResponse }) {
  const summary = response.summary;
  const navigateTo = useInvestigationNavigate();
  if (!summary) return null;
  return (
    <section className="xs-card" aria-label="关键事实">
      <Descriptions
        size="small"
        bordered
        column={{ xs: 1, sm: 2, lg: 3 }}
        items={[
          {
            key: "request",
            label: "请求 ID",
            children: <IdChip value={response.source_request_id} wrap />,
          },
          {
            key: "site",
            label: "站点",
            children: <span className="mono">{response.site_id}</span>,
          },
          {
            key: "method",
            label: "方法",
            children: summary.method ? (
              <span className="mono">{summary.method}</span>
            ) : (
              "方法未记录"
            ),
          },
          {
            key: "operation",
            label: "操作",
            children: summary.operation_id ? (
              <span className="mono">{summary.operation_id}</span>
            ) : (
              "操作未记录"
            ),
          },
          {
            key: "time",
            label: "观察时间",
            children: <TimeStamp value={summary.last_occurred_at} precision="millisecond" />,
          },
          {
            key: "duration",
            label: "总耗时",
            children: summary.duration_us === null ? "未记录" : formatDuration(summary.duration_us),
          },
          {
            key: "identity",
            label: "身份引用",
            children: (
              <span>
                {NOT_IN_SUMMARY}；
                <Button type="link" size="small" onClick={() => navigateTo.go(bindingListPath)}>
                  到「身份与资格」按 ID 查询
                </Button>
              </span>
            ),
          },
        ]}
      />
    </section>
  );
}
