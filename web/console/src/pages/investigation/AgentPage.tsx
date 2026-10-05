import { HistoryOutlined, ReloadOutlined } from "@ant-design/icons";
import { useParams } from "@tanstack/react-router";
import { Button, Descriptions, Skeleton } from "antd";
import { useState } from "react";
import { agentRunPattern } from "../../api-contract.ts";
import type { AgentRunEvent, AgentRunResponse } from "../../api.ts";
import {
  agentPath,
  requestPath,
  useInvestigationNavigate,
} from "../../investigation/navigation.ts";
import { canSearch, ROLE_OBSERVER_TEXT } from "../../investigation/roles.ts";
import { useSession } from "../../security/SessionProvider";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { EventTime } from "../../ui/EventTime";
import { ObjectId } from "../../ui/ObjectId";
import { ReasonCode } from "../../ui/ReasonCode";
import { sensitivityName } from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState } from "../../ui/states";
import type { PillTone } from "../../ui/TonePill";
import { AddToCaseModal } from "./AddToCaseModal";
import { ArtifactDrawer } from "./ArtifactDrawer";
import { IdLookup } from "./IdLookup";
import { LifecycleTimeline } from "./LifecycleTimeline";
import "./investigation.css";
import "./lifecycle.css";

const completenessWords: Record<AgentRunResponse["completeness"], string> = {
  complete: "生命周期完整",
  partial: "生命周期部分可见",
  not_indexed: "当前索引未找到运行",
};

const outcomeTone = (outcome: string | null): PillTone =>
  outcome === "PASS" || outcome === "ALLOW"
    ? "allow"
    : outcome === "DENY" || outcome === "ERROR"
      ? "deny"
      : "unknown";

/** Agent 运行: one run's redacted fixed events, or the box to open one by its ID. */
export function AgentPage() {
  const { agentRunId } = useParams({ strict: false }) as { agentRunId?: string };
  const navigateTo = useInvestigationNavigate();
  if (agentRunId) return <AgentDetail key={agentRunId} id={agentRunId} />;
  return (
    <div className="xs-page">
      <section className="xs-card" aria-label="查询 Agent 运行">
        <div className="xs-card-head">
          <h2>查询 Agent 运行</h2>
        </div>
        <IdLookup
          label="Agent 运行 ID"
          prefix="agt_"
          pattern={agentRunPattern}
          onOpen={(id) => navigateTo.go(agentPath(id))}
        />
        <p className="xs-foot">输入 Agent 运行 ID，读取脱敏生命周期与固定事件引用。</p>
        <p className="xs-foot">{ROLE_OBSERVER_TEXT}</p>
      </section>
    </div>
  );
}

function AgentDetail({ id }: { id: string }) {
  const { state } = useSession();
  const navigateTo = useInvestigationNavigate();
  const query = useGuardedQuery({
    key: ["investigation", "agent", id],
    fetch: (client, signal) => client.agentRun(id, signal),
    staleTime: MANUAL_REFRESH,
    gcTime: 0,
  });
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [caseTarget, setCaseTarget] = useState<string | null>(null);

  if (query.isPending && query.isFetching) {
    return <Skeleton active paragraph={{ rows: 6 }} aria-label="正在读取 Agent 运行" />;
  }
  if (query.isError) {
    return (
      <ErrorState
        error={query.error}
        onRetry={() => void query.refetch()}
        retryLabel="重新读取"
        title="无法读取 Agent 运行"
      />
    );
  }
  const response = query.data;
  if (!response) return null;
  const run = response.agent_run;
  const sourceRequest = run?.events[0]?.request_id ?? null;

  return (
    <div className="xs-page">
      <CompletenessBanner
        label="Agent 查询索引状态"
        verdict={completenessWords[response.completeness]}
        note="这里只展示固定事件的脱敏元数据；索引水位和保留窗口可能使生命周期暂时不完整。"
        input={{
          hasGaps: response.has_gaps,
          pendingSegments: response.pending_segments,
          notFound: response.completeness === "not_indexed",
          observations: [
            {
              label: "Agent",
              asOf: response.as_of,
              watermark: response.index_watermark,
              scope: response.watermark_scope,
            },
          ],
        }}
      />
      <section className="xs-card" aria-label="Agent 运行详情">
        <div className="xs-card-head">
          <h2>Agent 运行</h2>
          <ObjectId value={response.source_agent_run_id} wrap />
          <Button
            size="small"
            icon={<ReloadOutlined aria-hidden="true" />}
            onClick={() => void query.refetch()}
          >
            重新读取
          </Button>
        </div>
        {run ? (
          <div className="xs-detail-facts">
            <Descriptions
              bordered
              size="small"
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: "management",
                  label: "管理请求 ID",
                  children: <ObjectId value={response.request_id} wrap />,
                },
                {
                  key: "request",
                  label: "来源请求",
                  children: sourceRequest ? (
                    <ObjectId
                      value={sourceRequest}
                      wrap
                      href={requestPath(sourceRequest)}
                      onOpen={() => navigateTo.go(requestPath(sourceRequest))}
                    />
                  ) : (
                    "未记录"
                  ),
                },
                {
                  key: "lifecycle",
                  label: "生命周期",
                  children: run.lifecycle_complete ? "已观察到启动与终态" : "仍有缺口",
                },
                { key: "count", label: "事件数量", children: run.events.length },
              ]}
            />
            <p className="xs-foot">
              事件正文、工具参数/结果、提示和权限快照不进入此视图；证据引用仍需单独授权读取。
            </p>
            <div className="xs-actions">
              <Button
                icon={<HistoryOutlined aria-hidden="true" />}
                onClick={() =>
                  navigateTo.openSearch({ kind: "agent_run_id", value: run.agent_run_id })
                }
              >
                准备历史检索
              </Button>
            </div>
            <p className="xs-foot">
              历史检索仅预填 Agent 运行引用，仍需输入时间窗并由 Investigator 独立鉴权。
            </p>
            <h3>Agent 生命周期</h3>
            <LifecycleTimeline
              label="Agent 生命周期事件"
              items={run.events.map((event) => ({
                key: event.event_id,
                tone: outcomeTone(event.outcome),
                title: `#${event.request_seq} · ${event.event_type}`,
                time: <EventTime value={event.occurred_at} precision="millisecond" />,
                body: (
                  <AgentEventFacts
                    event={event}
                    onArtifact={setArtifactId}
                    onEvent={(eventId) =>
                      navigateTo.openSearch({ kind: "event_id", value: eventId })
                    }
                    onTrace={(traceId) =>
                      navigateTo.openSearch({ kind: "trace_id", value: traceId })
                    }
                  />
                ),
              }))}
            />
          </div>
        ) : (
          <EmptyState title="当前范围内未找到 Agent 运行" icon="search">
            当前作用域和索引水位内未找到该 Agent 运行；这不推断其他范围或保留窗口中的历史。
          </EmptyState>
        )}
        <p className="xs-foot">{ROLE_OBSERVER_TEXT}</p>
      </section>
      <ArtifactDrawer
        artifactId={artifactId}
        onClose={() => setArtifactId(null)}
        canAddToCase={canSearch(state.roles)}
        onAddToCase={setCaseTarget}
      />
      <AddToCaseModal artifactId={caseTarget} onClose={() => setCaseTarget(null)} />
    </div>
  );
}

function AgentEventFacts({
  event,
  onArtifact,
  onEvent,
  onTrace,
}: {
  event: AgentRunEvent;
  onArtifact: (id: string) => void;
  onEvent: (eventId: string) => void;
  onTrace: (traceId: string) => void;
}) {
  return (
    <Descriptions
      bordered
      size="small"
      column={1}
      items={[
        { key: "id", label: "事件 ID", children: <ObjectId value={event.event_id} wrap /> },
        {
          key: "outcome",
          label: "结果",
          children: <DecisionBadge decision={event.outcome} />,
        },
        {
          key: "time",
          label: "事件时间",
          children: (
            <span className="xs-times">
              <EventTime value={event.occurred_at} precision="microsecond" />
              <span className="mono xs-sub">{event.occurred_at}</span>
            </span>
          ),
        },
        {
          key: "trace",
          label: "Trace ID",
          children: <ObjectId value={event.trace_id} wrap onOpen={() => onTrace(event.trace_id)} />,
        },
        {
          key: "reason",
          label: "原因",
          children: <ReasonCode code={event.reason_code} variant="inline" />,
        },
        {
          key: "sensitivity",
          label: "数据分级",
          children: sensitivityName(event.sensitivity).label,
        },
        {
          key: "causes",
          label: "前驱事件",
          children: event.cause_event_ids.length ? (
            <span className="xs-chips">
              {event.cause_event_ids.map((cause) => (
                <ObjectId key={cause} value={cause} wrap onOpen={() => onEvent(cause)} />
              ))}
            </span>
          ) : (
            "起始事件"
          ),
        },
        {
          key: "evidence",
          label: "证据引用",
          children: event.evidence_refs.length ? (
            <span className="xs-chips">
              {event.evidence_refs.map((ref) =>
                ref.startsWith("artifact_") ? (
                  <ObjectId key={ref} value={ref} wrap onOpen={() => onArtifact(ref)} />
                ) : (
                  <ObjectId key={ref} value={ref} wrap />
                ),
              )}
            </span>
          ) : (
            "当前未记录"
          ),
        },
      ]}
    />
  );
}
