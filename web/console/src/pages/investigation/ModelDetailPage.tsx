import { HistoryOutlined, ReloadOutlined } from "@ant-design/icons";
import { useParams } from "@tanstack/react-router";
import { Button, Descriptions, Skeleton } from "antd";
import { type ReactNode, useState } from "react";
import type { ModelCallEvent, ModelCallResponse } from "../../api.ts";
import { modelTone, modelWord } from "../../investigation/model-status.ts";
import { requestPath, useInvestigationNavigate } from "../../investigation/navigation.ts";
import { canSearch, ROLE_OBSERVER_TEXT } from "../../investigation/roles.ts";
import { useSession } from "../../security/SessionProvider";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import { EventTime } from "../../ui/EventTime";
import { ObjectId } from "../../ui/ObjectId";
import { ReasonCode } from "../../ui/ReasonCode";
import { confidenceStateName, confidenceText, sensitivityName } from "../../ui/request-vocab.ts";
import { EmptyState, ErrorState } from "../../ui/states";
import { TonePill } from "../../ui/TonePill";
import { formatDuration } from "../../ui/time-range.ts";
import { AddToCaseModal } from "./AddToCaseModal";
import { ArtifactDrawer } from "./ArtifactDrawer";
import { LifecycleTimeline } from "./LifecycleTimeline";
import "./investigation.css";
import "./lifecycle.css";

const completenessWords: Record<ModelCallResponse["completeness"], string> = {
  complete: "生命周期完整",
  pending: "等待模型终态",
  partial: "生命周期部分可见",
  not_indexed: "当前索引未找到调用",
};

export function ModelDetailPage() {
  const { modelCallId } = useParams({ strict: false }) as { modelCallId?: string };
  return modelCallId ? <ModelDetail key={modelCallId} id={modelCallId} /> : null;
}

function ModelDetail({ id }: { id: string }) {
  const { state } = useSession();
  const navigateTo = useInvestigationNavigate();
  const query = useGuardedQuery({
    key: ["investigation", "model", id],
    fetch: (client, signal) => client.modelCall(id, signal),
    staleTime: MANUAL_REFRESH,
    // Each opening re-reads and re-authorizes: nothing is kept once the page is left.
    gcTime: 0,
  });
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [caseTarget, setCaseTarget] = useState<string | null>(null);

  if (query.isPending && query.isFetching) {
    return <Skeleton active paragraph={{ rows: 8 }} aria-label="正在读取模型调用" />;
  }
  if (query.isError) {
    return (
      <ErrorState
        error={query.error}
        onRetry={() => void query.refetch()}
        retryLabel="重新读取"
        title="无法读取模型调用"
      />
    );
  }
  const response = query.data;
  if (!response) return null;
  const model = response.model_call;
  const openArtifact = (artifact: string) => setArtifactId(artifact);
  const history = () => navigateTo.openSearch({ kind: "model_call_id", value: id });

  return (
    <div className="xs-page">
      <CompletenessBanner
        label="模型查询索引状态"
        verdict={completenessWords[response.completeness]}
        note="索引水位仅覆盖配置的日志源，不代表模型调用已全部追平；结果随发布与保留而变化。"
        input={{
          hasGaps: response.has_gaps,
          pendingSegments: response.pending_segments,
          notFound: response.completeness === "not_indexed",
          observations: [
            {
              label: "模型",
              asOf: response.as_of,
              watermark: response.index_watermark,
              scope: response.watermark_scope,
            },
          ],
        }}
      />
      <section className="xs-card" aria-label="模型调用详情">
        <div className="xs-card-head">
          <h2>模型调用</h2>
          <ObjectId value={response.source_model_call_id} wrap />
          <Button
            size="small"
            icon={<ReloadOutlined aria-hidden="true" />}
            onClick={() => void query.refetch()}
          >
            重新读取
          </Button>
        </div>
        {model ? (
          <div className="xs-detail-facts">
            <Descriptions
              bordered
              size="small"
              column={{ xs: 1, md: 2 }}
              items={[
                {
                  key: "request",
                  label: "来源请求",
                  children: (
                    <ObjectId
                      value={model.request_id}
                      wrap
                      href={requestPath(model.request_id)}
                      onOpen={() => navigateTo.go(requestPath(model.request_id))}
                    />
                  ),
                },
                {
                  key: "status",
                  label: "生命周期状态",
                  children: (
                    <TonePill tone={modelTone(model.status)} code={model.status}>
                      {modelWord(model.status)}
                    </TonePill>
                  ),
                },
                {
                  key: "reason",
                  label: "原因",
                  children: <ReasonCode code={model.reason_code} variant="full" />,
                },
                {
                  key: "provider",
                  label: "供应商路由",
                  children: model.provider ?? "历史记录未提供",
                },
                {
                  key: "providerModel",
                  label: "供应商模型 ID",
                  children: (
                    <span className="mono">{model.provider_model_id ?? "历史记录未提供"}</span>
                  ),
                },
                {
                  key: "revision",
                  label: "内部模型版本",
                  children: <span className="mono">{model.model_revision}</span>,
                },
                {
                  key: "prompt",
                  label: "提示版本",
                  children: <span className="mono">{model.prompt_revision}</span>,
                },
                {
                  key: "question",
                  label: "问题类型",
                  children: <span className="mono">{model.question_type}</span>,
                },
                {
                  key: "confidence",
                  label: "置信度",
                  children: confidenceText(model.confidence, model.confidence_status),
                },
                {
                  key: "confidenceState",
                  label: "置信度状态",
                  children: confidenceStateName(model.confidence_status).label,
                },
                { key: "duration", label: "耗时", children: formatDuration(model.duration_us) },
                ...(
                  [
                    ["input", "输入证据", model.input_artifact_id],
                    ["output", "输出证据", model.output_artifact_id],
                    ["call", "调用记录", model.call_artifact_id],
                  ] as const
                ).map(
                  ([key, label, artifact]): {
                    key: string;
                    label: string;
                    children: ReactNode;
                  } => ({
                    key,
                    label,
                    children: artifact ? (
                      <ObjectId value={artifact} wrap onOpen={() => openArtifact(artifact)} />
                    ) : (
                      "当前未记录"
                    ),
                  }),
                ),
              ]}
            />
            <p className="xs-foot">
              供应商模型 ID
              是请求所用标识，不代表已解析的精确模型版本。生命周期完整不等于索引无缺口。评估完成不表示业务操作获准。
            </p>
            <div className="xs-actions">
              <Button icon={<HistoryOutlined aria-hidden="true" />} onClick={history}>
                准备历史检索
              </Button>
            </div>
            <p className="xs-foot">
              历史检索仅预填模型调用引用，仍需输入时间窗并由 Investigator 独立鉴权。
            </p>
            <h3>模型生命周期</h3>
            <LifecycleTimeline
              label="模型生命周期事件"
              items={model.events.map((event) => ({
                key: event.event_id,
                tone: modelTone(event.status),
                title: `#${event.request_seq} · ${event.event_type} · ${event.status}`,
                time: <EventTime value={event.occurred_at} precision="millisecond" />,
                body: (
                  <ModelEventFacts
                    event={event}
                    onArtifact={openArtifact}
                    onPrevious={(eventId) =>
                      navigateTo.openSearch({ kind: "event_id", value: eventId })
                    }
                    onFollow={(eventId) =>
                      navigateTo.openSearch({ kind: "caused_by_event_id", value: eventId })
                    }
                  />
                ),
              }))}
            />
          </div>
        ) : (
          <EmptyState title="当前范围内未找到模型调用" icon="search">
            尚未发布、不存在、已过期或不在当前作用域的调用均可能返回此状态；请结合日志源与保留策略核对。
          </EmptyState>
        )}
        <p className="xs-foot">{ROLE_OBSERVER_TEXT}证据元数据另行鉴权，不显示任何正文。</p>
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

function ModelEventFacts({
  event,
  onArtifact,
  onPrevious,
  onFollow,
}: {
  event: ModelCallEvent;
  onArtifact: (id: string) => void;
  onPrevious: (eventId: string) => void;
  onFollow: (eventId: string) => void;
}) {
  return (
    <Descriptions
      bordered
      size="small"
      column={1}
      items={[
        { key: "id", label: "事件 ID", children: <ObjectId value={event.event_id} wrap /> },
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
          key: "reason",
          label: "原因",
          children: <ReasonCode code={event.reason_code} variant="inline" />,
        },
        {
          key: "confidence",
          label: "置信度",
          children: confidenceText(event.confidence, event.confidence_status),
        },
        {
          key: "confidenceState",
          label: "置信度状态",
          children: confidenceStateName(event.confidence_status).label,
        },
        { key: "duration", label: "耗时", children: formatDuration(event.duration_us) },
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
              {event.cause_event_ids.map((id) => (
                <ObjectId key={id} value={id} wrap onOpen={() => onPrevious(id)} />
              ))}
            </span>
          ) : (
            "起始事件"
          ),
        },
        {
          key: "follow",
          label: "直接后继",
          children: (
            <Button size="small" onClick={() => onFollow(event.event_id)}>
              准备关联检索
            </Button>
          ),
        },
        {
          key: "evidence",
          label: "证据引用",
          children: event.evidence_refs.length ? (
            <span className="xs-chips">
              {event.evidence_refs.map((id) =>
                id.startsWith("artifact_") ? (
                  <ObjectId key={id} value={id} wrap onOpen={() => onArtifact(id)} />
                ) : (
                  <ObjectId key={id} value={id} wrap />
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
