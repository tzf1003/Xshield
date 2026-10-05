import { BranchesOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Collapse, Descriptions, Drawer } from "antd";
import { buildCausalNeighborhood, type CausalNode } from "../../event-causality.ts";
import { artifactRefs, type EventView, toCausalRecord } from "../../investigation/event-view.ts";
import {
  modelPath,
  requestPath,
  useInvestigationNavigate,
} from "../../investigation/navigation.ts";
import { canSearch } from "../../investigation/roles.ts";
import { useSession } from "../../security/SessionProvider";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { IdChip } from "../../ui/IdChip";
import { ReasonCode } from "../../ui/ReasonCode";
import {
  confidenceText,
  eventTypeName,
  proofKindName,
  sensitivityName,
  stageName,
} from "../../ui/request-vocab.ts";
import { formatDuration } from "../../ui/time-range.ts";
import { TimeStamp } from "../../ui/TimeStamp";
import { CausalitySection } from "./CausalitySection";
import "./drawers.css";
import "./investigation.css";

type Props = {
  /** The event shown; `null` closes the drawer. */
  event: EventView | null;
  onClose: () => void;
  /** Events already loaded on the page, for the local causal neighbourhood. */
  related: readonly EventView[];
  /** Show another event in this drawer (a causality node, a loaded neighbour). */
  onSelectEvent: (event: EventView) => void;
  onOpenArtifact: (artifactId: string) => void;
  /** The request this page already shows, which needs no link. */
  currentRequestId?: string;
};

/**
 * One redacted event: the facts the DTO carries, its evidence and causal references as chips, and
 * the actions that follow from them. Every action only prepares something (a search form, a
 * bounded causality query that waits for the button); no payload, storage or key material is
 * ever shown because none reaches this component.
 */
export function EventDrawer({
  event,
  onClose,
  related,
  onSelectEvent,
  onOpenArtifact,
  currentRequestId,
}: Props) {
  return (
    <Drawer
      open={event !== null}
      onClose={onClose}
      title="事件详情"
      size={560}
      destroyOnHidden
      styles={{ wrapper: { maxWidth: "100vw" } }}
    >
      {event ? (
        <EventBody
          key={event.eventId}
          event={event}
          related={related}
          onSelectEvent={onSelectEvent}
          onOpenArtifact={onOpenArtifact}
          currentRequestId={currentRequestId}
        />
      ) : null}
    </Drawer>
  );
}

function EventBody({
  event,
  related,
  onSelectEvent,
  onOpenArtifact,
  currentRequestId,
}: Omit<Props, "onClose" | "event"> & { event: EventView }) {
  const { state } = useSession();
  const navigateTo = useInvestigationNavigate();
  const stage = stageName(event.stage);
  const type = eventTypeName(event.eventType);
  const artifacts = artifactRefs(event.evidenceRefs);
  const otherRefs = event.evidenceRefs.filter((ref) => !ref.startsWith("artifact_"));
  const canQuery = canSearch(state.roles);
  const { requestId, modelCallId, traceId } = event;

  const items = [
    { key: "id", label: "事件 ID", children: <IdChip value={event.eventId} wrap /> },
    {
      key: "type",
      label: "事件类型",
      children: (
        <>
          {type.label}
          {type.known ? <span className="xs-sub mono">{event.eventType}</span> : null}
        </>
      ),
    },
    {
      key: "request",
      label: "来源请求",
      children: requestId ? (
        requestId === currentRequestId ? (
          <IdChip value={requestId} wrap />
        ) : (
          <IdChip
            value={requestId}
            wrap
            href={requestPath(requestId)}
            onOpen={() => navigateTo.go(requestPath(requestId))}
          />
        )
      ) : (
        "未记录"
      ),
    },
    ...(traceId
      ? [{ key: "trace", label: "Trace ID", children: <IdChip value={traceId} wrap /> }]
      : []),
    {
      key: "stage",
      label: "阶段",
      children: event.stage ? (
        <>
          {stage.label}
          {stage.known ? <span className="xs-sub mono">{event.stage}</span> : null}
        </>
      ) : (
        "未记录"
      ),
    },
    { key: "outcome", label: "结果", children: <DecisionBadge decision={event.outcome} /> },
    {
      key: "reason",
      label: "原因",
      children: event.reasonCode ? <ReasonCode code={event.reasonCode} variant="full" /> : "未记录",
    },
    {
      key: "proof",
      label: "证明类型",
      children: event.proofKind ? proofKindName(event.proofKind).label : "未记录",
    },
    {
      key: "confidence",
      label: "置信度",
      children: confidenceText(event.confidence, event.confidenceStatus),
    },
    {
      key: "policy",
      label: "策略版本",
      children: event.policyRevision ? (
        <span className="mono">{event.policyRevision}</span>
      ) : (
        "未记录"
      ),
    },
    {
      key: "model",
      label: "模型调用",
      children: modelCallId ? (
        <IdChip
          value={modelCallId}
          wrap
          href={modelPath(modelCallId)}
          onOpen={() => navigateTo.go(modelPath(modelCallId))}
        />
      ) : (
        "未记录"
      ),
    },
    {
      key: "time",
      label: "事件时间",
      children: (
        <span className="xs-times">
          <TimeStamp value={event.occurredAt} precision="microsecond" />
          <span className="mono xs-sub">{event.occurredAt}</span>
        </span>
      ),
    },
    {
      key: "evidence",
      label: "证据引用",
      children:
        event.evidenceRefs.length === 0 ? (
          "该事件未记录证据引用。"
        ) : (
          <span className="xs-chips">
            {artifacts.map((ref) => (
              <IdChip key={ref} value={ref} wrap onOpen={() => onOpenArtifact(ref)} />
            ))}
            {otherRefs.map((ref) => (
              <IdChip key={ref} value={ref} wrap />
            ))}
          </span>
        ),
    },
  ];

  const causal = buildCausalNeighborhood(toCausalRecord(event), related.map(toCausalRecord));
  const causalCount = [...causal.predecessors, ...causal.successors].flat().length;
  const byId = new Map(related.map((view) => [view.eventId, view]));
  const openNode = (node: CausalNode) => {
    const loaded = byId.get(node.eventId);
    if (loaded) onSelectEvent(loaded);
    else navigateTo.openSearch({ kind: "event_id", value: node.eventId });
  };

  return (
    <div className="xs-drawer-body">
      <Descriptions bordered size="small" column={1} items={items} />
      <div className="xs-drawer-actions">
        <Button
          icon={<SearchOutlined aria-hidden="true" />}
          onClick={() =>
            navigateTo.openSearch({ kind: "caused_by_event_id", value: event.eventId })
          }
        >
          查找直接后继
        </Button>
        {traceId ? (
          <Button
            icon={<BranchesOutlined aria-hidden="true" />}
            onClick={() => navigateTo.openSearch({ kind: "trace_id", value: traceId })}
          >
            同 Trace 检索
          </Button>
        ) : null}
      </div>
      <p className="xs-foot">
        检索入口只预填条件并打开检索页；时间范围由你选择并显式提交，不会自动查询。
      </p>
      <Collapse
        size="small"
        className="xs-details"
        items={[
          {
            key: "more",
            label: "更多事件字段",
            children: (
              <Descriptions
                bordered
                size="small"
                column={1}
                items={[
                  { key: "seq", label: "事件序号", children: event.requestSeq },
                  { key: "duration", label: "耗时", children: formatDuration(event.durationUs) },
                  {
                    key: "sensitivity",
                    label: "数据分级",
                    children: sensitivityName(event.sensitivity).label,
                  },
                  {
                    key: "modelRevision",
                    label: "模型版本",
                    children: event.modelRevision ? (
                      <span className="mono">{event.modelRevision}</span>
                    ) : (
                      "未记录"
                    ),
                  },
                  {
                    key: "causes",
                    label: "前驱事件",
                    children:
                      event.causeEventIds.length === 0 ? (
                        "未记录前驱"
                      ) : (
                        <span className="xs-chips">
                          {event.causeEventIds.map((id) => (
                            <span className="xs-cause" key={id}>
                              <IdChip value={id} wrap />
                              <Button
                                size="small"
                                type="link"
                                onClick={() =>
                                  navigateTo.openSearch({ kind: "event_id", value: id })
                                }
                              >
                                在检索中查找
                              </Button>
                            </span>
                          ))}
                        </span>
                      ),
                  },
                ]}
              />
            ),
          },
          ...(causalCount > 0
            ? [
                {
                  key: "local",
                  label: `查看当前页因果关联（${causalCount} 个节点）`,
                  children: (
                    <div className="xs-local-causal">
                      <p className="xs-foot">
                        关联只依据当前页已载入事件的前驱引用；未载入的引用只会预填事件 ID
                        检索，仍由你提供时间窗并提交。
                      </p>
                      <LocalBranch
                        label="前驱方向"
                        levels={causal.predecessors}
                        onOpen={openNode}
                      />
                      <LocalBranch label="后继方向" levels={causal.successors} onOpen={openNode} />
                      {causal.truncated ? (
                        <p className="xs-foot" role="status">
                          视图已达到每方向 4 跳或 16 个节点上限。
                        </p>
                      ) : null}
                    </div>
                  ),
                },
              ]
            : []),
        ]}
      />
      <CausalitySection event={event} canQuery={canQuery} onOpenEvent={onSelectEvent} />
    </div>
  );
}

function LocalBranch({
  label,
  levels,
  onOpen,
}: {
  label: string;
  levels: CausalNode[][];
  onOpen: (node: CausalNode) => void;
}) {
  return (
    <section className="xs-branch" aria-label={label}>
      <h4>{label}</h4>
      {levels.length === 0 ? <p className="xs-foot">当前已加载事件中没有关联节点。</p> : null}
      {levels.map((nodes, index) => (
        <div className="xs-hop" key={nodes.map((node) => node.eventId).join("|")}>
          <span className="xs-hop-label">第 {index + 1} 跳</span>
          <ul>
            {nodes.map((node) => (
              <li key={node.eventId}>
                <button
                  type="button"
                  className="xs-node"
                  aria-label={`查看因果事件 ${node.eventId}`}
                  onClick={() => onOpen(node)}
                >
                  <span className="xs-node-main">
                    <strong>
                      {node.event ? eventTypeName(node.event.event_type).label : "引用事件未载入"}
                    </strong>
                  </span>
                  <span className="xs-node-id mono">{node.eventId}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}
