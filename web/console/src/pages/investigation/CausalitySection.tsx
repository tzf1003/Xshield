import { ApartmentOutlined } from "@ant-design/icons";
import { Button, Collapse, Select } from "antd";
import { useState } from "react";
import { eventTimeMs, fromSearchEvent, type EventView } from "../../investigation/event-view.ts";
import {
  buildCausalityPlan,
  type CausalityDirection,
  DEFAULT_CAUSALITY_DEPTH,
  DEFAULT_CAUSALITY_NODES,
} from "../../investigation/plans.ts";
import { ROLE_SEARCH_TEXT } from "../../investigation/roles.ts";
import type { CausalityNode, CausalityPlan, CausalityResponse } from "../../search.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { DecisionBadge } from "../../ui/DecisionBadge";
import { describeReason } from "../../ui/request-reasons.ts";
import { eventTypeName, stageName } from "../../ui/request-vocab.ts";
import { ErrorState } from "../../ui/states";
import { TimeStamp } from "../../ui/TimeStamp";
import { windowAround } from "../../ui/time-range.ts";
import { CompletenessBanner } from "../../ui/CompletenessBanner";
import "./drawers.css";
import "./investigation.css";

/** Half-width of the default window around the event, local time converted to UTC. */
export const CAUSALITY_SPREAD_MS = 15 * 60_000;

const directionOptions: { value: CausalityDirection; label: string }[] = [
  { value: "both", label: "前驱与后继" },
  { value: "predecessors", label: "仅前驱" },
  { value: "successors", label: "仅后继" },
];
const depthOptions = [1, 2, 3, 4].map((value) => ({ value, label: `${value} 跳` }));
const nodeOptions = Array.from({ length: 16 }, (_, index) => ({
  value: index + 1,
  label: `${index + 1} 个`,
}));

type Props = {
  event: EventView;
  /** Investigator; the server authorizes the query regardless. */
  canQuery: boolean;
  /** Open a node's event in the drawer. */
  onOpenEvent: (event: EventView) => void;
};

/**
 * Bounded server-side causality for one event. Nothing is sent until the operator presses the
 * button; the default window is plus or minus 15 minutes around the event (local time converted to
 * UTC), and depth and node limits sit behind "高级". Changing a limit discards the old result, and
 * a reply for an older plan can never show because the result is keyed by the plan.
 */
export function CausalitySection({ event, canQuery, onOpenEvent }: Props) {
  const [direction, setDirection] = useState<CausalityDirection>("both");
  const [depth, setDepth] = useState(DEFAULT_CAUSALITY_DEPTH);
  const [nodes, setNodes] = useState(DEFAULT_CAUSALITY_NODES);
  const [plan, setPlan] = useState<CausalityPlan | null>(null);
  const [formError, setFormError] = useState<unknown>(null);

  const query = useGuardedQuery({
    key: ["investigation", "causality", plan ? JSON.stringify(plan) : "none"],
    fetch: (client, signal) => {
      if (!plan) throw new Error("no causality plan");
      return client.causality(plan, signal);
    },
    staleTime: MANUAL_REFRESH,
    enabled: plan !== null,
  });

  function edit<T>(setter: (value: T) => void) {
    return (value: T) => {
      setter(value);
      setPlan(null);
      setFormError(null);
    };
  }

  function submit() {
    const center = eventTimeMs(event);
    const resolution = center === null ? null : windowAround(center, CAUSALITY_SPREAD_MS);
    if (!resolution?.window) {
      setFormError(new Error("event time unavailable"));
      return;
    }
    try {
      setPlan(
        buildCausalityPlan({
          window: resolution.window,
          eventId: event.eventId,
          direction,
          maxDepth: depth,
          maxNodes: nodes,
        }),
      );
      setFormError(null);
    } catch (error) {
      setPlan(null);
      setFormError(error);
    }
  }

  const response = plan ? query.data : undefined;
  return (
    <section className="xs-causality" aria-label="服务端因果查询" aria-busy={query.isFetching}>
      <h3>因果关系</h3>
      <p className="xs-foot">
        只查询该事件发生时刻前后各 15 分钟（UTC
        时间窗，含起不含止）内的脱敏事件节点，沿已记录的前驱引用有界遍历；不读取正文，也不会自动提交。
      </p>
      <div className="xs-causality-actions">
        <Button
          type="primary"
          icon={<ApartmentOutlined aria-hidden="true" />}
          disabled={!canQuery || query.isFetching}
          onClick={submit}
        >
          查看因果
        </Button>
        {query.isFetching ? <span className="xs-count">正在查询…</span> : null}
        {!canQuery ? <span className="xs-count">{ROLE_SEARCH_TEXT}</span> : null}
      </div>
      <Collapse
        size="small"
        ghost
        items={[
          {
            key: "advanced",
            label: "高级",
            children: (
              <div className="xs-causality-limits">
                <label htmlFor={`causality-direction-${event.eventId}`}>遍历方向</label>
                <Select
                  id={`causality-direction-${event.eventId}`}
                  value={direction}
                  options={directionOptions}
                  onChange={edit(setDirection)}
                />
                <label htmlFor={`causality-depth-${event.eventId}`}>最大跳数（1–4）</label>
                <Select
                  id={`causality-depth-${event.eventId}`}
                  value={depth}
                  options={depthOptions}
                  onChange={edit(setDepth)}
                />
                <label htmlFor={`causality-nodes-${event.eventId}`}>最大节点数（1–16）</label>
                <Select
                  id={`causality-nodes-${event.eventId}`}
                  value={nodes}
                  options={nodeOptions}
                  onChange={edit(setNodes)}
                  virtual={false}
                />
              </div>
            ),
          },
        ]}
      />
      {formError ? <ErrorState error={formError} /> : null}
      {plan && query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : null}
      {response && plan ? (
        <CausalityResult response={response} plan={plan} onOpenEvent={onOpenEvent} />
      ) : null}
    </section>
  );
}

type Level = { depth: number; nodes: CausalityNode[] };

function levels(nodes: readonly CausalityNode[], direction: CausalityNode["direction"]): Level[] {
  const byDepth = new Map<number, CausalityNode[]>();
  for (const node of nodes) {
    if (node.direction !== direction) continue;
    byDepth.set(node.depth, [...(byDepth.get(node.depth) ?? []), node]);
  }
  return [...byDepth.entries()]
    .sort(([left], [right]) => left - right)
    .map(([depth, list]) => ({ depth, nodes: list }));
}

function Branch({
  label,
  hops,
  onOpenEvent,
}: {
  label: string;
  hops: Level[];
  onOpenEvent: (event: EventView) => void;
}) {
  return (
    <section className="xs-branch" aria-label={label}>
      <h4>{label}</h4>
      {hops.length === 0 ? <p className="xs-foot">当前窗口没有该方向的关联节点。</p> : null}
      {hops.map((hop) => (
        <div className="xs-hop" key={hop.depth}>
          <span className="xs-hop-label">第 {hop.depth} 跳</span>
          <ul>
            {hop.nodes.map((node) => (
              <li key={node.event.event_id}>
                <button
                  type="button"
                  className="xs-node"
                  aria-label={`打开因果节点 ${node.event.event_id}`}
                  onClick={() => onOpenEvent(fromSearchEvent(node.event))}
                >
                  <DecisionBadge decision={node.event.outcome} />
                  <span className="xs-node-main">
                    <strong>{eventTypeName(node.event.event_type).label}</strong>
                    {node.event.stage ? (
                      <span className="xs-node-sub">{stageName(node.event.stage).label}</span>
                    ) : null}
                    {node.event.reason_code ? (
                      <span className="xs-node-sub">
                        {describeReason(node.event.reason_code).label}
                      </span>
                    ) : null}
                  </span>
                  <span className="xs-node-id mono">{node.event.event_id}</span>
                  <TimeStamp value={node.event.occurred_at} precision="millisecond" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

function CausalityResult({
  response,
  plan,
  onOpenEvent,
}: {
  response: CausalityResponse;
  plan: CausalityPlan;
  onOpenEvent: (event: EventView) => void;
}) {
  const showPredecessors = response.direction === "both" || response.direction === "predecessors";
  const showSuccessors = response.direction === "both" || response.direction === "successors";
  return (
    <section className="xs-causality-result" aria-label="服务端因果查询结果" aria-live="polite">
      <dl className="xs-facts">
        <div>
          <dt>根事件</dt>
          <dd>{response.found ? "已找到" : "当前窗口未找到"}</dd>
        </div>
        <div>
          <dt>时间窗（UTC，含起不含止）</dt>
          <dd className="mono">
            {plan.start} 至 {plan.end}
          </dd>
        </div>
        <div>
          <dt>节点数</dt>
          <dd>{response.nodes.length}</dd>
        </div>
        <div>
          <dt>扫描量</dt>
          <dd>
            {response.scanned_rows === null
              ? "行数未知"
              : `${response.scanned_rows.toLocaleString()} 行`}
            {response.scanned_bytes === null
              ? "，字节未知"
              : `，${response.scanned_bytes.toLocaleString()} 字节`}
          </dd>
        </div>
      </dl>
      <CompletenessBanner
        label="因果查询索引状态"
        input={{
          hasGaps: response.has_gaps,
          pendingSegments: response.pending_segments,
          notFound: !response.found,
          observations: [
            { label: "因果", asOf: response.as_of, watermark: response.index_watermark },
          ],
        }}
      />
      {response.truncated ? (
        <p className="xs-foot" role="status">
          结果已达到服务端有界遍历上限，不能据此推断完整因果图。
        </p>
      ) : null}
      <div className="xs-branches">
        {showPredecessors ? (
          <Branch
            label="前驱方向"
            hops={levels(response.nodes, "predecessor")}
            onOpenEvent={onOpenEvent}
          />
        ) : null}
        {showSuccessors ? (
          <Branch
            label="后继方向"
            hops={levels(response.nodes, "successor")}
            onOpenEvent={onOpenEvent}
          />
        ) : null}
      </div>
    </section>
  );
}
