import { useState } from "react";
import type { CausalityResponse } from "./search";

type Problem = { message: string; code: string; requestId?: string | null };

/** Explicit server traversal for the currently selected redacted event. */
export function CausalityPanel({
  eventId,
  response,
  busy,
  problem,
  onEdit,
  onSubmit,
}: {
  eventId: string;
  response: CausalityResponse | null;
  busy: boolean;
  problem: Problem | null;
  onEdit: () => void;
  onSubmit: (value: unknown) => void;
}) {
  const [window, setWindow] = useState({ start: "", end: "" });
  const [direction, setDirection] = useState<"both" | "predecessors" | "successors">("both");
  const [maxDepth, setMaxDepth] = useState("2");
  const [maxNodes, setMaxNodes] = useState("16");
  const visibleResponse =
    response?.root_event_id === eventId ? response : null;
  const utc = (value: string) =>
    `${value.length === 16 ? `${value}:00` : value}Z`;

  return (
    <section
      className="event-metadata causality-query"
      aria-label="服务端因果查询"
      aria-busy={busy}
    >
      <h4>服务端有界因果查询</h4>
      <p className="footnote">
        仅查询当前事件在指定 UTC 时间窗内的脱敏事件节点；不会读取正文，也不会自动提交。
      </p>
      <form
        className="causality-query-form"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({
            schema_version: 3,
            start: utc(window.start),
            end: utc(window.end),
            event_id: eventId,
            direction,
            max_depth: Number(maxDepth),
            max_nodes: Number(maxNodes),
          });
        }}
      >
        <div className="search-window">
          <label>
            因果开始时间（UTC，含）
            <input
              type="datetime-local"
              value={window.start}
              min="1970-01-01T00:00:00"
              max="2300-01-01T00:00:00"
              step="1"
              required
              onChange={(event) => {
                onEdit();
                setWindow({ ...window, start: event.target.value });
              }}
            />
          </label>
          <label>
            因果结束时间（UTC，不含）
            <input
              type="datetime-local"
              value={window.end}
              min="1970-01-01T00:00:00"
              max="2300-01-01T00:00:00"
              step="1"
              required
              onChange={(event) => {
                onEdit();
                setWindow({ ...window, end: event.target.value });
              }}
            />
          </label>
          <label htmlFor="causality-direction">
            遍历方向
            <select
              id="causality-direction"
              value={direction}
              onChange={(event) => {
                onEdit();
                setDirection(
                  event.target.value === "predecessors"
                    ? "predecessors"
                    : event.target.value === "successors"
                      ? "successors"
                      : "both",
                );
              }}
            >
              <option value="both">前驱与后继</option>
              <option value="predecessors">仅前驱</option>
              <option value="successors">仅后继</option>
            </select>
          </label>
          <label htmlFor="causality-max-depth">
            最大跳数
            <input
              id="causality-max-depth"
              type="number"
              min="1"
              max="4"
              step="1"
              value={maxDepth}
              required
              onChange={(event) => {
                onEdit();
                setMaxDepth(event.target.value);
              }}
            />
          </label>
          <label htmlFor="causality-max-nodes">
            最大节点数
            <input
              id="causality-max-nodes"
              type="number"
              min="1"
              max="16"
              step="1"
              value={maxNodes}
              required
              onChange={(event) => {
                onEdit();
                setMaxNodes(event.target.value);
              }}
            />
          </label>
        </div>
        <p className="footnote mono">根事件：{eventId}</p>
        <button type="submit" disabled={busy}>
          {busy ? "查询中…" : "查询服务端因果"}
        </button>
      </form>
      {problem && (
        <div className="notice danger" role="alert">
          {problem.message}
          <small className="mono">
            {problem.code}
            {problem.requestId ? ` · ${problem.requestId}` : ""}
          </small>
        </div>
      )}
      {visibleResponse && (
        <section
          className="causality-query-result"
          aria-label="服务端因果查询结果"
          aria-live="polite"
        >
          <dl>
            <div>
              <dt>根事件</dt>
              <dd>{visibleResponse.found ? "已找到" : "当前窗口未找到"}</dd>
            </div>
            <div>
              <dt>节点数</dt>
              <dd>{visibleResponse.nodes.length}</dd>
            </div>
            <div>
              <dt>索引状态</dt>
              <dd>
                {visibleResponse.has_gaps || visibleResponse.pending_segments > 0
                  ? "存在未发布片段"
                  : "已发布快照"}
              </dd>
            </div>
            <div>
              <dt>扫描量</dt>
              <dd>
                {visibleResponse.scanned_rows === null
                  ? "行数未知"
                  : `${visibleResponse.scanned_rows.toLocaleString()} 行`}
                {visibleResponse.scanned_bytes === null
                  ? "，字节未知"
                  : `，${visibleResponse.scanned_bytes.toLocaleString()} 字节`}
              </dd>
            </div>
          </dl>
          {visibleResponse.truncated && (
            <p className="footnote" role="status">
              结果已达到服务端有界遍历上限，不能据此推断完整因果图。
            </p>
          )}
          {visibleResponse.nodes.length > 0 && (
            <ul className="causality-query-nodes">
              {visibleResponse.nodes.map((node) => (
                <li key={node.event.event_id}>
                  <span>{node.direction === "predecessor" ? "前驱" : "后继"} · 第 {node.depth} 跳</span>
                  <strong>{node.event.event_type}</strong>
                  <span className="mono">{node.event.event_id}</span>
                  <span className="mono">{node.event.occurred_at}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </section>
  );
}
