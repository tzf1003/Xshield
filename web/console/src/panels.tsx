import type { ReactNode } from "react";
import type { SearchEvent } from "./search";
import type {
  ArtifactResponse,
  AuditEvent,
  EventsResponse,
  Manifest,
  ModelCallResponse,
  SummaryResponse,
} from "./api";

const stageNames: Record<string, string> = {
  admission: "准入检查",
  auth_binding: "认证绑定",
  ui_action: "界面来源",
  terminal: "请求终态",
  origin: "源站交互",
};
const stateNames: Record<string, string> = {
  complete: "已采集",
  entity_exact: "实体精确",
  semantic: "语义保真",
  redacted: "已脱敏",
  INTERNAL: "内部",
  SENSITIVE: "敏感",
  RESTRICTED: "受限",
};
const stageName = (stage: string | null) =>
  (stage && stageNames[stage]) || stage || "未记录阶段";
const label = (value: string) => stateNames[value] ?? value;
function time(value: string | number) {
  const date = new Date(
    typeof value === "number" ? Math.floor(value / 1000) : value,
  );
  return Number.isFinite(date.valueOf())
    ? `${date
        .toISOString()
        .replace("T", " ")
        .replace(/\.\d+Z$/, "")} UTC`
    : "时间不可用";
}
export function Rows({ entries }: { entries: [string, ReactNode][] }) {
  return (
    <dl>
      {entries.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}
function Badge({ value }: { value: string | null }) {
  return (
    <span
      className={`badge ${value === "DENY" || value === "ERROR" ? "denied" : value === "PASS" || value === "ALLOW" ? "passed" : ""}`}
    >
      {value || "未记录"}
    </span>
  );
}

/** Model evidence remains reference-only; opening a reference reads its catalog metadata. */
export function ModelCallOverview({
  response,
  onOpen,
}: {
  response: ModelCallResponse;
  onOpen: (id: string) => void;
}) {
  const model = response.model_call;
  const completeness = {
    complete: "生命周期完整",
    pending: "等待模型终态",
    partial: "生命周期部分可见",
    not_indexed: "当前索引未找到调用",
  }[response.completeness];
  return (
    <>
      <div
        className={`notice ${response.has_gaps || response.pending_segments > 0 ? "warning" : ""}`}
        role="status"
      >
        <div>
          <strong>{completeness}</strong>
          <p>
            索引水位仅覆盖配置的日志源，不代表模型调用已全部追平；结果随发布与保留而变化。
          </p>
          <details>
            <summary>查看模型查询水位</summary>
            <Rows
              entries={[
                ["观察时间", time(response.as_of)],
                ["水位范围", response.watermark_scope],
                [
                  "水位",
                  response.index_watermark
                    ? `${response.index_watermark.producer_boot_id} / ${response.index_watermark.producer_sequence}`
                    : "尚不可用",
                ],
                ["待发布段", response.pending_segments],
                ["索引缺口", response.has_gaps ? "存在" : "未观察到"],
              ]}
            />
          </details>
        </div>
      </div>
      <section className="panel" aria-label="模型调用详情">
        <div className="panel-heading model-heading">
          <h2>模型调用</h2>
          <span className="mono">{response.source_model_call_id}</span>
        </div>
        {model ? (
          <div className="detail-body">
            <Rows
              entries={[
                ["来源请求", <span className="mono">{model.request_id}</span>],
                ["生命周期状态", model.status],
                ["原因", <span className="mono">{model.reason_code}</span>],
                ["供应商路由", model.provider ?? "历史记录未提供"],
                [
                  "供应商模型 ID",
                  <span className="mono">
                    {model.provider_model_id ?? "历史记录未提供"}
                  </span>,
                ],
                [
                  "内部模型版本",
                  <span className="mono">{model.model_revision}</span>,
                ],
                [
                  "提示版本",
                  <span className="mono">{model.prompt_revision}</span>,
                ],
                ["问题类型", model.question_type],
                [
                  "置信度",
                  model.confidence === null
                    ? model.confidence_status === "not_applicable"
                      ? "不适用"
                      : "未提供"
                    : model.confidence,
                ],
                ["置信度状态", model.confidence_status],
                ["耗时", `${model.duration_us} μs`],
                ...(
                  [
                    ["输入证据", model.input_artifact_id],
                    ["输出证据", model.output_artifact_id],
                    ["调用记录", model.call_artifact_id],
                  ] as const
                ).map(([label, id]): [string, ReactNode] => [
                  label,
                  id ? (
                    <button
                      className="artifact-link mono"
                      onClick={() => onOpen(id)}
                    >
                      {id}
                    </button>
                  ) : (
                    "当前未记录"
                  ),
                ]),
              ]}
            />
            <p className="footnote">
              供应商模型 ID
              是请求所用标识，不代表已解析的精确模型版本。生命周期完整不等于索引无缺口。评估完成不表示业务操作获准。
            </p>
            <h3 className="model-lifecycle-title">模型生命周期</h3>
            {model.events.map((event) => (
              <details className="model-event" key={event.event_id}>
                <summary>
                  <span className="mono">
                    #{event.request_seq} · {event.event_type} · {event.status}
                  </span>
                </summary>
                <Rows
                  entries={[
                    ["事件 ID", <span className="mono">{event.event_id}</span>],
                    ["事件时间", time(event.occurred_at)],
                    ["原因", <span className="mono">{event.reason_code}</span>],
                    [
                      "置信度",
                      event.confidence === null
                        ? event.confidence_status === "not_applicable"
                          ? "不适用"
                          : "未提供"
                        : event.confidence,
                    ],
                    ["置信度状态", event.confidence_status],
                    ["耗时", `${event.duration_us} μs`],
                    ["数据分级", label(event.sensitivity)],
                    [
                      "前驱事件",
                      event.cause_event_ids.length
                        ? event.cause_event_ids.map((id) => (
                            <p className="mono" key={id}>
                              {id}
                            </p>
                          ))
                        : "起始事件",
                    ],
                    [
                      "证据引用",
                      event.evidence_refs.length
                        ? event.evidence_refs.map((id) =>
                            id.startsWith("artifact_") ? (
                              <button
                                className="artifact-link mono"
                                key={id}
                                onClick={() => onOpen(id)}
                              >
                                {id}
                              </button>
                            ) : (
                              <p className="mono" key={id}>
                                {id}
                              </p>
                            ),
                          )
                        : "当前未记录",
                    ],
                  ]}
                />
              </details>
            ))}
          </div>
        ) : (
          <p className="empty">
            尚未发布、不存在、已过期或不在当前作用域的调用均可能返回此状态；请结合日志源与保留策略核对。
          </p>
        )}
      </section>
    </>
  );
}

export function WatermarkNotice({
  summary,
  events,
}: {
  summary: SummaryResponse;
  events: EventsResponse | null;
}) {
  const pending = summary.pending_segments > 0;
  const gaps = summary.has_gaps || events?.has_gaps;
  const incomplete =
    pending || gaps || summary.completeness === "pending_index";
  return (
    <div
      className={`notice watermark-notice ${incomplete ? "warning" : ""}`}
      role="status"
    >
      <span aria-hidden="true">{incomplete ? "△" : "○"}</span>
      <div>
        <strong>
          {pending
            ? `索引仍在同步 · ${summary.pending_segments} 个待发布段`
            : gaps
              ? "索引存在缺口"
              : summary.index_watermark
                ? "已读取索引水位"
                : "索引水位尚不可用"}
        </strong>
        <span className="notice-context">
          {incomplete ? "当前结果可能不完整；" : ""}水位仅代表配置的日志源。
        </span>
        <details>
          <summary>查看水位</summary>
          <Rows
            entries={[
              ["摘要观察时间", time(summary.as_of)],
              [
                "摘要水位",
                summary.index_watermark
                  ? `${summary.index_watermark.producer_boot_id} / ${summary.index_watermark.producer_sequence}`
                  : "尚不可用",
              ],
              ["事件观察时间", events ? time(events.as_of) : "尚未读取"],
              [
                "事件水位",
                events?.index_watermark
                  ? `${events.index_watermark.producer_boot_id} / ${events.index_watermark.producer_sequence}`
                  : "尚不可用",
              ],
            ]}
          />
          <p>摘要和事件分别读取，水位不覆盖其他 Outbox 日志源。</p>
        </details>
      </div>
    </div>
  );
}

export function RequestOverview({ response }: { response: SummaryResponse }) {
  const summary = response.summary;
  return (
    <section className="panel overview" aria-label="请求摘要">
      <div className="overview-grid">
        <div className="request-identity">
          <h2>请求摘要</h2>
          <span className="mono">{response.source_request_id}</span>
        </div>
        {summary ? (
          <>
            <div>
              <span className="muted">最终判定</span>
              <strong>
                {!summary.terminal
                  ? "等待终态"
                  : summary.decision === null
                    ? "判定未记录"
                    : summary.decision === "DENY"
                      ? "DENY · 已拒绝"
                      : summary.decision === "ALLOW"
                        ? "ALLOW · 已允许"
                        : "UNKNOWN · 未知"}
              </strong>
            </div>
            <div>
              <span className="muted">主要原因</span>
              <strong className="mono">
                {summary.reason_code ?? "尚未记录"}
              </strong>
            </div>
            <div>
              <span className="muted">源站转发</span>
              <strong>
                {summary.forwarded
                  ? "已观察到转发意图"
                  : summary.origin_state === "not_sent"
                    ? "未转发"
                    : "未观察到转发"}
              </strong>
            </div>
            <div>
              <span className="muted">业务结果</span>
              <strong>
                {summary.business_result_confirmed
                  ? "已确认源站响应"
                  : "未确认"}
              </strong>
            </div>
          </>
        ) : (
          <div className="summary-empty">
            <strong>
              {response.completeness === "pending_index"
                ? "索引待就绪"
                : "当前未找到请求"}
            </strong>
            <span className="muted">
              {response.completeness === "pending_index"
                ? "待发布记录或索引缺口可能影响查询结果，请稍后重新查询。"
                : "请核对请求 ID 与当前访问范围。"}
            </span>
          </div>
        )}
      </div>
      {summary && (
        <div className="overview-meta">
          <span className="mono">{summary.method ?? "方法未记录"}</span>
          <span className="mono">{summary.operation_id ?? "操作未记录"}</span>
          <span>
            观察时间{" "}
            <span className="mono">{time(summary.last_occurred_at)}</span>
          </span>
          {summary.decision === "ALLOW" && (
            <span>
              检查范围：{summary.operation_id ?? "未记录"}
              ，以对应策略及阶段记录为准。
            </span>
          )}
          {summary.business_result_confirmed && (
            <span>源站响应已确认不等同于业务执行成功。</span>
          )}
        </div>
      )}
    </section>
  );
}

export function EventTable({
  events,
  selected,
  onSelect,
}: {
  events: (AuditEvent | SearchEvent)[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  if (events.length === 0)
    return <p className="empty">当前页暂无事件；请结合索引水位判断完整性。</p>;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th aria-label="选择事件" />
            <th>阶段</th>
            <th>结果</th>
            <th>原因</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              className={event.event_id === selected ? "selected" : ""}
              key={event.event_id}
            >
              <td>
                <input
                  type="radio"
                  name="selected-event"
                  aria-label={event.event_id}
                  checked={selected === event.event_id}
                  onChange={() => onSelect(event.event_id)}
                />
              </td>
              <td>
                <strong>{stageName(event.stage)}</strong>
                <small className="mono">{event.event_id}</small>
                {"request_id" in event && (
                  <small className="mono">{event.event_type}</small>
                )}
              </td>
              <td>
                <Badge value={event.outcome} />
              </td>
              <td className="mono reason">{event.reason_code || "未记录"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EventDetail({
  event,
  onOpen,
  onRequest,
}: {
  event: AuditEvent | SearchEvent;
  onOpen: (id: string) => void;
  onRequest?: (id: string) => void;
}) {
  return (
    <div className="detail-body">
      <h3>{stageName(event.stage)}</h3>
      <Rows
        entries={[
          ["事件 ID", <span className="mono">{event.event_id}</span>],
          ...("request_id" in event
            ? ([
                [
                  "来源请求",
                  event.request_id ? (
                    <button
                      className="artifact-link mono"
                      onClick={() =>
                        event.request_id && onRequest?.(event.request_id)
                      }
                    >
                      {event.request_id}
                    </button>
                  ) : (
                    "未记录"
                  ),
                ],
                ["事件时间", <span className="mono">{event.occurred_at}</span>],
              ] as [string, ReactNode][])
            : []),
          ["证明类型", event.proof_kind || "未记录"],
          [
            "置信度",
            event.confidence === null
              ? event.confidence_status === "not_applicable"
                ? "不适用"
                : "未提供"
              : event.confidence,
          ],
          [
            "策略版本",
            <span className="mono">{event.policy_revision || "未记录"}</span>,
          ],
          [
            "证据引用",
            event.evidence_refs.length
              ? event.evidence_refs.map((id) =>
                  id.startsWith("artifact_") ? (
                    <button
                      key={id}
                      className="artifact-link mono"
                      onClick={() => onOpen(id)}
                    >
                      {id}
                    </button>
                  ) : (
                    <p key={id} className="mono">
                      {id}
                    </p>
                  ),
                )
              : "该事件未记录证据引用。",
          ],
        ]}
      />
      <details className="event-metadata">
        <summary>更多事件字段</summary>
        <Rows
          entries={[
            ["事件类型", <span className="mono">{event.event_type}</span>],
            ...(typeof event.occurred_at === "number"
              ? ([["事件时间", time(event.occurred_at)]] as [
                  string,
                  ReactNode,
                ][])
              : []),
            ["事件序号", event.request_seq],
            ["置信度状态", event.confidence_status || "未记录"],
            [
              "模型版本",
              <span className="mono">{event.model_revision || "未记录"}</span>,
            ],
            ["耗时", `${event.duration_us} μs`],
            ["数据分级", label(event.sensitivity)],
            [
              "前驱事件",
              event.cause_event_ids.length
                ? event.cause_event_ids.map((id) => (
                    <p className="mono" key={id}>
                      {id}
                    </p>
                  ))
                : "未记录",
            ],
          ]}
        />
      </details>
    </div>
  );
}

export function EvidenceTable({
  artifacts,
  onOpen,
}: {
  artifacts: Manifest[];
  onOpen: (id: string) => void;
}) {
  if (artifacts.length === 0)
    return <p className="empty">当前页暂无可用证据目录记录。</p>;
  return (
    <div className="table-wrap">
      <table className="evidence-table">
        <thead>
          <tr>
            <th>证据</th>
            <th>采集 / 保真度</th>
            <th>分级</th>
          </tr>
        </thead>
        <tbody>
          {artifacts.map((artifact) => (
            <tr key={artifact.artifact_id}>
              <td>
                <button
                  className="text-button mono"
                  onClick={() => onOpen(artifact.artifact_id)}
                >
                  {artifact.artifact_id}
                </button>
                <small>{artifact.kind}</small>
              </td>
              <td>
                {label(artifact.capture_status)}
                <small>{label(artifact.fidelity)}</small>
              </td>
              <td>{label(artifact.classification)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ArtifactDetail({ response }: { response: ArtifactResponse }) {
  const artifact = response.artifact;
  if (!artifact)
    return (
      <div className="detail-body">
        <h3>证据当前不可用</h3>
        <p className="mono">{response.source_artifact_id}</p>
        <p className="muted">服务端未返回当前范围内的有效目录记录。</p>
      </div>
    );
  return (
    <div className="detail-body">
      <h3>证据元数据</h3>
      <Rows
        entries={[
          ["证据 ID", <span className="mono">{artifact.artifact_id}</span>],
          ["请求 ID", <span className="mono">{artifact.request_id}</span>],
          ["类型", artifact.kind],
          ["媒体类型", artifact.content_type],
          ["采集状态", label(artifact.capture_status)],
          ["保真度", label(artifact.fidelity)],
          ["分级", label(artifact.classification)],
          ["观察字节", artifact.bytes_observed.toLocaleString()],
          ["保存字节", artifact.bytes_saved.toLocaleString()],
          ["记录时间", time(artifact.recorded_at)],
          ["到期时间", time(artifact.expires_at)],
        ]}
      />
      <p className="footnote">
        目录记录用于定位证据。内容读取权限与对象完整性需独立校验。
      </p>
    </div>
  );
}
