import { useState } from "react";
import type { ReactNode } from "react";
import type { SearchEvent } from "./search";
import type { CausalityResponse } from "./search";
import { buildCausalNeighborhood } from "./event-causality";
import type { CausalNode } from "./event-causality";
import { CausalityPanel } from "./CausalityPanel";
import type {
  ArtifactResponse,
  AuditHealthResponse,
  AuditEvent,
  CalibrationReportResponse,
  EventsResponse,
  Manifest,
  ModelCallListPlan,
  ModelCallListResponse,
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

/** Displays only one frozen restricted report projection. The body retention
 * marker is an investigation observation, never a content-read affordance. */
export function CalibrationReportPanel({
  response,
  busy,
  onRefresh,
  onHistory,
}: {
  response: CalibrationReportResponse | null;
  busy: boolean;
  onRefresh: () => void;
  onHistory: (reportId: string) => void;
}) {
  return (
    <>
      <section className="panel" aria-label="校准报告调查说明">
        <h2>受限校准报告元数据</h2>
        <p className="footnote">
          这里仅显示已冻结的报告元数据与正文 tombstone 状态。它不显示或读取报告正文、样本、标签、概率、指标、提示词或任何内容读取能力。
        </p>
        <button onClick={onRefresh} disabled={busy}>
          {busy ? "读取中…" : response ? "手动刷新报告" : "读取报告"}
        </button>
        <p className="footnote">
          每次读取均由服务端独立重新鉴权并写管理审计；控制台不会自动轮询。
        </p>
      </section>
      {response?.report ? (
        <section className="panel" aria-label="校准报告详情" aria-busy={busy}>
          <div className="panel-heading model-heading">
            <h2>校准报告</h2>
            <span className="mono">{response.report.report_id}</span>
          </div>
          <div className="detail-body">
            <Rows
              entries={[
                ["管理请求 ID", <span className="mono">{response.request_id}</span>],
                ["数据库观察时间", <span className="mono">{time(response.as_of ?? "")}</span>],
                ["批次完成时间", <span className="mono">{time(response.report.completed_at)}</span>],
                ["报告冻结时间", <span className="mono">{time(response.report.reported_at)}</span>],
                ["报告 artifact", <span className="mono">{response.report.report_artifact_id}</span>],
                ["报告事件", <span className="mono">{response.report.reported_event_id}</span>],
                ["正文保留至", <span className="mono">{time(response.report.body_expires_at)}</span>],
                ["批准引用", <span className="mono">{response.report.approval_ref}</span>],
                ["数据集修订", <span className="mono">{response.report.dataset_revision}</span>],
                ["标签集修订", <span className="mono">{response.report.label_revision}</span>],
                ["任务语义修订", <span className="mono">{response.report.task_revision}</span>],
                ["阈值策略修订", <span className="mono">{response.report.threshold_policy_revision}</span>],
                ["风险映射修订", <span className="mono">{response.report.mapping_revision}</span>],
                ["评估 manifest", <span className="mono">{response.report.evaluation_manifest_artifact_id}</span>],
                ["训练 manifest", <span className="mono">{response.report.training_manifest_artifact_id}</span>],
                ["校准 manifest", <span className="mono">{response.report.calibration_manifest_artifact_id}</span>],
                ["标签 manifest", <span className="mono">{response.report.label_manifest_artifact_id}</span>],
                ["供应商", <span className="mono">{response.report.provider}</span>],
                ["供应商模型 ID", <span className="mono">{response.report.provider_model_id}</span>],
                ["内部模型修订", <span className="mono">{response.report.model_revision}</span>],
                ["提示修订", <span className="mono">{response.report.prompt_revision}</span>],
                [
                  "已解析模型修订",
                  response.report.resolved_model_revision ? (
                    <span className="mono">{response.report.resolved_model_revision}</span>
                  ) : "历史记录未提供",
                ],
                [
                  "血缘审查",
                  response.report.lineage_review_id ? (
                    <span className="mono">{response.report.lineage_review_id}</span>
                  ) : "历史记录未提供",
                ],
                [
                  "报告正文 tombstone",
                  response.report.body_status === "active"
                    ? "active（未记录终态删除）"
                    : "deleted（已记录终态删除）",
                ],
              ]}
            />
          </div>
          <p className="footnote">
            正文 tombstone 状态只说明专用加密正文的保留观察；它不表示正文可读、质量已验证、阈值或策略已发布，亦不表示业务资格。
          </p>
          <button
            type="button"
            className="outline"
            onClick={() => onHistory(response.report!.report_id)}
          >
            准备历史检索
          </button>
          <p className="footnote">
            历史检索仅预填报告引用，仍需输入时间窗并由 Investigator 独立鉴权。
          </p>
        </section>
      ) : response ? (
        <section className="panel" aria-label="校准报告详情" aria-busy={busy}>
          <h2>当前范围内未找到报告</h2>
          <p className="footnote">
            该结果不推断报告不存在于其他范围，也不提供任何内容或读取能力。
          </p>
        </section>
      ) : null}
    </>
  );
}

const confidenceStatusLabel = {
  provided: "已提供（详见详情）",
  not_applicable: "不适用",
  not_provided: "未提供",
  unavailable: "不可用",
} as const;

/** Displays one explicit, audited configuration journal publication snapshot.
 * This is an observation surface, so it never refreshes itself or presents the
 * counters as a business decision, an Outbox report, or service-wide health. */
export function AuditHealthPanel({
  response,
  busy,
  onRefresh,
}: {
  response: AuditHealthResponse | null;
  busy: boolean;
  onRefresh: () => void;
}) {
  return (
    <>
      <section className="panel audit-health-intro" aria-label="审计发布状态说明">
        <h2>配置日志发布观察</h2>
        <p className="footnote">
          此处仅观察一个配置 audit journal 到其索引目标的封存段发布状态。它不代表业务准入、全部 Outbox 状态或系统整体健康。
        </p>
        <button onClick={onRefresh} disabled={busy}>
          {busy ? "读取中…" : response ? "手动刷新发布状态" : "读取发布状态"}
        </button>
        <p className="footnote">每次读取均由服务端单独重新鉴权并写入管理审计；控制台不会自动轮询。</p>
      </section>
      {response && (
        <>
          <div
            className={`notice ${response.has_gaps || response.pending_segments > 0 || response.unsealed_segments > 0 ? "warning" : ""}`}
            role="status"
            aria-label="审计发布状态"
          >
            <div>
              <strong>
                {response.has_gaps ? "发布观察到缺口" : "未观察到发布缺口"} · {response.pending_segments} 个待发布段
              </strong>
              <p>
                连续水位只覆盖配置 journal 的已确认封存段；后续孤岛、未封存数据和其他发布路径须分别判断。
              </p>
            </div>
          </div>
          <section className="panel audit-health-result" aria-label="审计发布状态结果" aria-busy={busy}>
            <div className="panel-heading">
              <h2>发布快照</h2>
              <span className="mono">{response.request_id}</span>
            </div>
            <div className="detail-body">
              <Rows
                entries={[
                  ["观察时间", <span className="mono">{time(response.as_of)}</span>],
                  ["索引目标", <span className="mono">{response.target_id}</span>],
                  ["目标表", <span className="mono">{response.table}</span>],
                  ["元数据保留", `${response.metadata_retention_days} 天`],
                  ["关闭段", response.closed_segments.toLocaleString()],
                  ["关闭段字节", response.closed_segment_bytes.toLocaleString()],
                  ["已发布段", response.published_segments.toLocaleString()],
                  ["待发布段", response.pending_segments.toLocaleString()],
                  ["未封存段", response.unsealed_segments.toLocaleString()],
                  ["发布缺口", response.has_gaps ? "存在" : "未观察到"],
                  [
                    "连续索引水位",
                    response.index_watermark ? (
                      <span className="mono">
                        {response.index_watermark.producer_boot_id} / {response.index_watermark.producer_sequence}
                      </span>
                    ) : (
                      "尚无连续已发布封存段"
                    ),
                  ],
                ]}
              />
            </div>
          </section>
        </>
      )}
    </>
  );
}

/** Bounded Observer discovery. A row is only a latest-in-window observation;
 * opening it always performs the separately audited model-call detail read. */
export function ModelCallListPanel({
  response,
  plan,
  busy,
  onEdit,
  onSubmit,
  onNext,
  onOpen,
}: {
  response: ModelCallListResponse | null;
  plan: ModelCallListPlan | null;
  busy: boolean;
  onEdit: () => void;
  onSubmit: (value: unknown) => void;
  onNext: () => void;
  onOpen: (id: string) => void;
}) {
  const [window, setWindow] = useState(() => {
    const end = Math.floor(Date.now() / 1000) * 1000;
    return {
      start: new Date(end - 86_400_000).toISOString().slice(0, 19),
      end: new Date(end).toISOString().slice(0, 19),
    };
  });
  const [limit, setLimit] = useState("25");
  const utc = (value: string) =>
    `${value.length === 16 ? `${value}:00` : value}Z`;
  return (
    <>
      <form
        className="panel model-list-form"
        aria-label="模型调用列表条件"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit({
            start: utc(window.start),
            end: utc(window.end),
            limit: Number(limit),
          });
        }}
      >
        <div className="search-window">
          <label>
            开始时间（UTC，含）
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
            结束时间（UTC，不含）
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
          <label>
            每页条数
            <input
              type="number"
              min="1"
              max="100"
              step="1"
              required
              value={limit}
              onChange={(event) => {
                onEdit();
                setLimit(event.target.value);
              }}
            />
          </label>
        </div>
        <div className="search-actions">
          <p className="footnote">
            UTC 整秒半开时间窗，最多 31 天。结果固定按发生时间、模型调用 ID
            从新到旧排列。
          </p>
          <button type="submit" disabled={busy}>
            {busy ? "读取中…" : "读取模型调用"}
          </button>
        </div>
        <p className="footnote">
          此列表要求 Observer，只显示窗口内可见的最新脱敏记录；模型详情和证据元数据仍分别重新鉴权。
        </p>
      </form>
      {plan && (
        <section className="panel model-list-plan" aria-label="已提交模型调用列表条件">
          <details>
            <summary>已提交列表条件</summary>
            <Rows
              entries={[
                ["开始时间", <span className="mono">{plan.start}</span>],
                ["结束时间", <span className="mono">{plan.end}</span>],
                ["每页条数", plan.limit],
              ]}
            />
          </details>
          {response && (
            <Rows
              entries={[
                ["管理请求 ID", <span className="mono">{response.request_id}</span>],
                [
                  "实际扫描行",
                  response.scanned_rows === null
                    ? "未知（索引未报告）"
                    : response.scanned_rows.toLocaleString(),
                ],
                [
                  "实际扫描字节",
                  response.scanned_bytes === null
                    ? "未知（索引未报告）"
                    : response.scanned_bytes.toLocaleString(),
                ],
              ]}
            />
          )}
        </section>
      )}
      {response && (
        <>
          <div
            className={`notice ${response.has_gaps || response.pending_segments > 0 ? "warning" : ""}`}
            role="status"
            aria-label="模型调用列表索引状态"
          >
            <div>
              <strong>
                {response.has_gaps ? "索引存在缺口" : "未观察到索引缺口"} · {" "}
                {response.pending_segments} 个待发布段
              </strong>
              <p>
                水位仅覆盖配置的日志源；列表为空、生命周期是否完整和其他生产者是否追平都须分别判断。
              </p>
              <details>
                <summary>查看列表水位</summary>
                <Rows
                  entries={[
                    ["观察时间", <span className="mono">{response.as_of}</span>],
                    ["水位范围", response.watermark_scope],
                    [
                      "水位",
                      response.index_watermark
                        ? `${response.index_watermark.producer_boot_id} / ${response.index_watermark.producer_sequence}`
                        : "尚不可用",
                    ],
                  ]}
                />
              </details>
            </div>
          </div>
          <section className="panel" aria-label="模型调用列表结果" aria-busy={busy}>
            <div className="panel-heading">
              <h2>模型调用列表</h2>
              <span className="muted">本页 {response.items.length} 条</span>
            </div>
            <div className="table-wrap">
              <table className="model-list-table">
                <thead>
                  <tr>
                    <th scope="col">发生时间</th>
                    <th scope="col">模型调用</th>
                    <th scope="col">供应商 / 模型</th>
                    <th scope="col">内部版本</th>
                    <th scope="col">窗口内最新状态</th>
                  </tr>
                </thead>
                <tbody>
                  {response.items.map((item) => (
                    <tr key={item.model_call_id}>
                      <td className="mono">{time(item.occurred_at)}</td>
                      <td>
                        <button
                          className="artifact-link mono"
                          onClick={() => onOpen(item.model_call_id)}
                        >
                          {item.model_call_id}
                        </button>
                        <small className="mono">{item.request_id}</small>
                      </td>
                      <td>
                        <span>{item.provider ?? "历史记录未提供"}</span>
                        <small className="mono">
                          {item.provider_model_id ?? "历史记录未提供"}
                        </small>
                      </td>
                      <td>
                        <span className="mono">{item.model_revision}</span>
                        <small className="mono">{item.prompt_revision}</small>
                        <small>{item.question_type}</small>
                      </td>
                      <td>
                        <span
                          className={`badge ${item.latest_status === "success" ? "passed" : ["error", "timeout", "cancelled"].includes(item.latest_status) ? "denied" : ""}`}
                        >
                          {item.latest_status}
                        </span>
                        <small className="mono">{item.latest_reason_code}</small>
                        <small>
                          置信度：{confidenceStatusLabel[item.latest_confidence_status]}
                        </small>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {response.items.length === 0 && (
              <p className="footnote search-empty">
                当前窗口和作用域内没有可见调用；这不推断调用不存在、未发布记录不存在或索引完整。
              </p>
            )}
            <div className="pagination">
              <button
                className="outline"
                disabled={busy || !response.next_cursor}
                onClick={onNext}
              >
                下一页
              </button>
              <span className="muted">
                {response.truncated ? "本页已截断，可继续翻页" : "当前可见结果已读完"}
              </span>
            </div>
          </section>
        </>
      )}
    </>
  );
}

/** Model evidence remains reference-only; opening a reference reads its catalog metadata. */
export function ModelCallOverview({
  response,
  onOpen,
  onHistory,
  onPreviousEvent,
  onFollowEvent,
}: {
  response: ModelCallResponse;
  onOpen: (id: string) => void;
  onHistory: (modelCallId: string) => void;
  onPreviousEvent: (eventId: string) => void;
  onFollowEvent: (eventId: string) => void;
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
            <button onClick={() => onHistory(model.model_call_id)}>
              准备历史检索
            </button>
            <p className="footnote">
              历史检索仅预填模型调用引用，仍需输入时间窗并由 Investigator 独立鉴权。
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
                            <button
                              className="artifact-link mono"
                              key={id}
                              onClick={() => onPreviousEvent(id)}
                            >
                              {id}
                            </button>
                          ))
                        : "起始事件",
                    ],
                    [
                      "直接后继",
                      <button onClick={() => onFollowEvent(event.event_id)}>
                        准备关联检索
                      </button>,
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
  relatedEvents,
  onOpen,
  onRequest,
  onModelCall,
  onTraceId,
  onPreviousEvent,
  onFollowEvent,
  onCausalEvent,
  causality,
  causalityBusy,
  causalityProblem,
  onCausalityEdit,
  onCausalitySubmit,
}: {
  event: AuditEvent | SearchEvent;
  relatedEvents: (AuditEvent | SearchEvent)[];
  onOpen: (id: string) => void;
  onRequest?: (id: string) => void;
  onModelCall?: (id: string) => void;
  onTraceId?: (traceId: string) => void;
  onPreviousEvent: (eventId: string) => void;
  onFollowEvent: (eventId: string) => void;
  onCausalEvent: (eventId: string) => void;
  causality: CausalityResponse | null;
  causalityBusy: boolean;
  causalityProblem: {
    message: string;
    code: string;
    requestId?: string | null;
  } | null;
  onCausalityEdit: () => void;
  onCausalitySubmit: (value: unknown) => void;
}) {
  const traceId = "trace_id" in event ? event.trace_id : null;
  const causal = buildCausalNeighborhood(event, relatedEvents);
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
            "模型调用",
            event.model_call_id ? (
              <button
                className="artifact-link mono"
                onClick={() => onModelCall?.(event.model_call_id!)}
              >
                {event.model_call_id}
              </button>
            ) : (
              "未记录"
            ),
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
      <div className="event-actions">
        <button onClick={() => onFollowEvent(event.event_id)}>
          查找以此为前驱的事件
        </button>
        {traceId && (
          <button onClick={() => onTraceId?.(traceId)}>
            准备同 Trace 检索
          </button>
        )}
      </div>
      <details className="event-metadata">
        <summary>更多事件字段</summary>
        <Rows
          entries={[
            ["事件类型", <span className="mono">{event.event_type}</span>],
            ...(traceId
              ? ([["Trace ID", <span className="mono">{traceId}</span>]] as [
                  string,
                  ReactNode,
                ][])
              : []),
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
                    <button
                      className="artifact-link mono"
                      key={id}
                      onClick={() => onPreviousEvent(id)}
                    >
                      {id}
                    </button>
                  ))
                : "未记录",
            ],
          ]}
        />
      </details>
      {(causal.predecessors.length > 0 || causal.successors.length > 0) && (
        <CausalityGraph neighborhood={causal} onOpen={onCausalEvent} />
      )}
      <CausalityPanel
        key={event.event_id}
        eventId={event.event_id}
        response={causality}
        busy={causalityBusy}
        problem={causalityProblem}
        onEdit={onCausalityEdit}
        onSubmit={onCausalitySubmit}
      />
    </div>
  );
}

function CausalityGraph({
  neighborhood,
  onOpen,
}: {
  neighborhood: ReturnType<typeof buildCausalNeighborhood>;
  onOpen: (eventId: string) => void;
}) {
  const count = [...neighborhood.predecessors, ...neighborhood.successors]
    .flat()
    .length;
  return (
    <details className="event-metadata causal-graph">
      <summary>查看当前页因果关联（{count} 个节点）</summary>
      <p className="footnote">
        关联只依据已发布事件的前驱引用。未载入引用可准备事件 ID 检索；每次检索仍由操作者提供时间窗并提交。
      </p>
      <div className="causality-branches">
        <CausalityBranch
          label="前驱方向"
          levels={neighborhood.predecessors}
          onOpen={onOpen}
        />
        <CausalityBranch
          label="后继方向"
          levels={neighborhood.successors}
          onOpen={onOpen}
        />
      </div>
      {neighborhood.truncated && (
        <p className="footnote" role="status">
          视图已达到每方向 4 跳或 16 个节点上限。
        </p>
      )}
    </details>
  );
}

function CausalityBranch({
  label,
  levels,
  onOpen,
}: {
  label: string;
  levels: CausalNode[][];
  onOpen: (eventId: string) => void;
}) {
  return (
    <section aria-label={label} className="causality-branch">
      <h4>{label}</h4>
      {levels.length === 0 ? (
        <p className="empty">当前已加载事件中没有关联节点。</p>
      ) : (
        levels.map((nodes, index) => (
          <div
            className="causal-level"
            key={nodes.map((node) => node.eventId).join("|")}
          >
            <span className="footnote">第 {index + 1} 跳</span>
            <ul>
              {nodes.map((node) => (
                <li key={node.eventId}>
                  <button
                    className="artifact-link causal-node"
                    aria-label={`查看因果事件 ${node.eventId}`}
                    onClick={() => onOpen(node.eventId)}
                  >
                    <span>{node.event?.event_type ?? "引用事件未载入"}</span>
                    <span className="mono">{node.eventId}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ))
      )}
    </section>
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
