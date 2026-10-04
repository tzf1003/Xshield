import { useRef, useState } from "react";
import type { ReactNode } from "react";
import type { SearchPlan, SearchResponse } from "./search";
import { EventTable, Rows } from "./panels";

const fields = [
  ["request_id", "请求 ID"],
  ["event_id", "事件 ID"],
  ["trace_id", "Trace ID"],
  ["caused_by_event_id", "前驱事件 ID"],
  ["grant_id", "资格 ID"],
  ["auth_binding_id", "身份绑定 ID"],
  ["subject_ref", "主体引用"],
  ["case_id", "案件 ID"],
  ["artifact_id", "证据 ID"],
  ["calibration_report_id", "校准报告 ID"],
  ["evidence_access_request_id", "访问申请 ID"],
  ["evidence_hold_id", "保留锁 ID"],
  ["model_call_id", "模型调用 ID"],
  ["agent_run_id", "Agent 运行 ID"],
  ["job_id", "任务 ID"],
  ["share_grant_id", "分享资格 ID"],
  ["event_type", "事件类型"],
  ["stage", "阶段"],
  ["reason_code", "原因码"],
  ["operation_id", "操作 ID"],
  ["model_revision", "模型版本"],
  ["outcome", "结果"],
  ["confidence_at_most", "置信度上限（基点）"],
] as const;
type Field = (typeof fields)[number][0];
type DraftFilter = { id: number; field: Field; value: string };
export type SearchPreset = {
  kind:
    | "event_id"
    | "trace_id"
    | "caused_by_event_id"
    | "grant_id"
    | "auth_binding_id"
    | "calibration_report_id"
    | "evidence_access_request_id"
    | "evidence_hold_id"
    | "model_call_id"
    | "agent_run_id"
    | "job_id";
  value: string;
};
const outcomes = ["PASS", "ALLOW", "DENY", "UNKNOWN", "ERROR", "SKIPPED", "CANCELLED"];

/** Builds an allowlisted plan; App owns submission, scope and cancellation. */
export function SearchPanel({
  response,
  plan,
  busy,
  selected,
  details,
  onEdit,
  onSubmit,
  onNext,
  onSelect,
  initialFilter = null,
}: {
  response: SearchResponse | null;
  plan: SearchPlan | null;
  busy: boolean;
  selected: string | null;
  details: ReactNode;
  onEdit: () => void;
  onSubmit: (value: unknown) => void;
  onNext: () => void;
  onSelect: (id: string) => void;
  initialFilter?: SearchPreset | null;
}) {
  const [window, setWindow] = useState(() => {
    if (initialFilter) return { start: "", end: "" };
    const end = Math.floor(Date.now() / 1000) * 1000;
    return {
      start: new Date(end - 86_400_000).toISOString().slice(0, 19),
      end: new Date(end).toISOString().slice(0, 19),
    };
  });
  const [limit, setLimit] = useState("25");
  const [sort, setSort] = useState<SearchPlan["sort"]>("occurred_at_desc");
  const [filters, setFilters] = useState<DraftFilter[]>(() =>
    initialFilter ? [{ id: 0, field: initialFilter.kind, value: initialFilter.value }] : [],
  );
  const filterId = useRef(0);

  function updateFilter(id: number, change: Partial<DraftFilter>) {
    onEdit();
    setFilters((items) => items.map((item) => (item.id === id ? { ...item, ...change } : item)));
  }

  return (
    <>
      <form
        className="panel search-form"
        aria-label="结构化事件检索条件"
        onSubmit={(event) => {
          event.preventDefault();
          // datetime-local intentionally represents UTC wall time, independent of browser timezone.
          const utc = (value: string) => `${value.length === 16 ? `${value}:00` : value}Z`;
          onSubmit({
            schema_version: 3,
            start: utc(window.start),
            end: utc(window.end),
            sort,
            limit: Number(limit),
            filters: filters.map(({ field, value }) => {
              if (field === "confidence_at_most")
                return { kind: field, basis_points: Number(value) };
              if (
                ["event_type", "stage", "reason_code", "operation_id", "model_revision"].includes(
                  field,
                )
              )
                return { kind: "text", field, value };
              return { kind: field, value };
            }),
          });
        }}
      >
        {initialFilter && !plan && (
          <p className="search-preset-note" role="status">
            已预填目标引用，请确认 UTC 时间窗后提交历史检索。
          </p>
        )}
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
              max="1000"
              step="1"
              required
              value={limit}
              onChange={(event) => {
                onEdit();
                setLimit(event.target.value);
              }}
            />
          </label>
          <div className="search-field">
            <label htmlFor="search-sort">事件时间排序</label>
            <select
              id="search-sort"
              value={sort}
              onChange={(event) => {
                onEdit();
                setSort(
                  event.target.value === "occurred_at_asc" ? "occurred_at_asc" : "occurred_at_desc",
                );
              }}
            >
              <option value="occurred_at_desc">从新到旧</option>
              <option value="occurred_at_asc">从旧到新</option>
            </select>
          </div>
        </div>
        <p className="footnote">
          UTC 整秒半开时间窗，最多 31 天；最多 8 个条件，全部匹配同一事件。Trace ID 为 32
          个小写十六进制字符且仍受时间窗限制；前驱事件条件只查找直接关联，事件详情可在当前页显示有界因果邻域；主体引用仅用于精确筛选，结果不会回显主体值；置信度空值不会匹配数值阈值。
        </p>
        {filters.map((filter, index) => (
          <div className="search-filter" key={filter.id}>
            <div className="search-field">
              <label htmlFor={`search-field-${filter.id}`}>条件 {index + 1} 字段</label>
              <select
                id={`search-field-${filter.id}`}
                value={filter.field}
                onChange={(event) =>
                  updateFilter(filter.id, {
                    field: event.target.value as Field,
                    value: event.target.value === "outcome" ? "DENY" : "",
                  })
                }
              >
                {fields.map(([value, name]) => (
                  <option value={value} key={value}>
                    {name}
                  </option>
                ))}
              </select>
            </div>
            <div className="search-field">
              <label htmlFor={`search-value-${filter.id}`}>条件 {index + 1} 值</label>
              {filter.field === "outcome" ? (
                <select
                  id={`search-value-${filter.id}`}
                  value={filter.value}
                  onChange={(event) => updateFilter(filter.id, { value: event.target.value })}
                >
                  {outcomes.map((outcome) => (
                    <option key={outcome}>{outcome}</option>
                  ))}
                </select>
              ) : (
                <input
                  id={`search-value-${filter.id}`}
                  className="mono"
                  type={filter.field === "confidence_at_most" ? "number" : "text"}
                  min={filter.field === "confidence_at_most" ? 0 : undefined}
                  max={filter.field === "confidence_at_most" ? 10000 : undefined}
                  step={1}
                  maxLength={
                    filter.field === "subject_ref" ? 256 : filter.field === "trace_id" ? 32 : 128
                  }
                  value={filter.value}
                  autoComplete="off"
                  spellCheck={false}
                  required
                  onChange={(event) => updateFilter(filter.id, { value: event.target.value })}
                />
              )}
            </div>
            <button
              type="button"
              className="text-button"
              aria-label={`删除条件 ${index + 1}`}
              onClick={() => {
                onEdit();
                setFilters((items) => items.filter((item) => item.id !== filter.id));
              }}
            >
              删除
            </button>
          </div>
        ))}
        <div className="search-actions">
          <button
            type="button"
            className="outline"
            disabled={filters.length >= 8}
            onClick={() => {
              onEdit();
              const id = ++filterId.current;
              setFilters((items) => [...items, { id, field: "request_id", value: "" }]);
            }}
          >
            添加条件
          </button>
          <button type="submit" disabled={busy}>
            {busy ? "检索中…" : "检索事件"}
          </button>
        </div>
        <p className="footnote">
          检索要求 Investigator；请求详情与证据元数据另需 Observer。权限由服务端分别校验。
        </p>
      </form>
      {plan && (
        <section className="panel search-plan" aria-label="已提交查询计划">
          <details>
            <summary>已提交查询计划</summary>
            <pre className="mono">{JSON.stringify(plan, null, 2)}</pre>
          </details>
          {response && (
            <Rows
              entries={[
                ["查询摘要", <span className="mono">{response.query_digest}</span>],
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
            aria-label="搜索索引状态"
          >
            <div>
              <strong>
                {response.has_gaps ? "索引存在缺口" : "未观察到索引缺口"} ·{" "}
                {response.pending_segments} 个待发布段
              </strong>
              <p>
                水位仅覆盖配置的日志源，独立 Outbox 可能仍待发布。结果为空与索引完整性分别判断。
              </p>
              <details>
                <summary>查看搜索水位</summary>
                <Rows
                  entries={[
                    ["观察时间", <span className="mono">{response.as_of}</span>],
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
          <div className="investigation-grid">
            <section className="panel" aria-label="搜索事件结果">
              <div className="panel-heading">
                <h2>搜索事件</h2>
                <span className="muted">本页 {response.events.length} 条</span>
              </div>
              <EventTable events={response.events} selected={selected} onSelect={onSelect} />
              {response.events.length === 0 && (
                <p className="footnote search-empty">
                  未发布、到期或作用域不匹配均可能返回空结果；请结合来源与保留策略核对。
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
              <p className="footnote search-empty">
                分页沿用已提交计划；新发布和到期可能改变后续可见记录。
              </p>
            </section>
            {details}
          </div>
        </>
      )}
    </>
  );
}
