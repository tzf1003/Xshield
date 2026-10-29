import { BarChartOutlined } from "@ant-design/icons";
import { Alert, Button, Table, type TableColumnsType } from "antd";
import { useState } from "react";
import { ApiError } from "../../api-contract.ts";
import {
  COVERAGE_REPORT_ROWS_MAX,
  COVERAGE_REPORT_UNCOVERED_MAX,
  type CoverageReport,
  type CoverageReportRequest,
  type CoverageVerdict,
  coverageReportQuery,
  coverageVerdict,
  type RouteRefusal,
  type RouteTraffic,
  share,
  type UncoveredEndpoint,
} from "../../coverage-report.ts";
import { ROLE_OBSERVER_TEXT } from "../../investigation/roles.ts";
import { useRemembered } from "../../investigation/view-memory.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { EventTime } from "../../ui/EventTime";
import { IdChip } from "../../ui/IdChip";
import { ReasonCode } from "../../ui/ReasonCode";
import { EmptyState, ErrorState, LoadingState } from "../../ui/states";
import { checkedResolution, TimeRangePicker } from "../../ui/TimeRangePicker";
import type { RangeIntent, UtcWindow } from "../../ui/time-range.ts";
import "./investigation.css";
import "./coverage.css";

const defaultRange: RangeIntent = { kind: "preset", preset: "24h" };

function acceptsWindow(window: UtcWindow): boolean {
  try {
    coverageReportQuery(window);
    return true;
  } catch {
    return false;
  }
}

const verdictText: Record<CoverageVerdict, readonly ["warning" | "info" | "success", string]> = {
  incomplete: [
    "warning",
    "不足以判断：审计索引有缺口或仍有待发布的段，下面的计数可能偏少。等索引追上后重新统计。",
  ],
  no_traffic: ["warning", "窗口内没有完成的请求，统计无法说明覆盖情况。"],
  uncovered: [
    "info",
    "窗口内有请求因为没有匹配任何路由而被拒绝。逐条确认它们是需要补登记的端点，还是本该拒绝的访问。",
  ],
  covered: ["success", "窗口内没有因未匹配路由而被拒绝的请求。"],
};

type Applied = Readonly<{ request: CoverageReportRequest; nonce: number }>;

/** Counts reads for the life of the page bundle, so no two reads share a cache entry. */
let submissions = 0;

/**
 * 拒绝与覆盖统计 (docs/29 29.39): what the index holds about one UTC window, read only when the
 * operator asks. Each read is authorized and audited by the server (`console.coverage_report.read`)
 * and scans the index, so the page never reads on arrival, on a timer or on focus.
 */
export function CoveragePage() {
  const [range, setRange] = useRemembered<RangeIntent>("coverage.range", () => defaultRange);
  const [applied, setApplied] = useState<Applied | null>(null);
  const [formError, setFormError] = useState<unknown>(null);
  const [rangeNotice, setRangeNotice] = useState<string | null>(null);

  function edit(next: RangeIntent) {
    setRange(next);
    setApplied(null);
    setFormError(null);
    setRangeNotice(null);
  }

  function submit() {
    const resolution = checkedResolution(range, Date.now(), acceptsWindow);
    if (!resolution.window) {
      setApplied(null);
      if (resolution.problem === "missing" || resolution.problem === "incomplete") {
        setFormError(null);
        setRangeNotice("请先选择完整的时间范围。");
      } else {
        setRangeNotice(null);
        setFormError(new ApiError("CONTROL_COVERAGE_REPORT_REQUEST_INVALID"));
      }
      return;
    }
    submissions += 1;
    setFormError(null);
    setRangeNotice(null);
    setApplied({
      request: { start: resolution.window.start, end: resolution.window.end },
      nonce: submissions,
    });
  }

  return (
    <div className="xs-page">
      <section className="xs-card xs-toolbar" aria-label="拒绝与覆盖统计条件">
        <div className="xs-toolbar-row">
          <TimeRangePicker
            value={range}
            accepts={acceptsWindow}
            presets={["1h", "24h", "7d"]}
            onChange={(next) => edit(next)}
          />
        </div>
        {rangeNotice ? (
          <p className="xs-field-error" role="alert">
            {rangeNotice}
          </p>
        ) : null}
        <div className="xs-options">
          <div className="xs-toolbar-actions">
            <Button type="primary" icon={<BarChartOutlined aria-hidden="true" />} onClick={submit}>
              生成统计
            </Button>
          </div>
        </div>
        <p className="xs-toolbar-hint">
          UTC 整秒半开时间窗，最多 31
          天。按需生成，不会自动刷新；每次生成都会在服务端写入一条审计记录。
        </p>
        <p className="xs-toolbar-hint">
          {ROLE_OBSERVER_TEXT}
          未覆盖端点只按路径形状列出：像 ID 的段写作 {"{}"}，原始路径不进入索引。
        </p>
      </section>
      {formError ? <ErrorState error={formError} title="统计条件未通过校验" /> : null}
      {applied ? <CoverageResult key={applied.nonce} applied={applied} /> : null}
    </div>
  );
}

function CoverageResult({ applied }: { applied: Applied }) {
  const { request, nonce } = applied;
  const query = useGuardedQuery({
    key: ["investigation", "coverage-report", nonce, request.start, request.end],
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => client.coverageReport(request, signal),
  });
  if (query.isError) {
    return <ErrorState error={query.error} title="拒绝与覆盖统计读取失败" />;
  }
  if (!query.data) return <LoadingState label="正在生成统计…" />;
  return <Report report={query.data} />;
}

function Report({ report }: { report: CoverageReport }) {
  const verdict = coverageVerdict(report);
  const [tone, text] = verdictText[verdict];
  const routed = report.completed_requests - report.unrouted_refusals;
  return (
    <>
      <section className="xs-card" aria-label="拒绝与覆盖统计结果">
        <div className="xs-card-head">
          <h2>统计概况</h2>
        </div>
        <Alert type={tone} showIcon title={text} />
        <ul className="xs-cov-stats" aria-label="窗口内计数">
          <li>
            <span>完成的请求</span>
            <strong>{report.completed_requests.toLocaleString("zh-CN")}</strong>
          </li>
          <li>
            <span>被拒绝</span>
            <strong>{report.refused_requests.toLocaleString("zh-CN")}</strong>
            <small>占 {share(report.refused_requests, report.completed_requests)}</small>
          </li>
          <li>
            <span>观察期间放行的拒绝</span>
            <strong>{report.observed_requests.toLocaleString("zh-CN")}</strong>
          </li>
          <li>
            <span>未匹配路由而被拒绝</span>
            <strong>{report.unrouted_refusals.toLocaleString("zh-CN")}</strong>
            <small>
              其中无路径形状 {report.unshaped_unrouted_refusals.toLocaleString("zh-CN")}
            </small>
          </li>
        </ul>
        <dl className="xs-cov-meta">
          <div>
            <dt>窗口（UTC）</dt>
            <dd className="mono">
              {report.start} – {report.end}
            </dd>
          </div>
          <div>
            <dt>索引观察时间</dt>
            <dd>
              <EventTime value={report.as_of} />
            </dd>
          </div>
          <div>
            <dt>报告摘要</dt>
            <dd>
              <IdChip value={report.report_digest} label="报告摘要" maxLength={20} />
            </dd>
          </div>
          <div>
            <dt>管理请求</dt>
            <dd>
              <IdChip value={report.request_id} label="管理请求 ID" maxLength={20} />
            </dd>
          </div>
        </dl>
        {report.unshaped_unrouted_refusals > 0 && (
          <p className="xs-foot">
            没有路径形状的未匹配拒绝来自升级前的 edge，或在窗口开始前进入的请求；它们只计入总数。
          </p>
        )}
      </section>
      <RoutesCard report={report} routed={routed} />
      <RefusalsCard report={report} />
      <UncoveredCard report={report} />
    </>
  );
}

function RoutesCard({ report, routed }: { report: CoverageReport; routed: number }) {
  const columns: TableColumnsType<RouteTraffic> = [
    {
      title: "路由",
      dataIndex: "operation_id",
      render: (value: string) => <span className="mono">{value}</span>,
    },
    { title: "完成", dataIndex: "completed", align: "right" },
    { title: "拒绝", dataIndex: "refused", align: "right" },
    {
      title: "拒绝率",
      key: "rate",
      align: "right",
      render: (_value: unknown, row) => share(row.refused, row.completed),
    },
    { title: "观察放行", dataIndex: "observed", align: "right" },
  ];
  return (
    <section className="xs-card" aria-label="按路由的流量">
      <div className="xs-card-head">
        <h2>按路由的流量</h2>
      </div>
      {report.routes.length === 0 ? (
        <EmptyState title="窗口内没有匹配到路由的请求" />
      ) : (
        <Table<RouteTraffic>
          size="small"
          rowKey="operation_id"
          pagination={false}
          dataSource={report.routes}
          columns={columns}
          scroll={{ x: "max-content" }}
        />
      )}
      {report.routes_truncated && (
        <p className="xs-foot">
          只列出流量最多的 {COVERAGE_REPORT_ROWS_MAX} 条路由；匹配到路由的请求至多{" "}
          {routed.toLocaleString("zh-CN")} 个，其余仅计入总数。
        </p>
      )}
    </section>
  );
}

function RefusalsCard({ report }: { report: CoverageReport }) {
  const columns: TableColumnsType<RouteRefusal> = [
    {
      title: "路由",
      dataIndex: "operation_id",
      render: (value: string) =>
        value === "" ? "（未匹配任何路由）" : <span className="mono">{value}</span>,
    },
    {
      title: "拒绝原因",
      dataIndex: "reason_code",
      render: (value: string) => <ReasonCode code={value} quietCopy />,
    },
    { title: "次数", dataIndex: "count", align: "right" },
    {
      title: "最近一次",
      dataIndex: "last_seen",
      render: (value: string) => <EventTime value={value} />,
    },
  ];
  return (
    <section className="xs-card" aria-label="按路由与原因的拒绝">
      <div className="xs-card-head">
        <h2>按路由与原因的拒绝</h2>
      </div>
      {report.refusals.length === 0 ? (
        <EmptyState title="窗口内没有被拒绝的请求" />
      ) : (
        <Table<RouteRefusal>
          size="small"
          rowKey={(row) => `${row.operation_id}|${row.reason_code}`}
          pagination={false}
          dataSource={report.refusals}
          columns={columns}
          scroll={{ x: "max-content" }}
        />
      )}
      {report.refusals_truncated && (
        <p className="xs-foot">
          只列出最多的 {COVERAGE_REPORT_ROWS_MAX} 组路由与原因；其余仅计入总数。
        </p>
      )}
    </section>
  );
}

function UncoveredCard({ report }: { report: CoverageReport }) {
  const columns: TableColumnsType<UncoveredEndpoint> = [
    { title: "方法", dataIndex: "method", className: "mono" },
    {
      title: "路径形状",
      dataIndex: "path_shape",
      render: (value: string) => <span className="xs-cov-shape">{value}</span>,
    },
    { title: "次数", dataIndex: "count", align: "right" },
    {
      title: "最近一次",
      dataIndex: "last_seen",
      render: (value: string) => <EventTime value={value} />,
    },
  ];
  return (
    <section className="xs-card" aria-label="未覆盖端点">
      <div className="xs-card-head">
        <h2>未覆盖端点</h2>
      </div>
      <p className="xs-foot">
        这些请求没有匹配任何路由而被拒绝。需要放行的端点可在站点的“路由与操作”中登记。
      </p>
      {report.uncovered.length === 0 ? (
        <EmptyState title="窗口内没有带路径形状的未覆盖端点" />
      ) : (
        <Table<UncoveredEndpoint>
          size="small"
          rowKey={(row) => `${row.method} ${row.path_shape}`}
          pagination={false}
          dataSource={report.uncovered}
          columns={columns}
          scroll={{ x: "max-content" }}
        />
      )}
      {report.uncovered_truncated && (
        <p className="xs-foot">
          只列出最多的 {COVERAGE_REPORT_UNCOVERED_MAX} 个端点；其余仅计入总数。
        </p>
      )}
    </section>
  );
}
