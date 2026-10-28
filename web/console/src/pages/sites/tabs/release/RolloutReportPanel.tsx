import { FileSearchOutlined } from "@ant-design/icons";
import { Alert, Button, Table } from "antd";
import { useEffect, useState } from "react";
import type { SiteRollout } from "../../../../api.ts";
import {
  type RolloutObservation,
  type RolloutReportRequest,
  reportVerdict,
} from "../../../../rollout-report.ts";
import { safeError } from "../../../../security/errors.ts";
import { reportWindow } from "../../../../sites/model/rollout.ts";
import { useRolloutReport } from "../../../../sites/state/detail-queries.ts";
import { IdChip } from "../../../../ui/IdChip";
import { ProblemAlert } from "../../../../ui/ProblemAlert";
import { reasonText } from "../../../../ui/reason-codes.ts";
import { busy } from "../../fields";
import type { WorkspaceApi } from "../../workspace/use-workspace.ts";

const verdictText = {
  incomplete: [
    "warning",
    "不足以判断：审计索引有缺口或仍有待发布的段，报告中的计数可能偏少。等索引追上后重新生成。",
  ],
  no_traffic: ["warning", "窗口内没有完成的请求，报告无法说明强制后的影响。"],
  would_deny: ["info", "观察期间有请求本应被拒绝。逐条确认它们是配置遗漏还是本该拒绝的访问。"],
  clean: ["success", "观察期间没有本应被拒绝的请求。"],
} as const;

/**
 * 退出报告 (docs/32 32.4): what the index holds about the served observe window, generated only
 * on request (each read is audited and scans the index). Facts only: whether to enforce stays
 * the approver's decision, and an index that is behind reads as "cannot judge", never a pass.
 */
export function RolloutReportPanel({ ws, rollout }: { ws: WorkspaceApi; rollout: SiteRollout }) {
  const siteId = ws.siteId ?? "";
  const [request, setRequest] = useState<RolloutReportRequest | null>(null);
  const [notStarted, setNotStarted] = useState(false);
  const report = useRolloutReport(siteId, request);
  const { read } = report;
  // A new window is fixed when the operator asks, then read once.
  useEffect(() => {
    if (request) void read();
  }, [request, read]);
  const data = report.data;
  const verdict = data ? reportVerdict(data) : null;
  const generate = () => {
    const window = reportWindow(rollout, ws.revisions, Math.floor(Date.now() / 1000));
    setNotStarted(window === null);
    if (window) setRequest(window);
  };
  return (
    <section className="xs-card xs-health" aria-label="观察退出报告">
      <div className="xs-health-head">
        <h3>观察退出报告（{rollout.revision}）</h3>
        <Button
          icon={<FileSearchOutlined aria-hidden="true" />}
          loading={busy(report.isFetching)}
          onClick={generate}
        >
          生成报告
        </Button>
      </div>
      <p className="muted">
        按需生成，不会自动刷新；每次生成都会在服务端写入一条审计记录。报告只陈述审计索引中的事实，是否收紧为强制由审批人决定。
      </p>
      {report.isError && <ProblemAlert problem={safeError(report.error)} />}
      {data && verdict && !report.isError && (
        <div className="xs-health-result">
          <Alert type={verdictText[verdict][0]} showIcon title={verdictText[verdict][1]} />
          <dl className="xs-facts">
            <div>
              <dt>窗口（UTC）</dt>
              <dd className="mono">
                {data.start} – {data.end}
              </dd>
            </div>
            <div>
              <dt>完成的请求</dt>
              <dd className="mono">{data.completed_requests}</dd>
            </div>
            <div>
              <dt>本应拒绝、仍被转发</dt>
              <dd className="mono">{data.observed_requests}</dd>
            </div>
            <div>
              <dt>未匹配任何路由而被拒绝</dt>
              <dd className="mono">{data.unrouted_refusals}</dd>
            </div>
            <div>
              <dt>报告摘要</dt>
              <dd>
                <IdChip value={data.report_digest} label="报告摘要" maxLength={20} />
              </dd>
            </div>
          </dl>
          {data.observations.length > 0 && (
            <Table<RolloutObservation>
              size="small"
              rowKey={(row) => `${row.operation_id}|${row.reason_code}`}
              pagination={false}
              dataSource={data.observations}
              columns={[
                {
                  title: "路由",
                  dataIndex: "operation_id",
                  render: (value: string) =>
                    value === "" ? (
                      "（窗口开始前进入的请求）"
                    ) : (
                      <span className="mono">{value}</span>
                    ),
                },
                {
                  title: "本应生效的拒绝",
                  dataIndex: "reason_code",
                  render: (value: string) => reasonText(value).text,
                },
                { title: "次数", dataIndex: "count", align: "right" },
                { title: "最近一次（UTC）", dataIndex: "last_seen", className: "mono" },
              ]}
            />
          )}
          {data.truncated && (
            <p className="muted">只列出最多的 200 组路由与原因；其余仅计入总数。</p>
          )}
          {data.unrouted_refusals > 0 && (
            <p className="muted">
              未匹配路由的请求在观察期间也被拒绝；它们说明还有端点没有登记为路由，可在“请求检索”中按时间窗查看。
            </p>
          )}
        </div>
      )}
      {notStarted && <p className="muted">观察窗口还没有开始，暂时无法生成报告。</p>}
    </section>
  );
}
