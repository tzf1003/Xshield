import { ArrowRightOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Skeleton } from "antd";
import { type ReactNode, useState } from "react";
import type { WorkbenchOverviewResponse } from "../../api.ts";
import { deniedRequestsPlan, scanStats } from "../../operations/denied.ts";
import { RoleHint } from "../../operations/Parts";
import { quickLinks } from "../../operations/roles.ts";
import { isRoleRefusal, type SourceState } from "../../operations/sources.ts";
import type { SearchPlan } from "../../search.ts";
import { useGuardedQuery } from "../../security/hooks";
import { MANUAL_REFRESH } from "../../security/query-client.ts";
import { operationReason } from "../../ui/operation-reasons.ts";
import { TimeStamp } from "../../ui/TimeStamp";
import { formatUtc } from "../../work/format.ts";
import { RouteLink } from "../../work/nav";
import { ErrorNotice, Facts, IdText, TonePill } from "../../work/Parts";

/** Audit publication as the snapshot saw it; AuditAdministrator only, a role hint otherwise. */
export function AuditCard({
  overview,
  roles,
}: {
  overview: SourceState<WorkbenchOverviewResponse>;
  roles: readonly string[] | null;
}) {
  const auditRole = roles === null || roles.includes("audit_administrator");
  let body: ReactNode;
  if (!auditRole) {
    body = (
      <RoleHint title="需要 AuditAdministrator 角色">
        封存段、缺口与连续水位只对 AuditAdministrator 读取；快照不包含它们，这也不代表审计发布正常。
      </RoleHint>
    );
  } else if (overview.status === "loading" || overview.status === "skipped") {
    body = <Skeleton active paragraph={{ rows: 3 }} title={false} />;
  } else if (overview.status !== "ok") {
    body = <p className="xs-w-muted">工作台快照不可用，见页面顶部的提示。</p>;
  } else {
    const audit = overview.data.audit;
    const posture = operationReason(overview.data.posture.reason_code);
    if (audit.source_state !== "available" || audit.value === null) {
      const reason = operationReason(audit.reason_code);
      body = (
        <Alert
          type="info"
          showIcon
          title="快照没有包含审计发布观察"
          description={
            <div className="xs-w-stack">
              <span>{reason?.text ?? "服务端没有给出可识别的原因。"}</span>
              <small className="mono xs-wb-code">{audit.reason_code}</small>
              <RouteLink to="/operations/audit">在审计发布状态页手动读取</RouteLink>
            </div>
          }
        />
      );
    } else {
      const value = audit.value;
      const state = value.has_gaps
        ? ({ label: "存在缺口", tone: "error" } as const)
        : value.pending_segments > 0
          ? ({ label: "有待发布段", tone: "warning" } as const)
          : ({ label: "连续发布", tone: "success" } as const);
      body = (
        <div className="xs-w-stack">
          <span>
            <TonePill tone={state.tone} label={state.label} />
          </span>
          <Facts
            rows={[
              [
                "连续水位",
                value.index_watermark ? (
                  <span key="w" className="mono" title={value.index_watermark.producer_boot_id}>
                    #{value.index_watermark.producer_sequence.toLocaleString("zh-CN")}
                  </span>
                ) : (
                  "尚无连续已发布封存段"
                ),
              ],
              ["已发布段", value.published_segments.toLocaleString("zh-CN")],
              ["待发布段", value.pending_segments.toLocaleString("zh-CN")],
              ["未封存段", value.unsealed_segments.toLocaleString("zh-CN")],
              ["发布缺口", value.has_gaps ? "存在" : "未观察到"],
              ["观察于", <TimeStamp key="t" value={value.as_of} />],
              [
                "快照姿态",
                `${overview.data.posture.value === "degraded" ? "降级" : "已观察"} · ${posture?.label ?? overview.data.posture.reason_code}`,
              ],
            ]}
          />
          <p className="xs-w-muted">
            只观察配置 journal 到索引目标的封存段发布；不代表业务准入、全部 Outbox
            状态或系统整体健康。
          </p>
          <RouteLink to="/operations/audit">查看审计发布状态</RouteLink>
        </div>
      );
    }
  }
  return (
    <section className="xs-w-card" aria-labelledby="wb-audit-title">
      <h2 id="wb-audit-title" className="xs-wb-card-title">
        审计发布
      </h2>
      {body}
    </section>
  );
}

/**
 * The newest denied requests of the last 24 hours: one bounded structured search (an audited
 * Investigator query that spends index budget), run only when the operator presses the button.
 */
export function DeniedCard() {
  const [plan, setPlan] = useState<SearchPlan | null>(null);
  const query = useGuardedQuery({
    key: ["workbench", "denied", plan?.start ?? "", plan?.end ?? ""],
    enabled: plan !== null,
    staleTime: MANUAL_REFRESH,
    fetch: (client, signal) => {
      if (plan === null) throw new Error("no plan");
      return client.search(plan, undefined, signal);
    },
  });
  const data = query.data;
  const stats = data ? scanStats(data) : null;
  return (
    <section className="xs-w-card" aria-labelledby="wb-denied-title">
      <h2 id="wb-denied-title" className="xs-wb-card-title">
        最近被拒绝的请求
      </h2>
      <p className="xs-w-muted">
        点击后才执行一次结构化检索（Investigator 查询，会被审计并消耗检索预算）：最近 24
        小时、终态为拒绝的请求，最新 10 条。
      </p>
      <span>
        <Button
          icon={<SearchOutlined aria-hidden="true" />}
          loading={query.isFetching}
          onClick={() => setPlan(deniedRequestsPlan(Date.now()))}
        >
          {plan === null ? "读取最近被拒绝的请求" : "重新读取"}
        </Button>
      </span>
      {plan !== null && query.isPending && query.isFetching && (
        <Skeleton active paragraph={{ rows: 3 }} title={false} />
      )}
      {query.isError &&
        (isRoleRefusal(query.error) ? (
          <RoleHint title="结构化检索被服务端拒绝">
            读取被拒绝的请求需要 Investigator 角色。
          </RoleHint>
        ) : (
          <ErrorNotice
            error={query.error}
            title="检索失败"
            action={
              <Button size="small" onClick={() => void query.refetch()}>
                重试
              </Button>
            }
          />
        ))}
      {data && stats && plan && (
        <>
          {(data.has_gaps || data.pending_segments > 0) && (
            <Alert
              type="warning"
              showIcon
              title="索引可能不完整"
              description={`检索只覆盖已发布的索引：${data.has_gaps ? "存在缺口；" : ""}待发布段 ${data.pending_segments} 个。`}
            />
          )}
          {data.events.length === 0 ? (
            <p className="xs-w-muted">已发布的索引中，最近 24 小时没有被拒绝的请求。</p>
          ) : (
            <ul className="xs-wb-denied" aria-label="被拒绝的请求">
              {data.events.map((event) => (
                <li key={event.event_id}>
                  {event.request_id ? (
                    <RouteLink
                      to={`/investigation/requests/${event.request_id}`}
                      label={`打开请求 ${event.request_id}`}
                    >
                      <IdText id={event.request_id} />
                    </RouteLink>
                  ) : (
                    <span className="xs-w-muted">事件 {event.event_id}（无请求 ID）</span>
                  )}
                  <small>
                    <span className="mono">{event.reason_code ?? "未记录原因码"}</span>
                    {event.stage ? ` · ${event.stage}` : ""} ·{" "}
                    <TimeStamp value={event.occurred_at} compact />
                  </small>
                </li>
              ))}
            </ul>
          )}
          <small className="xs-w-muted">
            时间窗 {formatUtc(plan.start)} 至 {formatUtc(plan.end)} · 索引观察于{" "}
            <TimeStamp value={data.as_of} compact /> · 扫描行数 {stats.rows} · 扫描字节{" "}
            {stats.bytes}
            {data.truncated ? " · 还有更早的结果" : ""}
          </small>
          <RouteLink to="/investigation/search">在结构化检索中查看更多</RouteLink>
        </>
      )}
    </section>
  );
}

/** The pages this operator's roles open most often, as plain links (the sidebar has the rest). */
export function QuickLinks({
  roles,
  siteId,
}: {
  roles: readonly string[] | null;
  siteId: string | null;
}) {
  const items = quickLinks(roles, siteId);
  return (
    <nav className="xs-w-card" aria-labelledby="wb-links-title">
      <h2 id="wb-links-title" className="xs-wb-card-title">
        快捷入口
      </h2>
      <ul className="xs-wb-links">
        {items.map((item) => (
          <li key={item.href}>
            <RouteLink to={item.href}>
              <span>{item.label}</span>
              <ArrowRightOutlined aria-hidden="true" />
            </RouteLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
