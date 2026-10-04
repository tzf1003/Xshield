import {
  ArrowRightOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
} from "@ant-design/icons";
import type { ReactNode } from "react";
import type { WorkbenchOverviewResponse, WorkbenchSite } from "./api";

type Props = {
  overview: WorkbenchOverviewResponse | null;
  failed: boolean;
  onNavigate: (path: string) => void;
};
function time(value?: string | null) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString("zh-CN", { hour12: false });
}
function State({ label, tone, icon }: { label: string; tone: string; icon: ReactNode }) {
  return (
    <span className={`workbench-status ${tone}`}>
      {icon}
      <span>{label}</span>
    </span>
  );
}
function state(site: WorkbenchSite) {
  if (site.apply_state === "failed")
    return { label: "应用失败", tone: "danger", icon: <CloseCircleOutlined /> };
  if (site.apply_state === "pending" || site.apply_state === "awaiting_approval")
    return { label: "待处理", tone: "warning", icon: <ClockCircleOutlined /> };
  if (site.apply_state === "paused")
    return { label: "已暂停", tone: "muted", icon: <ExclamationCircleOutlined /> };
  if (site.apply_state === "active")
    return { label: "运行中", tone: "success", icon: <CheckCircleOutlined /> };
  return { label: "未知", tone: "muted", icon: <ExclamationCircleOutlined /> };
}

/** Presentational: the page title and the refresh action belong to the shell page heading. */
export function OverviewWorkbench({ overview, failed, onNavigate }: Props) {
  const sites = overview?.sites ?? [],
    pending = sites.filter(
      (site) => site.apply_state === "pending" || site.apply_state === "awaiting_approval",
    ).length,
    failedSites = sites.filter((site) => site.apply_state === "failed").length,
    healthy = sites.filter((site) => site.apply_state === "active").length,
    audit = overview?.audit.value;
  const auditLabel = !overview
    ? "未读取"
    : overview.audit.source_state !== "available"
      ? "不可用"
      : overview.has_gaps
        ? "存在缺口"
        : audit && audit.pending_segments > 0
          ? "待发布"
          : "连续";
  return (
    <section className="workbench-overview" aria-label="运行概览">
      <p className="workbench-caption">
        服务器按当前会话范围生成的运营快照 · {overview ? `请求 ${overview.request_id}` : "等待读取"}
      </p>
      {overview && overview.completeness !== "complete" && (
        <div className="notice notice-warning" role="status">
          当前快照为{overview.completeness === "partial" ? "部分结果" : "不可用"}
          ，每个来源的状态和原因码已单独标明。
        </div>
      )}
      {failed && (
        <div className="workbench-inline-error" role="alert">
          工作台快照读取失败，请刷新重试。
        </div>
      )}
      <div className="workbench-kpis">
        <article className="workbench-kpi">
          <span>受保护站点</span>
          <strong>{overview ? sites.length : "—"}</strong>
          <small>{overview ? "服务器授权范围" : "尚未读取"}</small>
        </article>
        <article className="workbench-kpi">
          <span>健康站点</span>
          <strong className="success-value">{overview ? healthy : "—"}</strong>
          <small>已确认 active</small>
        </article>
        <article className="workbench-kpi">
          <span>待处理事项</span>
          <strong className="warning-value">{overview ? pending : "—"}</strong>
          <small>策略应用与审批</small>
        </article>
        <article className="workbench-kpi">
          <span>应用失败</span>
          <strong className="danger-value">{overview ? failedSites : "—"}</strong>
          <small>需要人工复核</small>
        </article>
        <article className="workbench-kpi">
          <span>审计发布</span>
          <strong className={overview?.has_gaps ? "danger-value" : ""}>{auditLabel}</strong>
          <small>{overview ? `观察于 ${time(overview.as_of)}` : "尚未读取"}</small>
        </article>
      </div>
      <div className="workbench-grid">
        <section className="panel workbench-section" aria-label="受保护站点">
          <div className="workbench-section-heading">
            <div>
              <h3>受保护站点</h3>
              <span>Edge、源站、审计和版本</span>
            </div>
            <button className="text-button" type="button" onClick={() => onNavigate("/sites")}>
              查看全部 <ArrowRightOutlined />
            </button>
          </div>
          {!overview && !failed ? (
            <div className="workbench-empty">正在读取服务器快照…</div>
          ) : sites.length === 0 ? (
            <div className="workbench-empty">当前范围暂无可展示的站点。</div>
          ) : (
            <div className="table-wrap workbench-table-wrap">
              <table className="workbench-table">
                <thead>
                  <tr>
                    <th>站点</th>
                    <th>Edge</th>
                    <th>源站</th>
                    <th>审计</th>
                    <th>版本</th>
                    <th>应用状态</th>
                    <th>观察时间</th>
                  </tr>
                </thead>
                <tbody>
                  {sites.map((site) => {
                    const item = state(site);
                    return (
                      <tr key={site.site_id}>
                        <td>
                          <button
                            className="text-button workbench-site-name"
                            type="button"
                            onClick={() => onNavigate(`/sites/${site.site_id}/overview`)}
                          >
                            {site.display_name || site.site_id}
                          </button>
                          <small className="mono">{site.site_id}</small>
                        </td>
                        <td>
                          <State
                            label={site.edge.value ?? "未知"}
                            tone={site.edge.source_state === "available" ? "success" : "muted"}
                            icon={<CheckCircleOutlined />}
                          />
                        </td>
                        <td>
                          <State
                            label={site.upstream.value ?? "未知"}
                            tone={site.upstream.source_state === "available" ? "success" : "muted"}
                            icon={<CheckCircleOutlined />}
                          />
                        </td>
                        <td>
                          <State
                            label={site.audit.value ?? "未知"}
                            tone={site.audit.source_state === "available" ? "success" : "muted"}
                            icon={<CheckCircleOutlined />}
                          />
                        </td>
                        <td>
                          <span className="mono">
                            {site.current_revision === null ? "—" : `r${site.current_revision}`}
                          </span>
                        </td>
                        <td>
                          <State {...item} />
                        </td>
                        <td>{time(site.updated_at)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
        <section className="panel workbench-section workbench-attention" aria-label="待处理事项">
          <div className="workbench-section-heading">
            <div>
              <h3>待处理事项</h3>
              <span>需要关注的策略状态</span>
            </div>
            <span className="workbench-count">{pending}</span>
          </div>
          {pending === 0 ? (
            <div className="workbench-empty">
              <CheckCircleOutlined />
              <span>当前没有待处理配置。</span>
            </div>
          ) : (
            <div className="attention-list">
              {sites
                .filter(
                  (site) =>
                    site.apply_state === "pending" || site.apply_state === "awaiting_approval",
                )
                .map((site) => (
                  <button
                    className="attention-row"
                    type="button"
                    key={site.site_id}
                    onClick={() => onNavigate(`/sites/${site.site_id}/releases`)}
                  >
                    <span className="attention-icon">
                      <ClockCircleOutlined />
                    </span>
                    <span>
                      <strong>{site.display_name || site.site_id}</strong>
                      <small>
                        {site.apply_state === "awaiting_approval" ? "等待独立审批" : "等待配置应用"}
                      </small>
                    </span>
                    <ArrowRightOutlined />
                  </button>
                ))}
            </div>
          )}
        </section>
        <section className="panel workbench-section workbench-audit" aria-label="审计发布状态">
          <div className="workbench-section-heading">
            <div>
              <h3>审计发布状态</h3>
              <span>journal 到索引的观察</span>
            </div>
            <button
              className="text-button"
              type="button"
              onClick={() => onNavigate("/operations/audit")}
            >
              查看详情 <ArrowRightOutlined />
            </button>
          </div>
          {audit ? (
            <div className="audit-summary">
              <State
                label={
                  overview?.has_gaps
                    ? "发布存在缺口"
                    : audit.pending_segments
                      ? "有待发布段"
                      : "连续发布"
                }
                tone={
                  overview?.has_gaps ? "danger" : audit.pending_segments ? "warning" : "success"
                }
                icon={<CheckCircleOutlined />}
              />
              <dl>
                <div>
                  <dt>已发布段</dt>
                  <dd>{audit.published_segments.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>待发布段</dt>
                  <dd>{audit.pending_segments.toLocaleString()}</dd>
                </div>
                <div>
                  <dt>水位</dt>
                  <dd>
                    {overview?.index_watermark
                      ? overview.index_watermark.producer_sequence.toLocaleString()
                      : "—"}
                  </dd>
                </div>
              </dl>
              <small>
                观察于 {time(audit.as_of)} · {overview?.request_id}
              </small>
            </div>
          ) : (
            <div className="workbench-empty">审计状态当前不可用或主体无权读取。</div>
          )}
        </section>
        <section className="panel workbench-section workbench-quick-links" aria-label="快捷入口">
          <div className="workbench-section-heading">
            <div>
              <h3>快捷入口</h3>
              <span>进入常用工作流</span>
            </div>
          </div>
          <div className="quick-link-list">
            <button type="button" onClick={() => onNavigate("/investigation/search")}>
              <span>
                <span className="quick-link-icon">⌕</span>结构化检索
              </span>
              <ArrowRightOutlined />
            </button>
            <button type="button" onClick={() => onNavigate("/cases")}>
              <span>
                <span className="quick-link-icon">▣</span>案件工作台
              </span>
              <ArrowRightOutlined />
            </button>
            <button type="button" onClick={() => onNavigate("/access/session")}>
              <span>
                <span className="quick-link-icon">⚙</span>权限中心
              </span>
              <ArrowRightOutlined />
            </button>
          </div>
        </section>
      </div>
    </section>
  );
}
