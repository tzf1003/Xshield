/**
 * The four numbers at the top of the workbench. Each one names its source and the time it
 * describes; a source that could not answer is "—" with the reason, never 0. Pure and
 * unit-tested (tests/operations-model.test.ts).
 */
import type { SiteListResponse, WorkbenchOverviewResponse, WorkbenchSite } from "../api.ts";
import { siteApprovals } from "../work/inbox.ts";
import type { SourceState } from "./sources.ts";

export type KpiTone = "success" | "warning" | "error" | "default";

export type Kpi = Readonly<{
  key: "serving" | "approval" | "failed" | "audit";
  label: string;
  /** `null` renders as "—": the source could not say. */
  value: string | null;
  tone: KpiTone;
  /** What the value means, or why there is none. */
  detail: string;
  source: string;
  /** Server observation time, when the source has one. */
  asOf: string | null;
  /** Browser receipt time (ms) for a source without a server observation time. */
  receivedAt: number | null;
}>;

export type KpiInput = Readonly<{
  overview: SourceState<WorkbenchOverviewResponse>;
  sites: SourceState<SiteListResponse>;
  /** `null` is the local machine-login mode: roles are unknown. */
  roles: readonly string[] | null;
}>;

const SNAPSHOT = "工作台快照";
const SITE_LIST = "站点清单首页";

/** A site whose edge serves some confirmed revision: it was applied once and is not paused. */
export function isServing(site: Pick<WorkbenchSite, "current_revision" | "apply_state">): boolean {
  return site.current_revision !== null && site.apply_state !== "paused";
}

/**
 * Whether the snapshot's site list can be taken at face value. Only SystemAdmin gets the site
 * projection, and the snapshot does not say whether an empty list means "no sites" or "not
 * projected / failed to load"; an empty list in a partial snapshot is confirmed as zero only by
 * an empty, complete site-list read.
 */
export function siteProjection(
  overview: WorkbenchOverviewResponse,
  roles: readonly string[] | null,
  sites: SourceState<SiteListResponse>,
): { projected: true } | { projected: false; reason: string } {
  if (overview.completeness === "unavailable") {
    return { projected: false, reason: "快照不可用，没有站点数据。" };
  }
  if (overview.sites.length > 0) return { projected: true };
  if (roles !== null && !roles.includes("system_admin")) {
    return { projected: false, reason: "快照只为 SystemAdmin 投影站点列表，当前身份看不到。" };
  }
  if (overview.completeness === "complete") return { projected: true };
  if (sites.status === "ok" && sites.data.sites.length === 0 && !sites.data.truncated) {
    return { projected: true };
  }
  return {
    projected: false,
    reason: "快照为部分结果且没有站点：可能没有投影站点列表或读取失败，不能确认为 0。",
  };
}

function unavailable(source: SourceState<unknown>, what: string): string {
  switch (source.status) {
    case "loading":
      return "正在读取…";
    case "skipped":
      return `当前角色不读取${what}。`;
    case "denied":
      return `${what}被服务端拒绝：需要相应角色。`;
    case "failed":
      return `${what}读取失败，见下方提示。`;
    default:
      return "";
  }
}

function snapshotKpi(
  key: "serving" | "failed",
  input: KpiInput,
  compute: (sites: readonly WorkbenchSite[], partial: boolean) => Omit<Kpi, "key" | "source">,
): Kpi {
  const label = key === "serving" ? "正在服务的站点" : "应用失败";
  const { overview } = input;
  if (overview.status !== "ok") {
    return {
      key,
      label,
      value: null,
      tone: "default",
      detail: unavailable(overview, "工作台快照"),
      source: SNAPSHOT,
      asOf: null,
      receivedAt: null,
    };
  }
  const projection = siteProjection(overview.data, input.roles, input.sites);
  if (!projection.projected) {
    return {
      key,
      label,
      value: null,
      tone: "default",
      detail: projection.reason,
      source: SNAPSHOT,
      asOf: overview.data.as_of,
      receivedAt: null,
    };
  }
  // A full page (128 sites) is reported as partial by the server: there may be more.
  const partial = overview.data.completeness !== "complete" && overview.data.sites.length >= 128;
  return { key, source: SNAPSHOT, ...compute(overview.data.sites, partial) };
}

export function deriveKpis(input: KpiInput): Kpi[] {
  const serving = snapshotKpi("serving", input, (sites, partial) => {
    const count = sites.filter(isServing).length;
    return {
      label: "正在服务的站点",
      value: `${count}${partial ? "+" : ""}`,
      tone: count === sites.length ? "success" : "default",
      detail: `共 ${sites.length}${partial ? "+" : ""} 个站点；未生效、已暂停或从未应用的站点不计入。`,
      asOf: input.overview.status === "ok" ? input.overview.data.as_of : null,
      receivedAt: null,
    };
  });
  const failed = snapshotKpi("failed", input, (sites, partial) => {
    const count = sites.filter((site) => site.apply_state === "failed").length;
    return {
      label: "应用失败",
      value: `${count}${partial ? "+" : ""}`,
      tone: count > 0 ? "error" : "success",
      detail:
        count > 0
          ? "edge 没有确认这些站点的配置；它们继续使用上一份已确认的配置。"
          : "快照中没有应用失败的站点。",
      asOf: input.overview.status === "ok" ? input.overview.data.as_of : null,
      receivedAt: null,
    };
  });
  return [serving, approvalKpi(input), failed, auditKpi(input)];
}

function approvalKpi(input: KpiInput): Kpi {
  const { sites } = input;
  const base = { key: "approval", label: "待审批修订", source: SITE_LIST, asOf: null } as const;
  if (sites.status !== "ok") {
    return {
      ...base,
      value: null,
      tone: "default",
      detail:
        sites.status === "denied"
          ? "站点清单被服务端拒绝：读取它需要 SystemAdmin。"
          : unavailable(sites, "站点清单"),
      receivedAt: null,
    };
  }
  const count = siteApprovals(sites.data.sites).length;
  return {
    ...base,
    value: `${count}${sites.data.truncated ? "+" : ""}`,
    tone: count > 0 ? "warning" : "success",
    detail: sites.data.truncated
      ? "只统计了站点清单首页，后续页可能还有。"
      : "等待另一位审批人批准的站点修订。",
    receivedAt: sites.receivedAt,
  };
}

function auditKpi(input: KpiInput): Kpi {
  const { overview, roles } = input;
  const base = { key: "audit", label: "审计发布", source: `${SNAPSHOT} · 审计发布观察` } as const;
  if (overview.status !== "ok") {
    return {
      ...base,
      value: null,
      tone: "default",
      detail: unavailable(overview, "工作台快照"),
      asOf: null,
      receivedAt: null,
    };
  }
  const audit = overview.data.audit;
  if (audit.source_state !== "available" || audit.value === null) {
    const detail =
      roles !== null && !roles.includes("audit_administrator")
        ? "审计发布观察只对 AuditAdministrator 读取。"
        : roles === null
          ? "快照没有包含审计发布观察：无 AuditAdministrator 角色或读取失败。"
          : "当前身份有 AuditAdministrator，但这次读取失败（服务端用同一原因码报告）。";
    return { ...base, value: null, tone: "default", detail, asOf: null, receivedAt: null };
  }
  const value = audit.value;
  const state = value.has_gaps
    ? { value: "存在缺口", tone: "error" as const }
    : value.pending_segments > 0
      ? { value: "有待发布段", tone: "warning" as const }
      : { value: "连续", tone: "success" as const };
  return {
    ...base,
    ...state,
    detail: `已发布 ${value.published_segments} 段 · 待发布 ${value.pending_segments} 段 · 未封存 ${value.unsealed_segments} 段`,
    asOf: value.as_of,
    receivedAt: null,
  };
}
