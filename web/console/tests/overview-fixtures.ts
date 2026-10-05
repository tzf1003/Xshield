import { auditHealthFixture, REQUEST_ID } from "./fixtures";

/** An upstream health read stored long before the snapshot: it must read as "last observed". */
export const UPSTREAM_OBSERVED_AT = "2026-09-20T05:10:30Z";

type Observed = {
  observed_at: string;
  source_state: "available" | "partial" | "unavailable" | "not_authorized";
  reason_code: string;
  value: string | null;
};

export type OverviewOptions = {
  tenant_id?: string;
  site_id?: string;
  /** Leave the site projection out, as the server does for non-SystemAdmin callers. */
  noSites?: boolean;
  /** Leave the audit publication observation out (no AuditAdministrator role). */
  noAudit?: boolean;
};

/**
 * Synthetic workbench snapshot in the shape of crates/xshield-control/src/workbench.rs: an
 * active site, one whose revision waits for approval (the snapshot says `pending`; only the site
 * list carries `requires_approval`) and one whose apply failed. Edge and its audit barrier are
 * probed live at snapshot time; the upstream values are stored observations with their own time.
 */
export function workbenchOverviewFixture(options: OverviewOptions = {}) {
  const health = auditHealthFixture();
  const { request_id: _r, tenant_id: _t, site_id: _s, ...audit } = health;
  const asOf = "2026-09-20T08:10:30Z";
  const observed = (
    source_state: Observed["source_state"],
    value: string | null,
    reason_code: string,
    observed_at = asOf,
  ): Observed => ({ observed_at, source_state, reason_code, value });
  const site = (
    id: string,
    name: string,
    applyState: string,
    revision: number | null,
    reason: string,
    upstream: Observed,
  ) => ({
    site_id: id,
    display_name: name,
    public_origin: `https://${id.replace(/_/g, "-")}.example`,
    edge: observed("available", "healthy", "WORKBENCH_EDGE_PROBED"),
    upstream,
    audit: observed("available", "healthy", "WORKBENCH_EDGE_AUDIT_PROBED"),
    current_revision: revision,
    apply_state: applyState,
    reason_code: reason,
    updated_at: asOf,
  });
  const partial = options.noSites || options.noAudit;
  return {
    request_id: REQUEST_ID,
    tenant_id: options.tenant_id ?? "tenant_demo",
    site_id: options.site_id ?? "site_demo",
    as_of: asOf,
    completeness: partial ? "partial" : "complete",
    index_watermark: options.noAudit ? null : health.index_watermark,
    has_gaps: false,
    posture: observed("available", "observed", "WORKBENCH_POSTURE_SCOPED"),
    sites: options.noSites
      ? []
      : [
          site(
            "site_alpha",
            "Alpha 官网",
            "active",
            4,
            "CONTROL_SITE_APPLY_ACTIVE",
            observed(
              "available",
              "healthy",
              "WORKBENCH_UPSTREAM_LAST_OBSERVED",
              UPSTREAM_OBSERVED_AT,
            ),
          ),
          site(
            "site_beta",
            "Beta 商城",
            "pending",
            2,
            "CONTROL_SITE_APPROVAL_REQUIRED",
            observed("unavailable", null, "WORKBENCH_UPSTREAM_NEVER_OBSERVED"),
          ),
          site(
            "site_gamma",
            "Gamma 支付",
            "failed",
            7,
            "EDGE_APPLY_REJECTED",
            observed(
              "available",
              "unavailable",
              "WORKBENCH_UPSTREAM_LAST_OBSERVED",
              UPSTREAM_OBSERVED_AT,
            ),
          ),
        ],
    queues: [],
    recent_activity: [],
    audit: options.noAudit
      ? observed("unavailable", null, "WORKBENCH_AUDIT_NOT_AUTHORIZED")
      : {
          observed_at: asOf,
          source_state: "available",
          reason_code: "WORKBENCH_AUDIT_READ",
          value: {
            ...audit,
            closed_segments: 5,
            published_segments: 5,
            pending_segments: 0,
            unsealed_segments: 0,
            has_gaps: false,
          },
        },
  };
}
