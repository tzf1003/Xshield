import { auditHealthFixture, REQUEST_ID } from "./fixtures";

/** Synthetic workbench snapshot: one active, one awaiting-approval and one failed site. */
export function workbenchOverviewFixture(overrides: { tenant_id?: string; site_id?: string } = {}) {
  const health = auditHealthFixture();
  const { request_id: _r, tenant_id: _t, site_id: _s, ...audit } = health;
  const observed = (state: "available" | "unavailable", value: string | null, reason: string) => ({
    observed_at: health.as_of,
    source_state: state,
    reason_code: reason,
    value,
  });
  const site = (id: string, name: string, applyState: string, revision: number | null) => ({
    site_id: id,
    display_name: name,
    public_origin: `https://${id.replace(/_/g, "-")}.example`,
    edge: observed("available", "healthy", "EDGE_OK"),
    upstream: observed(
      applyState === "failed" ? "unavailable" : "available",
      applyState === "failed" ? null : "healthy",
      applyState === "failed" ? "UPSTREAM_UNKNOWN" : "UPSTREAM_OK",
    ),
    audit: observed("available", "continuous", "AUDIT_OK"),
    current_revision: revision,
    apply_state: applyState,
    reason_code: `SITE_${applyState.toUpperCase()}`,
    updated_at: health.as_of,
  });
  return {
    request_id: REQUEST_ID,
    tenant_id: overrides.tenant_id ?? "tenant_demo",
    site_id: overrides.site_id ?? "site_demo",
    as_of: health.as_of,
    completeness: "complete",
    index_watermark: health.index_watermark,
    has_gaps: false,
    posture: observed("available", "healthy", "WORKBENCH_POSTURE_SCOPED"),
    sites: [
      site("site_alpha", "Alpha 官网", "active", 4),
      site("site_beta", "Beta 商城", "awaiting_approval", 2),
      site("site_gamma", "Gamma 支付", "failed", 7),
    ],
    queues: [],
    recent_activity: [],
    audit: {
      observed_at: health.as_of,
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
