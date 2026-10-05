import { type RiskToken, riskText } from "../../ui/reason-codes.ts";
import { canonicalJson, effectivePolicy, type SiteConfigDraft } from "./config.ts";
import { diffConfigs, type FieldChange, isServing } from "./diff.ts";

/**
 * Client-side port of `assess_change_risk` (crates/xshield-core/src/site/risk.rs): which of
 * the approval reasons apply when `desired` replaces what the edge serves now.
 *
 * `baseline` is the configuration of the active revision, or `null` when the site was never
 * applied; a baseline that is not itself served (draft or paused) counts as no baseline. The
 * server never returns its risk reasons, so this is the console's reconstruction from the two
 * stored revisions. It is explanatory only: the server decides, and a field the console does
 * not know (the server's catch-all OTHER_CHANGE) can make the server stricter than this.
 */
export function assessChangeRisk(
  baseline: SiteConfigDraft | null,
  desired: SiteConfigDraft,
): RiskToken[] {
  const served = baseline !== null && isServing(baseline) ? baseline : null;
  if (!isServing(desired)) return served ? ["TAKEDOWN"] : [];
  if (served === null) return ["ACTIVATION"];

  const before = effectivePolicy(served);
  const after = effectivePolicy(desired);
  const same = (left: unknown, right: unknown) => canonicalJson(left) === canonicalJson(right);
  const byId = <T extends { operation_id: string }>(items: readonly T[]) =>
    [...items].sort((a, b) =>
      a.operation_id < b.operation_id ? -1 : a.operation_id > b.operation_id ? 1 : 0,
    );
  const byKind = <T extends { kind: string }>(items: readonly T[]) =>
    [...items].sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0));

  const checks: [boolean, RiskToken][] = [
    [
      served.upstream_address !== desired.upstream_address ||
        served.upstream_server_name !== desired.upstream_server_name ||
        served.upstream_tls !== desired.upstream_tls,
      "UPSTREAM_CHANGED",
    ],
    [served.public_origin !== desired.public_origin, "ORIGIN_CHANGED"],
    [served.listen_port !== desired.listen_port, "LISTEN_PORT_CHANGED"],
    [
      served.entry_path !== desired.entry_path || served.security_entry !== desired.security_entry,
      "ENTRY_CHANGED",
    ],
    [!same(byId(before.routes), byId(after.routes)), "ROUTES_CHANGED"],
    [!same(before.identity, after.identity), "IDENTITY_CHANGED"],
    [!same(before.crypto, after.crypto), "CRYPTO_CHANGED"],
    [!same(before.waf, after.waf), "WAF_CHANGED"],
    [!same(before.limits, after.limits), "LIMITS_CHANGED"],
    [!same(before.health_check, after.health_check), "HEALTH_CHECK_CHANGED"],
    [!same(byKind(before.secret_refs), byKind(after.secret_refs)), "SECRET_REFS_CHANGED"],
    [served.sensor_enabled !== desired.sensor_enabled, "SENSOR_CHANGED"],
    [
      before.static_asset_max_path_depth !== after.static_asset_max_path_depth,
      "STATIC_ASSET_POLICY_CHANGED",
    ],
    [
      before.origin_object_access_enforced !== after.origin_object_access_enforced,
      "OBJECT_ACCESS_CHANGED",
    ],
  ];
  return checks.filter(([changed]) => changed).map(([, token]) => token);
}

export type ApprovalReason = Readonly<{
  token: RiskToken;
  label: string;
  detail: string;
  /** The field changes that fall under this reason (empty for a first activation). */
  changes: readonly FieldChange[];
}>;

export type ApprovalExplanation = Readonly<{
  required: boolean;
  reasons: readonly ApprovalReason[];
  /** Changes that may happen without approval: the display name, the policy label, ordering. */
  free: readonly FieldChange[];
  /** What the edge serves is the baseline; `false` means no active revision was available. */
  hasBaseline: boolean;
}>;

/** Why the staged revision needs approval, in words, from the two revisions' stored configs. */
export function explainApproval(
  baseline: SiteConfigDraft | null,
  desired: SiteConfigDraft,
): ApprovalExplanation {
  const tokens = assessChangeRisk(baseline, desired);
  const changes = baseline ? diffConfigs(baseline, desired) : [];
  const reasons = tokens.map((token) => ({
    token,
    ...riskText(token),
    changes: changes.filter((change) => change.risk === token),
  }));
  return {
    required: tokens.length > 0,
    reasons,
    free: changes.filter((change) => change.risk === null),
    hasBaseline: baseline !== null,
  };
}
