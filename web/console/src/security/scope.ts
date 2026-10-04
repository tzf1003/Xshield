/** Tenant/site scope confirmed by the server for the current session. */
export type Scope = Readonly<{ tenant_id: string; site_id: string }>;

/** Every control response carries the scope it was authorized for. */
export type ScopedResponse = { tenant_id: string; site_id: string };

export type ScopeCheck =
  /** `confirm` is set only when no scope had been established yet (machine login). */
  | { kind: "ok"; confirm: Scope | null }
  /** A site-specific read answered for another site. Not a session violation. */
  | { kind: "wrong_site" }
  /** The response belongs to another tenant (or site): the session must end. */
  | { kind: "mismatch" };

/**
 * Pure scope verification shared by every guarded read and write.
 *
 * - Without `expectedSiteId` the response must match the confirmed tenant AND site.
 * - With `expectedSiteId` (multi-site reads such as `/sites/{id}/config`) the response must
 *   be for exactly that site and the confirmed tenant; the confirmed site is not consulted.
 * - The first unscoped response of a machine-login session establishes the scope.
 */
export function checkScope(
  confirmed: Scope | null,
  response: ScopedResponse,
  expectedSiteId?: string,
): ScopeCheck {
  if (expectedSiteId !== undefined && response.site_id !== expectedSiteId) {
    return { kind: "wrong_site" };
  }
  if (
    confirmed !== null &&
    (confirmed.tenant_id !== response.tenant_id ||
      (expectedSiteId === undefined && confirmed.site_id !== response.site_id))
  ) {
    return { kind: "mismatch" };
  }
  if (expectedSiteId === undefined && confirmed === null) {
    return { kind: "ok", confirm: { tenant_id: response.tenant_id, site_id: response.site_id } };
  }
  return { kind: "ok", confirm: null };
}
