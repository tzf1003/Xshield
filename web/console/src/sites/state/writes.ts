import type {
  SiteApplyResponse,
  SiteConfigResponse,
  SiteDeleteResponse,
  SiteValidationResponse,
} from "../../api.ts";
import { useGuardedMutation } from "../../security/hooks.ts";
import type { SiteConfigDraft } from "../model/config.ts";

const sitePath = (siteId: string) => `/control/v1/sites/${siteId}`;

/** Creating a site posts the whole draft plus its ID; the ID is the scope of the answer. */
export function useCreateSite() {
  return useGuardedMutation<{ siteId: string; config: SiteConfigDraft }, SiteConfigResponse>({
    label: "创建站点",
    method: "POST",
    path: () => "/control/v1/sites",
    body: (vars) => ({ site_id: vars.siteId, ...vars.config }),
    expectedSiteId: (vars) => vars.siteId,
    execute: (client, vars, context) =>
      client.createSite(vars.siteId, vars.config, context.idempotencyKey, context.signal),
  });
}

/**
 * Every write of one site. Each freezes its method, path, body and a framework-generated
 * idempotency key at submit time (`useGuardedMutation` / the pending-operation registry), so an
 * unknown outcome can only be continued with the identical request. Keys are never form fields.
 */
export function useSiteWrites(siteId: string) {
  const save = useGuardedMutation<{ config: SiteConfigDraft }, SiteConfigResponse>({
    label: `保存站点配置 · ${siteId}`,
    method: "PUT",
    path: () => `${sitePath(siteId)}/config`,
    body: (vars) => vars.config,
    expectedSiteId: () => siteId,
    execute: (client, vars, context) =>
      client.saveSiteConfig(siteId, vars.config, context.idempotencyKey, context.signal),
  });
  const validate = useGuardedMutation<Record<string, never>, SiteValidationResponse>({
    label: `验证站点配置 · ${siteId}`,
    method: "POST",
    path: () => `${sitePath(siteId)}/validate`,
    expectedSiteId: () => siteId,
    execute: (client, _vars, context) =>
      client.validateSite(siteId, context.signal, context.idempotencyKey),
  });
  const apply = useGuardedMutation<Record<string, never>, SiteApplyResponse>({
    label: `应用站点配置 · ${siteId}`,
    method: "POST",
    path: () => `${sitePath(siteId)}/apply`,
    expectedSiteId: () => siteId,
    execute: (client, _vars, context) =>
      client.applySite(siteId, context.idempotencyKey, context.signal),
  });
  /** `digest` is the config digest of the revision the reviewer read (never typed by hand). */
  const approve = useGuardedMutation<{ digest: string | null }, SiteApplyResponse>({
    label: `批准并应用 · ${siteId}`,
    method: "POST",
    path: () => `${sitePath(siteId)}/approve`,
    expectedSiteId: () => siteId,
    execute: (client, vars, context) =>
      client.approveSite(siteId, context.idempotencyKey, context.signal, vars.digest ?? undefined),
  });
  const rollback = useGuardedMutation<Record<string, never>, SiteApplyResponse>({
    label: `回滚站点配置 · ${siteId}`,
    method: "POST",
    path: () => `${sitePath(siteId)}/rollback`,
    expectedSiteId: () => siteId,
    execute: (client, _vars, context) =>
      client.rollbackSite(siteId, context.idempotencyKey, context.signal),
  });
  const remove = useGuardedMutation<Record<string, never>, SiteDeleteResponse>({
    label: `删除站点 · ${siteId}`,
    method: "DELETE",
    path: () => sitePath(siteId),
    expectedSiteId: () => siteId,
    execute: (client, _vars, context) =>
      client.deleteSite(siteId, context.idempotencyKey, context.signal),
  });
  return { save, validate, apply, approve, rollback, remove };
}
