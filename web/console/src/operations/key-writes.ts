/**
 * The reads and writes of Agent API key administration, bound to the session.
 *
 * The four endpoints are tenant-wide and their replies carry no tenant/site envelope, so the
 * console checks what they do carry and binds the rest to the confirmed session scope:
 *  - the list: every key's `tenant_id` (a key of another tenant ends the session, as any
 *    cross-scope reply does);
 *  - create and rotate: the echoed scope rows must be exactly the frozen request's rows (a reply
 *    that grants anything else is a contract failure and its plaintext is never shown), and their
 *    tenant is checked like the list's;
 *  - revoke: the reply must name the targeted key and say `revoked`.
 *
 * The plaintext of an issued key goes to `keySecrets(runtime)` and nowhere else (see
 * key-secret.ts); the write layer only ever sees the reply without `api_key`.
 */
import type { ControlClient, ManagementApiKeyRecord, ManagementApiKeyResponse } from "../api.ts";
import { ApiError } from "../api-contract.ts";
import { StaleSessionError } from "../security/errors.ts";
import type { GuardedQuerySpec } from "../security/guarded-query.ts";
import { MANUAL_REFRESH } from "../security/query-client.ts";
import type { SessionRuntime } from "../security/runtime.ts";
import type { Owner } from "../work/operations.ts";
import type { KeyRequest } from "./api-keys.ts";
import { keySecrets } from "./key-secret.ts";

const base = "/control/v1/agent-api-keys";

export const keyPaths = {
  collection: base,
  revoke: (apiKeyId: string) => `${base}/${apiKeyId}/revoke`,
  rotate: (apiKeyId: string) => `${base}/${apiKeyId}/rotate`,
};

/** Which control owns which unresolved key write. */
export const keyOwners = {
  create: (): Owner => (operation) => operation.path === base,
  revoke:
    (apiKeyId: string): Owner =>
    (operation) =>
      operation.path === keyPaths.revoke(apiKeyId),
  rotate:
    (apiKeyId: string): Owner =>
    (operation) =>
      operation.path === keyPaths.rotate(apiKeyId),
  /** Any unresolved write on this key: a revoke and a rotation never run side by side. */
  key:
    (apiKeyId: string): Owner =>
    (operation) =>
      operation.path.startsWith(`${base}/${apiKeyId}/`),
};

export const keyListKey = ["admin", "api-keys"] as const;

export type KeyList = Readonly<{
  request_id: string;
  tenant_id: string;
  site_id: string;
  keys: readonly ManagementApiKeyRecord[];
}>;

/** The confirmed session scope; key administration needs a browser session, which has one. */
function sessionScope(runtime: SessionRuntime): { tenant_id: string; site_id: string } {
  const scope = runtime.store.getState().scope;
  if (!scope) throw new StaleSessionError("disconnected");
  return scope;
}

/** One tenant for all rows, or the session's when there are none (nothing to contradict). */
function soleTenant(tenants: readonly string[], fallback: string, status: number): string {
  const distinct = [...new Set(tenants)];
  if (distinct.length > 1) throw new ApiError("INVALID_RESPONSE", status);
  return distinct[0] ?? fallback;
}

export function keyListSpec(runtime: SessionRuntime, enabled: boolean): GuardedQuerySpec<KeyList> {
  return {
    key: keyListKey,
    enabled,
    staleTime: MANUAL_REFRESH,
    fetch: async (client, signal) => {
      const scope = sessionScope(runtime);
      const list = await client.managementApiKeys(signal);
      return {
        request_id: list.request_id,
        tenant_id: soleTenant(
          list.keys.map((key) => key.tenant_id),
          scope.tenant_id,
          200,
        ),
        site_id: scope.site_id,
        keys: list.keys,
      };
    },
  };
}

/** The issued key as the write layer keeps it: the reply without its plaintext. */
export type IssuedKey = Readonly<{
  request_id: string;
  tenant_id: string;
  site_id: string;
  api_key_id: string;
  key_prefix: string;
  expires_at: string;
  scopes: readonly Readonly<{ site_id: string; capabilities: readonly string[] }>[];
}>;

function sameScopes(response: ManagementApiKeyResponse, request: KeyRequest): boolean {
  return (
    response.scopes.length === request.scopes.length &&
    response.scopes.every((row, index) => {
      const sent = request.scopes[index];
      return (
        sent !== undefined &&
        row.tenant_id === sent.tenant_id &&
        row.site_id === sent.site_id &&
        row.capabilities.length === sent.capabilities.length &&
        row.capabilities.every((name, at) => name === sent.capabilities[at])
      );
    })
  );
}

/**
 * Checks an issuing reply, files its plaintext for the one-time dialog and returns the rest.
 * `epoch` is the session the write was frozen in: a reply that outlived it is dropped.
 */
export function receiveIssued(
  runtime: SessionRuntime,
  epoch: number,
  response: ManagementApiKeyResponse,
  request: KeyRequest,
  rotation: { replaced: string } | null,
): IssuedKey {
  if (!sameScopes(response, request)) throw new ApiError("INVALID_RESPONSE", 201);
  if (!runtime.store.isCurrent(epoch)) throw new StaleSessionError("epoch");
  const scope = sessionScope(runtime);
  const tenant = soleTenant(
    response.scopes.map((row) => row.tenant_id),
    scope.tenant_id,
    201,
  );
  const issued: IssuedKey = {
    request_id: response.request_id,
    tenant_id: tenant,
    site_id: scope.site_id,
    api_key_id: response.api_key_id,
    key_prefix: response.key_prefix,
    expires_at: response.expires_at,
    scopes: response.scopes.map((row) => ({
      site_id: row.site_id,
      capabilities: row.capabilities,
    })),
  };
  // A reply for another tenant ends the session in the write layer; its plaintext is never kept.
  if (tenant !== scope.tenant_id) return issued;
  keySecrets(runtime).put({
    epoch,
    kind: rotation ? "rotated" : "created",
    apiKeyId: response.api_key_id,
    replaced: rotation?.replaced ?? null,
    displayName: request.display_name,
    subject: request.subject,
    keyPrefix: response.key_prefix,
    expiresAt: response.expires_at,
    scopes: issued.scopes,
    secret: response.api_key,
  });
  return issued;
}

export type CreateVars = Readonly<{ request: KeyRequest }>;
export type RotateVars = Readonly<{ apiKeyId: string; request: KeyRequest }>;
export type RevokeVars = Readonly<{ apiKeyId: string }>;

export type Revoked = Readonly<{
  request_id: string;
  tenant_id: string;
  site_id: string;
  api_key_id: string;
}>;

export function createKey(
  runtime: SessionRuntime,
  epoch: number,
  client: ControlClient,
  vars: CreateVars,
  context: { signal: AbortSignal; idempotencyKey: string },
): Promise<IssuedKey> {
  return client
    .createManagementApiKey(vars.request, context.idempotencyKey, context.signal)
    .then((response) => receiveIssued(runtime, epoch, response, vars.request, null));
}

export function rotateKey(
  runtime: SessionRuntime,
  epoch: number,
  client: ControlClient,
  vars: RotateVars,
  context: { signal: AbortSignal; idempotencyKey: string },
): Promise<IssuedKey> {
  return client
    .rotateManagementApiKey(vars.apiKeyId, vars.request, context.idempotencyKey, context.signal)
    .then((response) =>
      receiveIssued(runtime, epoch, response, vars.request, { replaced: vars.apiKeyId }),
    );
}

export async function revokeKey(
  runtime: SessionRuntime,
  client: ControlClient,
  vars: RevokeVars,
  context: { signal: AbortSignal; idempotencyKey: string },
): Promise<Revoked> {
  const reply = await client.revokeManagementApiKey(
    vars.apiKeyId,
    context.idempotencyKey,
    context.signal,
  );
  const scope = sessionScope(runtime);
  return { ...scope, request_id: reply.request_id, api_key_id: reply.api_key_id };
}
