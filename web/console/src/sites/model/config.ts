import type {
  RouteAdmission,
  SiteAuthBinding,
  SiteConfig,
  SiteIssuedBy,
  SitePageActions,
  SitePolicyConfig,
  SiteQueryPagination,
  SiteResourceGrant,
  SiteRouteConfig,
  SiteSecretReference,
  SiteSensorHtml,
  SiteSensorHtmlAdapter,
} from "../../api.ts";

/** What an operator edits: a site configuration without identity and revision metadata. */
export type SiteConfigDraft = Omit<
  SiteConfig,
  "revision" | "config_digest" | "updated_by" | "created_at" | "updated_at" | "gateway_config"
>;

export type SecurityEntry = SiteConfig["security_entry"];
export type ConfigStatus = SiteConfig["status"];

/** The edge serves this route when `policy.routes` is empty (`SiteConfig::effective_policy`). */
export const ENTRY_OPERATION_ID = "protected.entry";
export const ENTRY_SOURCE_ACTION = "protected.entry";
export const MAX_ROUTES = 256;
export const MAX_SECRET_REFS = 32;

export const securityEntryLabel: Record<SecurityEntry, string> = {
  public: "公开",
  authenticated_root: "已认证根",
  ui_action_required: "必须有界面操作来源",
};

/** Route admissions: the site entry's three plus the route-only authentication entry. */
export const routeAdmissionLabel: Record<RouteAdmission, string> = {
  ...securityEntryLabel,
  auth_entry: "认证入口",
};

export const statusLabel: Record<ConfigStatus, string> = {
  draft: "草稿",
  active: "启用",
  paused: "暂停",
};

export function defaultPolicy(): SitePolicyConfig {
  return {
    routes: [],
    identity: {
      enabled: false,
      cookie_name: "__Host-xshield_sid",
      credential_header: "Authorization",
      profile: "default",
      session_ttl_seconds: 3600,
      generation: 1,
    },
    crypto: {
      adapter_revision: "observe-v1",
      failure_strategy: "fail_closed",
      protocol_version: null,
    },
    waf: {
      enabled: true,
      blocked_headers: [],
      blocked_query_fragments: [],
      max_cookie_bytes: 8192,
    },
    limits: {
      max_request_body_bytes: 1_048_576,
      max_response_body_bytes: 16_777_216,
      requests_per_second: 1000,
      burst: 2000,
    },
    health_check: { path: "/health", interval_seconds: 15, timeout_ms: 2000, expected_status: 200 },
    secret_refs: [],
    // Off: the fallback admits GET requests with no identity and no exact route (docs/15), so a
    // site opts in explicitly (the wizard's static-assets switch or the policy tab).
    static_asset_max_path_depth: 0,
    origin_object_access_enforced: false,
  };
}

/** A blank configuration for a new site; it is saved as a draft, never served. */
export function emptyDraft(): SiteConfigDraft {
  return {
    display_name: "",
    public_origin: "",
    upstream_address: "",
    upstream_server_name: "",
    upstream_tls: true,
    listen_port: 0,
    entry_path: "/",
    security_entry: "ui_action_required",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status: "draft",
    policy: defaultPolicy(),
  };
}

export function draftFromConfig(config: SiteConfig): SiteConfigDraft {
  const {
    revision: _revision,
    config_digest: _digest,
    updated_by: _updatedBy,
    created_at: _createdAt,
    updated_at: _updatedAt,
    gateway_config: _gateway,
    ...rest
  } = config;
  return structuredClone(rest);
}

export function newRoute(over: Partial<SiteRouteConfig> = {}): SiteRouteConfig {
  return {
    operation_id: "",
    method: "GET",
    path: "/",
    security_entry: "public",
    source_action: null,
    resource_type: null,
    view_profile: null,
    resource_query_parameter: null,
    resource_path_parameter: null,
    request_crypto: null,
    response_crypto: null,
    response_mode: "",
    max_response_bytes: 1_048_576,
    ...over,
  };
}

/** The route the server derives from the top-level entry fields when no route is configured. */
export function entryRoute(draft: Pick<SiteConfigDraft, "entry_path" | "security_entry">) {
  return newRoute({
    operation_id: ENTRY_OPERATION_ID,
    method: "GET",
    path: draft.entry_path,
    security_entry: draft.security_entry,
    source_action: draft.security_entry === "ui_action_required" ? ENTRY_SOURCE_ACTION : null,
  });
}

/** `SiteConfig::effective_policy`: with no explicit route the entry route is the policy. */
export function effectivePolicy(draft: SiteConfigDraft): SitePolicyConfig {
  if (draft.policy.routes.length > 0) return draft.policy;
  return { ...draft.policy, routes: [entryRoute(draft)] };
}

/**
 * The top-level entry fields and the `protected.entry` route describe the same door. Changing
 * the fields therefore moves that route too (when one exists), exactly as the previous editor
 * moved its first route; a configuration without an explicit entry route needs no sync.
 */
export function withEntry(
  draft: SiteConfigDraft,
  entry: Partial<Pick<SiteConfigDraft, "entry_path" | "security_entry">>,
): SiteConfigDraft {
  const next = { ...draft, ...entry };
  const routes = draft.policy.routes.map((route) =>
    route.operation_id === ENTRY_OPERATION_ID
      ? {
          ...route,
          path: next.entry_path,
          security_entry: next.security_entry,
          source_action: next.security_entry === "ui_action_required" ? ENTRY_SOURCE_ACTION : null,
        }
      : route,
  );
  return { ...next, policy: { ...next.policy, routes } };
}

// ---- Tolerant reading of stored revisions -------------------------------------------------

type Record_ = Record<string, unknown>;
const isRecord = (value: unknown): value is Record_ =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const str = (value: unknown, fallback = ""): string =>
  typeof value === "string" ? value : fallback;
const strOrNull = (value: unknown): string | null => (typeof value === "string" ? value : null);
const num = (value: unknown, fallback: number): number =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;
const bool = (value: unknown, fallback = false): boolean =>
  typeof value === "boolean" ? value : fallback;
const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const oneOf = <T extends string>(value: unknown, allowed: readonly T[], fallback: T): T =>
  typeof value === "string" && (allowed as readonly string[]).includes(value)
    ? (value as T)
    : fallback;

const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
const entries = ["public", "authenticated_root", "ui_action_required"] as const;
const admissions = ["public", "auth_entry", "authenticated_root", "ui_action_required"] as const;

const adapterFromStored = (row: Record_): SiteSensorHtmlAdapter => ({
  adapter_revision: str(row.adapter_revision),
  origin_sha256: str(row.origin_sha256),
  injection_offset: num(row.injection_offset, 0),
});

const sensorFromStored = (row: Record_): SiteSensorHtml => {
  const additional = Array.isArray(row.additional_adapters)
    ? row.additional_adapters.filter(isRecord).map(adapterFromStored)
    : [];
  return {
    ...adapterFromStored(row),
    ...(additional.length > 0 ? { additional_adapters: additional } : {}),
  };
};

const bindingFromStored = (row: Record_): SiteAuthBinding => ({
  success_status: num(row.success_status, 0),
  principal_pointer: str(row.principal_pointer),
  authorization_context_pointer: str(row.authorization_context_pointer),
  bearer_pointer: str(row.bearer_pointer),
  credential_ttl_seconds: num(row.credential_ttl_seconds, 0),
  session_ttl_seconds: num(row.session_ttl_seconds, 0),
});

const pageFromStored = (row: Record_): SitePageActions => ({
  mapping_revision: str(row.mapping_revision),
  max_active_pages: num(row.max_active_pages, 0),
});

const issuedFromStored = (row: Record_): SiteIssuedBy => ({
  page_operation_id: str(row.page_operation_id),
  ttl_seconds: num(row.ttl_seconds, 0),
});

const grantFromStored = (row: Record_): SiteResourceGrant => ({
  success_status: num(row.success_status, 0),
  items_pointer: str(row.items_pointer),
  resource_pointer: str(row.resource_pointer),
  action_ref_field: str(row.action_ref_field),
  target_operation_id: str(row.target_operation_id),
  target_mapping_revision: str(row.target_mapping_revision),
  ttl_seconds: num(row.ttl_seconds, 0),
  max_items: num(row.max_items, 0),
  max_active_grants: num(row.max_active_grants, 0),
});

const paginationFromStored = (row: Record_): SiteQueryPagination => ({
  parameters: Array.isArray(row.parameters)
    ? row.parameters.filter(isRecord).map((parameter) => ({
        name: str(parameter.name),
        kind: oneOf(parameter.kind, ["page", "page_size", "offset"] as const, "page"),
        ...(typeof parameter.max_value === "number" ? { max_value: parameter.max_value } : {}),
      }))
    : [],
});

/**
 * The provenance-flow blocks of a stored route, in the server's order and only when present, so
 * the approval explanation and diffs of a revision see exactly what the server compares.
 */
function flowFromStored(row: Record_): Partial<SiteRouteConfig> {
  const {
    auth_binding,
    auth_revoke,
    sensor_html,
    page_actions,
    issued_by,
    resource_grant,
    query_pagination,
  } = row;
  return {
    ...(isRecord(auth_binding) ? { auth_binding: bindingFromStored(auth_binding) } : {}),
    ...(isRecord(auth_revoke)
      ? { auth_revoke: { success_status: num(auth_revoke.success_status, 0) } }
      : {}),
    ...(isRecord(sensor_html) ? { sensor_html: sensorFromStored(sensor_html) } : {}),
    ...(isRecord(page_actions) ? { page_actions: pageFromStored(page_actions) } : {}),
    ...(isRecord(issued_by) ? { issued_by: issuedFromStored(issued_by) } : {}),
    ...(isRecord(resource_grant) ? { resource_grant: grantFromStored(resource_grant) } : {}),
    ...(isRecord(query_pagination)
      ? { query_pagination: paginationFromStored(query_pagination) }
      : {}),
  };
}

function routeFromStored(value: unknown): SiteRouteConfig {
  const row = isRecord(value) ? value : {};
  return {
    operation_id: str(row.operation_id),
    method: oneOf(row.method, methods, "GET"),
    path: str(row.path),
    security_entry: oneOf(row.security_entry, admissions, "public"),
    source_action: strOrNull(row.source_action),
    resource_type: strOrNull(row.resource_type),
    view_profile: strOrNull(row.view_profile),
    resource_query_parameter: strOrNull(row.resource_query_parameter),
    resource_path_parameter: strOrNull(row.resource_path_parameter),
    request_crypto: isRecord(row.request_crypto) ? row.request_crypto : null,
    response_crypto: isRecord(row.response_crypto) ? row.response_crypto : null,
    response_mode: oneOf(row.response_mode, ["", "BUFFERED_JSON", "SENSOR_HTML"] as const, ""),
    max_response_bytes: num(row.max_response_bytes, 1_048_576),
    ...flowFromStored(row),
  };
}

function secretFromStored(value: unknown): SiteSecretReference {
  const row = isRecord(value) ? value : {};
  return {
    kind: oneOf(
      row.kind,
      ["tls", "session_hmac", "request_crypto", "response_crypto", "model"] as const,
      "tls",
    ),
    secret_ref: str(row.secret_ref),
    key_id: str(row.key_id),
    state: oneOf(
      row.state,
      ["active", "pending_rotation", "retired", "unavailable"] as const,
      "unavailable",
    ),
  };
}

/**
 * Reads the complete configuration a revision stores. Older revisions can lack fields
 * (`policy_revision` lives in its own column, the oldest rows have no policy at all), so every
 * gap is filled with the value the server would apply, the way `SiteConfig::from_stored` does.
 * Returns `null` when the value is not an object, so a diff is never drawn from garbage.
 */
export function configFromStored(
  value: unknown,
  policyRevision = "policy-v1",
): SiteConfigDraft | null {
  if (!isRecord(value)) return null;
  const defaults = defaultPolicy();
  const policy = isRecord(value.policy) ? value.policy : {};
  const identity = isRecord(policy.identity) ? policy.identity : {};
  const crypto = isRecord(policy.crypto) ? policy.crypto : {};
  const waf = isRecord(policy.waf) ? policy.waf : {};
  const limits = isRecord(policy.limits) ? policy.limits : {};
  const health = isRecord(policy.health_check) ? policy.health_check : {};
  return {
    display_name: str(value.display_name),
    public_origin: str(value.public_origin),
    upstream_address: str(value.upstream_address),
    upstream_server_name: str(value.upstream_server_name),
    upstream_tls: bool(value.upstream_tls),
    listen_port: num(value.listen_port, 0),
    entry_path: str(value.entry_path, "/"),
    security_entry: oneOf(value.security_entry, entries, "ui_action_required"),
    sensor_enabled: bool(value.sensor_enabled),
    policy_revision: str(value.policy_revision, policyRevision),
    status: oneOf(value.status, ["draft", "active", "paused"] as const, "draft"),
    policy: {
      routes: Array.isArray(policy.routes) ? policy.routes.map(routeFromStored) : [],
      identity: {
        enabled: bool(identity.enabled, defaults.identity.enabled),
        cookie_name: str(identity.cookie_name, defaults.identity.cookie_name),
        credential_header: str(identity.credential_header, defaults.identity.credential_header),
        profile: str(identity.profile, defaults.identity.profile),
        session_ttl_seconds: num(
          identity.session_ttl_seconds,
          defaults.identity.session_ttl_seconds,
        ),
        generation: num(identity.generation, defaults.identity.generation),
      },
      crypto: {
        adapter_revision: str(crypto.adapter_revision, defaults.crypto.adapter_revision),
        failure_strategy: str(crypto.failure_strategy, defaults.crypto.failure_strategy),
        protocol_version: strOrNull(crypto.protocol_version),
      },
      waf: {
        enabled: bool(waf.enabled, defaults.waf.enabled),
        blocked_headers: strings(waf.blocked_headers),
        blocked_query_fragments: strings(waf.blocked_query_fragments),
        max_cookie_bytes: num(waf.max_cookie_bytes, defaults.waf.max_cookie_bytes),
      },
      limits: {
        max_request_body_bytes: num(
          limits.max_request_body_bytes,
          defaults.limits.max_request_body_bytes,
        ),
        max_response_body_bytes: num(
          limits.max_response_body_bytes,
          defaults.limits.max_response_body_bytes,
        ),
        requests_per_second: num(limits.requests_per_second, defaults.limits.requests_per_second),
        burst: num(limits.burst, defaults.limits.burst),
      },
      health_check: {
        path: str(health.path, defaults.health_check.path),
        interval_seconds: num(health.interval_seconds, defaults.health_check.interval_seconds),
        timeout_ms: num(health.timeout_ms, defaults.health_check.timeout_ms),
        expected_status: num(health.expected_status, defaults.health_check.expected_status),
      },
      secret_refs: Array.isArray(policy.secret_refs)
        ? policy.secret_refs.map(secretFromStored)
        : [],
      static_asset_max_path_depth: num(
        policy.static_asset_max_path_depth,
        defaults.static_asset_max_path_depth,
      ),
      origin_object_access_enforced: bool(
        policy.origin_object_access_enforced,
        defaults.origin_object_access_enforced,
      ),
    },
  };
}

/**
 * Key order independent JSON, so two objects compare equal exactly when the server would. A
 * member whose value is `undefined` is left out, as `JSON.stringify` (and so the server) never
 * sees it: an optional flow block that was cleared and one that was never set are the same.
 */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const row = value as Record_;
    return `{${Object.keys(row)
      .filter((key) => row[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(row[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
