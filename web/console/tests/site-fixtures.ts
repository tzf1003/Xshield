import type { Page, Route } from "@playwright/test";
import { errorFixture, REQUEST_ID, TOKEN } from "./fixtures";

/** Synthetic site control API for the site workspace specs (wire contracts, not captured data). */
export const AT = "2026-09-20T08:10:30.000Z";
export const DIGEST = "b".repeat(64);

export const envelope = (siteId: string) => ({
  request_id: REQUEST_ID,
  tenant_id: "tenant_demo",
  site_id: siteId,
});

export type Route_ = {
  operation_id: string;
  method: string;
  path: string;
  security_entry: string;
  source_action: string | null;
  resource_type: string | null;
  view_profile: string | null;
  resource_query_parameter: string | null;
  resource_path_parameter: string | null;
  request_crypto: Record<string, unknown> | null;
  response_crypto: Record<string, unknown> | null;
  response_mode: string;
  max_response_bytes: number;
};

export function route(id: string, path: string, over: Partial<Route_> = {}): Route_ {
  return {
    operation_id: id,
    method: "GET",
    path,
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

export const entryRoute = () =>
  route("protected.entry", "/", {
    security_entry: "ui_action_required",
    source_action: "protected.entry",
  });

export function siteConfig(over: Record<string, unknown> = {}, routes?: Route_[]) {
  return {
    display_name: "Alpha 官网",
    public_origin: "https://www.example.test",
    upstream_address: "8.8.8.8:443",
    upstream_server_name: "origin.example.test",
    upstream_tls: true,
    listen_port: 6101,
    entry_path: "/",
    security_entry: "ui_action_required",
    sensor_enabled: false,
    policy_revision: "policy-v3",
    status: "active",
    policy: {
      routes: routes ?? [entryRoute(), route("docs", "/docs")],
      identity: {
        enabled: true,
        cookie_name: "__Host-xshield_sid",
        credential_header: "Authorization",
        profile: "default",
        session_ttl_seconds: 3600,
        generation: 2,
      },
      crypto: {
        adapter_revision: "observe-v1",
        failure_strategy: "fail_closed",
        protocol_version: null,
      },
      waf: {
        enabled: true,
        blocked_headers: ["X-Debug"],
        blocked_query_fragments: ["<script"],
        max_cookie_bytes: 8192,
      },
      limits: {
        max_request_body_bytes: 1_048_576,
        max_response_body_bytes: 16_777_216,
        requests_per_second: 1000,
        burst: 2000,
      },
      health_check: {
        path: "/health",
        interval_seconds: 15,
        timeout_ms: 2000,
        expected_status: 200,
      },
      secret_refs: [
        {
          kind: "session_hmac",
          secret_ref: "secret://sites/alpha/session",
          key_id: "k-2026-09",
          state: "active",
        },
      ],
      static_asset_max_path_depth: 5,
      origin_object_access_enforced: false,
    },
    ...over,
  };
}

export type SiteState = {
  desired_revision: number;
  active_revision: number | null;
  apply_state: "active" | "pending" | "failed" | "paused";
  requires_approval: boolean;
  reason_code: string;
};

export const ACTIVE: SiteState = {
  desired_revision: 3,
  active_revision: 3,
  apply_state: "active",
  requires_approval: false,
  reason_code: "EDGE_APPLY_CONFIRMED",
};

export function configBody(id: string, config: Record<string, unknown>, state: SiteState = ACTIVE) {
  return {
    ...envelope(id),
    found: true,
    ...state,
    apply_id: "apply_fixture",
    config_digest: DIGEST,
    config: {
      ...config,
      revision: state.desired_revision,
      config_digest: DIGEST,
      updated_by: "author@example.test",
      created_at: AT,
      updated_at: AT,
      gateway_config: {},
    },
  };
}

export const applyBody = (id: string, state: SiteState) => ({
  ...envelope(id),
  listen_port: 6101,
  desired_revision: state.desired_revision,
  active_revision: state.active_revision,
  config_digest: DIGEST,
  apply_state: state.apply_state,
  apply_id: "apply_fixture",
  reason_code: state.reason_code,
  requires_approval: state.requires_approval,
});

export type StoredRevision = {
  revision: number;
  config: Record<string, unknown>;
  by?: string;
  digest?: string;
};

export const revisionsBody = (id: string, items: StoredRevision[]) => ({
  ...envelope(id),
  revisions: items.map((item) => ({
    revision: item.revision,
    policy_revision: String(
      (item.config as { policy_revision?: string }).policy_revision ?? "policy-v1",
    ),
    config_digest:
      item.digest ??
      String(item.revision)
        .padStart(64, "a")
        .slice(-64)
        .replace(/[^0-9a-f]/g, "a"),
    config: item.config,
    created_by: item.by ?? "author@example.test",
    created_at: AT,
  })),
});

export type Write = {
  method: string;
  path: string;
  body: string | null;
  key: string | null;
  digest: string | null;
};

export type SiteMock = {
  id: string;
  config: Record<string, unknown>;
  state: SiteState;
  revisions: StoredRevision[];
  writes: Write[];
  /** Overrides a single request; return true when handled. */
  intercept?: (route: Route, url: URL) => Promise<boolean>;
  calls: string[];
};

/** Routes every control call of one site; PUT echoes the posted configuration back as saved. */
export async function mockSite(page: Page, init: Partial<SiteMock> = {}): Promise<SiteMock> {
  const mock: SiteMock = {
    id: "site_alpha",
    config: siteConfig(),
    state: ACTIVE,
    revisions: [],
    writes: [],
    calls: [],
    ...init,
  };
  await page.route("**/control/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    mock.calls.push(`${request.method()} ${path}`);
    if (await mock.intercept?.(route, url)) return;
    const parts = path.split("/");
    const tail = parts.at(-1) ?? "";
    if (path === "/control/v1/sites" && request.method() === "POST") {
      mock.writes.push({
        method: "POST",
        path,
        body: request.postData(),
        key: await request.headerValue("idempotency-key"),
        digest: null,
      });
      const { site_id: createdId, ...created } = request.postDataJSON() as {
        site_id: string;
      } & Record<string, unknown>;
      mock.id = createdId;
      mock.config = {
        ...created,
        listen_port: created.listen_port === 0 ? 6102 : created.listen_port,
      };
      mock.state = {
        desired_revision: 1,
        active_revision: null,
        apply_state: "pending",
        requires_approval: created.status === "active",
        reason_code:
          created.status === "draft"
            ? "CONTROL_SITE_DRAFT_NOT_APPLICABLE"
            : "CONTROL_SITE_APPROVAL_REQUIRED",
      };
      await route.fulfill({ status: 201, json: configBody(createdId, mock.config, mock.state) });
      return;
    }
    if (path === "/control/v1/sites") {
      await route.fulfill({
        json: { ...envelope("site_demo"), sites: [], truncated: false, next_cursor: null },
      });
      return;
    }
    if (request.method() !== "GET") {
      mock.writes.push({
        method: request.method(),
        path,
        body: request.postData(),
        key: await request.headerValue("idempotency-key"),
        digest: await request.headerValue("x-xshield-expected-config-digest"),
      });
    }
    if (tail === "config" && request.method() === "PUT") {
      const posted = request.postDataJSON() as Record<string, unknown>;
      mock.config = {
        ...posted,
        listen_port: posted.listen_port === 0 ? 6102 : posted.listen_port,
      };
      mock.state = { ...mock.state, desired_revision: mock.state.desired_revision + 1 };
      await route.fulfill({ json: configBody(mock.id, mock.config, mock.state) });
    } else if (tail === "config") {
      await route.fulfill({ json: configBody(mock.id, mock.config, mock.state) });
    } else if (tail === "revisions") {
      // As on the server, the staged revision's digest is the one the status reports.
      const stored = mock.revisions.map((item) =>
        item.revision === mock.state.desired_revision && item.digest === undefined
          ? { ...item, digest: DIGEST }
          : item,
      );
      await route.fulfill({ json: revisionsBody(mock.id, stored) });
    } else if (tail === "status") {
      await route.fulfill({ json: applyBody(mock.id, mock.state) });
    } else if (tail === "health") {
      await route.fulfill({
        json: {
          ...applyBody(mock.id, mock.state),
          edge_health: {
            edge_state: "healthy",
            upstream_state: "degraded",
            audit_state: "healthy",
          },
        },
      });
    } else if (tail === "validate") {
      await route.fulfill({
        json: {
          ...envelope(mock.id),
          revision: mock.state.desired_revision,
          config_digest: DIGEST,
          valid: true,
          reason_code: "CONTROL_SITE_VALIDATED",
        },
      });
    } else if (["apply", "approve", "rollback"].includes(tail)) {
      await route.fulfill({ json: applyBody(mock.id, mock.state) });
    } else {
      await route.fulfill({ status: 404, json: errorFixture("CONTROL_SITE_NOT_FOUND") });
    }
  });
  return mock;
}

export async function signInAt(page: Page, path: string) {
  await page.goto(path);
  await page.getByLabel("管理凭证", { exact: true }).fill(TOKEN);
  await page.getByRole("button", { name: "连接", exact: true }).click();
}

export const sectionLink = (page: Page, name: string) =>
  page.getByRole("navigation", { name: "站点运营导航" }).getByRole("link", { name, exact: true });
