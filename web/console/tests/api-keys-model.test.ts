import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import {
  buildKeyRequest,
  canIssueAnything,
  capabilityCatalog,
  displayNameProblem,
  EXPIRY_MARGIN_MS,
  EXPIRY_MAX_MS,
  expiryInstant,
  issuerGaps,
  type KeyDraft,
  keyStatus,
  type ScopeRow,
  scopeProblems,
  scopeSummary,
  subjectProblem,
  TENANT_WIDE,
} from "../src/operations/api-keys.ts";
import { KeySecretStore } from "../src/operations/key-secret.ts";

const NOW = Date.parse("2026-10-05T08:00:00Z");
const DAY = 24 * 60 * 60 * 1000;
const TOKEN = "synthetic-observer-token-for-browser-tests-000000000000";
const KEY_ID = "key_018f2a3b-4c5d-7000-8000-000000000051";
const REQUEST_ID = "req_018f2a3b-4c5d-7000-8000-000000000001";

const row = (overrides: Partial<ScopeRow>): ScopeRow => ({
  id: "r1",
  target: "site",
  siteId: "site_alpha",
  capabilities: ["site.read"],
  ...overrides,
});

test("the capability catalogue mirrors the server's capabilities and issuer roles", () => {
  const core = readFileSync(
    new URL("../../../crates/xshield-core/src/admin.rs", import.meta.url),
    "utf8",
  );
  const names = [...core.matchAll(/Self::\w+ => "(site\.[a-z_.]+)"/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(names)].sort(), capabilityCatalog.map((info) => info.name).sort());
  const authz = readFileSync(
    new URL("../../../crates/xshield-control/src/api_key_authz.rs", import.meta.url),
    "utf8",
  );
  const body = authz.slice(authz.indexOf("pub(crate) fn issuer_roles"));
  const role = (name: string) =>
    name.replace(/[A-Z]/g, (letter, at) =>
      at === 0 ? letter.toLowerCase() : `_${letter.toLowerCase()}`,
    );
  const expect: Record<string, string[]> = {
    "site.read": ["SystemAdmin", "Observer"],
    "site.health.read": ["Observer"],
    "site.create": ["SystemAdmin"],
    "site.config.write": ["SystemAdmin"],
    "site.config.validate": ["PolicyAuthor"],
    "site.config.apply_direct": ["ReleaseOperator", "PolicyApprover"],
    "site.rollback": ["ReleaseOperator"],
  };
  for (const info of capabilityCatalog) {
    assert.deepEqual(
      [...info.issuerRoles].sort(),
      (expect[info.name] ?? []).map(role).sort(),
      info.name,
    );
    for (const name of expect[info.name] ?? []) {
      assert.ok(body.includes(`ManagementRole::${name}`), `${name} in issuer_roles`);
    }
    assert.equal(info.tenantWide, info.name === "site.create");
    assert.match(info.description, /[一-鿿]/);
  }
});

test("subjects and names follow the server's rules, never normalized", () => {
  assert.equal(subjectProblem("agent-deploy.bot@ci/1"), null);
  assert.match(subjectProblem("") ?? "", /填写/);
  assert.match(subjectProblem("-agent") ?? "", /字母或数字开头/);
  assert.match(subjectProblem("agent bot") ?? "", /ASCII/);
  assert.match(subjectProblem("代理") ?? "", /字母或数字开头/);
  assert.match(subjectProblem("a".repeat(129)) ?? "", /128/);
  assert.equal(displayNameProblem("部署机器人 #1"), null);
  assert.match(displayNameProblem(" 部署") ?? "", /首尾/);
  assert.match(displayNameProblem("部​署") ?? "", /零宽/);
  assert.match(displayNameProblem("a‮b") ?? "", /零宽|双向/);
  assert.match(displayNameProblem("a\nb") ?? "", /控制/);
  assert.equal(displayNameProblem("名".repeat(128)), null);
  assert.match(displayNameProblem("名".repeat(129)) ?? "", /128/);
});

test("expiry presets stay inside the server's 90 days; custom values are checked", () => {
  assert.equal(expiryInstant({ kind: "preset", days: 7 }, NOW).ms, NOW + 7 * DAY);
  assert.equal(
    expiryInstant({ kind: "preset", days: 90 }, NOW).ms,
    NOW + EXPIRY_MAX_MS - EXPIRY_MARGIN_MS,
  );
  const local = (ms: number) => {
    const date = new Date(ms);
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  };
  assert.equal(expiryInstant({ kind: "custom", local: local(NOW + 3 * DAY) }, NOW).problem, null);
  assert.match(expiryInstant({ kind: "custom", local: "" }, NOW).problem ?? "", /选择/);
  assert.match(
    expiryInstant({ kind: "custom", local: local(NOW + 60_000) }, NOW).problem ?? "",
    /10 分钟/,
  );
  assert.match(
    expiryInstant({ kind: "custom", local: local(NOW + 91 * DAY) }, NOW).problem ?? "",
    /90 天/,
  );
  assert.match(expiryInstant({ kind: "custom", local: "soon" }, NOW).problem ?? "", /识别/);
});

test("scope rows: site.create only on the tenant row, which carries nothing else", () => {
  assert.equal(scopeProblems([row({})]).rows.size, 0);
  assert.deepEqual(scopeProblems([]).overall, ["至少添加一行范围"]);
  const check = (input: ScopeRow) => scopeProblems([input]).rows.get(input.id) ?? [];
  assert.match(check(row({ capabilities: ["site.create"] })).join(), /只能授予“整个租户”/);
  assert.match(check(row({ capabilities: [] })).join(), /至少勾选/);
  assert.match(check(row({ siteId: "" })).join(), /选择或输入站点/);
  assert.match(check(row({ siteId: TENANT_WIDE })).join(), /保留标记/);
  assert.match(check(row({ siteId: "site/alpha" })).join(), /字母、数字/);
  assert.equal(
    check(row({ target: "tenant", siteId: "", capabilities: ["site.create"] })).length,
    0,
  );
  assert.match(
    check(row({ target: "tenant", capabilities: ["site.create", "site.read"] })).join(),
    /只能授予“创建站点”/,
  );
  assert.match(check(row({ target: "tenant", capabilities: [] })).join(), /勾选“创建站点”/);
  const twice = scopeProblems([row({ id: "a" }), row({ id: "b" })]);
  assert.match((twice.rows.get("a") ?? []).join(), /同一站点只需要一行/);
  const many = Array.from({ length: 33 }, (_, index) =>
    row({ id: `r${index}`, siteId: `s${index}` }),
  );
  assert.match(scopeProblems(many).overall.join(), /最多 32 行/);
});

test("issuer gaps name the missing roles; a pure KeyAdministrator can issue nothing", () => {
  const rows = [
    row({ capabilities: ["site.read", "site.config.apply_direct"] }),
    row({ id: "t", target: "tenant", siteId: "", capabilities: ["site.create"] }),
  ];
  assert.deepEqual(issuerGaps(rows, ["system_admin", "observer"]), [
    { capability: "site.config.apply_direct", missing: ["release_operator", "policy_approver"] },
  ]);
  assert.deepEqual(issuerGaps(rows, null), []);
  assert.equal(canIssueAnything(["key_administrator"]), false);
  assert.equal(canIssueAnything(["key_administrator", "observer"]), true);
  assert.equal(canIssueAnything(["system_admin"]), true);
  assert.equal(canIssueAnything(null), true);
});

test("the request is built once, exactly as the server takes it", () => {
  const draft: KeyDraft = {
    displayName: "部署机器人",
    subject: "agent-deploy",
    expiry: { kind: "preset", days: 30 },
    scopes: [
      row({ capabilities: ["site.config.write", "site.read"] }),
      row({ id: "t", target: "tenant", siteId: "", capabilities: ["site.create"] }),
    ],
  };
  const built = buildKeyRequest(draft, "tenant_demo", NOW);
  assert.ok(built.ok);
  assert.deepEqual(built.request, {
    subject: "agent-deploy",
    display_name: "部署机器人",
    expires_at: new Date(NOW + 30 * DAY).toISOString(),
    scopes: [
      {
        tenant_id: "tenant_demo",
        site_id: "site_alpha",
        capabilities: ["site.read", "site.config.write"],
      },
      { tenant_id: "tenant_demo", site_id: TENANT_WIDE, capabilities: ["site.create"] },
    ],
  });
  const bad = buildKeyRequest({ ...draft, subject: " x", scopes: [] }, "tenant_demo", NOW);
  assert.equal(bad.ok, false);
  if (!bad.ok) {
    assert.ok(bad.subject);
    assert.deepEqual(bad.scopes.overall, ["至少添加一行范围"]);
  }
});

test("status and scope summary", () => {
  const future = new Date(NOW + DAY).toISOString();
  const past = new Date(NOW - 1).toISOString();
  assert.equal(keyStatus({ status: "active", expires_at: future }, NOW), "active");
  assert.equal(keyStatus({ status: "active", expires_at: past }, NOW), "expired");
  assert.equal(keyStatus({ status: "revoked", expires_at: future }, NOW), "revoked");
  assert.deepEqual(
    scopeSummary([
      { site_id: "site_alpha", capabilities: ["site.read", "site.config.apply_direct"] },
      { site_id: TENANT_WIDE, capabilities: ["site.create"] },
    ]),
    ["site_alpha：读取站点、直接应用", "整个租户：创建站点"],
  );
});

test("a secret lives in its store until acknowledged, and a session end drops everything", () => {
  const store = new KeySecretStore();
  const issued = {
    epoch: 3,
    kind: "created" as const,
    apiKeyId: KEY_ID,
    replaced: null,
    displayName: "部署机器人",
    subject: "agent-deploy",
    keyPrefix: "xsk_0123abcd",
    expiresAt: new Date(NOW + DAY).toISOString(),
    scopes: [{ site_id: "site_alpha", capabilities: ["site.read"] }],
    secret: `xsk_0123abcd${"0".repeat(40)}`,
  };
  store.put(issued);
  assert.equal(store.getSnapshot().pending.length, 1);
  store.acknowledge(KEY_ID);
  assert.equal(store.getSnapshot().pending.length, 0);
  assert.equal(JSON.stringify(store.getSnapshot().pending).includes("xsk_0123abcd0"), false);
  // The non-secret scopes are kept to label the row.
  assert.deepEqual(store.getSnapshot().scopes.get(KEY_ID), issued.scopes);
  store.put(issued);
  store.clear();
  assert.equal(store.getSnapshot().pending.length, 0);
  assert.equal(store.getSnapshot().scopes.size, 0);
});

const reply = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });

test("the client reads key metadata strictly and sends rotate and revoke to fixed paths", async (t) => {
  const key = {
    api_key_id: KEY_ID,
    tenant_id: "tenant_demo",
    subject: "agent-deploy",
    display_name: "部署机器人",
    key_prefix: "xsk_0123abcd",
    status: "active",
    expires_at: "2026-11-04T08:00:00+00:00",
    created_at: "2026-10-05T08:00:00+00:00",
    last_used_at: null,
  };
  const calls: { path: string; method: string; body: string | null; key: string | null }[] = [];
  let next: Response = reply({ request_id: REQUEST_ID, keys: [key] });
  t.mock.method(globalThis, "fetch", async (path: string, init: RequestInit) => {
    const headers = new Headers(init.headers);
    calls.push({
      path,
      method: String(init.method),
      body: typeof init.body === "string" ? init.body : null,
      key: headers.get("Idempotency-Key"),
    });
    return next;
  });
  const client = new ControlClient(TOKEN);
  const list = await client.managementApiKeys();
  assert.equal(list.request_id, REQUEST_ID);
  assert.equal(list.keys[0]?.status, "active");
  for (const bad of [
    { request_id: REQUEST_ID, keys: [{ ...key, status: "disabled" }] },
    { request_id: REQUEST_ID, keys: [{ ...key, fingerprint: "00" }] },
    { request_id: REQUEST_ID, keys: [key], extra: true },
    { request_id: REQUEST_ID, keys: [{ ...key, key_prefix: "pk_1234" }] },
  ]) {
    next = reply(bad);
    await assert.rejects(client.managementApiKeys(), (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, "INVALID_RESPONSE");
      return true;
    });
  }
  const body = {
    subject: "agent-deploy",
    display_name: "部署机器人",
    expires_at: "2026-11-04T08:00:00.000Z",
    scopes: [{ tenant_id: "tenant_demo", site_id: "site_alpha", capabilities: ["site.read"] }],
  };
  const issued = {
    request_id: REQUEST_ID,
    api_key_id: "key_018f2a3b-4c5d-7000-8000-000000000052",
    api_key: `xsk_0123abcd${"f".repeat(40)}`,
    key_prefix: "xsk_0123abcd",
    expires_at: "2026-11-04T08:00:00Z",
    scopes: body.scopes,
  };
  next = reply(issued, 201);
  const rotated = await client.rotateManagementApiKey(KEY_ID, body, "rotate-key-0000000001");
  assert.equal(rotated.api_key_id, issued.api_key_id);
  assert.deepEqual(calls.at(-1), {
    path: `/control/v1/agent-api-keys/${KEY_ID}/rotate`,
    method: "POST",
    body: JSON.stringify(body),
    key: "rotate-key-0000000001",
  });
  // A plaintext that does not start with its prefix is not a key of this reply.
  next = reply({ ...issued, api_key: `xsk_ffffffff${"0".repeat(40)}` }, 201);
  await assert.rejects(client.createManagementApiKey(body, "create-key-0000000001"));
  next = reply({ request_id: REQUEST_ID, api_key_id: KEY_ID, status: "revoked" });
  const revoked = await client.revokeManagementApiKey(KEY_ID, "revoke-key-0000000001");
  assert.equal(revoked.status, "revoked");
  assert.equal(calls.at(-1)?.path, `/control/v1/agent-api-keys/${KEY_ID}/revoke`);
  // The reply must name the key that was revoked.
  next = reply({
    request_id: REQUEST_ID,
    api_key_id: "key_018f2a3b-4c5d-7000-8000-000000000099",
    status: "revoked",
  });
  await assert.rejects(client.revokeManagementApiKey(KEY_ID, "revoke-key-0000000002"));
  // Malformed key IDs never reach the network.
  const before = calls.length;
  await assert.rejects(client.revokeManagementApiKey("key_../x", "revoke-key-0000000003"));
  await assert.rejects(client.rotateManagementApiKey("../sites", body, "rotate-key-0000000004"));
  assert.equal(calls.length, before);
});
