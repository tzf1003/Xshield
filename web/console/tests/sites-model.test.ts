import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteRouteConfig } from "../src/api.ts";
import {
  canonicalJson,
  configFromStored,
  defaultPolicy,
  draftFromConfig,
  effectivePolicy,
  emptyDraft,
  ENTRY_OPERATION_ID,
  newRoute,
  type SiteConfigDraft,
  withEntry,
} from "../src/sites/model/config.ts";
import { diffConfigs, groupChanges } from "../src/sites/model/diff.ts";
import { deriveLifecycle, edgeSummary } from "../src/sites/model/lifecycle.ts";
import { assessChangeRisk, explainApproval } from "../src/sites/model/risk.ts";
import { formatBytes, formatMillis, formatSeconds } from "../src/sites/model/units.ts";

function route(id: string, path: string, entry: SiteRouteConfig["security_entry"]) {
  return newRoute({
    operation_id: id,
    path,
    security_entry: entry,
    source_action: entry === "ui_action_required" ? `${id}.open` : null,
  });
}

/** The fixture of crates/xshield-core/src/site/risk.rs tests. */
function base(): SiteConfigDraft {
  return {
    ...emptyDraft(),
    display_name: "Demo",
    public_origin: "https://demo.example.test",
    upstream_address: "8.8.8.8:9000",
    upstream_server_name: "origin.example.test",
    upstream_tls: false,
    listen_port: 6100,
    status: "active",
    policy: {
      ...defaultPolicy(),
      routes: [route("home", "/", "ui_action_required"), route("docs", "/docs", "public")],
      secret_refs: [
        { kind: "tls", secret_ref: "secret://tls/demo", key_id: "tls-v1", state: "active" },
      ],
    },
  };
}

const edit = (mutate: (config: SiteConfigDraft) => void): SiteConfigDraft => {
  const copy = structuredClone(base());
  mutate(copy);
  return copy;
};

test("canonical JSON ignores key order and nothing else", () => {
  assert.equal(
    canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] }),
    canonicalJson({ a: [2, { c: 2, d: 1 }], b: 1 }),
  );
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  assert.notEqual(canonicalJson({ a: null }), canonicalJson({}));
});

test("a stored revision is read tolerantly and filled with the server's defaults", () => {
  const old = configFromStored(
    {
      display_name: "Old",
      public_origin: "https://old.example.test",
      upstream_address: "8.8.8.8:80",
      status: "active",
    },
    "policy-v9",
  );
  assert.ok(old);
  assert.equal(old.policy_revision, "policy-v9");
  assert.equal(old.policy.static_asset_max_path_depth, 5);
  assert.equal(old.policy.origin_object_access_enforced, false);
  assert.deepEqual(old.policy.routes, []);
  assert.equal(old.policy.limits.burst, 2000);
  assert.equal(configFromStored(null), null);
  assert.equal(configFromStored([1]), null);
  assert.equal(configFromStored("x"), null);
  // Garbage in a field falls back instead of poisoning a diff.
  const odd = configFromStored({ status: "weird", security_entry: 7, listen_port: "6100" });
  assert.equal(odd?.status, "draft");
  assert.equal(odd?.security_entry, "ui_action_required");
  assert.equal(odd?.listen_port, 0);
});

test("a server config becomes a draft without identity, digest or gateway projection", () => {
  const config = {
    ...base(),
    revision: 3,
    config_digest: "a".repeat(64),
    updated_by: "author",
    created_at: "x",
    updated_at: "y",
    gateway_config: { listen: "127.0.0.1:6100" },
  };
  const draft = draftFromConfig(config);
  assert.deepEqual(draft, base());
  draft.policy.routes.push(newRoute());
  assert.equal(config.policy.routes.length, 2, "the draft is a deep copy");
});

test("with no routes the entry fields are the route, as on the server", () => {
  const draft = { ...base(), policy: { ...base().policy, routes: [] } };
  const effective = effectivePolicy(draft);
  assert.equal(effective.routes.length, 1);
  assert.equal(effective.routes[0]?.operation_id, ENTRY_OPERATION_ID);
  assert.equal(effective.routes[0]?.source_action, "protected.entry");
  const open = effectivePolicy({ ...draft, security_entry: "public" });
  assert.equal(open.routes[0]?.source_action, null);
});

test("changing the entry fields moves the protected.entry route and only that one", () => {
  const draft = edit((c) => {
    c.policy.routes = [
      route(ENTRY_OPERATION_ID, "/", "ui_action_required"),
      route("docs", "/docs", "public"),
    ];
  });
  const moved = withEntry(draft, { entry_path: "/start", security_entry: "authenticated_root" });
  assert.equal(moved.entry_path, "/start");
  const entry = moved.policy.routes.find((item) => item.operation_id === ENTRY_OPERATION_ID);
  assert.deepEqual(
    [entry?.path, entry?.security_entry, entry?.source_action],
    ["/start", "authenticated_root", null],
  );
  assert.equal(moved.policy.routes.find((item) => item.operation_id === "docs")?.path, "/docs");
  const noEntryRoute = withEntry(base(), { entry_path: "/x" });
  assert.deepEqual(noEntryRoute.policy.routes, base().policy.routes);
});

// ---- approval risk: the scenarios of risk.rs, both directions ------------------------------

const triggers: [string, (c: SiteConfigDraft) => void, string[]][] = [
  [
    "upstream address",
    (c) => {
      c.upstream_address = "8.8.4.4:9000";
    },
    ["UPSTREAM_CHANGED"],
  ],
  [
    "upstream port",
    (c) => {
      c.upstream_address = "8.8.8.8:9001";
    },
    ["UPSTREAM_CHANGED"],
  ],
  [
    "upstream server name",
    (c) => {
      c.upstream_server_name = "other.example.test";
    },
    ["UPSTREAM_CHANGED"],
  ],
  [
    "upstream tls",
    (c) => {
      c.upstream_tls = true;
    },
    ["UPSTREAM_CHANGED"],
  ],
  [
    "public origin",
    (c) => {
      c.public_origin = "https://other.example.test";
    },
    ["ORIGIN_CHANGED"],
  ],
  [
    "listen port",
    (c) => {
      c.listen_port = 6101;
    },
    ["LISTEN_PORT_CHANGED"],
  ],
  [
    "entry path",
    (c) => {
      c.entry_path = "/start";
    },
    ["ENTRY_CHANGED"],
  ],
  [
    "security entry",
    (c) => {
      c.security_entry = "public";
    },
    ["ENTRY_CHANGED"],
  ],
  [
    "route added",
    (c) => {
      c.policy.routes.push(route("api", "/api", "public"));
    },
    ["ROUTES_CHANGED"],
  ],
  [
    "route downgraded",
    (c) => {
      c.policy.routes[0] = route("home", "/", "authenticated_root");
    },
    ["ROUTES_CHANGED"],
  ],
  [
    "route response size",
    (c) => {
      c.policy.routes[1] = { ...route("docs", "/docs", "public"), max_response_bytes: 2_097_152 };
    },
    ["ROUTES_CHANGED"],
  ],
  [
    "identity",
    (c) => {
      c.policy.identity.generation = 2;
    },
    ["IDENTITY_CHANGED"],
  ],
  [
    "crypto",
    (c) => {
      c.policy.crypto.failure_strategy = "observe";
    },
    ["CRYPTO_CHANGED"],
  ],
  [
    "waf fragments",
    (c) => {
      c.policy.waf.blocked_query_fragments = ["<script"];
    },
    ["WAF_CHANGED"],
  ],
  [
    "waf cookie cap",
    (c) => {
      c.policy.waf.max_cookie_bytes = 4096;
    },
    ["WAF_CHANGED"],
  ],
  [
    "limits raised",
    (c) => {
      c.policy.limits.requests_per_second = 50_000;
      c.policy.limits.burst = 100_000;
    },
    ["LIMITS_CHANGED"],
  ],
  [
    "health check",
    (c) => {
      c.policy.health_check.path = "/ready";
    },
    ["HEALTH_CHECK_CHANGED"],
  ],
  [
    "secret",
    (c) => {
      c.policy.secret_refs[0] = {
        kind: "tls",
        secret_ref: "secret://tls/demo",
        key_id: "tls-v2",
        state: "active",
      };
    },
    ["SECRET_REFS_CHANGED"],
  ],
  [
    "sensor",
    (c) => {
      c.sensor_enabled = true;
    },
    ["SENSOR_CHANGED"],
  ],
  [
    "static asset depth",
    (c) => {
      c.policy.static_asset_max_path_depth = 0;
    },
    ["STATIC_ASSET_POLICY_CHANGED"],
  ],
  [
    "object access",
    (c) => {
      c.policy.origin_object_access_enforced = true;
    },
    ["OBJECT_ACCESS_CHANGED"],
  ],
];

test("every approval trigger fires in both directions, with exactly its reason", () => {
  for (const [name, mutate, expected] of triggers) {
    const changed = edit(mutate);
    assert.notDeepEqual(changed, base(), `${name} must change the configuration`);
    assert.deepEqual(assessChangeRisk(base(), changed), expected, `${name}: forwards`);
    assert.deepEqual(assessChangeRisk(changed, base()), expected, `${name}: backwards`);
  }
});

test("cosmetic and order-only changes need no approval", () => {
  assert.deepEqual(assessChangeRisk(base(), base()), []);
  assert.deepEqual(
    assessChangeRisk(
      base(),
      edit((c) => {
        c.display_name = "Renamed";
        c.policy_revision = "policy-v2";
      }),
    ),
    [],
  );
  assert.deepEqual(
    assessChangeRisk(
      base(),
      edit((c) => {
        c.policy.routes.reverse();
      }),
    ),
    [],
  );
  const two = edit((c) => {
    c.policy.secret_refs.push({
      kind: "session_hmac",
      secret_ref: "secret://hmac/demo",
      key_id: "hmac-v1",
      state: "active",
    });
  });
  const reordered = structuredClone(two);
  reordered.policy.secret_refs.reverse();
  assert.deepEqual(assessChangeRisk(two, reordered), []);
  // Header order is not free: the server compares the list as written.
  const headers = edit((c) => {
    c.policy.waf.blocked_headers = ["A-One", "B-Two"];
  });
  assert.deepEqual(
    assessChangeRisk(
      headers,
      edit((c) => {
        c.policy.waf.blocked_headers = ["B-Two", "A-One"];
      }),
    ),
    ["WAF_CHANGED"],
  );
});

test("the implicit entry route and its explicit spelling are the same configuration", () => {
  const implicit = edit((c) => {
    c.policy.routes = [];
  });
  const explicit = structuredClone(implicit);
  explicit.policy.routes = effectivePolicy(implicit).routes;
  assert.deepEqual(assessChangeRisk(implicit, explicit), []);
  assert.deepEqual(diffConfigs(implicit, explicit), []);
  const moved = { ...implicit, entry_path: "/start" };
  assert.deepEqual(assessChangeRisk(implicit, moved), ["ENTRY_CHANGED", "ROUTES_CHANGED"]);
});

test("going live always needs approval and taking a served site down does too", () => {
  const draft = edit((c) => {
    c.status = "draft";
  });
  const paused = edit((c) => {
    c.status = "paused";
  });
  assert.deepEqual(assessChangeRisk(null, base()), ["ACTIVATION"]);
  assert.deepEqual(assessChangeRisk(paused, base()), ["ACTIVATION"]);
  assert.deepEqual(assessChangeRisk(draft, base()), ["ACTIVATION"]);
  assert.deepEqual(assessChangeRisk(base(), paused), ["TAKEDOWN"]);
  assert.deepEqual(assessChangeRisk(base(), draft), ["TAKEDOWN"]);
  // Nothing is served on either side: not an exposure change.
  const edited = edit((c) => {
    c.status = "paused";
    c.upstream_address = "1.1.1.1:9000";
  });
  assert.deepEqual(assessChangeRisk(paused, edited), []);
  assert.deepEqual(assessChangeRisk(null, paused), []);
  assert.deepEqual(assessChangeRisk(null, draft), []);
  assert.deepEqual(assessChangeRisk(draft, paused), []);
});

test("the explanation groups field changes under the reason that needs approval", () => {
  const staged = edit((c) => {
    c.upstream_address = "8.8.4.4:9000";
    c.policy.limits.burst = 4000;
    c.display_name = "Renamed";
  });
  const explained = explainApproval(base(), staged);
  assert.equal(explained.required, true);
  assert.deepEqual(
    explained.reasons.map((reason) => reason.token),
    ["UPSTREAM_CHANGED", "LIMITS_CHANGED"],
  );
  assert.deepEqual(
    explained.reasons[0]?.changes.map((change) => change.label),
    ["源站地址"],
  );
  assert.deepEqual(
    explained.reasons[1]?.changes.map((change) => [change.label, change.before, change.after]),
    [["突发容量", "2000", "4000"]],
  );
  assert.deepEqual(
    explained.free.map((change) => change.label),
    ["站点名称"],
  );
  assert.match(explained.reasons[0]?.label ?? "", /上游/);
  const first = explainApproval(null, base());
  assert.deepEqual(
    first.reasons.map((reason) => reason.token),
    ["ACTIVATION"],
  );
  assert.equal(first.hasBaseline, false);
  assert.equal(explainApproval(base(), base()).required, false);
});

// ---- the field diff ------------------------------------------------------------------------

test("the diff speaks in operators' words with before and after", () => {
  const changes = diffConfigs(
    base(),
    edit((c) => {
      c.listen_port = 0;
      c.security_entry = "public";
      c.upstream_tls = true;
      c.policy.waf.blocked_headers = ["X-Debug", "X-Trace"];
      c.policy.limits.max_request_body_bytes = 2_097_152;
      c.policy.health_check.timeout_ms = 3000;
      c.policy.crypto.failure_strategy = "observe";
      c.policy.static_asset_max_path_depth = 0;
    }),
  );
  const by = Object.fromEntries(changes.map((change) => [change.id, change]));
  assert.deepEqual([by.listen_port?.before, by.listen_port?.after], ["6100", "自动分配"]);
  assert.deepEqual(
    [by.security_entry?.before, by.security_entry?.after],
    ["必须有界面操作来源", "公开"],
  );
  assert.deepEqual([by.upstream_tls?.before, by.upstream_tls?.after], ["停用", "启用"]);
  assert.equal(by["waf.blocked_headers"]?.before, "（空）");
  assert.equal(by["waf.blocked_headers"]?.after, "X-Debug、X-Trace");
  assert.deepEqual(
    [by["limits.max_request_body_bytes"]?.before, by["limits.max_request_body_bytes"]?.after],
    ["1 MiB", "2 MiB"],
  );
  assert.deepEqual(
    [by["health_check.timeout_ms"]?.before, by["health_check.timeout_ms"]?.after],
    ["2 秒", "3 秒"],
  );
  assert.deepEqual(
    [by["crypto.failure_strategy"]?.before, by["crypto.failure_strategy"]?.after],
    ["严格拒绝", "仅观察"],
  );
  assert.deepEqual(
    [by.static_asset_max_path_depth?.before, by.static_asset_max_path_depth?.after],
    ["5", "关闭"],
  );
  assert.equal(by.display_name, undefined);
  assert.equal(groupChanges(changes).get("network")?.length, 2);
});

test("routes are matched by operation, so order is silent and edits are field level", () => {
  assert.deepEqual(
    diffConfigs(
      base(),
      edit((c) => {
        c.policy.routes.reverse();
      }),
    ),
    [],
  );
  const changes = diffConfigs(
    base(),
    edit((c) => {
      c.policy.routes[1] = {
        ...route("docs", "/documents", "public"),
        max_response_bytes: 2_097_152,
      };
      c.policy.routes.push(route("api", "/api", "authenticated_root"));
      c.policy.routes.splice(0, 1);
    }),
  );
  assert.deepEqual(
    changes.map((change) => [change.kind, change.label]),
    [
      ["changed", "路由 docs · 路径"],
      ["changed", "路由 docs · 响应上限"],
      ["added", "路由 api"],
      ["removed", "路由 home"],
    ],
  );
  assert.ok(
    changes.every((change) => change.risk === "ROUTES_CHANGED" && change.group === "routes"),
  );
});

test("a crypto change the summary cannot show is still shown, as JSON", () => {
  const withCrypto = (expires: number) =>
    edit((c) => {
      c.policy.routes[1] = {
        ...route("docs", "/docs", "public"),
        method: "POST",
        request_crypto: {
          mode: "DIRECT_DECRYPT",
          adapter_revision: "a1",
          key_id: "k1",
          key_expires_at: expires,
        },
      };
    });
  const changes = diffConfigs(withCrypto(100), withCrypto(200));
  assert.equal(changes.length, 1);
  assert.match(changes[0]?.before ?? "", /"key_expires_at":100/);
  assert.match(changes[0]?.after ?? "", /"key_expires_at":200/);
});

test("secret references are matched by use and never show a secret value", () => {
  const changes = diffConfigs(
    base(),
    edit((c) => {
      c.policy.secret_refs = [
        {
          kind: "tls",
          secret_ref: "secret://tls/demo",
          key_id: "tls-v2",
          state: "pending_rotation",
        },
        { kind: "model", secret_ref: "secret://model/demo", key_id: "m1", state: "active" },
      ];
    }),
  );
  assert.deepEqual(
    changes.map((change) => [change.group, change.kind, change.label]),
    [
      ["crypto", "changed", "密钥引用 TLS · Key ID"],
      ["crypto", "changed", "密钥引用 TLS · 状态"],
      ["crypto", "added", "密钥引用 模型"],
    ],
  );
  assert.ok(changes.every((change) => change.risk === "SECRET_REFS_CHANGED"));
});

test("a status change is activation or takedown only when serving changes", () => {
  const status = (from: SiteConfigDraft["status"], to: SiteConfigDraft["status"]) =>
    diffConfigs(
      edit((c) => {
        c.status = from;
      }),
      edit((c) => {
        c.status = to;
      }),
    ).find((change) => change.id === "status")?.risk;
  assert.equal(status("draft", "active"), "ACTIVATION");
  assert.equal(status("paused", "active"), "ACTIVATION");
  assert.equal(status("active", "paused"), "TAKEDOWN");
  assert.equal(status("active", "draft"), "TAKEDOWN");
  assert.equal(status("draft", "paused"), null);
});

test("units read the way operators say them", () => {
  assert.equal(formatBytes(1_048_576), "1 MiB");
  assert.equal(formatBytes(16_777_216), "16 MiB");
  assert.equal(formatBytes(8192), "8 KiB");
  assert.equal(formatBytes(1500), "1,500 字节");
  assert.equal(formatSeconds(3600), "1 小时");
  assert.equal(formatSeconds(86_400), "1 天");
  assert.equal(formatSeconds(90), "90 秒");
  assert.equal(formatSeconds(120), "2 分钟");
  assert.equal(formatMillis(2000), "2 秒");
  assert.equal(formatMillis(1500), "1500 毫秒");
});

// ---- lifecycle ----------------------------------------------------------------------------

const input = (over: Partial<Parameters<typeof deriveLifecycle>[0]> = {}) => ({
  apply_state: "active" as const,
  requires_approval: false,
  status: "active" as const,
  reason_code: "EDGE_APPLY_CONFIRMED",
  desired_revision: 3,
  active_revision: 3,
  ...over,
});
const statuses = (lifecycle: ReturnType<typeof deriveLifecycle>) =>
  lifecycle.steps.map((step) => step.status);
const titles = (lifecycle: ReturnType<typeof deriveLifecycle>) =>
  lifecycle.steps.map((step) => step.title);

test("the five lifecycle steps follow the server's state", () => {
  const draft = deriveLifecycle(
    input({ apply_state: "pending", status: "draft", active_revision: null, desired_revision: 1 }),
  );
  assert.equal(draft.state, "draft");
  assert.deepEqual(titles(draft), ["草稿", "已校验", "待审批", "应用中", "已生效"]);
  assert.deepEqual(statuses(draft), ["process", "wait", "wait", "wait", "wait"]);

  const awaiting = deriveLifecycle(
    input({
      apply_state: "pending",
      requires_approval: true,
      desired_revision: 5,
      active_revision: 4,
      reason_code: "CONTROL_SITE_APPROVAL_REQUIRED",
    }),
  );
  assert.equal(awaiting.state, "awaiting_approval");
  assert.deepEqual(statuses(awaiting), ["finish", "finish", "process", "wait", "wait"]);
  assert.match(awaiting.edgeSummary, /edge 正在服务 r4；暂存的 r5 尚未生效/);

  const applying = deriveLifecycle(
    input({
      apply_state: "pending",
      reason_code: "EDGE_APPLY_NOT_CONFIRMED",
      desired_revision: 4,
      active_revision: 3,
    }),
  );
  assert.deepEqual(statuses(applying), ["finish", "finish", "finish", "process", "wait"]);

  const live = deriveLifecycle(input());
  assert.deepEqual(statuses(live), ["finish", "finish", "finish", "finish", "finish"]);
  assert.match(live.edgeSummary, /与最新修订一致/);

  const paused = deriveLifecycle(input({ apply_state: "paused", status: "paused" }));
  assert.equal(paused.steps[4]?.title, "已暂停");
  assert.deepEqual(statuses(paused), ["finish", "finish", "finish", "finish", "finish"]);

  const unread = deriveLifecycle(
    input({
      apply_state: null,
      requires_approval: null,
      status: null,
      desired_revision: null,
      active_revision: null,
    }),
  );
  assert.equal(unread.state, null);
  assert.deepEqual(statuses(unread), ["wait", "wait", "wait", "wait", "wait"]);
});

test("a failure stops at the step that failed and says why", () => {
  const edge = deriveLifecycle(
    input({
      apply_state: "failed",
      reason_code: "EDGE_UNAVAILABLE",
      desired_revision: 4,
      active_revision: 3,
    }),
  );
  assert.equal(edge.state, "failed");
  assert.deepEqual(statuses(edge), ["finish", "finish", "finish", "error", "wait"]);
  assert.equal(edge.failure?.at, "applying");
  assert.match(edge.failure?.text ?? "", /连不上 edge/);
  assert.match(edge.failure?.action ?? "", /检查 edge/);
  assert.equal(edge.steps[3]?.note, edge.failure?.text);

  const invalid = deriveLifecycle(
    input({ apply_state: "failed", reason_code: "CONTROL_SITE_POLICY_INVALID" }),
  );
  assert.deepEqual(statuses(invalid), ["finish", "error", "wait", "wait", "wait"]);
  assert.equal(invalid.failure?.at, "validated");
});

test("the edge summary names what is served and what is staged", () => {
  assert.equal(
    edgeSummary({ desired_revision: 1, active_revision: null }),
    "edge 目前没有服务该站点；暂存的是 r1。",
  );
  assert.equal(
    edgeSummary({ desired_revision: 2, active_revision: 2 }),
    "edge 正在服务 r2，与最新修订一致。",
  );
  assert.equal(
    edgeSummary({ desired_revision: null, active_revision: null }),
    "尚未读取到修订信息。",
  );
});
