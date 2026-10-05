import assert from "node:assert/strict";
import { test } from "node:test";
import { routeQueryKind } from "../src/admin-routes.ts";
import {
  activeItem,
  breadcrumbs,
  flattenNav,
  isVisible,
  legacyKinds,
  navCatalog,
  pageMeta,
  siteEntries,
  visibleNav,
} from "../src/shell/nav-model.ts";
import {
  fuzzyScore,
  normalizePaste,
  paletteSearch,
  recognise,
} from "../src/shell/palette-classifier.ts";
import { isPaletteShortcut } from "../src/shell/shortcut.ts";

const uuid = (n: number) => `018f2a3b-4c5d-7000-8000-${String(n).padStart(12, "0")}`;
const ids = {
  req: `req_${uuid(1)}`,
  mdl: `mdl_${uuid(2)}`,
  agt: `agt_${uuid(3)}`,
  grant: `grant_${uuid(4)}`,
  auth: `auth_${uuid(5)}`,
  calr: `calr_${uuid(6)}`,
  case: `case_${uuid(7)}`,
  access: `access_${uuid(8)}`,
  export: `export_${uuid(9)}`,
  job: `job_${uuid(10)}`,
  artifact: `artifact_${uuid(11)}`,
  ev: `ev_${uuid(12)}`,
  trace: "018f2a3b4c5d70008000000000000003",
};
const all = ["observer", "investigator", "audit_administrator", "system_admin"];
const labels = (roles: string[] | null, siteId: string | null = "site_demo") =>
  flattenNav(visibleNav(roles, siteId)).map((entry) => entry.label);

test("navigation is regrouped into the console sections; cases and approvals replace four pages", () => {
  assert.deepEqual(
    navCatalog.map((group) => group.label),
    ["工作台", "站点", "流量与调查", "案件与审批", "运维与治理"],
  );
  assert.deepEqual(
    flattenNav(navCatalog).map((entry) => [entry.label, entry.href]),
    [
      ["概览", "/"],
      ["受保护站点", "/sites"],
      ["请求调查", "/investigation/requests"],
      ["结构化检索", "/investigation/search"],
      ["资格与身份账本", "/investigation/grants"],
      ["身份绑定", "/investigation/bindings"],
      ["模型调用列表", "/investigation/models"],
      ["模型调用详情", "/investigation/models/lookup"],
      ["Agent 运行", "/investigation/agents"],
      ["案件工作台", "/cases"],
      ["审批中心", "/approvals"],
      ["运行状态", "/operations/jobs"],
      ["审计发布状态", "/operations/audit"],
      ["校准报告", "/investigation/calibration"],
      ["API Key", "/admin/api-keys"],
      ["权限中心", "/access/session"],
    ],
  );
  // Every entry is a page the router can resolve.
  for (const entry of flattenNav(navCatalog)) {
    assert.notEqual(routeQueryKind(entry.href), "not-found", entry.href);
  }
});

test("role visibility matches the previous shell for every role", () => {
  assert.deepEqual(labels(["observer"]), [
    "概览",
    "站点状态",
    "请求调查",
    "资格与身份账本",
    "身份绑定",
    "模型调用列表",
    "模型调用详情",
    "Agent 运行",
    "权限中心",
  ]);
  assert.deepEqual(labels(["investigator"]), [
    "概览",
    "请求调查",
    "结构化检索",
    "资格与身份账本",
    "身份绑定",
    "案件工作台",
    "审批中心",
    "运行状态",
    "权限中心",
  ]);
  assert.deepEqual(labels(["system_admin"]), ["概览", "受保护站点", "API Key", "权限中心"]);
  for (const role of ["policy_author", "release_operator"]) {
    assert.deepEqual(labels([role]), ["概览", "站点发布", "权限中心"], role);
  }
  // A policy approver also finds site revisions awaiting a decision in the approval center.
  assert.deepEqual(labels(["policy_approver"]), ["概览", "站点发布", "审批中心", "权限中心"]);
  for (const role of ["sensitive_evidence_reader", "sensitive_evidence_approver"]) {
    assert.deepEqual(labels([role]), ["概览", "审批中心", "权限中心"], role);
  }
  // Holds moved into the case detail: the audit role reaches them through the case center.
  assert.deepEqual(labels(["audit_administrator"]), [
    "概览",
    "案件工作台",
    "审计发布状态",
    "校准报告",
    "权限中心",
  ]);
  assert.deepEqual(labels(["key_administrator"]), ["概览", "API Key", "权限中心"]);
  assert.deepEqual(labels([]), ["概览", "权限中心"]);
});

test("per-site entries appear only for non-admins, scoped to the session site", () => {
  assert.deepEqual(
    siteEntries(["observer", "policy_author"], "site_demo").map((entry) => [
      entry.label,
      entry.href,
    ]),
    [
      ["站点状态", "/sites/site_demo/overview"],
      ["站点发布", "/sites/site_demo/releases"],
    ],
  );
  assert.deepEqual(siteEntries(["system_admin", "observer"], "site_demo"), []);
  assert.deepEqual(siteEntries(["observer"], null), []);
  assert.deepEqual(siteEntries(null, "site_demo"), [], "machine login has no per-site shortcuts");
  assert.deepEqual(siteEntries(["investigator"], "site_demo"), []);
});

test("machine login (null roles) offers everything; empty requirements are public", () => {
  assert.equal(isVisible(null, ["system_admin"]), true);
  assert.equal(isVisible([], ["system_admin"]), false);
  assert.equal(isVisible([], []), true);
  assert.equal(flattenNav(visibleNav(null, null)).length, flattenNav(navCatalog).length);
});

test("the longest matching entry is current, including ID forms and sub-routes", () => {
  const items = flattenNav(visibleNav(all, "site_demo"));
  const key = (path: string) => activeItem(path, items)?.href;
  assert.equal(key("/"), "/");
  assert.equal(key("/sites/site_a/network"), "/sites");
  assert.equal(key("/investigation/models/lookup"), "/investigation/models/lookup");
  assert.equal(key(`/investigation/models/${ids.mdl}`), "/investigation/models");
  assert.equal(key(`/investigation/requests/${ids.req}`), "/investigation/requests");
  assert.equal(key("/unknown"), undefined);
  const scoped = flattenNav(visibleNav(["observer"], "site_demo"));
  assert.equal(activeItem("/sites/site_demo/overview", scoped)?.label, "站点状态");
});

test("page titles, leads and breadcrumbs", () => {
  assert.equal(pageMeta("/").title, "运行概览");
  assert.equal(pageMeta("/access/session").title, "权限中心");
  assert.equal(pageMeta("/unknown").title, "页面不存在");
  assert.equal(pageMeta("/sites/new/network").kind, "site-config");
  assert.ok(pageMeta("/cases").lead.length > 0);
  const groups = visibleNav(all, "site_demo");
  assert.deepEqual(breadcrumbs("/", groups), [{ label: "运行概览" }]);
  assert.deepEqual(breadcrumbs("/cases", groups), [
    { label: "案件与审批" },
    { label: "案件工作台" },
  ]);
  assert.deepEqual(breadcrumbs("/sites/site_a/network", groups), [
    { label: "站点" },
    { label: "site_a", href: "/sites/site_a/overview" },
    { label: "网络" },
  ]);
  assert.deepEqual(breadcrumbs("/sites/new/network", groups)[1], { label: "新建站点" });
  assert.equal(legacyKinds.has("overview"), false);
  assert.equal(legacyKinds.has("session"), false);
  assert.equal(legacyKinds.has("request"), true);
});

test("IDs are recognised by prefix and exact canonical shape", () => {
  assert.equal(recognise(ids.req)?.noun, "请求 ID");
  assert.equal(recognise(ids.trace)?.noun, "Trace ID");
  for (const bad of [
    `req_${uuid(1).toUpperCase()}`,
    `req_${uuid(1)}x`,
    `req_${uuid(1)}\n`,
    `req_018f2a3b-4c5d-4000-8000-000000000001`,
    "req_123",
    ids.trace.toUpperCase(),
    `${ids.trace}0`,
    ids.trace.slice(1),
    "",
  ]) {
    assert.equal(recognise(bad), null, JSON.stringify(bad));
  }
  assert.equal(normalizePaste(`  "${ids.req}"  `), ids.req);
  assert.equal(normalizePaste(`\`${ids.req}\``), ids.req);
});

test("detail IDs open the existing detail routes", () => {
  const expected: [string, string][] = [
    [ids.req, `/investigation/requests/${ids.req}`],
    [ids.mdl, `/investigation/models/${ids.mdl}`],
    [ids.agt, `/investigation/agents/${ids.agt}`],
    [ids.grant, `/investigation/grants/${ids.grant}`],
    [ids.auth, `/investigation/bindings/${ids.auth}`],
    [ids.calr, `/investigation/calibration/${ids.calr}`],
  ];
  for (const [id, route] of expected) {
    const { results } = paletteSearch(id, null, null);
    assert.deepEqual(results[0]?.action, { type: "navigate", to: route }, id);
    assert.equal(results[0]?.group, "object");
    // The route must be one the router actually serves, with the matching detail kind.
    assert.notEqual(routeQueryKind(route), "not-found", route);
  }
});

test("search-capable IDs are offered as event-search presets, others open their owning page", () => {
  const preset = (id: string) =>
    paletteSearch(id, null, null)
      .results.filter((result) => result.action.type === "search")
      .map((result) => result.action);
  assert.deepEqual(preset(ids.trace), [
    { type: "search", preset: { kind: "trace_id", value: ids.trace } },
  ]);
  assert.deepEqual(preset(ids.job), [
    { type: "search", preset: { kind: "job_id", value: ids.job } },
  ]);
  assert.deepEqual(preset(ids.access), [
    { type: "search", preset: { kind: "evidence_access_request_id", value: ids.access } },
  ]);
  assert.deepEqual(preset(ids.ev), [
    { type: "search", preset: { kind: "event_id", value: ids.ev } },
    { type: "search", preset: { kind: "evidence_hold_id", value: ids.ev } },
  ]);
  const page = (id: string) =>
    paletteSearch(id, null, null)
      .results.filter((result) => result.action.type === "navigate")
      .map((result) => result.action);
  // A case opens its detail page; an access request or export opens the approval center with
  // that item selected (the item travels as the URL query, never spliced into the path).
  assert.deepEqual(page(ids.case), [{ type: "navigate", to: `/cases/${ids.case}` }]);
  assert.deepEqual(page(ids.access), [
    { type: "navigate", to: "/approvals", search: { item: ids.access } },
  ]);
  assert.deepEqual(page(ids.export), [
    { type: "navigate", to: "/approvals", search: { item: ids.export } },
  ]);
  // A job opens the small status dialog of the case center; evidence is reached through a case.
  assert.deepEqual(page(ids.job), [{ type: "navigate", to: `/cases/jobs/${ids.job}` }]);
  assert.deepEqual(page(ids.artifact), [{ type: "navigate", to: "/cases" }]);
  assert.ok(
    paletteSearch(ids.trace, null, null).results[0]?.label.startsWith("在事件检索中查找"),
    "the offered action is named as such",
  );
  assert.equal(preset(ids.case).length, 0, "no case_id preset exists");
});

test("the palette never offers what the roles hide", () => {
  const observer = ["observer"];
  assert.deepEqual(
    paletteSearch(ids.req, observer, "site_demo").results.map((result) => result.action),
    [{ type: "navigate", to: `/investigation/requests/${ids.req}` }],
  );
  // Search needs Investigator; an Observer gets a notice instead of a dead link.
  const blocked = paletteSearch(ids.trace, observer, "site_demo");
  assert.deepEqual(blocked.results, []);
  assert.match(blocked.notice ?? "", /看不到对应页面/);
  // Hold-ID search additionally needs the AuditAdministrator page.
  const investigator = paletteSearch(ids.ev, ["investigator"], null);
  assert.deepEqual(
    investigator.results.map((result) =>
      result.action.type === "search" ? result.action.preset.kind : "page",
    ),
    ["event_id"],
  );
  const both = paletteSearch(ids.ev, ["investigator", "audit_administrator"], null);
  assert.deepEqual(
    both.results.map((result) =>
      result.action.type === "search" ? result.action.preset.kind : "page",
    ),
    ["event_id", "evidence_hold_id"],
  );
  // Pages are filtered the same way.
  const pages = paletteSearch("", ["system_admin"], null).results.map((result) => result.label);
  assert.deepEqual(pages, ["概览", "受保护站点", "API Key", "权限中心"]);
  assert.deepEqual(paletteSearch("案件", ["observer"], null).results, []);
});

test("fuzzy page search ranks exact, prefix, substring and subsequence matches", () => {
  assert.equal(fuzzyScore("案件", "案件工作台") > fuzzyScore("工作", "案件工作台"), true);
  assert.equal(fuzzyScore("案件工作台", "案件工作台"), 100);
  assert.equal(fuzzyScore("xyz", "案件工作台"), 0);
  assert.ok(fuzzyScore("sjdc", "调查导出") === 0);
  assert.ok(fuzzyScore("ajt", "案件工作台") === 0, "latin letters do not match Chinese labels");
  assert.ok(fuzzyScore("案台", "案件工作台") > 0, "ordered subsequence matches");
  assert.ok(fuzzyScore("台案", "案件工作台") === 0, "order matters");
  const top = (query: string, roles: string[] | null = null) =>
    paletteSearch(query, roles, null).results[0]?.label;
  assert.equal(top("案件"), "案件工作台");
  assert.equal(top("audit"), "审计发布状态");
  assert.equal(top("search"), "结构化检索");
  assert.equal(top("api"), "API Key");
  assert.equal(top("权限"), "权限中心");
  assert.equal(top("审批"), "审批中心");
  // Exports are requested in a case and approved in the approval center: both are offered.
  assert.deepEqual(
    paletteSearch("导出", null, null)
      .results.map((result) => result.label)
      .sort(),
    ["审批中心", "案件工作台"].sort(),
  );
  assert.equal(paletteSearch("zzzz", null, null).results.length, 0);
});

test("malformed IDs get a notice and still fall through to page search", () => {
  const outcome = paletteSearch("req_123", null, null);
  assert.match(outcome.notice ?? "", /规范/);
  assert.ok(outcome.results.some((result) => result.label === "请求调查"));
  assert.equal(paletteSearch("case", null, null).notice, null);
});

test("the shortcut is Command/Ctrl+K without Alt or Shift", () => {
  const event = (init: Partial<Parameters<typeof isPaletteShortcut>[0]>) =>
    isPaletteShortcut({
      key: "k",
      metaKey: false,
      ctrlKey: false,
      altKey: false,
      shiftKey: false,
      ...init,
    });
  assert.equal(event({ metaKey: true }), true);
  assert.equal(event({ ctrlKey: true }), true);
  assert.equal(event({ ctrlKey: true, key: "K" }), true);
  assert.equal(event({}), false);
  assert.equal(event({ ctrlKey: true, shiftKey: true }), false);
  assert.equal(event({ ctrlKey: true, altKey: true }), false);
  assert.equal(event({ ctrlKey: true, key: "j" }), false);
});
