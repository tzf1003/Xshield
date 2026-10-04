import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteListItem } from "../src/api.ts";
import { siteAccess } from "../src/sites/access.ts";
import {
  dedupeSites,
  filterSites,
  listItemState,
  matchesSearch,
  revisionsText,
  summarize,
} from "../src/sites/list-model.ts";

function site(id: string, overrides: Partial<SiteListItem> = {}): SiteListItem {
  return {
    site_id: id,
    display_name: `站点 ${id}`,
    public_origin: `https://${id}.example.test`,
    listen_port: 6100,
    security_entry: "ui_action_required",
    sensor_enabled: false,
    policy_revision: "policy-v1",
    status: "active",
    revision: 1,
    config_digest: "a".repeat(64),
    updated_by: "author@example.test",
    updated_at: "2026-09-20T08:10:30.000Z",
    desired_revision: 1,
    active_revision: 1,
    apply_id: "apply_1",
    apply_state: "active",
    reason_code: "EDGE_APPLY_CONFIRMED",
    requires_approval: false,
    ...overrides,
  };
}

const rows = [
  site("alpha"),
  site("beta", { apply_state: "pending", requires_approval: true, desired_revision: 3 }),
  site("gamma", { apply_state: "failed", reason_code: "EDGE_UNAVAILABLE" }),
  site("delta", { status: "draft", apply_state: "pending", active_revision: null }),
  site("epsilon", { status: "paused", apply_state: "paused" }),
  site("zeta", { apply_state: "pending" }),
];

test("each row gets the one-word state operators read", () => {
  assert.deepEqual(rows.map(listItemState), [
    "active",
    "awaiting_approval",
    "failed",
    "draft",
    "paused",
    "pending",
  ]);
});

test("the summary counts only the rows that are loaded", () => {
  const summary = summarize(rows);
  assert.equal(summary.total, 6);
  assert.deepEqual(summary.counts, {
    active: 1,
    awaiting_approval: 1,
    failed: 1,
    draft: 1,
    paused: 1,
    pending: 1,
  });
  assert.equal(summarize([]).total, 0);
});

test("search needs every term and looks at name, ID, origin, author and policy label", () => {
  const named = site("a1", { display_name: "官网 Alpha" });
  assert.equal(matchesSearch(named, ""), true);
  assert.equal(matchesSearch(named, "  "), true);
  assert.equal(matchesSearch(named, "官网"), true);
  assert.equal(matchesSearch(named, "ALPHA"), true);
  assert.equal(matchesSearch(named, "a1.example"), true);
  assert.equal(matchesSearch(named, "官网 beta"), false);
  assert.equal(matchesSearch(named, "author@"), true);
  assert.equal(matchesSearch(named, "policy-v1"), true);
});

test("filters combine search with the status chip", () => {
  assert.deepEqual(
    filterSites(rows, "", "awaiting_approval").map((item) => item.site_id),
    ["beta"],
  );
  assert.deepEqual(
    filterSites(rows, "gamma", "all").map((item) => item.site_id),
    ["gamma"],
  );
  assert.deepEqual(filterSites(rows, "gamma", "active"), []);
  assert.equal(filterSites(rows, "", "all").length, 6);
});

test("pages that overlap do not list a site twice", () => {
  assert.deepEqual(
    dedupeSites([site("a"), site("b"), site("a", { display_name: "changed" })]).map(
      (item) => item.site_id,
    ),
    ["a", "b"],
  );
});

test("revisions read desired and active, with a dash for a site that was never served", () => {
  assert.equal(
    revisionsText(site("a", { desired_revision: 3, active_revision: 2 })),
    "desired r3 · active r2",
  );
  assert.equal(
    revisionsText(site("a", { desired_revision: 1, active_revision: null })),
    "desired r1 · active —",
  );
});

test("role access offers what the previous pages offered", () => {
  const admin = siteAccess(["system_admin"]);
  assert.equal(admin.canConfigure, true);
  assert.equal(admin.canObserve, false);
  assert.equal(admin.canRelease, false);
  const observer = siteAccess(["observer"]);
  assert.deepEqual(
    [observer.canConfigure, observer.canObserve, observer.canRelease],
    [false, true, false],
  );
  assert.equal(siteAccess(["policy_author"]).canValidate, true);
  assert.equal(siteAccess(["policy_author"]).canApprove, false);
  assert.equal(siteAccess(["policy_approver"]).canApprove, true);
  assert.equal(siteAccess(["release_operator"]).canApply, true);
  assert.equal(siteAccess(["investigator"]).canRelease, false);
  const machine = siteAccess(null);
  assert.equal(machine.machine, true);
  assert.deepEqual(
    [
      machine.canConfigure,
      machine.canObserve,
      machine.canValidate,
      machine.canApprove,
      machine.canApply,
    ],
    [true, true, true, true, true],
  );
});
