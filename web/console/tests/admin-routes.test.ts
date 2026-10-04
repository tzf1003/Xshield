import assert from "node:assert/strict";
import { test } from "node:test";
import { routeQueryKind, routeTarget, siteRoute, siteSections } from "../src/admin-routes.ts";
test("admin routes preserve exact pages and reject malformed deep links", () => {
  for (const [section] of siteSections) {
    assert.deepEqual(siteRoute("/sites/site_a/" + section), { siteId: "site_a", section, creating: false });
  }
  assert.equal(siteRoute("/sites/new/network")?.creating, true);
  assert.equal(routeQueryKind("/investigation/grants"), "grant");
  assert.equal(routeQueryKind("/investigation/bindings"), "binding");
  assert.equal(routeQueryKind("/investigation/agents"), "agent");
  assert.equal(routeQueryKind("/operations/jobs"), "jobs");
  const id = "req_018f2a3b-4c5d-7000-8000-000000000001";
  assert.equal(routeTarget("/investigation/requests/" + id, "request"), id);
  for (const path of ["/sites/a/unknown", "/sites/%2f/network", "/sites/a/network/extra", "/investigation/models-extra", "/investigation/requests/" + id + "/suffix", "/constructor", "/unknown"]) {
    assert.equal(routeQueryKind(path), "not-found", path);
  }
});
