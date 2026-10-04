import assert from "node:assert/strict";
import { test } from "node:test";
import { emptyDraft, ENTRY_OPERATION_ID } from "../src/sites/model/config.ts";
import {
  applyRouteTemplate,
  routeTemplates,
  spaTemplate,
} from "../src/sites/model/route-templates.ts";
import { validateDraft, validateRoute, validateRouteSet } from "../src/sites/model/validation.ts";

const filled = () => ({
  ...emptyDraft(),
  display_name: "Demo",
  public_origin: "https://demo.example.com",
  upstream_address: "8.8.8.8:443",
  upstream_server_name: "origin.example.com",
});

test("every template is valid by the server's own route rules", () => {
  for (const template of routeTemplates) {
    const routes = template.build({ entry_path: "/", security_entry: "ui_action_required" });
    assert.ok(routes.length > 0 && routes.length <= 256, template.id);
    const limits = emptyDraft().policy.limits;
    for (const route of routes) {
      assert.deepEqual(validateRoute(route, limits), [], `${template.id}: ${route.operation_id}`);
    }
    assert.equal(validateRouteSet(routes).size, 0, template.id);
    assert.deepEqual(validateDraft(applyRouteTemplate(filled(), template)), [], template.id);
  }
});

test("the template's entry route is the draft's entry route, whatever its path and admission", () => {
  for (const [path, entry] of [
    ["/", "ui_action_required"],
    ["/app", "authenticated_root"],
    ["/start", "public"],
  ] as const) {
    const applied = applyRouteTemplate(
      { ...filled(), entry_path: path, security_entry: entry },
      spaTemplate,
    );
    const first = applied.policy.routes[0];
    assert.equal(first?.operation_id, ENTRY_OPERATION_ID);
    assert.equal(first?.path, path);
    assert.equal(first?.security_entry, entry);
    assert.equal(first?.source_action, entry === "ui_action_required" ? "protected.entry" : null);
    assert.deepEqual(validateDraft(applied), []);
  }
});

test("a template says it is an example, and applying it never touches anything but the routes", () => {
  assert.match(spaTemplate.description, /示例/);
  assert.match(spaTemplate.description, /不是推荐/);
  const before = filled();
  const applied = applyRouteTemplate(before, spaTemplate);
  assert.deepEqual(
    { ...applied, policy: { ...applied.policy, routes: [] } },
    { ...before, policy: { ...before.policy, routes: [] } },
  );
  assert.equal(before.policy.routes.length, 0, "the input is not mutated");
});
