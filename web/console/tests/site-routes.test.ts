// The interface-name rules in a configuration (header-routes-design 2, 3): their shape, their checks, their YAML
// round trip, their merge on save, and how a change to them reads in the diff.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { RouteRule, SiteSpec } from "../src/api/types.ts";
import { normalizeSpec, rebaseSpec } from "../src/features/sites/spec-model.ts";
import { semanticChanges } from "../src/lib/diff.ts";
import { shapeIssues, validateSpec } from "../src/lib/site-validate.ts";
import { parseSiteText, specToYaml } from "../src/lib/yaml.ts";

const GATEWAY = "/weixin/wx/mp/wx361163d21a65f679/gateway";

const base: SiteSpec = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { header: "Authorization" },
  entries: ["/login"],
  bypass: ["/static/*"],
  mode: "observe",
  on_jev_unavailable: "deny",
};

function withRoutes(routes: unknown): SiteSpec {
  return { ...base, routes: routes as RouteRule[] };
}

/** The messages of the errors of a configuration, for the checks that name one message. */
function errorMessages(spec: SiteSpec): string[] {
  return validateSpec(spec).errors.map((issue) => issue.message);
}

test("接口名规则随 YAML 往返，路径和每一段的位置都保留", () => {
  const spec = withRoutes([
    {
      path: GATEWAY,
      name_from: [["header.X-Service-Id"], ["query.action", "body.action"]],
    },
  ]);
  const parsed = parseSiteText(specToYaml(spec));
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.deepEqual(parsed.value, spec);
});

test("没有接口名规则时，YAML 里不出现 routes 键", () => {
  assert.doesNotMatch(specToYaml(base), /^routes:/m);
});

test("接口名规则写成对象而不是列表时，表单检查指出 routes", () => {
  const issues = shapeIssues(withRoutes({ path: GATEWAY }));
  assert.ok(issues.some((issue) => issue.group === "routes" && issue.field === "routes"));
});

test("接口名规则的结构不对时，读取配置就报错，不会丢掉它", () => {
  const checked = normalizeSpec({ ...base, routes: { path: GATEWAY } });
  assert.deepEqual(checked, {
    ok: false,
    message: "接口名规则应写成列表，每条有 path 和 name_from",
  });
});

test("两条接口名规则的路径重叠时，后一条报错", () => {
  const spec = withRoutes([
    { path: GATEWAY, name_from: [["header.X-Service-Id"]] },
    { path: GATEWAY, name_from: [["header.X-Service-Method"]] },
  ]);
  const { errors } = validateSpec(spec);
  assert.ok(
    errors.some(
      (issue) => issue.field === "routes[1].path" && issue.message === "与第 1 条规则的路径重叠",
    ),
  );
});

test("前缀规则覆盖的精确路径，与它重叠", () => {
  const spec = withRoutes([
    { path: "/gw/*", name_from: [["header.X-Service-Id"]] },
    { path: "/gw/x", name_from: [["header.X-Service-Id"]] },
  ]);
  assert.ok(errorMessages(spec).includes("与第 1 条规则的路径重叠"));
});

test("位置只能是请求头、查询参数或正文字段，各自的名称也有规则", () => {
  const cases: Array<[string, string]> = [
    ["cookie.SID", "来源只能是请求头、查询参数或正文字段"],
    ["header.", "名称不能为空"],
    ["body.items[0].id", "正文字段不支持数组下标，批量调用按未知接口处理"],
    ["query.a/b", "参数名只能含字母、数字、. _ -，最长 64 个字符"],
    ["header.X/Id", "请求头名只能含 HTTP 头名的字符：字母、数字和 - _ . 等"],
  ];
  for (const [source, message] of cases) {
    const spec = withRoutes([{ path: GATEWAY, name_from: [[source]] }]);
    assert.ok(errorMessages(spec).includes(message), `${source} -> ${message}`);
  }
});

test("同一段里的重复位置报错，请求头名不分大小写", () => {
  const spec = withRoutes([{ path: GATEWAY, name_from: [["header.X-Id", "header.x-id"]] }]);
  assert.ok(errorMessages(spec).includes("第 1 段的位置不能重复"));
});

test("接口名最多 4 段，每段至少写一个位置", () => {
  const five = withRoutes([
    {
      path: GATEWAY,
      name_from: [["header.A"], ["header.B"], ["header.C"], ["header.D"], ["header.E"]],
    },
  ]);
  assert.ok(errorMessages(five).includes("接口名最多 4 段"));
  const empty = withRoutes([{ path: GATEWAY, name_from: [[]] }]);
  assert.ok(errorMessages(empty).includes("第 1 段至少写一个位置"));
});

test("入口的路径被接口名规则覆盖时，给出入口不再命中的警告，而不是保存错误", () => {
  const spec: SiteSpec = {
    ...withRoutes([{ path: GATEWAY, name_from: [["header.X-Service-Id"]] }]),
    entries: ["/login", GATEWAY],
  };
  const { errors, warnings } = validateSpec(spec);
  assert.deepEqual(errors, []);
  assert.ok(
    warnings.some(
      (issue) => issue.field === "entries[1]" && issue.message.startsWith("入口不再命中"),
    ),
  );
});

test("保存时合并接口名规则：别人新增的保留，自己新增的加上，删掉的去掉", () => {
  const kept = { path: "/a", name_from: [["header.X-A"]] };
  const removed = { path: "/b", name_from: [["header.X-B"]] };
  const mine = { path: "/c", name_from: [["header.X-C"]] };
  const theirs = { path: "/d", name_from: [["header.X-D"]] };
  const result = rebaseSpec(
    withRoutes([kept, removed]),
    withRoutes([kept, mine]),
    withRoutes([kept, removed, theirs]),
  );
  assert.deepEqual(result.spec.routes, [kept, theirs, mine]);
  assert.deepEqual(result.conflicts, []);
});

test("接口名规则的增删改在差异里各说一句话", () => {
  const before = withRoutes([{ path: GATEWAY, name_from: [["header.X-Service-Id"]] }]);
  const after = withRoutes([{ path: GATEWAY, name_from: [["header.X-Service-Method"]] }]);
  assert.deepEqual(semanticChanges(before, after), [`接口名规则 改动：${GATEWAY}`]);
  assert.deepEqual(semanticChanges(base, before), [`接口名规则 ＋1：${GATEWAY}`]);
  assert.deepEqual(semanticChanges(before, base), [`接口名规则 －1：${GATEWAY}`]);
});
