import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyInput } from "../src/lib/palette.ts";

const SITES = ["emr", "juice"];
const ID = "req_01a19741107477ff9224781077354552";

function labels(input: string): string[] {
  return classifyInput(input, SITES).flatMap((group) => group.items.map((item) => item.label));
}

test("one pasted request id opens that request first", () => {
  const groups = classifyInput(`see ${ID}`, SITES);
  assert.equal(groups[0]?.items[0]?.action.kind, "route");
  const first = groups[0]?.items[0];
  assert.ok(first && first.action.kind === "route" && first.action.to === `/requests/${ID}`);
});

test("two or more request ids become a batch lookup", () => {
  const other = "req_01a197410a1b2c3d4e5f60718293a4b5";
  assert.deepEqual(labels(`${ID} ${other}`), ["批量对照 2 个请求 ID"]);
});

test("a sixteen-digit hex string opens a session", () => {
  assert.ok(labels("7c1e9a40d2b35f61").includes("打开会话 7c1e9a40"));
});

test("a path offers a filter and a prefix filter", () => {
  assert.deepEqual(labels("/rest/basket/6"), ["筛选路径 /rest/basket/6", "筛选路径前缀 /rest/basket/6*"]);
});

test("a site name offers the site and its tabs", () => {
  assert.ok(labels("emr").includes("打开站点 emr"));
  assert.ok(labels("emr").includes("打开 emr 的站点配置"));
});

test("a condition with an error is shown disabled with the reason", () => {
  const groups = classifyInput("outcome:bogus", SITES);
  const item = groups.find((group) => group.title === "条件")?.items[0];
  assert.ok(item?.disabled);
});

test("plain words match commands", () => {
  assert.ok(labels("主题").includes("切换主题"));
  assert.ok(labels("导入").includes("导入判定日志"));
});
