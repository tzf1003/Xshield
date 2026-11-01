import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteSpec } from "../src/api/types.ts";
import { lineDiff, semanticChanges } from "../src/lib/diff.ts";
import { parseSiteText, specToYaml } from "../src/lib/yaml.ts";
import { shapeIssues, validateSpec, validOrigin } from "../src/lib/site-validate.ts";
import { csvCell, csvLine, tsvCell } from "../src/lib/csv.ts";

const base: SiteSpec = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { header: "Authorization" },
  entries: ["/login", "/api/home"],
  bypass: ["/static/*"],
  mode: "enforce",
  on_jev_unavailable: "deny",
  advanced: { jev_timeout_ms: 3000, secret_fields: ["idcard", "ssn"] },
};

test("a configuration round-trips through YAML without losing a field", () => {
  const parsed = parseSiteText(specToYaml(base));
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.deepEqual(parsed.value, base);
});

test("JSON configurations are read too, and unknown fields are refused", () => {
  const json = JSON.stringify({ ...base, advanced: undefined });
  assert.equal(parseSiteText(json).ok, true);
  const bad = parseSiteText(
    "name: emr\nhosts: [a.example.com]\norigin: http://10.0.0.5:8080\nsession:\n  cookie: SID\nentries: [/login]\nflavour: red\n",
  );
  assert.equal(bad.ok, false);
  if (!bad.ok) assert.match(bad.message, /未知字段 flavour/);
  const nested = parseSiteText(
    "name: emr\nhosts: [a.example.com]\norigin: http://10.0.0.5:8080\nsession:\n  cookie: SID\nentries: [/login]\nadvanced:\n  jev_timeout: 3\n",
  );
  assert.equal(nested.ok, false);
});

test("a YAML syntax error reports its line", () => {
  const parsed = parseSiteText("name: emr\nentries: [/login\n");
  assert.equal(parsed.ok, false);
  if (!parsed.ok) assert.ok(parsed.line !== null);
});

test("line diff marks removed and added lines in order", () => {
  const ops = lineDiff("a\nb\nc", "a\nc\nd");
  assert.deepEqual(ops, [
    { op: "eq", text: "a" },
    { op: "del", text: "b" },
    { op: "eq", text: "c" },
    { op: "add", text: "d" },
  ]);
});

test("semantic changes describe what changed in plain words", () => {
  const after: SiteSpec = {
    ...base,
    entries: ["/login", "/api/home", "/rest/admin/application-configuration"],
    advanced: { jev_timeout_ms: 2000, secret_fields: ["idcard", "ssn", "phone"] },
  };
  assert.deepEqual(semanticChanges(base, after), [
    "入口 ＋1：/rest/admin/application-configuration",
    "Jev 超时 3000 ms → 2000 ms",
    "追加脱敏词 ＋phone",
  ]);
  assert.deepEqual(semanticChanges(null, base), ["创建站点"]);
  assert.deepEqual(semanticChanges(base, base), []);
});

test("origins and rules are validated like the gateway does", () => {
  assert.equal(validOrigin("http://10.0.0.5:8080"), true);
  assert.equal(validOrigin("https://app.example.com"), true);
  assert.equal(validOrigin("http://app.example.com/path"), false);
  assert.equal(validOrigin("ftp://app.example.com"), false);
  assert.deepEqual(validateSpec(base).errors, []);
  const broken = validateSpec({ ...base, origin: "http://a/b", entries: [] });
  assert.ok(broken.errors.some((issue) => issue.field === "origin"));
  assert.ok(broken.errors.some((issue) => issue.field === "entries"));
});

test("advanced parameters are checked against their documented ranges", () => {
  const issues = validateSpec({
    ...base,
    advanced: {
      jev_timeout_ms: 50,
      allow_cache_minutes: 61,
      secret_fields: ["password", "ab"],
      synonyms: [["payment", "payment"]],
    },
  }).errors;
  const messages = issues.map((issue) => issue.message);
  assert.ok(messages.includes("Jev 超时需在 100–30000 ms 之间"));
  assert.ok(messages.includes("放行缓存时长需在 0–60 分钟之间"));
  assert.ok(messages.some((message) => message.includes("“password” 与内置词或已有词重复")));
  assert.ok(messages.some((message) => message.includes("“payment ↔ payment” 两个词不能相同")));
});

test("an object word as a secret field is a warning, not an error", () => {
  const result = validateSpec({ ...base, advanced: { secret_fields: ["card"] } });
  assert.deepEqual(result.errors, []);
  assert.equal(
    result.warnings[0]?.message,
    "“card” 会让 cardId 这类对象引用也被脱敏，Jev 无法判断越权",
  );
});

test("CSV and TSV cells never start with a formula character", () => {
  assert.equal(csvCell("=HYPERLINK(1)"), "'=HYPERLINK(1)");
  assert.equal(csvCell("a,b"), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvLine(["x", 1, null]), "x,1,");
  assert.equal(tsvCell("a\tb\nc"), "a b c");
  assert.equal(tsvCell("+1"), "'+1");
});

const HEAD = [
  "name: emr",
  "hosts:",
  "  - emr.example.com",
  "origin: http://10.0.0.5:8080",
  "session:",
  "  header: Authorization",
  "entries:",
  "  - /login",
  "",
].join("\n");

test("a well-formed configuration has no type errors, and the YAML head parses", () => {
  assert.deepEqual(shapeIssues(base), []);
  assert.equal(parseSiteText(HEAD).ok, true);
});

test("a field of the wrong type, or written with no value, is an error that names the field and its line", () => {
  const cases: Array<[label: string, text: string, line: number | null, message: RegExp]> = [
    ["a number as the name", HEAD.replace("name: emr", "name: 123"), 1, /纯数字的值要加引号/],
    [
      "hosts written with no value",
      HEAD.replace("hosts:\n  - emr.example.com", "hosts:"),
      2,
      /hosts 写了键却没有值/,
    ],
    [
      "hosts written as one text",
      HEAD.replace("  - emr.example.com", "  emr.example.com").replace(
        "hosts:",
        "hosts: emr.example.com",
      ),
      2,
      /hosts 要写成文本列表/,
    ],
    [
      "a nested list inside hosts",
      HEAD.replace("  - emr.example.com", "  - [a]"),
      2,
      /hosts 的每一项要写成文本/,
    ],
    [
      "a number inside entries",
      HEAD.replace("  - /login", "  - 5"),
      7,
      /entries 的每一项要写成文本，纯数字/,
    ],
    [
      "a number as the cookie name",
      HEAD.replace("header: Authorization", "cookie: 123"),
      6,
      /cookie 要写成文本，纯数字/,
    ],
    [
      "a required field left out",
      HEAD.replace("origin: http://10.0.0.5:8080\n", ""),
      null,
      /缺少必填字段 origin/,
    ],
    ["bypass written with no value", `${HEAD}bypass:\n`, 9, /bypass 写了键却没有值/],
    [
      "a synonym that is not a pair",
      `${HEAD}advanced:\n  synonyms:\n    - [payment]\n`,
      10,
      /synonyms 要写成两个词一组/,
    ],
    [
      "a number parameter written as text",
      `${HEAD}advanced:\n  jev_timeout_ms: "3000"\n`,
      10,
      /jev_timeout_ms 要写成数字/,
    ],
  ];
  for (const [label, text, line, message] of cases) {
    const parsed = parseSiteText(text);
    assert.equal(parsed.ok, false, label);
    if (!parsed.ok) {
      assert.equal(parsed.line, line, label);
      assert.match(parsed.message, message, label);
    }
  }
});

test("an empty advanced group or parameter is its default, not an error", () => {
  const parsed = parseSiteText(`${HEAD}advanced:\n  jev_timeout_ms:\n  secret_fields:\n`);
  assert.equal(parsed.ok, true);
  if (parsed.ok) assert.equal(parsed.value.advanced, undefined);
  const bare = parseSiteText(`${HEAD}advanced:\n`);
  assert.equal(bare.ok, true);
});

test("JSON configurations get the same type checks", () => {
  const parsed = parseSiteText(JSON.stringify({ ...base, name: null }));
  assert.equal(parsed.ok, false);
  if (!parsed.ok) assert.match(parsed.message, /name 写了键却没有值/);
});

test("validateSpec never throws, and a value of the wrong type is never judged valid", () => {
  const wrong: unknown[] = [
    undefined,
    null,
    5,
    "emr",
    [],
    {},
    { name: 1, hosts: "emr.example.com", origin: null, session: null, entries: 5 },
    { ...base, hosts: [[1]] },
    { ...base, entries: [5] },
    { ...base, session: { cookie: 123 } },
    { ...base, advanced: { jev_timeout_ms: "3000" } },
    { ...base, advanced: { synonyms: [["payment"]] } },
    { ...base, bypass: null },
  ];
  for (const input of wrong) {
    const result = validateSpec(input);
    assert.ok(result.errors.length > 0, JSON.stringify(input));
  }
});
