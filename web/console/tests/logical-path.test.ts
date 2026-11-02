import assert from "node:assert/strict";
import { test } from "node:test";
import type { RouteRule } from "../src/api/types.ts";
import {
  BODY_PARSE_LIMIT,
  isSensitiveHeader,
  latestNamed,
  logicalPath,
  type LogicalRequest,
  MASK,
  maskRequestText,
  nameAfter,
  parseRawRequest,
  type RecentRow,
  recentPaths,
  ruleCovers,
  testRequest,
  typedUnderRule,
  unknownCount,
} from "../src/lib/logical-path.ts";
import cases from "./fixtures/logical-path-cases.json" with { type: "json" };
import consoleCases from "./fixtures/logical-path-console-cases.json" with { type: "json" };

// The shared cases (logical-path-cases.json): the same file is run against the gateway's implementation. The console's
// own cases (logical-path-console-cases.json) are the ones the rule tester shows, and only the console runs them. A case
// whose name carries [body-too-large] has its body omitted from the file; the run sends a body over the parse limit.
const TOO_LARGE_FLAG = "[body-too-large]";

function bigBody(): string {
  return `{"method":"${"a".repeat(BODY_PARSE_LIMIT)}"}`;
}

/** A header pair from the JSON file: `[name, value]`. */
function header(pair: readonly string[]): [string, string] {
  const [name = "", value = ""] = pair;
  return [name, value];
}

type CaseFile = {
  name: string;
  routes: RouteRule[];
  request: {
    path: string;
    query: string | null;
    content_type: string | null;
    headers: string[][];
    body: string | null;
    /** The gateway did not read this body (it was over the parse limit): the run sends one that is. */
    body_unread?: boolean;
  };
  expect: unknown;
};

function runCase(item: CaseFile): void {
  const { body_unread: unread, body: text, ...rest } = item.request;
  const body = unread === true || item.name.includes(TOO_LARGE_FLAG) ? bigBody() : text;
  const request: LogicalRequest = {
    ...rest,
    headers: rest.headers.map(header),
    body,
  };
  assert.deepEqual(logicalPath(item.routes, request), item.expect);
}

for (const item of cases.cases) test(`shared case: ${item.name}`, () => runCase(item));
for (const item of consoleCases.cases) test(`console case: ${item.name}`, () => runCase(item));

const GATEWAY: RouteRule = {
  path: "/weixin/wx/mp/wx361163d21a65f679/gateway",
  name_from: [["header.X-Service-Id"], ["header.X-Service-Method"]],
};

function requestAt(path: string, extra: Partial<LogicalRequest> = {}): LogicalRequest {
  return { path, query: null, content_type: null, headers: [], body: null, ...extra };
}

test("一条规则的路径不匹配时，请求的逻辑路径不变", () => {
  const routes: RouteRule[] = [GATEWAY];
  assert.deepEqual(logicalPath(routes, requestAt("/weixin/wx/mp/other")), {
    logical_path: "/weixin/wx/mp/other",
    api: null,
  });
});

test("规则路径不合法时跳过它，不因此放宽或收紧其他规则", () => {
  const routes: RouteRule[] = [{ path: "rest/x", name_from: [["header.X-Op"]] }];
  assert.deepEqual(logicalPath(routes, requestAt("/rest/x", { headers: [["X-Op", "a"]] })), {
    logical_path: "/rest/x",
    api: null,
  });
});

test("不需要正文字段时不读取正文，超过解析上限的正文不影响请求头来源的接口名", () => {
  const routes: RouteRule[] = [{ path: "/api/up", name_from: [["header.X-Op"]] }];
  const request = requestAt("/api/up", {
    content_type: "text/plain",
    headers: [["X-Op", "upload"]],
    body: "x".repeat(BODY_PARSE_LIMIT + 1),
  });
  assert.deepEqual(logicalPath(routes, request), {
    logical_path: "/api/up/upload",
    api: { name: "upload", from: ["header.X-Op"] },
  });
});

test("同一段里的多个位置都要读，任一位置的正文不能读时按正文的原因处理", () => {
  const routes: RouteRule[] = [{ path: "/index.php", name_from: [["header.X-Op", "body.op"]] }];
  const request = requestAt("/index.php", {
    headers: [["X-Op", "list"]],
    content_type: "text/plain",
    body: "op=list",
  });
  assert.deepEqual(logicalPath(routes, request), {
    logical_path: "/index.php",
    api: { unknown: "body_unsupported", source: "body.op" },
  });
});

test("请求头名在规则里怎么写，来源就怎么写；请求头值的首尾空白不计入", () => {
  const routes: RouteRule[] = [{ path: "/gw", name_from: [["header.X-Op"]] }];
  assert.deepEqual(logicalPath(routes, requestAt("/gw", { headers: [["x-op", "  get  "]] })), {
    logical_path: "/gw/get",
    api: { name: "get", from: ["header.X-Op"] },
  });
});

test("查询参数按名字精确匹配，大小写不同不算同一个参数", () => {
  const routes: RouteRule[] = [{ path: "/index.php", name_from: [["query.action"]] }];
  assert.deepEqual(logicalPath(routes, requestAt("/index.php", { query: "Action=get" })), {
    logical_path: "/index.php",
    api: { unknown: "missing", source: "query.action" },
  });
});

test("表单和查询串里的加号是空格，百分号转义按原样解码", () => {
  const routes: RouteRule[] = [{ path: "/index.php", name_from: [["query.action"]] }];
  assert.deepEqual(logicalPath(routes, requestAt("/index.php", { query: "action=get+list" })), {
    logical_path: "/index.php",
    api: { unknown: "invalid_name", source: "query.action" },
  });
  assert.deepEqual(logicalPath(routes, requestAt("/index.php", { query: "action=a%2Fb" })), {
    logical_path: "/index.php",
    api: { unknown: "invalid_name", source: "query.action" },
  });
});

test("JSON 字符串里的转义先解码再作为接口名", () => {
  const routes: RouteRule[] = [{ path: "/api/rpc", name_from: [["body.method"]] }];
  const request = requestAt("/api/rpc", {
    content_type: "application/json",
    body: '{"method":"\\u0075ser.get"}',
  });
  assert.deepEqual(logicalPath(routes, request), {
    logical_path: "/api/rpc/user.get",
    api: { name: "user.get", from: ["body.method"] },
  });
});

test("JSON 文本不合法时即使字段存在也按正文不能解析处理", () => {
  const routes: RouteRule[] = [{ path: "/api/rpc", name_from: [["body.method"]] }];
  for (const body of [
    '{"method":"a.b",}',
    '{"method":"a.b"',
    "{'method':'a.b'}",
    '{"a":"\u0001"}',
  ]) {
    assert.deepEqual(
      logicalPath(routes, requestAt("/api/rpc", { content_type: "application/json", body })),
      { logical_path: "/api/rpc", api: { unknown: "body_not_json", source: "body.method" } },
      body,
    );
  }
});

test("带参数的正文类型按媒体类型判断，大小写不敏感", () => {
  const routes: RouteRule[] = [{ path: "/api/rpc", name_from: [["body.method"]] }];
  const request = requestAt("/api/rpc", {
    content_type: "Application/JSON; charset=UTF-8",
    body: '{"method":"get"}',
  });
  assert.deepEqual(logicalPath(routes, request).api, { name: "get", from: ["body.method"] });
});

test("路径带规则但接口名部分的值来自正文时，正文为空按缺失处理", () => {
  const routes: RouteRule[] = [{ path: "/api/rpc", name_from: [["body.method"]] }];
  const request = requestAt("/api/rpc", { content_type: "application/json", body: "" });
  assert.deepEqual(logicalPath(routes, request).api, {
    unknown: "missing",
    source: "body.method",
  });
});

test("前缀规则的覆盖范围由路径决定，接口名不影响是否覆盖", () => {
  const rule: RouteRule = { path: "/rest/*", name_from: [["header.X-Op"]] };
  assert.equal(ruleCovers(rule, "/rest/a/b"), true);
  assert.equal(ruleCovers(rule, "/rest"), false);
  assert.equal(ruleCovers(rule, "/rest//a"), false);
});

test("隐藏 Cookie、Authorization 和名字含 token 的请求头的值，并计数", () => {
  const text = [
    "POST /weixin/wx/mp/wx361163d21a65f679/gateway HTTP/1.1",
    "Host: juice.example.com",
    "Cookie: JSESSIONID=abc; other=1",
    "Authorization: Bearer xyz",
    "X-Access-Token: tok-1",
    "X-Service-Id: bus.buriedPointService",
    "X-Service-Method: saveBuriedPointList",
    "Content-Type: application/json",
    "",
    '{"Cookie":"not a header"}',
  ].join("\r\n");
  const masked = maskRequestText(text);
  assert.equal(masked.hidden.count, 3);
  assert.deepEqual(masked.hidden.names, ["Cookie", "Authorization", "X-Access-Token"]);
  assert.ok(masked.text.includes(`Cookie: ${MASK}`));
  assert.ok(!masked.text.includes("JSESSIONID"));
  assert.ok(!masked.text.includes("Bearer xyz"));
  assert.ok(!masked.text.includes("tok-1"));
  assert.ok(masked.text.includes('{"Cookie":"not a header"}'), "the body is not masked");
  assert.ok(masked.text.includes("X-Service-Id: bus.buriedPointService"));
});

test("空的凭证值不计入隐藏的数量，折行的凭证值一并隐藏", () => {
  const text = "GET /a HTTP/1.1\nCookie:\nAuthorization: part-one\n  part-two\nX-Op: list";
  const masked = maskRequestText(text);
  assert.equal(masked.hidden.count, 1);
  assert.ok(!masked.text.includes("part-one"));
  assert.ok(!masked.text.includes("part-two"));
  assert.ok(masked.text.includes("X-Op: list"));
});

test("凭证请求头按名字判断，大小写不敏感", () => {
  for (const name of ["Cookie", "cookie", "AUTHORIZATION", "Proxy-Authorization", "X-CSRF-Token"]) {
    assert.equal(isSensitiveHeader(name), true, name);
  }
  for (const name of ["Content-Type", "X-Service-Id", "Host"]) {
    assert.equal(isSensitiveHeader(name), false, name);
  }
});

test("粘贴的请求：读出方法、路径、查询串、请求头和正文", () => {
  const parsed = parseRawRequest(
    'POST https://juice.example.com/api/rpc?trace=1 HTTP/1.1\nContent-Type: application/json\n\n{"method":"a.b"}\n\n',
  );
  assert.equal(parsed.ok, true);
  if (!parsed.ok) return;
  assert.deepEqual(parsed.request, {
    method: "POST",
    path: "/api/rpc",
    query: "trace=1",
    headers: [["Content-Type", "application/json"]],
    content_type: "application/json",
    body: '{"method":"a.b"}',
  });
});

test("粘贴的请求：没有请求行、请求头格式不对或两个不同的 Content-Type 时的结果", () => {
  assert.deepEqual(parseRawRequest("not a request"), { ok: false, reason: "request_line" });
  assert.deepEqual(parseRawRequest("GET /a HTTP/1.1\nno colon here"), {
    ok: false,
    reason: "header_line",
  });
  const parsed = parseRawRequest(
    "POST /a HTTP/1.1\nContent-Type: application/json\nContent-Type: text/plain\n\n{}",
  );
  assert.equal(parsed.ok && parsed.request.content_type, null);
});

test("测试器：只有路径时没有请求头，命中名字规则就是缺失；粘贴的请求先隐藏凭证再解析", () => {
  const onlyPath = testRequest("/weixin/wx/mp/wx361163d21a65f679/gateway", [GATEWAY]);
  assert.equal(onlyPath.kind, "ok");
  if (onlyPath.kind !== "ok") return;
  assert.equal(onlyPath.method, null);
  assert.deepEqual(onlyPath.logical.api, {
    unknown: "missing",
    source: "header.X-Service-Id",
  });

  const pasted = testRequest(
    [
      "POST /weixin/wx/mp/wx361163d21a65f679/gateway HTTP/1.1",
      "Cookie: JSESSIONID=secret",
      "X-Service-Id: bus.buriedPointService",
      "X-Service-Method: saveBuriedPointList",
    ].join("\n"),
    [GATEWAY],
  );
  assert.equal(pasted.kind, "ok");
  if (pasted.kind !== "ok") return;
  assert.equal(pasted.hidden.count, 1);
  assert.equal(
    pasted.logical.logical_path,
    "/weixin/wx/mp/wx361163d21a65f679/gateway/bus.buriedPointService/saveBuriedPointList",
  );
  assert.equal(testRequest("   ", []).kind, "empty");
  assert.deepEqual(testRequest("GET", []), { kind: "invalid", reason: "request_line" });
});

test("近期记录按逻辑路径分组，只计入规则覆盖的、取得了接口名的请求", () => {
  const site = "/weixin/wx/mp/wx361163d21a65f679/gateway";
  const named = (logical: string): RecentRow => ({
    path: site,
    logical_path: logical,
    api: { name: nameAfter(logical, site), from: ["header.X-Service-Id"] },
  });
  const rows: RecentRow[] = [
    named(`${site}/bus.a/x`),
    named(`${site}/bus.a/x`),
    named(`${site}/bus.b/y`),
    {
      path: site,
      logical_path: site,
      api: { unknown: "missing", source: "header.X-Service-Method" },
    },
    { path: "/elsewhere", logical_path: "/elsewhere/a/x", api: null },
  ];
  assert.deepEqual(recentPaths(rows, GATEWAY), [
    { logical_path: `${site}/bus.a/x`, count: 2 },
    { logical_path: `${site}/bus.b/y`, count: 1 },
  ]);
  assert.equal(unknownCount(rows, GATEWAY), 1);
  assert.equal(latestNamed(rows, GATEWAY), `${site}/bus.a/x`);
});

test("近期记录缺少逻辑路径字段时不出错，只是没有候选", () => {
  const legacy = JSON.parse(
    '[{"path":"/weixin/wx/mp/wx361163d21a65f679/gateway","api":null}]',
  ) as RecentRow[];
  assert.deepEqual(recentPaths(legacy, GATEWAY), []);
  assert.equal(latestNamed(legacy, GATEWAY), null);
});

test("输入在规则之下时才补全：路径要延伸到规则之后的 /", () => {
  assert.equal(typedUnderRule("/weixin/wx/mp/wx361163d21a65f679/gateway/", GATEWAY), true);
  assert.equal(typedUnderRule("/weixin/wx/mp/wx361163d21a65f679/gateway", GATEWAY), false);
  assert.equal(typedUnderRule("/weixin/wx/mp/wx361163d21a65f679/gatewayx", GATEWAY), false);
  const prefix: RouteRule = { path: "/gw/*", name_from: [["header.X-Op"]] };
  assert.equal(typedUnderRule("/gw/a", prefix), true);
  assert.equal(nameAfter("/gw/a/b/c", "/gw/"), "a/b/c");
  assert.equal(nameAfter("/gw/x/bus.a", "/gw/x"), "bus.a");
});
