import assert from "node:assert/strict";
import { test } from "node:test";
import { emptyDraft, newRoute, type SiteConfigDraft } from "../src/sites/model/config.ts";
import {
  checkServerName,
  checkUpstreamAddress,
  parseIpv4,
  parseIpv6,
  parseUpstreamSocket,
  refuseUpstream,
  type UpstreamRefusal,
} from "../src/sites/model/upstream.ts";
import {
  checkDisplayName,
  checkEntryPath,
  checkListenPort,
  checkPolicyRevision,
  checkPublicOrigin,
  checkSiteId,
  validateDraft,
  validateRoute,
  validateRouteSet,
} from "../src/sites/model/validation.ts";

/** Classifies `ip` exactly as xshield_core::site::upstream::refuse_upstream_ip does. */
function classify(ip: string): UpstreamRefusal | null {
  const socket = parseUpstreamSocket(ip.includes(":") ? `[${ip}]:80` : `${ip}:80`);
  assert.ok(socket, `${ip} must parse`);
  return refuseUpstream(socket);
}

test("IPv4 ranges are refused with their category, boundaries included (upstream.rs table)", () => {
  const table: [string, UpstreamRefusal | null][] = [
    ["0.0.0.0", "unspecified"],
    ["0.255.255.255", "unspecified"],
    ["1.0.0.0", null],
    ["9.255.255.255", null],
    ["10.0.0.0", "private"],
    ["10.255.255.255", "private"],
    ["11.0.0.0", null],
    ["100.63.255.255", null],
    ["100.64.0.0", "shared_address_space"],
    ["100.100.100.200", "cloud_metadata"],
    ["100.127.255.255", "shared_address_space"],
    ["100.128.0.0", null],
    ["126.255.255.255", null],
    ["127.0.0.1", "loopback"],
    ["127.255.255.255", "loopback"],
    ["128.0.0.0", null],
    ["169.253.255.255", null],
    ["169.254.0.0", "link_local"],
    ["169.254.169.254", "cloud_metadata"],
    ["169.254.255.255", "link_local"],
    ["169.255.0.0", null],
    ["168.63.129.16", "cloud_metadata"],
    ["168.63.129.17", null],
    ["172.15.255.255", null],
    ["172.16.0.0", "private"],
    ["172.31.255.255", "private"],
    ["172.32.0.0", null],
    ["192.0.0.0", "reserved"],
    ["192.0.0.192", "cloud_metadata"],
    ["192.0.0.255", "reserved"],
    ["192.0.1.0", null],
    ["192.0.2.0", "documentation"],
    ["192.0.3.0", null],
    ["192.88.99.1", "reserved"],
    ["192.167.255.255", null],
    ["192.168.0.0", "private"],
    ["192.168.255.255", "private"],
    ["192.169.0.0", null],
    ["198.17.255.255", null],
    ["198.18.0.0", "reserved"],
    ["198.19.255.255", "reserved"],
    ["198.20.0.0", null],
    ["198.51.100.255", "documentation"],
    ["203.0.113.0", "documentation"],
    ["223.255.255.255", null],
    ["224.0.0.0", "multicast"],
    ["239.255.255.255", "multicast"],
    ["240.0.0.0", "reserved"],
    ["255.255.255.255", "reserved"],
    ["8.8.8.8", null],
    ["1.1.1.1", null],
  ];
  for (const [ip, expected] of table) assert.equal(classify(ip), expected, ip);
});

test("IPv6 ranges are refused with their category (upstream.rs table)", () => {
  const table: [string, UpstreamRefusal | null][] = [
    ["::", "unspecified"],
    ["::1", "loopback"],
    ["::2", "reserved"],
    ["::127.0.0.1", "reserved"],
    ["::ffff:8.8.8.8", "ipv4_mapped"],
    ["::ffff:127.0.0.1", "ipv4_mapped"],
    ["::ffff:169.254.169.254", "ipv4_mapped"],
    ["64:ff9b::7f00:1", "translation"],
    ["64:ff9b::808:808", "translation"],
    ["64:ff9b:1::1", "translation"],
    ["100::1", "reserved"],
    ["2001::1", "translation"],
    ["2001:db8::1", "documentation"],
    ["2001:4860:4860::8888", null],
    ["2002:7f00:1::", "translation"],
    ["2606:4700:4700::1111", null],
    ["3fff::1", "documentation"],
    ["fc00::1", "unique_local"],
    ["fd00::1", "unique_local"],
    ["fd00:ec2::254", "cloud_metadata"],
    ["fe80::1", "link_local"],
    ["fe80::a9fe:a9fe", "cloud_metadata"],
    ["febf::1", "link_local"],
    ["fec0::1", "reserved"],
    ["ff02::1", "multicast"],
  ];
  for (const [ip, expected] of table) assert.equal(classify(ip), expected, ip);
});

test("only a literal socket with a non-zero port parses (upstream.rs bad list)", () => {
  assert.equal(parseUpstreamSocket("8.8.8.8:80")?.port, 80);
  assert.equal(parseUpstreamSocket("[2001:4860:4860::8888]:443")?.port, 443);
  for (const bad of [
    "8.8.8.8",
    "8.8.8.8:0",
    "8.8.8.8:65536",
    "8.8.8.8:+80",
    "8.8.8.8: 80",
    " 8.8.8.8:80",
    "example.com:80",
    "localhost:80",
    "[::1]",
    "::1:80",
    "[fe80::1%eth0]:80",
    "[2001:4860:4860::8888%1]:80",
    "08.8.8.8:80",
    "8.8.8:80",
    "",
  ]) {
    assert.equal(parseUpstreamSocket(bad), null, JSON.stringify(bad));
  }
  assert.equal(parseIpv4("256.1.1.1"), null);
  assert.equal(parseIpv6("1::2::3"), null);
  assert.equal(parseIpv6("12345::1"), null);
  assert.equal(parseIpv6("1:2:3:4:5:6:7:8:9"), null);
});

test("the address field explains what the server will refuse, and loopback only warns", () => {
  assert.deepEqual(checkUpstreamAddress("8.8.8.8:443"), {
    severity: "ok",
    message: null,
    refusal: null,
  });
  assert.equal(checkUpstreamAddress("[2001:4860:4860::8888]:443").severity, "ok");
  const loopback = checkUpstreamAddress("127.0.0.1:8080");
  assert.equal(loopback.severity, "warning");
  assert.equal(loopback.refusal, "loopback");
  const lab = checkUpstreamAddress("10.0.0.5:8080");
  assert.equal(lab.severity, "error");
  assert.match(lab.message ?? "", /内网地址/);
  const documentation = checkUpstreamAddress("203.0.113.9:443");
  assert.equal(documentation.severity, "error", "the documentation range is refused by the server");
  assert.match(documentation.message ?? "", /文档示例网段/);
  assert.match(checkUpstreamAddress("169.254.169.254:80").message ?? "", /云平台元数据/);
  assert.match(checkUpstreamAddress("[::ffff:8.8.8.8]:80").message ?? "", /IPv4 映射/);
  const name = checkUpstreamAddress("origin.example.com:443");
  assert.equal(name.severity, "error");
  assert.match(name.message ?? "", /不能填域名/);
  assert.match(checkUpstreamAddress("8.8.8.8").message ?? "", /IP 字面量加端口/);
  assert.match(checkUpstreamAddress("").message ?? "", /请填写/);
});

test("the server name must be a domain, never something that reads as an IP", () => {
  for (const good of ["origin.example.test", "a.b-c.example", "localhost", "Example.COM"]) {
    assert.equal(checkServerName(good), null, good);
  }
  for (const bad of [
    "",
    "127.0.0.1",
    "2130706433",
    "0x7f.1",
    "127.1",
    "a..b",
    "-a.example",
    "a-.example",
    "a b.example",
    "x".repeat(64) + ".example",
  ]) {
    assert.notEqual(checkServerName(bad), null, JSON.stringify(bad));
  }
});

test("public origin follows validate_public_origin", () => {
  for (const good of [
    "https://www.example.com",
    "https://www.example.com:8443",
    "http://localhost",
    "http://127.0.0.1:8080/",
    "http://127.5.5.5",
  ]) {
    assert.equal(checkPublicOrigin(good, false), null, good);
  }
  for (const bad of [
    "",
    "www.example.com",
    "ftp://www.example.com",
    "https://www.example.com/",
    "https://www.example.com/path",
    "https://user@www.example.com",
    "https://[2001:db8::1]",
    "https://www.example.com:0",
    "https://www.example.com:65536",
    "https://-bad.example.com",
    "https://bad_host.example.com",
    "http://www.example.com",
    "https://",
    `https://${"a".repeat(64)}.example.com`,
  ]) {
    assert.notEqual(checkPublicOrigin(bad, false), null, JSON.stringify(bad));
  }
  assert.equal(
    checkPublicOrigin("http://127.5.5.5", true) !== null,
    true,
    "sensor limits plain http to two names",
  );
  assert.equal(checkPublicOrigin("http://localhost", true), null);
  assert.equal(checkPublicOrigin("http://127.0.0.1", true), null);
});

test("identifiers and scalars", () => {
  assert.equal(checkSiteId("site_alpha.v2-1"), null);
  assert.equal(checkSiteId("a".repeat(123)), null);
  assert.notEqual(checkSiteId("a".repeat(124)), null, "edge- prefix keeps it within 128 bytes");
  for (const bad of ["", "new", "a b", "a/b", "站点"]) assert.notEqual(checkSiteId(bad), null, bad);
  assert.equal(checkDisplayName("Alpha 官网"), null);
  for (const bad of ["", "  ", " x", "x ", "x\u0007", "x".repeat(129)])
    assert.notEqual(checkDisplayName(bad), null, JSON.stringify(bad));
  assert.equal(checkListenPort(0), null);
  assert.equal(checkListenPort(6100), null);
  assert.equal(checkListenPort(65535), null);
  for (const bad of [1, 6099, 65536, 1.5]) assert.notEqual(checkListenPort(bad), null, String(bad));
  assert.equal(checkPolicyRevision("policy-v1.2_a"), null);
  for (const bad of ["", "a b", "x".repeat(129)]) assert.notEqual(checkPolicyRevision(bad), null);
  assert.equal(checkEntryPath("/"), null);
  assert.equal(checkEntryPath("/app/index.html"), null);
  for (const bad of ["", "app", "/a b", "/a?x=1", "/a#x", "/__xshield/x", "/a/../b", "/中文"]) {
    assert.notEqual(checkEntryPath(bad), null, JSON.stringify(bad));
  }
});

const goodRoute = () =>
  newRoute({
    operation_id: "orders.get",
    method: "GET",
    path: "/api/orders/{order_id}",
    security_entry: "ui_action_required",
    source_action: "orders.open",
    resource_type: "order",
    view_profile: "customer",
    resource_path_parameter: "order_id",
  });
const limits = { max_response_body_bytes: 16_777_216 };
const fields = (issues: ReturnType<typeof validateRoute>) => issues.map((issue) => issue.field);

test("a route follows the per-route rules of SitePolicyConfig::validate", () => {
  assert.deepEqual(validateRoute(goodRoute(), limits), []);
  // Admission and operation source go together.
  assert.deepEqual(fields(validateRoute({ ...goodRoute(), source_action: null }, limits)), [
    "source_action",
  ]);
  assert.deepEqual(
    fields(validateRoute(newRoute({ operation_id: "x", path: "/x", source_action: "a" }), limits)),
    ["source_action"],
  );
  // Resource binding needs GET, ui admission, type, profile and exactly one parameter.
  const post = validateRoute({ ...goodRoute(), method: "POST" }, limits);
  assert.ok(fields(post).includes("method"));
  assert.ok(
    fields(validateRoute({ ...goodRoute(), resource_type: null }, limits)).includes(
      "resource_type",
    ),
  );
  assert.ok(
    fields(validateRoute({ ...goodRoute(), resource_query_parameter: "q" }, limits)).includes(
      "resource_query_parameter",
    ),
  );
  assert.ok(
    fields(validateRoute({ ...goodRoute(), resource_path_parameter: null }, limits)).includes(
      "resource_query_parameter",
    ),
  );
  // Path rules.
  for (const path of ["", "api", "/a b", "/a?b", "/__xshield/x", "/a/./b", "/api/orders/{other}"]) {
    assert.ok(fields(validateRoute({ ...goodRoute(), path }, limits)).includes("path"), path);
  }
  assert.ok(
    fields(validateRoute(newRoute({ operation_id: "x", path: "/a/{b}" }), limits)).includes("path"),
  );
  assert.ok(
    fields(validateRoute({ ...goodRoute(), operation_id: "bad id" }, limits)).includes(
      "operation_id",
    ),
  );
  assert.ok(
    fields(validateRoute({ ...goodRoute(), response_mode: "SENSOR_HTML" }, limits)).includes(
      "response_mode",
    ),
  );
  assert.ok(
    fields(validateRoute({ ...goodRoute(), max_response_bytes: 0 }, limits)).includes(
      "max_response_bytes",
    ),
  );
  assert.ok(
    fields(
      validateRoute(
        { ...goodRoute(), max_response_bytes: 2_000_000 },
        { max_response_body_bytes: 1_000_000 },
      ),
    ).includes("max_response_bytes"),
  );
  const crypto = newRoute({
    operation_id: "x",
    path: "/x",
    method: "GET",
    request_crypto: { mode: "OBSERVE", adapter_revision: "a" },
  });
  assert.ok(fields(validateRoute(crypto, limits)).includes("request_crypto"));
});

test("routes must not collide, shadow each other or exceed 64 parameter routes", () => {
  const a = newRoute({ operation_id: "a", path: "/a" });
  assert.equal(validateRouteSet([a, newRoute({ operation_id: "b", path: "/b" })]).size, 0);
  assert.ok(
    validateRouteSet([a, newRoute({ operation_id: "a", path: "/b" })])
      .get(1)?.[0]
      ?.includes("重复"),
  );
  assert.ok(
    validateRouteSet([a, newRoute({ operation_id: "b", path: "/a" })])
      .get(1)?.[0]
      ?.includes("已被另一条路由占用"),
  );
  assert.equal(
    validateRouteSet([a, newRoute({ operation_id: "b", path: "/a", method: "POST" })]).size,
    0,
  );
  const param = (id: string, prefix: string) =>
    newRoute({
      operation_id: id,
      path: `${prefix}{id}`,
      resource_path_parameter: "id",
      security_entry: "ui_action_required",
      source_action: "x",
      resource_type: "t",
      view_profile: "p",
    });
  // Same method and prefix, whatever the parameter is called.
  assert.ok(
    validateRouteSet([
      param("p1", "/orders/"),
      { ...param("p2", "/orders/"), path: "/orders/{other}", resource_path_parameter: "other" },
    ]).size > 0,
  );
  // A fixed route one segment below a parameter route is shadowed.
  const shadowed = validateRouteSet([
    param("p1", "/orders/"),
    newRoute({ operation_id: "fixed", path: "/orders/new" }),
  ]);
  assert.ok(shadowed.get(1)?.[0]?.includes("永远不会命中"));
  assert.equal(
    validateRouteSet([
      param("p1", "/orders/"),
      newRoute({ operation_id: "deep", path: "/orders/a/b" }),
    ]).size,
    0,
  );
  const many = Array.from({ length: 65 }, (_, index) => param(`p${index}`, `/r${index}/`));
  assert.ok(validateRouteSet(many).get(64)?.[0]?.includes("64"));
});

function valid(): SiteConfigDraft {
  return {
    ...emptyDraft(),
    display_name: "Alpha",
    public_origin: "https://alpha.example.com",
    upstream_address: "8.8.8.8:443",
    upstream_server_name: "origin.example.com",
  };
}
const paths = (draft: SiteConfigDraft, options?: Parameters<typeof validateDraft>[1]) =>
  validateDraft(draft, options)
    .filter((issue) => issue.severity === "error")
    .map((issue) => issue.path);

test("a sensible draft has no error, and each broken field points at its own path and tab", () => {
  assert.deepEqual(validateDraft(valid(), { creating: true, siteId: "alpha" }), []);
  assert.deepEqual(paths(emptyDraft(), { creating: true, siteId: "" }), [
    "site_id",
    "display_name",
    "public_origin",
    "upstream_address",
    "upstream_server_name",
  ]);
  const broken = valid();
  broken.policy.limits.requests_per_second = 5000;
  broken.policy.limits.burst = 100;
  broken.policy.health_check.path = "ready";
  broken.policy.waf.blocked_headers = ["X-A", "x-a"];
  broken.policy.waf.blocked_query_fragments = ["ab"];
  broken.policy.secret_refs = [{ kind: "tls", secret_ref: "tls/x", key_id: "", state: "active" }];
  broken.policy.identity.session_ttl_seconds = 0;
  broken.policy.static_asset_max_path_depth = 17;
  const issues = validateDraft(broken);
  assert.deepEqual(
    new Set(issues.map((issue) => issue.path)),
    new Set([
      "limits.burst",
      "health_check.path",
      "waf.blocked_headers",
      "waf.blocked_query_fragments",
      "secret_refs[0].secret_ref",
      "secret_refs[0].key_id",
      "identity.session_ttl_seconds",
      "static_asset_max_path_depth",
    ]),
  );
  assert.equal(issues.find((issue) => issue.path === "limits.burst")?.group, "waf-limits");
  assert.equal(issues.find((issue) => issue.path === "secret_refs[0].key_id")?.group, "crypto");
});

test("loopback upstream is a warning, never an error", () => {
  const draft = { ...valid(), upstream_address: "127.0.0.1:8080" };
  const issues = validateDraft(draft);
  assert.equal(issues.length, 1);
  assert.equal(issues[0]?.severity, "warning");
});

test("route problems carry the route's name and tab", () => {
  const draft = valid();
  draft.policy.routes = [
    newRoute({ operation_id: "home", path: "/", security_entry: "public" }),
    newRoute({ operation_id: "home", path: "/x", security_entry: "public" }),
  ];
  const issues = validateDraft(draft);
  assert.ok(issues.some((issue) => issue.group === "routes" && issue.message.includes("home")));
});
