import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePattern } from "../src/lib/patterns.ts";
import { validHost, validOrigin, validToken } from "../src/lib/site-validate.ts";

// The boundary cases shared with crates/xshield-core/src/context/config.rs (docs/07 7.10.8): the same
// inputs must be accepted or refused by the console and by the gateway.

test("host: no port, no dot runs, no edge dots or hyphens, at most 253 characters", () => {
  assert.equal(validHost("a"), true);
  assert.equal(
    validHost(`${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`),
    true,
  );
  assert.equal(
    validHost(`${"a".repeat(64)}.${"b".repeat(64)}.${"c".repeat(64)}.${"d".repeat(60)}`),
    false,
  );
  assert.equal(validHost("emr.example.com:8080"), false);
  assert.equal(validHost("a..b"), false);
  assert.equal(validHost(".a"), false);
  assert.equal(validHost("a."), false);
  assert.equal(validHost("-a"), false);
  assert.equal(validHost("a-"), false);
  assert.equal(validHost("ex_ample.com"), false);
  assert.equal(validHost(""), false);
});

test("origin: a scheme, a host, and an optional port of one to five digits, and nothing else", () => {
  assert.equal(validOrigin("http://10.0.0.5"), true);
  assert.equal(validOrigin("https://emr.example.com:443"), true);
  assert.equal(validOrigin("http://h:1"), true);
  assert.equal(validOrigin("http://h:99999"), true);
  assert.equal(validOrigin("http://h:123456"), false);
  assert.equal(validOrigin("http://h:"), false);
  assert.equal(validOrigin("http://h:80/path"), false);
  assert.equal(validOrigin("http://h/"), false);
  assert.equal(validOrigin("http://user@h"), false);
  assert.equal(validOrigin("http://[::1]:80"), false);
  assert.equal(validOrigin("http://:80"), false);
  assert.equal(validOrigin("ftp://h"), false);
  assert.equal(validOrigin("http://a:b:80"), false);
});

test("credential name: RFC 7230 token characters, at most 64", () => {
  assert.equal(validToken("X-Api-Key"), true);
  assert.equal(validToken("!#$%&'*+-.^_`|~"), true);
  assert.equal(validToken("a".repeat(64)), true);
  assert.equal(validToken("a".repeat(65)), false);
  assert.equal(validToken("a b"), false);
  assert.equal(validToken("a:b"), false);
  assert.equal(validToken("密钥"), false);
  assert.equal(validToken(""), false);
});

test("path rule: absolute, no backslash, no query, at most 256 bytes", () => {
  assert.equal(parsePattern("/").ok, true);
  assert.equal(parsePattern("/api/*").ok, true);
  assert.equal(parsePattern(`/${"a".repeat(255)}`).ok, true);
  assert.equal(parsePattern(`/${"a".repeat(256)}`).ok, false);
  assert.equal(parsePattern("/a\\b").ok, false);
  assert.equal(parsePattern("/a?b").ok, false);
  assert.equal(parsePattern("/a b").ok, false);
  assert.equal(parsePattern("/a/../b").ok, false);
  assert.equal(parsePattern("/a/*/b").ok, false);
  assert.equal(parsePattern("api").ok, false);
});

test("path rule: the 256-byte limit counts bytes, so 86 CJK characters are refused", () => {
  // Each CJK character is three bytes in UTF-8: 1 + 85 * 3 = 256 bytes is accepted, 1 + 86 * 3 = 259 is not.
  assert.equal(parsePattern(`/${"中".repeat(85)}`).ok, true);
  assert.equal(parsePattern(`/${"中".repeat(86)}`).ok, false);
});

test("path rule: an emoji is four bytes, and only ASCII spaces and control bytes are refused", () => {
  // 1 + 63 * 4 = 253 bytes is accepted, 1 + 64 * 4 = 257 is not.
  assert.equal(parsePattern(`/${"\u{1F600}".repeat(63)}`).ok, true);
  assert.equal(parsePattern(`/${"\u{1F600}".repeat(64)}`).ok, false);
  // U+3000 (the ideographic space) is not an ASCII space, so the gateway accepts it inside a rule.
  assert.equal(parsePattern("/a　b").ok, true);
  assert.equal(parsePattern("/a\tb").ok, false);
  assert.equal(parsePattern("/a b").ok, false);
});
