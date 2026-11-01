import assert from "node:assert/strict";
import { test } from "node:test";
import { isPlainPath, judgePath, parsePattern } from "../src/lib/patterns.ts";
import { entryCandidates, bypassCandidates, isStaticAsset } from "../src/lib/quick-rules.ts";
import { presetWindow, validCustom, windowFor } from "../src/lib/time-range.ts";

// Cases follow crates/xshield-core/src/context/config.rs (the Rust tests use the same spellings).
test("rules must be absolute, wildcard only at the end, and free of dot segments", () => {
  assert.equal(parsePattern("/rest/basket/*").ok, true);
  assert.equal(parsePattern("/rest/user/login").ok, true);
  assert.equal(parsePattern("rest/x").ok, false);
  assert.equal(parsePattern("/a/*/b").ok, false);
  assert.equal(parsePattern("/a/../b").ok, false);
  assert.equal(parsePattern("/a?x=1").ok, false);
  assert.equal(parsePattern("").ok, false);
  assert.equal(parsePattern("/a b").ok, false);
});

test("a prefix rule covers the children of its directory, not the directory itself", () => {
  const verdict = judgePath("/rest/basket/6", ["/rest/basket/*"], []);
  assert.deepEqual(verdict, { kind: "entry", rule: "/rest/basket/*" });
  assert.deepEqual(judgePath("/rest/basket", ["/rest/basket/*"], []), { kind: "needs_session" });
  assert.deepEqual(judgePath("/rest/basketx", ["/rest/basket/*"], []), { kind: "needs_session" });
});

test("bypass is checked before entries", () => {
  assert.deepEqual(judgePath("/assets/a.js", ["/*"], ["/assets/*"]), {
    kind: "bypass",
    rule: "/assets/*",
  });
});

test("spellings the origin may resolve differently never match", () => {
  for (const path of [
    "/assets/..;/rest/basket/1",
    "/rest//basket",
    "/rest/basket/%2e%2e/x",
    "/rest/a%2fb",
    "/rest\\basket",
    "/rest/basket/./6",
    "/rest/basket?x=1",
  ]) {
    assert.equal(isPlainPath(path), false, path);
    assert.deepEqual(judgePath(path, ["/*"], ["/assets/*"]), { kind: "invalid_spelling" }, path);
  }
  assert.equal(isPlainPath("/rest/basket/6"), true);
});

test("candidates for entries and bypass are proposed from the path shape", () => {
  assert.deepEqual(
    entryCandidates("/rest/admin/application-configuration").map((c) => c.rule),
    ["/rest/admin/application-configuration", "/rest/admin/*"],
  );
  assert.deepEqual(
    bypassCandidates("/assets/i18n/en.json").map((c) => c.rule),
    ["/assets/i18n/en.json", "/assets/i18n/*", "/assets/*"],
  );
  assert.equal(isStaticAsset("/chunk-ABC.js"), true);
  assert.equal(isStaticAsset("/rest/basket/6"), false);
});

test("time windows: presets end now, custom windows must be ordered and within retention", () => {
  const now = Date.parse("2026-11-01T13:00:00Z");
  assert.deepEqual(presetWindow("1h", now), { since: now - 3_600_000, until: now });
  assert.equal(validCustom(now - 1000, now - 2000, now), false);
  assert.equal(validCustom(now - 8 * 24 * 3600 * 1000, now, now), false);
  assert.equal(windowFor("custom", null, null, now), null);
  assert.deepEqual(windowFor("custom", now - 5000, now, now), { since: now - 5000, until: now });
});
