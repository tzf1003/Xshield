import assert from "node:assert/strict";
import { test } from "node:test";
import { healthValue, siteDisplayState } from "../src/ui/state-model.ts";
import { formatLocal, formatUtc, parseTimestamp, relativeTime, timeView } from "../src/ui/time.ts";

test("one word per site: failed beats approval beats draft beats the server's apply state", () => {
  const cases: [Parameters<typeof siteDisplayState>[0], ReturnType<typeof siteDisplayState>][] = [
    [{ apply_state: "failed", requires_approval: false }, "failed"],
    [{ apply_state: "failed", requires_approval: true }, "failed"],
    [{ apply_state: "pending", requires_approval: true }, "awaiting_approval"],
    // A pause that is itself waiting for approval is still awaiting approval.
    [{ apply_state: "paused", requires_approval: true }, "awaiting_approval"],
    [{ apply_state: "pending", requires_approval: false, status: "draft" }, "draft"],
    [{ apply_state: "active", requires_approval: false, status: "draft" }, "draft"],
    [{ apply_state: "pending", requires_approval: false, status: "active" }, "pending"],
    [{ apply_state: "pending", requires_approval: false }, "pending"],
    [{ apply_state: "paused", requires_approval: false, status: "paused" }, "paused"],
    [{ apply_state: "active", requires_approval: false, status: "active" }, "active"],
    [{ apply_state: "active", requires_approval: null }, "active"],
    [{ apply_state: null, requires_approval: null }, null],
    [{ apply_state: undefined, requires_approval: undefined }, null],
  ];
  for (const [input, expected] of cases) {
    assert.equal(siteDisplayState(input), expected, JSON.stringify(input));
  }
});

test("health values are bounded: anything else is unknown", () => {
  for (const value of ["healthy", "degraded", "unavailable", "unconfigured"]) {
    assert.equal(healthValue(value), value);
  }
  for (const value of ["", "ok", "HEALTHY", undefined, null, 1, {}, ["healthy"]]) {
    assert.equal(healthValue(value), "unknown", String(value));
  }
});

const AT = Date.UTC(2026, 8, 20, 8, 10, 30);

test("local and UTC renderings are explicit about the zone", () => {
  assert.equal(formatUtc(AT), "2026-09-20 08:10:30 UTC");
  assert.equal(formatLocal(AT, "Asia/Shanghai"), "2026-09-20 16:10:30");
  assert.equal(formatLocal(AT, "UTC"), "2026-09-20 08:10:30");
  // Midnight is 00, never 24.
  assert.equal(formatLocal(Date.UTC(2026, 0, 1, 0, 5, 0), "UTC"), "2026-01-01 00:05:00");
});

test("relative time rounds to the nearest unit and flips to a date after thirty days", () => {
  const now = AT;
  const at = (offsetSeconds: number) => relativeTime(now + offsetSeconds * 1000, now, "UTC");
  assert.equal(at(-10), "刚刚");
  assert.equal(at(10), "即将");
  assert.equal(at(-60), "1 分钟前");
  assert.equal(at(-5 * 60), "5 分钟前");
  assert.equal(at(-3 * 3600), "3 小时前");
  assert.equal(at(3 * 3600), "3 小时后");
  assert.equal(at(-2 * 86400), "2 天前");
  assert.equal(at(-29 * 86400), "29 天前");
  assert.equal(at(-45 * 86400), "2026-08-06");
});

test("only parseable times produce a view", () => {
  assert.equal(parseTimestamp(null), null);
  assert.equal(parseTimestamp(undefined), null);
  assert.equal(parseTimestamp(""), null);
  assert.equal(parseTimestamp("not a time"), null);
  assert.equal(parseTimestamp(Number.NaN), null);
  assert.equal(timeView("nope", AT), null);
  const view = timeView("2026-09-20T08:10:30.000Z", AT + 5 * 60_000, "Asia/Shanghai");
  assert.deepEqual(view, {
    iso: "2026-09-20T08:10:30.000Z",
    local: "2026-09-20 16:10:30",
    utc: "2026-09-20 08:10:30 UTC",
    relative: "5 分钟前",
  });
  // RFC 3339 microseconds and +00:00 offsets (what the control plane writes) parse too.
  assert.equal(parseTimestamp("2026-09-20T08:10:30.123456+00:00"), AT + 123);
});
