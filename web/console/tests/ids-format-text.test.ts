import assert from "node:assert/strict";
import { test } from "node:test";
import { fmtAgo, fmtBytes, fmtElapsed, fmtInt, pct, plural } from "../src/lib/format.ts";
import {
  findRequestIds,
  isRequestId,
  isSessionLabel,
  isSiteName,
  requestIdMillis,
  shortRequestId,
} from "../src/lib/ids.ts";
import { hasHidden, splitHidden } from "../src/lib/text.ts";

const ID = "req_01a19741107477ff9224781077354552";

test("request ids are recognised by shape only", () => {
  assert.equal(isRequestId(ID), true);
  assert.equal(isRequestId(ID.toUpperCase()), false);
  assert.equal(isRequestId(`${ID}0`), false);
  assert.equal(isRequestId("req_short"), false);
});

test("the millisecond clock is decoded from the first twelve hex digits", () => {
  // 0x01a197411074 is 2026-11-01 13:16:26.100 UTC (docs/07 7.3.1).
  assert.equal(requestIdMillis(ID), Date.parse("2026-11-01T13:16:26.100Z"));
  assert.equal(requestIdMillis("nope"), null);
});

test("ids are found in free text, once each, in order", () => {
  const other = "req_01a197410a1b2c3d4e5f60718293a4b5";
  const text = `first ${ID}, then ${other} and again ${ID}`;
  assert.deepEqual(findRequestIds(text), [ID, other]);
});

test("short ids keep the last eight digits", () => {
  assert.equal(shortRequestId(ID), "…77354552");
});

test("session labels are sixteen lower-case hex digits", () => {
  assert.equal(isSessionLabel("7c1e9a40d2b35f61"), true);
  assert.equal(isSessionLabel("7c1e9a40"), false);
});

test("site names follow the gateway rule", () => {
  assert.equal(isSiteName("juice-shop_2"), true);
  assert.equal(isSiteName("Juice"), false);
  assert.equal(isSiteName("a".repeat(65)), false);
});

test("numbers and percentages use the documented formats", () => {
  assert.equal(fmtInt(6204), "6,204");
  assert.equal(fmtInt(null), "—");
  assert.equal(pct(0.8612), "86%");
  assert.equal(fmtBytes(3500), "3.4 KiB");
  assert.equal(fmtElapsed(11 * 60 + 20), "11 分钟");
  assert.equal(fmtAgo(1000, 1000 + 180_000), "3 分钟前");
  assert.equal(plural(1, "1 条", "{n} 条"), "1 条");
  assert.equal(plural(12, "1 条", "{n} 条"), "12 条");
});

test("invisible and direction-changing characters are split out for escaping", () => {
  const text = `a‮b​c`;
  assert.equal(hasHidden(text), true);
  assert.deepEqual(splitHidden(text), [
    { kind: "text", text: "a" },
    { kind: "hidden", code: "\\u202e" },
    { kind: "text", text: "b" },
    { kind: "hidden", code: "\\u200b" },
    { kind: "text", text: "c" },
  ]);
  assert.equal(hasHidden("plain"), false);
});
