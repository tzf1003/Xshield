import assert from "node:assert/strict";
import { test } from "node:test";

import {
  LIVE_LIMIT,
  LIVE_LOOKBACK_MS,
  liveOverflow,
  liveQuery,
  liveSince,
} from "../src/features/requests/live.ts";

const NOW = 1_800_000_000_000;

/** `count` rows whose times run from `oldest` upwards, one millisecond apart. */
const rowsFrom = (oldest: number, count: number): { at_millis: number }[] =>
  Array.from({ length: count }, (_, index) => ({ at_millis: oldest + index }));

test("a poll starts one lookback before the newest row on screen", () => {
  assert.equal(liveSince("?outcome=blocked", NOW - 5_000, NOW), NOW - 5_000 - LIVE_LOOKBACK_MS);
});

test("a poll never starts before the window of the page", () => {
  const windowStart = NOW - 10_000;
  assert.equal(liveSince(`?since_millis=${windowStart}`, NOW - 5_000, NOW), windowStart);
  assert.equal(liveSince(`since_millis=${windowStart}`, NOW - 5_000, NOW), windowStart);
});

test("with no row on screen a poll starts one lookback before now", () => {
  assert.equal(liveSince("", null, NOW), NOW - LIVE_LOOKBACK_MS);
});

test("the poll query carries the start and the limit, without the cursor", () => {
  const params = new URLSearchParams(
    liveQuery("?site=shop&outcome=blocked&since_millis=1&cursor=abc", 42).slice(1),
  );
  assert.equal(params.get("since_millis"), "42");
  assert.equal(params.get("limit"), String(LIVE_LIMIT));
  assert.equal(params.has("cursor"), false);
  assert.equal(params.get("site"), "shop");
  assert.equal(params.get("outcome"), "blocked");
});

test("the poll query is the same with or without the leading question mark", () => {
  const withMark = liveQuery("?site=shop&cursor=abc", 42);
  assert.equal(withMark.startsWith("?"), true);
  assert.equal(liveQuery("site=shop&cursor=abc", 42), withMark);
});

test("a poll below the limit did not overflow", () => {
  assert.equal(liveOverflow(rowsFrom(NOW, LIVE_LIMIT - 1), NOW - 1), false);
  assert.equal(liveOverflow([], NOW), false);
});

test("a poll at the limit overflowed when its oldest row is newer than the start", () => {
  assert.equal(liveOverflow(rowsFrom(NOW + 1, LIVE_LIMIT), NOW), true);
});

test("a poll at the limit that reached the start did not overflow", () => {
  assert.equal(liveOverflow(rowsFrom(NOW, LIVE_LIMIT), NOW), false);
  assert.equal(liveOverflow(rowsFrom(NOW - 1, LIVE_LIMIT), NOW), false);
});
