// Telling a moved window from a changed filter (the request and Jev lists keep their rows across the first only).

import assert from "node:assert/strict";
import { test } from "node:test";
import { sameListOtherWindow, withoutWindow } from "../src/lib/window-key.ts";

test("the window bounds are dropped and the rest is put in a fixed order", () => {
  assert.equal(
    withoutWindow("?site=emr&since_millis=1&until_millis=2&outcome=blocked"),
    "outcome=blocked&site=emr",
  );
  assert.equal(withoutWindow(""), "");
});

test("a moved window is the same list", () => {
  assert.equal(
    sameListOtherWindow(
      "?site=emr&since_millis=1000&until_millis=2000",
      "?site=emr&since_millis=31000&until_millis=32000",
    ),
    true,
  );
});

test("another filter, site or scope is another list", () => {
  const base = "?site=emr&since_millis=1&until_millis=2";
  assert.equal(sameListOtherWindow(base, "?site=juice&since_millis=1&until_millis=2"), false);
  assert.equal(sameListOtherWindow(base, `${base}&outcome=blocked`), false);
  assert.equal(sameListOtherWindow(base, `${base}&scope=all`), false);
});
