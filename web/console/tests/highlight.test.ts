import assert from "node:assert/strict";
import { test } from "node:test";

import { countHits, splitHighlight } from "../src/lib/highlight.ts";
import { requestList } from "./helpers/fixtures.ts";

test("a blank term leaves the text whole", () => {
  assert.deepEqual(splitHighlight("GET /rest/products", ""), [
    { text: "GET /rest/products", hit: false },
  ]);
  assert.deepEqual(splitHighlight("GET /rest/products", "   "), [
    { text: "GET /rest/products", hit: false },
  ]);
});

test("empty text gives one empty part", () => {
  assert.deepEqual(splitHighlight("", "basket"), [{ text: "", hit: false }]);
});

test("a text without the term is one part", () => {
  assert.deepEqual(splitHighlight("/rest/products", "login"), [
    { text: "/rest/products", hit: false },
  ]);
});

test("matches ignore case and keep the text's own case", () => {
  assert.deepEqual(splitHighlight("Basket and basket", "BASKET"), [
    { text: "Basket", hit: true },
    { text: " and ", hit: false },
    { text: "basket", hit: true },
  ]);
});

test("the term is trimmed before matching", () => {
  assert.deepEqual(splitHighlight("a b", " b "), [
    { text: "a ", hit: false },
    { text: "b", hit: true },
  ]);
});

test("matches run left to right without overlapping", () => {
  assert.deepEqual(splitHighlight("aaaa", "aa"), [
    { text: "aa", hit: true },
    { text: "aa", hit: true },
  ]);
  assert.deepEqual(splitHighlight("aaa", "aa"), [
    { text: "aa", hit: true },
    { text: "a", hit: false },
  ]);
});

test("markup in the text comes back as plain text parts", () => {
  assert.deepEqual(splitHighlight("<img src=x onerror=alert(1)>", "img"), [
    { text: "<", hit: false },
    { text: "img", hit: true },
    { text: " src=x onerror=alert(1)>", hit: false },
  ]);
});

test("the parts of every request path join back to the path, with no empty part", () => {
  for (const row of requestList.rows) {
    const parts = splitHighlight(row.path, "/");
    assert.equal(parts.map((part) => part.text).join(""), row.path);
    assert.ok(
      parts.every((part) => part.text.length > 0),
      row.path,
    );
  }
});

test("countHits counts the non-overlapping matches, ignoring case", () => {
  assert.equal(countHits("Basket basket BASKET", "basket"), 3);
  assert.equal(countHits("aaaa", "aa"), 2);
  assert.equal(countHits("abc", ""), 0);
  assert.equal(countHits("abc", "x"), 0);
});

test("countHits agrees with a split over every request path", () => {
  for (const row of requestList.rows) {
    const expected = row.path.toLowerCase().split("/").length - 1;
    assert.equal(countHits(row.path, "/"), expected, row.path);
  }
});

test("a hit is placed on the original text even when lowercasing changes its length", () => {
  assert.deepEqual(splitHighlight("İa", "a"), [
    { text: "İ", hit: false },
    { text: "a", hit: true },
  ]);
});
