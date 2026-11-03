// The bell's badges (docs/06 6.3.2): serious and warning rows are alerts, hints are counted apart, and the
// words that name the count say the same thing as the badges. These are pure, so the page is not needed.

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type AttentionItem,
  attentionCounts,
  countsText,
} from "../src/features/overview/attention.ts";

function row(key: string, level: AttentionItem["level"]): AttentionItem {
  return { key, level, text: key, actions: [] };
}

test("serious and warning rows are alerts, and hints are counted apart", () => {
  const counts = attentionCounts([row("a", "serious"), row("b", "warn"), row("c", "info")]);
  assert.deepEqual(counts, { alert: 2, hint: 1, serious: true });
});

test("alerts without a serious row are not serious, and an empty list counts nothing", () => {
  assert.deepEqual(attentionCounts([row("a", "warn"), row("b", "warn")]), {
    alert: 2,
    hint: 0,
    serious: false,
  });
  assert.deepEqual(attentionCounts([]), { alert: 0, hint: 0, serious: false });
});

test("the count names alerts and hints, and says so when nothing shows", () => {
  assert.equal(countsText({ alert: 3, hint: 2, serious: true }), "3 项，2 条提示");
  assert.equal(countsText({ alert: 0, hint: 1, serious: false }), "1 条提示");
  assert.equal(countsText({ alert: 1234, hint: 0, serious: false }), "1,234 项");
  assert.equal(countsText({ alert: 0, hint: 0, serious: false }), "没有事项");
});
