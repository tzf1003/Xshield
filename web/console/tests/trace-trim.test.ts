import assert from "node:assert/strict";
import { test } from "node:test";
import type { JevState, Trace, TraceSource, TraceValue } from "../src/api/types.ts";
import { clipBytes, sameName, seenAsText, TRACE_NAME_BYTES_MAX } from "../src/lib/align.ts";
import { alignState, sentRows, valuesNotice } from "../src/features/request-detail/detail-model.ts";

const GET_ORDERS = "GET /api/orders";
const POST_CART = "POST /api/cart";
const TWO_SOURCES: TraceSource[] = [
  { field: "quantity", request: GET_ORDERS, request_id: null, at_millis: null },
  { field: "quantity", request: POST_CART, request_id: null, at_millis: null },
];

function traceValue(at: string, extra: Partial<TraceValue> = {}): TraceValue {
  return {
    at,
    key: null,
    value: "2",
    kind: "reference",
    inert: false,
    seen: true,
    verified: false,
    sources: TWO_SOURCES,
    ...extra,
  };
}

function jevState(at: string): JevState {
  return {
    request: { values: [{ at, value: "2", seen_as: TWO_SOURCES.map(seenAsText) }] },
    recent: [],
    session: { entries_passed: [] },
  } as unknown as JevState;
}

function trace(values: TraceValue[], extra: Partial<Trace> = {}): Trace {
  return { v: 1, values, trimmed: false, session: null, ...extra };
}

test("clipBytes keeps the longest prefix that fits, on a character boundary", () => {
  assert.equal(clipBytes("abc", 10), "abc");
  assert.equal(clipBytes("a".repeat(300), 256), "a".repeat(256));
  // é is two bytes: 255 + 2 = 257 does not fit, so the cut keeps 255 bytes.
  assert.equal(clipBytes(`${"a".repeat(255)}é`, 256), "a".repeat(255));
  // An emoji is four bytes: 254 + 4 = 258 does not fit; 252 + 4 = 256 does.
  assert.equal(clipBytes(`${"a".repeat(254)}😀`, 256), "a".repeat(254));
  assert.equal(clipBytes(`${"a".repeat(252)}😀`, 256), `${"a".repeat(252)}😀`);
});

test("a name the trace cut compares equal to the state's full name", () => {
  const full = `body.${"k".repeat(1000)}`;
  assert.equal(sameName(full, full.slice(0, TRACE_NAME_BYTES_MAX)), true);
  assert.equal(sameName(full, `${full.slice(0, 255)}x`), false);
  assert.equal(sameName("query.q", "query.q"), true);
  // A trace written before the cut existed keeps its full name; both sides are cut the same way.
  assert.equal(sameName(full, full), true);
});

test("a trace location cut to 256 bytes still aligns, and its row keeps the original length", () => {
  const full = `body.${"k".repeat(600)}`;
  const record = trace([traceValue(full.slice(0, TRACE_NAME_BYTES_MAX), { at_len: full.length })]);
  const alignment = alignState(jevState(full), record);
  assert.equal(alignment.aligned, true);
  const [row] = sentRows(record, jevState(full), alignment);
  assert.equal(row?.atLen, full.length);
});

test("a row without a state keeps its cut length too, and an uncut row has none", () => {
  const full = `body.${"k".repeat(600)}`;
  const record = trace([
    traceValue(full.slice(0, TRACE_NAME_BYTES_MAX), { at_len: full.length }),
    traceValue("query.q"),
  ]);
  const [cut, plain] = sentRows(record, null, null);
  assert.equal(cut?.atLen, full.length);
  assert.equal(plain?.atLen, null);
});

test("the values note names a trim, a cleared record and an unread request", () => {
  assert.equal(valuesNotice(trace([traceValue("query.q")])), null);
  assert.equal(
    valuesNotice(trace([], { trimmed: true, values_truncated: true })),
    "已裁剪：为满足 16 KiB 上限，这条记录的值被清空。",
  );
  assert.equal(
    valuesNotice(trace([traceValue("query.q")], { trimmed: true })),
    "已裁剪：为满足 16 KiB 上限，这条记录的部分内容被去掉了。",
  );
  assert.equal(
    valuesNotice(trace([], { values_truncated: true })),
    "请求体不是结构化数据，或含有文件部分（文件内容不拆值），拆出的值没有覆盖全部内容。",
  );
  assert.equal(
    valuesNotice(trace([traceValue("query.q")], { trimmed: true, values_truncated: true })),
    "已裁剪：为满足 16 KiB 上限，这条记录的部分内容被去掉了。请求体不是结构化数据，或含有文件部分（文件内容不拆值），拆出的值没有覆盖全部内容。",
  );
});
