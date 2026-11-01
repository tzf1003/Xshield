import assert from "node:assert/strict";
import { test } from "node:test";
import type { JevState, Trace, TraceSource, TraceValue } from "../src/api/types.ts";
import { seenAsAligned, seenAsText } from "../src/lib/align.ts";
import { alignState } from "../src/features/request-detail/detail-model.ts";

const GET_ORDERS = "GET /api/orders";
const POST_CART = "POST /api/cart";

function source(field: string, request: string): TraceSource {
  return { field, request, request_id: null, at_millis: null };
}

function traceValue(at: string, sources: TraceSource[]): TraceValue {
  return {
    at,
    key: null,
    value: "2",
    kind: "reference",
    inert: false,
    seen: true,
    verified: false,
    sources,
  };
}

function jevState(values: Array<{ at: string; seen_as: string[] }>): JevState {
  return {
    request: {
      values: values.map((value) => ({ at: value.at, value: "2", seen_as: value.seen_as })),
    },
    recent: [],
    session: { entries_passed: [] },
  } as unknown as JevState;
}

function trace(values: TraceValue[], trimmed: boolean): Trace {
  return { v: 1, values, trimmed, session: null };
}

const TWO_SOURCES = [source("quantity", GET_ORDERS), source("quantity", POST_CART)];
const THREE_SOURCES = [...TWO_SOURCES, source("id", GET_ORDERS)];

test("seen_as that repeats every source in order aligns", () => {
  const state = jevState([{ at: "query.q", seen_as: TWO_SOURCES.map(seenAsText) }]);
  const result = alignState(state, trace([traceValue("query.q", TWO_SOURCES)], false));
  assert.equal(result.aligned, true);
});

test("swapped sources do not align, even with the same count", () => {
  const swapped = [...TWO_SOURCES].reverse().map(seenAsText);
  const state = jevState([{ at: "query.q", seen_as: swapped }]);
  const result = alignState(state, trace([traceValue("query.q", TWO_SOURCES)], false));
  assert.equal(result.aligned, false);
});

test("a trimmed trace may keep a shorter prefix of its sources", () => {
  const prefix = THREE_SOURCES.slice(0, 1).map(seenAsText);
  const state = jevState([{ at: "query.q", seen_as: prefix }]);
  const result = alignState(state, trace([traceValue("query.q", THREE_SOURCES)], true));
  assert.equal(result.aligned, true);
});

test("a shorter seen_as does not align when the trace was not trimmed", () => {
  const prefix = THREE_SOURCES.slice(0, 1).map(seenAsText);
  const state = jevState([{ at: "query.q", seen_as: prefix }]);
  const result = alignState(state, trace([traceValue("query.q", THREE_SOURCES)], false));
  assert.equal(result.aligned, false);
});

test("a trimmed prefix in the wrong order does not align", () => {
  const wrong = THREE_SOURCES.slice(0, 2).reverse().map(seenAsText);
  const state = jevState([{ at: "query.q", seen_as: wrong }]);
  const result = alignState(state, trace([traceValue("query.q", THREE_SOURCES)], true));
  assert.equal(result.aligned, false);
});

test("seen_as longer than the sources never aligns", () => {
  const longer = [...TWO_SOURCES, source("id", GET_ORDERS)].map(seenAsText);
  assert.equal(seenAsAligned(longer, TWO_SOURCES, true), false);
  assert.equal(seenAsAligned(longer, TWO_SOURCES, false), false);
});

test("an empty seen_as aligns only with a trimmed trace or with no sources", () => {
  assert.equal(seenAsAligned([], [], false), true);
  assert.equal(seenAsAligned([], TWO_SOURCES, true), true);
  assert.equal(seenAsAligned([], TWO_SOURCES, false), false);
});

test("a changed location does not align", () => {
  const state = jevState([{ at: "query.id", seen_as: TWO_SOURCES.map(seenAsText) }]);
  const result = alignState(state, trace([traceValue("query.q", TWO_SOURCES)], false));
  assert.equal(result.aligned, false);
});
