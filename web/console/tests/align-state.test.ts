import assert from "node:assert/strict";
import { test } from "node:test";
import type { JevState, JevStateValue, Trace, TraceSource, TraceValue } from "../src/api/types.ts";
import {
  clipChars,
  seenAsAligned,
  seenAsShown,
  seenAsText,
  stateEntries,
} from "../src/lib/align.ts";
import {
  alignState,
  isReadable,
  needsEvidence,
  sentRows,
} from "../src/features/request-detail/detail-model.ts";

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

/** A state holding exactly these values, for the tests of pieces. */
function stateOf(values: JevStateValue[]): JevState {
  return {
    request: { values },
    recent: [],
    session: { entries_passed: [] },
  } as unknown as JevState;
}

/** A whole value whose `seen_as` repeats its sources in order. */
function wholeValue(at: string, sources: TraceSource[]): JevStateValue {
  return { at, value: "2", seen_as: sources.map(seenAsText) };
}

/** Piece `part` (`k/n`) of a value at `at`, as the judge writes it: a piece carries no `seen_as`. */
function piece(at: string, part: string): JevStateValue {
  return { at, value: "x", seen_as: [], part };
}

function trace(values: TraceValue[], trimmed: boolean): Trace {
  return { v: 1, values, trimmed, session: null };
}

const TWO_SOURCES = [source("quantity", GET_ORDERS), source("quantity", POST_CART)];
const THREE_SOURCES = [...TWO_SOURCES, source("id", GET_ORDERS)];
const LONG_SOURCE = source("quantity", `GET /api/${"a".repeat(300)}`);

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

test("a seen_as the judge cut to 256 characters aligns with its source", () => {
  const shown = seenAsShown(LONG_SOURCE);
  assert.equal(shown.endsWith("..."), true);
  assert.equal([...shown].length, 259);
  const state = jevState([{ at: "query.q", seen_as: [shown] }]);
  const result = alignState(state, trace([traceValue("query.q", [LONG_SOURCE])], false));
  assert.equal(result.aligned, true);
});

test("a cut seen_as that differs from its source does not align", () => {
  const wrong = seenAsShown(LONG_SOURCE).replace("quantity", "quantxty");
  const state = jevState([{ at: "query.q", seen_as: [wrong] }]);
  const result = alignState(state, trace([traceValue("query.q", [LONG_SOURCE])], false));
  assert.equal(result.aligned, false);
});

test("the uncut text of a long source is not a seen_as the judge writes", () => {
  const state = jevState([{ at: "query.q", seen_as: [seenAsText(LONG_SOURCE)] }]);
  const result = alignState(state, trace([traceValue("query.q", [LONG_SOURCE])], false));
  assert.equal(result.aligned, false);
});

test("clipChars counts characters, not bytes", () => {
  assert.equal(clipChars("abc", 3), "abc");
  assert.equal(clipChars("abcd", 3), "abc...");
  assert.equal(clipChars("你好世界", 2), "你好...");
});

test("a value cut into pieces aligns by its place, and its sources are not shown", () => {
  const state = stateOf([piece("query.q", "1/2"), piece("query.q", "2/2")]);
  const values = [traceValue("query.q", TWO_SOURCES)];
  const result = alignState(state, trace(values, false));
  assert.equal(result.aligned, true);
  if (!result.aligned) return;
  assert.deepEqual(result.sent[0]?.split, { pieces: 2, piece: null });
  const rows = sentRows(trace(values, false), state, result);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0]?.sources, []);
  assert.deepEqual(rows[0]?.split, { pieces: 2, piece: null });
});

test("a piece run does not check sources its pieces do not carry", () => {
  const state = stateOf([piece("query.q", "1/2"), piece("query.q", "2/2")]);
  const result = alignState(
    state,
    trace([traceValue("query.q", [source("id", GET_ORDERS)])], false),
  );
  assert.equal(result.aligned, true);
});

test("pieces among whole values align value by value", () => {
  const state = stateOf([
    wholeValue("query.a", TWO_SOURCES),
    piece("query.b", "1/2"),
    piece("query.b", "2/2"),
    wholeValue("query.c", THREE_SOURCES),
  ]);
  const values = [
    traceValue("query.a", TWO_SOURCES),
    traceValue("query.b", TWO_SOURCES),
    traceValue("query.c", THREE_SOURCES),
  ];
  const result = alignState(state, trace(values, false));
  assert.equal(result.aligned, true);
  if (!result.aligned) return;
  assert.deepEqual(
    result.sent.map((item) => item.split),
    [null, { pieces: 2, piece: null }, null],
  );
});

test("a split value at another location does not align", () => {
  const state = stateOf([piece("query.id", "1/2"), piece("query.id", "2/2")]);
  const result = alignState(state, trace([traceValue("query.q", TWO_SOURCES)], false));
  assert.equal(result.aligned, false);
});

test("a broken run of pieces does not align", () => {
  assert.equal(
    stateEntries([piece("query.q", "1/3"), piece("query.q", "2/3"), piece("query.r", "3/3")]),
    null,
  );
  assert.equal(stateEntries([piece("query.q", "2/2")]), null);
  assert.equal(stateEntries([piece("query.q", "1/2"), piece("query.q", "3/2")]), null);
  assert.equal(stateEntries([piece("query.q", "0/2")]), null);
  assert.equal(stateEntries([piece("query.q", "1/x")]), null);
});

test("three pieces are one value at the position of the first", () => {
  const entries = stateEntries([
    wholeValue("query.a", TWO_SOURCES),
    piece("query.b", "1/3"),
    piece("query.b", "2/3"),
    piece("query.b", "3/3"),
  ]);
  assert.deepEqual(
    entries?.map((entry) => [entry.stateIndex, entry.pieces]),
    [
      [0, 1],
      [1, 3],
    ],
  );
});

test("a piece shown from the state alone has no reading and needs no evidence", () => {
  const state = stateOf([piece("query.q", "1/2"), piece("query.q", "2/2")]);
  const rows = sentRows(trace([], false), state, { aligned: false });
  assert.equal(rows.length, 2);
  const [first] = rows;
  assert.ok(first);
  assert.deepEqual(first.split, { pieces: 2, piece: 1 });
  assert.equal(isReadable(first), false);
  assert.equal(needsEvidence(first), false);
});

test("seen_as carries the object class and the tier the judge wrote", () => {
  const doctor: TraceSource = {
    ...source("quantity", GET_ORDERS),
    object: "doctor",
    tier: "public",
    reliability: "high",
  };
  assert.equal(
    seenAsText(doctor),
    "quantity @ GET /api/orders [doctor] (tier public, reliability high)",
  );
  const state = jevState([{ at: "query.q", seen_as: [seenAsText(doctor)] }]);
  const result = alignState(state, trace([traceValue("query.q", [doctor])], false));
  assert.equal(result.aligned, true);
});

test("a seen_as without the class and tier of its source does not align", () => {
  const doctor: TraceSource = { ...source("quantity", GET_ORDERS), object: "doctor" };
  const state = jevState([
    { at: "query.q", seen_as: [seenAsText(source("quantity", GET_ORDERS))] },
  ]);
  const result = alignState(state, trace([traceValue("query.q", [doctor])], false));
  assert.equal(result.aligned, false);
});

test("a long seen_as with a class and tier aligns with its cut text", () => {
  const long: TraceSource = { ...LONG_SOURCE, object: "doctor", tier: "admin", reliability: "low" };
  const state = jevState([{ at: "query.q", seen_as: [seenAsShown(long)] }]);
  const result = alignState(state, trace([traceValue("query.q", [long])], false));
  assert.equal(result.aligned, true);
});
