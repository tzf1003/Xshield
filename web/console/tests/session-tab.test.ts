// The session tab's two lists (docs/06 6.4.4). The gateway writes them for Jev records only, so a record that
// made no Jev call (a fast or cached allow) carries neither: the tab must say they were not kept, not crash
// on them, and the alignment check must not read them either.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { EntryPass, JevState, RecentAccess, Trace, TraceSession } from "../src/api/types.ts";
import {
  alignState,
  newestFirst,
  sessionLists,
} from "../src/features/request-detail/detail-model.ts";

function entry(path: string, atMillis: number | null): EntryPass {
  return { path, at_millis: atMillis, request_id: null };
}

function access(path: string, atMillis: number | null): RecentAccess {
  return { method: "GET", path, status: 200, request_id: null, at_millis: atMillis };
}

test("a record that made no Jev call keeps neither list", () => {
  // The fast and cached allow paths write only the session's age and known values (judge engine.rs).
  const session: TraceSession = { age_seconds: 48, known_values: 3 };
  assert.deepEqual(sessionLists(session), { entries: null, recent: null });
});

test("a Jev record keeps its lists, and its recent accesses read newest first", () => {
  const session: TraceSession = {
    age_seconds: 2040,
    known_values: 140,
    entries_passed: [entry("/login", 1), entry("/api/home", 2)],
    recent: [access("/older", 100), access("/newest", 300), access("/untimed", null)],
  };
  const lists = sessionLists(session);
  assert.deepEqual(lists.entries, session.entries_passed);
  assert.deepEqual(
    lists.recent?.map((item) => item.path),
    ["/newest", "/older", "/untimed"],
  );
});

test("an empty list from a Jev record stays empty, which is not the same as absent", () => {
  const session: TraceSession = { age_seconds: 0, known_values: 0, entries_passed: [], recent: [] };
  assert.deepEqual(sessionLists(session), { entries: [], recent: [] });
});

test("newestFirst sorts a copy and leaves the gateway's order alone", () => {
  const items = [access("/a", 1), access("/b", 3), access("/c", 2)];
  assert.deepEqual(
    newestFirst(items).map((item) => item.path),
    ["/b", "/c", "/a"],
  );
  assert.deepEqual(
    items.map((item) => item.path),
    ["/a", "/b", "/c"],
  );
});

test("the alignment check reads no list that a record does not carry", () => {
  // Before the fix, `trace.session?.recent.length` threw for a session that had no recent list.
  const state = {
    entry: { matched: false },
    session: { age_seconds: 0, entries_passed: [] },
    recent: [],
    request: { method: "GET", path: "/", values: [] },
  } as unknown as JevState;
  const trace: Trace = { v: 1, values: [], session: { age_seconds: 48, known_values: 0 } };
  assert.deepEqual(alignState(state, trace), { aligned: true, sent: [] });
});
