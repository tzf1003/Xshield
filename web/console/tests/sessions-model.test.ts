import assert from "node:assert/strict";
import { test } from "node:test";

import type { LogGap, TimelineRow } from "../src/api/types.ts";
import {
  type LostWindow,
  lostWindowBetween,
  lostWindows,
  withGaps,
} from "../src/features/sessions/sessions-model.ts";
import { sessionTimeline } from "./helpers/fixtures.ts";

const MINUTE = 60_000;

const sample = sessionTimeline.rows[0];
assert.ok(sample !== undefined, "the session timeline fixture has rows");

/** A row at `at` (Unix milliseconds). Only its time and identity matter to the gap rules. */
const rowAt = (at: number, requestId: string): TimelineRow => ({
  ...sample,
  request_id: requestId,
  at_millis: at,
});

/** One loss window of a gateway's log (docs/07 7.7.4). */
const gap = (
  from_ms: number,
  to_ms: number,
  counts: Pick<LogGap, "dropped" | "dropped_bypass" | "write_errors">,
): LogGap => ({ from_ms, to_ms, ...counts });

test("withGaps puts a gap row where two requests are more than five minutes apart", () => {
  const items = withGaps([
    rowAt(0, "req_a"),
    rowAt(6 * MINUTE, "req_b"),
    rowAt(11 * MINUTE, "req_c"),
  ]);

  assert.deepEqual(
    items.map((item) => item.kind),
    ["row", "gap", "row", "row"],
  );
  assert.deepEqual(items[1], {
    kind: "gap",
    key: "gap-req_b",
    ms: 6 * MINUTE,
    from: 0,
    to: 6 * MINUTE,
  });
});

test("lostWindows keeps the windows that cost decision records, named by their gateway", () => {
  const windows = lostWindows([
    {
      edge: "edge-1",
      gaps: [
        gap(0, MINUTE, { dropped: 31, dropped_bypass: 6, write_errors: 0 }),
        gap(10 * MINUTE, 11 * MINUTE, { dropped: 0, dropped_bypass: 4, write_errors: 0 }),
      ],
    },
    {
      edge: "edge-2",
      gaps: [gap(20 * MINUTE, 21 * MINUTE, { dropped: 0, dropped_bypass: 0, write_errors: 5 })],
    },
  ]);

  assert.deepEqual(windows, [
    { edge: "edge-1", from_ms: 0, to_ms: MINUTE, dropped: 31, write_errors: 0 },
    { edge: "edge-2", from_ms: 20 * MINUTE, to_ms: 21 * MINUTE, dropped: 0, write_errors: 5 },
  ]);
});

test("lostWindowBetween finds the window a quiet time overlaps, and not one it only touches", () => {
  const outage: LostWindow = {
    edge: "edge-1",
    from_ms: 10 * MINUTE,
    to_ms: 12 * MINUTE,
    dropped: 31,
    write_errors: 0,
  };
  const windows = [outage];

  // A quiet time that covers the window, starts inside it, or ends inside it overlaps it.
  assert.equal(lostWindowBetween(windows, 9 * MINUTE, 13 * MINUTE), outage);
  assert.equal(lostWindowBetween(windows, 11 * MINUTE, 13 * MINUTE), outage);
  assert.equal(lostWindowBetween(windows, 8 * MINUTE, 11 * MINUTE), outage);
  // A quiet time that only meets the window at one of its ends does not.
  assert.equal(lostWindowBetween(windows, 12 * MINUTE, 13 * MINUTE), null);
  assert.equal(lostWindowBetween(windows, 8 * MINUTE, 10 * MINUTE), null);
  assert.equal(lostWindowBetween([], 0, MINUTE), null);
});
