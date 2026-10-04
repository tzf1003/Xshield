import assert from "node:assert/strict";
import { test } from "node:test";
import { validateModelCallListPlan } from "../src/api.ts";
import { validateCausalityPlan, validateSearchPlan } from "../src/search.ts";
import {
  DEFAULT_PRESET,
  formatDuration,
  formatLocal,
  formatSpan,
  formatUtc,
  MAX_INSTANT_MS,
  MAX_WINDOW_MS,
  microsOf,
  microsToIso,
  parseLocalInput,
  type RangePreset,
  rangePresets,
  resolveRange,
  toLocalInput,
  toUtcSecond,
  windowAround,
  windowFromInstants,
} from "../src/ui/time-range.ts";

/** Runs `body` with the process time zone set, restoring the previous one afterwards. */
function inZone<T>(zone: string, body: () => T): T {
  const previous = process.env.TZ;
  process.env.TZ = zone;
  try {
    return body();
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
}

const NOW = Date.parse("2026-09-20T08:10:30.400Z");

function searchAccepts(start: string, end: string): boolean {
  try {
    validateSearchPlan({
      schema_version: 3,
      start,
      end,
      filters: [],
      sort: "occurred_at_desc",
      limit: 1,
    });
    return true;
  } catch {
    return false;
  }
}

test("presets end at the next whole second and are whole-second UTC windows", () => {
  const start: Record<RangePreset, string> = {
    "15m": "2026-09-20T07:55:31Z",
    "1h": "2026-09-20T07:10:31Z",
    "24h": "2026-09-19T08:10:31Z",
    "7d": "2026-09-13T08:10:31Z",
  };
  // 08:10:30.400 -> the half-open window must still contain an event at 08:10:30.9.
  for (const preset of rangePresets) {
    const resolution = resolveRange({ kind: "preset", preset: preset.id }, NOW);
    assert.equal(resolution.problem, null, preset.id);
    assert.deepEqual(resolution.window, { start: start[preset.id], end: "2026-09-20T08:10:31Z" });
  }
  assert.equal(DEFAULT_PRESET, "1h");
});

test("an exact whole second does not advance the window end", () => {
  const resolution = resolveRange(
    { kind: "preset", preset: "1h" },
    Date.parse("2026-09-20T08:10:30.000Z"),
  );
  assert.deepEqual(resolution.window, {
    start: "2026-09-20T07:10:30Z",
    end: "2026-09-20T08:10:30Z",
  });
});

test("every preset is accepted by all three plan validators", () => {
  for (const preset of rangePresets) {
    const { window } = resolveRange({ kind: "preset", preset: preset.id }, NOW);
    assert.ok(window);
    assert.doesNotThrow(() =>
      validateSearchPlan({
        schema_version: 3,
        ...window,
        filters: [],
        sort: "occurred_at_desc",
        limit: 25,
      }),
    );
    assert.doesNotThrow(() => validateModelCallListPlan({ ...window, limit: 25 }));
    assert.doesNotThrow(() =>
      validateCausalityPlan({
        schema_version: 3,
        ...window,
        event_id: "ev_018f2a3b-4c5d-7000-8000-000000000001",
        direction: "both",
        max_depth: 2,
        max_nodes: 16,
      }),
    );
  }
});

test("no choice and half-filled custom ranges are reported, not guessed", () => {
  assert.deepEqual(resolveRange({ kind: "none" }, NOW), { window: null, problem: "missing" });
  assert.deepEqual(resolveRange({ kind: "custom", start: "", end: "2026-09-20T01:00" }, NOW), {
    window: null,
    problem: "incomplete",
  });
  assert.deepEqual(
    resolveRange({ kind: "custom", start: "garbage", end: "2026-09-20T01:00" }, NOW),
    {
      window: null,
      problem: "invalid",
    },
  );
});

test("custom local time converts to UTC in the browser's zone", () => {
  inZone("Asia/Shanghai", () => {
    const resolution = resolveRange(
      { kind: "custom", start: "2026-09-20T08:00", end: "2026-09-20T09:30:15" },
      NOW,
    );
    // UTC+8: the same wall clock is eight hours earlier in UTC. Seconds are optional on input.
    assert.deepEqual(resolution.window, {
      start: "2026-09-20T00:00:00Z",
      end: "2026-09-20T01:30:15Z",
    });
  });
  inZone("America/Los_Angeles", () => {
    const resolution = resolveRange(
      { kind: "custom", start: "2026-09-20T00:00", end: "2026-09-21T00:00" },
      NOW,
    );
    assert.deepEqual(resolution.window, {
      start: "2026-09-20T07:00:00Z",
      end: "2026-09-21T07:00:00Z",
    });
  });
});

test("a local time that does not exist lands after the spring-forward gap", () => {
  inZone("America/New_York", () => {
    // 2026-03-08 02:00-03:00 never happens in New York; the platform reads 02:30 as 02:30 EST.
    assert.equal(
      toUtcSecond(parseLocalInput("2026-03-08T02:30") ?? Number.NaN),
      "2026-03-08T07:30:00Z",
    );
    // The surrounding times are unaffected.
    assert.equal(
      toUtcSecond(parseLocalInput("2026-03-08T01:59:59") ?? Number.NaN),
      "2026-03-08T06:59:59Z",
    );
    assert.equal(
      toUtcSecond(parseLocalInput("2026-03-08T03:00") ?? Number.NaN),
      "2026-03-08T07:00:00Z",
    );
  });
});

test("an ambiguous local time takes its first occurrence after the fall-back", () => {
  inZone("America/New_York", () => {
    // 2026-11-01 01:30 happens twice; the first one is EDT (UTC-4).
    assert.equal(
      toUtcSecond(parseLocalInput("2026-11-01T01:30") ?? Number.NaN),
      "2026-11-01T05:30:00Z",
    );
    assert.equal(
      toUtcSecond(parseLocalInput("2026-11-01T02:30") ?? Number.NaN),
      "2026-11-01T07:30:00Z",
    );
  });
});

test("calendar overflow and malformed text are rejected rather than rolled over", () => {
  inZone("UTC", () => {
    assert.notEqual(parseLocalInput("2026-02-28T23:59:59"), null);
    assert.notEqual(parseLocalInput("2028-02-29T00:00"), null, "leap day");
    for (const bad of [
      "2026-02-29T00:00",
      "2026-04-31T00:00",
      "2026-13-01T00:00",
      "2026-00-10T00:00",
      "2026-09-20T24:00",
      "2026-09-20T00:60",
      "2026-09-20T00:00:60",
      "2026-09-20 00:00",
      "0099-01-01T00:00",
      "",
      "2026-09-20",
    ]) {
      assert.equal(parseLocalInput(bad), null, bad);
    }
  });
});

test("month ends and year ends convert without drifting", () => {
  inZone("Asia/Tokyo", () => {
    const resolution = resolveRange(
      { kind: "custom", start: "2026-12-31T23:00", end: "2027-01-01T01:00" },
      NOW,
    );
    assert.deepEqual(resolution.window, {
      start: "2026-12-31T14:00:00Z",
      end: "2026-12-31T16:00:00Z",
    });
  });
});

test("the 31-day limit is absolute elapsed time, even across a DST change", () => {
  inZone("UTC", () => {
    const ok = resolveRange(
      { kind: "custom", start: "2026-09-01T00:00", end: "2026-10-02T00:00" },
      NOW,
    );
    assert.deepEqual(ok.window, { start: "2026-09-01T00:00:00Z", end: "2026-10-02T00:00:00Z" });
    const over = resolveRange(
      { kind: "custom", start: "2026-09-01T00:00", end: "2026-10-02T00:00:01" },
      NOW,
    );
    assert.deepEqual(over, { window: null, problem: "too_long" });
  });
  inZone("America/New_York", () => {
    // 31 calendar days that span the November fall-back are 31 days and one hour long.
    const fallBack = resolveRange(
      { kind: "custom", start: "2026-10-15T00:00", end: "2026-11-15T00:00" },
      NOW,
    );
    assert.deepEqual(fallBack, { window: null, problem: "too_long" });
    // The same span over the March spring-forward is an hour shorter, so it still fits.
    const springForward = resolveRange(
      { kind: "custom", start: "2026-03-01T00:00", end: "2026-04-01T00:00" },
      NOW,
    );
    assert.equal(springForward.problem, null);
  });
});

test("order and bounds problems", () => {
  inZone("UTC", () => {
    assert.deepEqual(
      resolveRange({ kind: "custom", start: "2026-09-20T01:00", end: "2026-09-20T01:00" }, NOW),
      {
        window: null,
        problem: "order",
      },
    );
    assert.deepEqual(
      resolveRange({ kind: "custom", start: "2026-09-20T02:00", end: "2026-09-20T01:00" }, NOW),
      {
        window: null,
        problem: "order",
      },
    );
    assert.deepEqual(
      resolveRange({ kind: "custom", start: "1969-12-31T23:00", end: "1970-01-01T01:00" }, NOW),
      {
        window: null,
        problem: "bounds",
      },
    );
    assert.deepEqual(
      resolveRange({ kind: "custom", start: "2299-12-31T23:00", end: "2300-01-01T01:00" }, NOW),
      {
        window: null,
        problem: "bounds",
      },
    );
    assert.deepEqual(
      resolveRange({ kind: "custom", start: "2299-12-31T23:00", end: "2300-01-01T00:00" }, NOW)
        .window,
      { start: "2299-12-31T23:00:00Z", end: "2300-01-01T00:00:00Z" },
    );
  });
});

test("the explanatory limits agree with the validators on the edge cases", () => {
  const instants = [
    // [start, end] in epoch ms
    [0, 3_600_000],
    [-1000, 3_599_000],
    [1_000_000, 1_000_000 + MAX_WINDOW_MS],
    [1_000_000, 1_000_000 + MAX_WINDOW_MS + 1000],
    [MAX_INSTANT_MS - 3_600_000, MAX_INSTANT_MS],
    [MAX_INSTANT_MS - 3_599_000, MAX_INSTANT_MS + 1000],
    [5_000_000, 5_000_000],
    [6_000_000, 5_000_000],
  ] as const;
  for (const [start, end] of instants) {
    const hint = windowFromInstants(start, end);
    const text = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
    // Years before 1970 and after 2300 still format; the validator is the one that decides.
    const validator = searchAccepts(text(start), text(end));
    assert.equal(hint.problem === null, validator, `${start}..${end}: hint ${hint.problem}`);
  }
});

test("a causality window is centred on the event and always contains it", () => {
  const center = Date.parse("2026-09-20T08:10:30.900Z");
  const resolution = windowAround(center, 15 * 60_000);
  assert.deepEqual(resolution.window, {
    start: "2026-09-20T07:55:30Z",
    end: "2026-09-20T08:25:31Z",
  });
  assert.ok(Date.parse(resolution.window?.start ?? "") <= center);
  assert.ok(center < Date.parse(resolution.window?.end ?? ""));
  assert.deepEqual(windowAround(Number.NaN, 1000), { window: null, problem: "invalid" });
});

test("microsecond wire times keep every digit", () => {
  assert.equal(microsToIso(1_789_891_830_123_456), "2026-09-20T08:10:30.123456Z");
  assert.equal(microsToIso(1_789_891_830_000_001), "2026-09-20T08:10:30.000001Z");
  assert.equal(microsToIso(0), "1970-01-01T00:00:00.000000Z");
  assert.equal(microsToIso(-1), "1969-12-31T23:59:59.999999Z");
  assert.equal(microsToIso(Number.NaN), "");
  assert.equal(microsOf("2026-09-20T08:10:30.1Z"), "100000");
  assert.equal(microsOf("2026-09-20T08:10:30Z"), "000000");
  assert.equal(microsOf("2026-09-20T08:10:30.123456789Z"), "123456");
});

test("local and UTC text for an instant", () => {
  inZone("Asia/Shanghai", () => {
    assert.equal(formatLocal("2026-09-20T08:10:30.123456Z"), "2026-09-20 16:10:30");
    assert.equal(
      formatLocal("2026-09-20T08:10:30.123456Z", "millisecond"),
      "2026-09-20 16:10:30.123",
    );
    assert.equal(
      formatLocal("2026-09-20T08:10:30.123456Z", "microsecond"),
      "2026-09-20 16:10:30.123456",
    );
    assert.equal(formatLocal("not a time"), "时间不可用");
  });
  assert.equal(
    formatUtc("2026-09-20T08:10:30.123456Z", "microsecond"),
    "2026-09-20 08:10:30.123456 UTC",
  );
  assert.equal(formatUtc("2026-09-20T08:10:30Z"), "2026-09-20 08:10:30 UTC");
  inZone("Asia/Shanghai", () => {
    assert.equal(toLocalInput(Date.parse("2026-09-20T08:10:30Z")), "2026-09-20T16:10:30");
  });
});

test("durations and spans read naturally", () => {
  assert.equal(formatDuration(84), "84 µs");
  assert.equal(formatDuration(1200), "1.20 ms");
  assert.equal(formatDuration(12_400), "12.4 ms");
  assert.equal(formatDuration(1_250_000), "1.25 s");
  assert.equal(formatSpan(42_000), "42 秒");
  assert.equal(formatSpan(180_000), "3 分钟");
  assert.equal(formatSpan(5 * 3_600_000), "5 小时");
  assert.equal(formatSpan(3 * 24 * 3_600_000), "3 天");
  assert.equal(formatSpan(-5), "0 秒");
});
