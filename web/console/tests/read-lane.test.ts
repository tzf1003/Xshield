import assert from "node:assert/strict";
import { test } from "node:test";
import { ReadLane } from "../src/security/read-lane.ts";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

test("the lane never runs two reads at once and keeps the queue order", async () => {
  const lane = new ReadLane();
  let running = 0;
  let peak = 0;
  const read = (value: string, ms: number) => async () => {
    running += 1;
    peak = Math.max(peak, running);
    await sleep(ms);
    running -= 1;
    return value;
  };
  const results = await Promise.all([
    lane.run(read("first", 20)),
    lane.run(read("second", 0)),
    lane.run(read("third", 5)),
  ]);
  assert.deepEqual(results, ["first", "second", "third"]);
  assert.equal(peak, 1);
});

test("a read that fails does not hold up the reads queued behind it", async () => {
  const lane = new ReadLane();
  const failed = lane.run(async () => {
    throw new Error("CONTROL_EVIDENCE_ACCESS_BUSY");
  });
  const next = lane.run(async () => "served");
  await assert.rejects(failed, /CONTROL_EVIDENCE_ACCESS_BUSY/);
  assert.equal(await next, "served");
});
