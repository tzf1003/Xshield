import assert from "node:assert/strict";
import test from "node:test";
import { buildCausalNeighborhood, type CausalRecord } from "../src/event-causality.ts";

const event = (id: string, causeIds: string[] = []): CausalRecord => ({
  event_id: id,
  event_type: "stage.completed",
  stage: "admission",
  cause_event_ids: causeIds,
});

test("builds bounded predecessor and successor paths from recorded edges", () => {
  const root = event("ev-root", ["ev-parent"]);
  const records = [
    root,
    event("ev-parent", ["ev-grandparent"]),
    event("ev-grandparent"),
    event("ev-child", ["ev-root"]),
  ];

  const result = buildCausalNeighborhood(root, records);

  assert.deepEqual(
    result.predecessors.map((level) => level.map((node) => node.eventId)),
    [["ev-parent"], ["ev-grandparent"]],
  );
  assert.deepEqual(
    result.successors.map((level) => level.map((node) => node.eventId)),
    [["ev-child"]],
  );
  assert.equal(result.predecessors[0]?.[0]?.event?.event_type, "stage.completed");
  assert.equal(result.truncated, false);
});

test("keeps unloaded references navigable and terminates cycles", () => {
  const root = event("ev-root", ["ev-missing", "ev-cycle"]);
  const cycle = event("ev-cycle", ["ev-root"]);

  const result = buildCausalNeighborhood(root, [root, cycle]);

  assert.deepEqual(
    result.predecessors.map((level) => level.map((node) => node.eventId)),
    [["ev-cycle", "ev-missing"]],
  );
  assert.equal(result.predecessors[0]?.[1]?.event, null);
  assert.equal(result.predecessors.length, 1);
  assert.equal(result.truncated, false);
});

test("caps broad neighborhoods deterministically", () => {
  const root = event("ev-root");
  const records = [
    root,
    ...Array.from({ length: 20 }, (_, index) =>
      event(`ev-child-${String(index).padStart(2, "0")}`, ["ev-root"]),
    ),
  ];

  const result = buildCausalNeighborhood(root, records);
  const ids = result.successors.flatMap((level) => level.map((node) => node.eventId));

  assert.equal(ids.length, 16);
  assert.deepEqual(ids, [...ids].sort());
  assert.equal(result.truncated, true);
});
