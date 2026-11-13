// A batch of calls: every item is sent, and a refusal is reported only after all have settled.

import assert from "node:assert/strict";
import { test } from "node:test";
import { sendAll } from "../src/lib/settle.ts";

test("every item is sent and the batch resolves when none is refused", async () => {
  const sent: string[] = [];
  await sendAll(["a", "b", "c"], async (id) => {
    sent.push(id);
  });
  assert.deepEqual(sent, ["a", "b", "c"]);
});

test("a refused item does not stop the others and its error is the one reported", async () => {
  const sent: string[] = [];
  const first = new Error("first refusal");
  await assert.rejects(
    sendAll(["a", "b", "c"], async (id) => {
      sent.push(id);
      if (id === "a") throw first;
      if (id === "c") throw new Error("later refusal");
    }),
    (error) => error === first,
  );
  assert.deepEqual(sent, ["a", "b", "c"]);
});

test("an empty batch resolves without a call", async () => {
  await sendAll([], () => Promise.reject(new Error("never called")));
});
