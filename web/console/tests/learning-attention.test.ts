import assert from "node:assert/strict";
import { test } from "node:test";
import type { TraceResponse } from "../src/api/types.ts";
import { learningAttention } from "../src/features/request-detail/detail-model.ts";

/** A response as the trace stores it; only the fields the attention line reads are set. */
function response(fields: Partial<TraceResponse>): TraceResponse {
  return { observed: "json", after_would_block: false, ...fields } as TraceResponse;
}

test("a refused response that was not read says it stayed out of the context", () => {
  const note = learningAttention(
    response({ observed: "skipped", skip: "would_block", after_would_block: true }),
  );
  assert.equal(note, "本应拦截请求的响应没有进入上下文");
});

test("a record written before refused responses stopped teaching says the response did enter the context", () => {
  const note = learningAttention(
    response({ observed: "json", values: 14, new_values: 9, after_would_block: true }),
  );
  assert.equal(note, "本应拦截请求的响应也进入了上下文（旧版本的记录）");
});

test("an ordinary response has no attention line", () => {
  assert.equal(learningAttention(response({ observed: "json", exposure: null })), null);
});
