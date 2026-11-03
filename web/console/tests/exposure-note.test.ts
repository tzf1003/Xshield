import assert from "node:assert/strict";
import { test } from "node:test";
import type { ResponseExposure } from "../src/api/types.ts";
import { exposureNote } from "../src/features/request-detail/detail-model.ts";

test("an exposure names each kind of contact detail once, in the order the response showed them", () => {
  const exposure: ResponseExposure = {
    users: ["GET /api/comments comments[].author.id"],
    attributes: [
      { slot: "GET /api/comments comments[].author.email", kind: "email", by: "name" },
      { slot: "GET /api/comments comments[].author.phone", kind: "phone", by: "name" },
      { slot: "GET /api/comments comments[].contact", kind: "phone", by: "format" },
    ],
  };
  assert.equal(
    exposureNote(exposure),
    "疑似属性越权，仅告警未拦截：响应里有不属于本会话的用户的邮箱、手机号",
  );
});

test("an absent or empty exposure has no note", () => {
  assert.equal(exposureNote(undefined), null);
  assert.equal(exposureNote(null), null);
  assert.equal(exposureNote({ users: [], attributes: [] }), null);
});

test("an identity-card exposure is named as such", () => {
  const exposure: ResponseExposure = {
    users: ["GET /api/cases records[].owner.id"],
    attributes: [{ slot: "GET /api/cases records[].owner.card", kind: "id_card", by: "format" }],
  };
  assert.equal(
    exposureNote(exposure),
    "疑似属性越权，仅告警未拦截：响应里有不属于本会话的用户的身份证号",
  );
});
