// The control API client (src/api/client.ts). The control answers GET /api/session with 401 and
// {"authenticated": false} for a visitor who is not signed in. That is an answer, not a failure: the
// root guard must read it and send the visitor to the sign-in page. Any other 401 still opens the
// sign-in dialog and throws.

import assert from "node:assert/strict";
import { test } from "node:test";
import { api, ApiError, onUnauthorized } from "../src/api/client.ts";

type Requested = { url: string; method: string };

/** Replaces fetch with one fixed answer, and records the calls the client made. */
function answerEveryCallWith(
  status: number,
  body: unknown,
): { requested: Requested[]; restore: () => void } {
  const original = globalThis.fetch;
  const requested: Requested[] = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    requested.push({ url: String(input), method: init?.method ?? "GET" });
    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  return {
    requested,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

/** Counts how often the client asked for the sign-in dialog. */
function countSignInRequests(): { count: () => number; stop: () => void } {
  let calls = 0;
  const stop = onUnauthorized(() => {
    calls += 1;
  });
  return { count: () => calls, stop };
}

test("a signed-out session check is an answer: authenticated false, no error, no sign-in dialog", async () => {
  const fetchStub = answerEveryCallWith(401, { authenticated: false });
  const dialog = countSignInRequests();
  try {
    assert.deepEqual(await api.session(), { authenticated: false });
    assert.deepEqual(fetchStub.requested, [{ url: "/api/session", method: "GET" }]);
    assert.equal(dialog.count(), 0);
  } finally {
    dialog.stop();
    fetchStub.restore();
  }
});

test("a signed-in session check returns the state", async () => {
  const fetchStub = answerEveryCallWith(200, { authenticated: true });
  try {
    assert.deepEqual(await api.session(), { authenticated: true });
  } finally {
    fetchStub.restore();
  }
});

test("any other 401 still opens the sign-in dialog and throws the server's code", async () => {
  const fetchStub = answerEveryCallWith(401, { error: "UNAUTHENTICATED" });
  const dialog = countSignInRequests();
  try {
    await assert.rejects(api.requestCounts(""), (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.status, 401);
      assert.equal(error.code, "UNAUTHENTICATED");
      return true;
    });
    assert.equal(dialog.count(), 1);
  } finally {
    dialog.stop();
    fetchStub.restore();
  }
});
