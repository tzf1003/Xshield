import { test } from "node:test";
import assert from "node:assert/strict";
import { api, ApiError, describeApiError, onUnauthorized } from "../src/api.ts";

type Call = { url: string; init?: RequestInit };

function mockFetch(responder: (call: Call) => { status: number; body?: unknown }) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL, init?: RequestInit) => {
    const call = { url: String(url), init };
    calls.push(call);
    const { status, body } = responder(call);
    return new Response(body === undefined ? null : JSON.stringify(body), {
      status,
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

test("api.login posts the password and includes credentials", async () => {
  const { calls, restore } = mockFetch(() => ({ status: 200, body: {} }));
  try {
    await api.login("hunter2");
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.url, "/api/login");
    assert.equal(calls[0]?.init?.method, "POST");
    assert.equal(calls[0]?.init?.credentials, "include");
    assert.deepEqual(JSON.parse(String(calls[0]?.init?.body)), { password: "hunter2" });
  } finally {
    restore();
  }
});

test("api.listSites performs a plain GET and returns the parsed array", async () => {
  const sites = [
    {
      name: "emr",
      hosts: ["emr.example.com"],
      origin: "http://10.0.0.5:8080",
      session: { cookie: "SESSIONID" },
      entries: ["/login"],
      bypass: [],
      mode: "observe",
      on_jev_unavailable: "deny",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    },
  ];
  const { calls, restore } = mockFetch(() => ({ status: 200, body: sites }));
  try {
    const result = await api.listSites();
    assert.equal(calls[0]?.url, "/api/sites");
    assert.equal(calls[0]?.init?.method, undefined);
    assert.deepEqual(result, sites);
  } finally {
    restore();
  }
});

test("api.decisions builds a query string and omits undefined/empty params", async () => {
  const { calls, restore } = mockFetch(() => ({ status: 200, body: [] }));
  try {
    await api.decisions({
      site: "emr",
      session: undefined,
      path: "",
      outcome: "blocked",
      before_id: 42,
      limit: 50,
    });
    const url = new URL(calls[0]?.url ?? "", "http://localhost");
    assert.equal(url.pathname, "/api/decisions");
    assert.equal(url.searchParams.get("site"), "emr");
    assert.equal(url.searchParams.get("outcome"), "blocked");
    assert.equal(url.searchParams.get("before_id"), "42");
    assert.equal(url.searchParams.has("session"), false);
    assert.equal(url.searchParams.has("path"), false);
  } finally {
    restore();
  }
});

test("a non-2xx response throws ApiError carrying the server's error code", async () => {
  const { restore } = mockFetch(() => ({
    status: 400,
    body: { error: "SITE_CONFIG_HOSTS_INVALID" },
  }));
  try {
    await assert.rejects(
      () =>
        api.createSite({
          name: "bad",
          hosts: [],
          origin: "http://x",
          session: { cookie: "S" },
          entries: ["/login"],
          bypass: [],
          mode: "observe",
          on_jev_unavailable: "deny",
        }),
      (error: unknown) => {
        assert.ok(error instanceof ApiError);
        assert.equal(error.status, 400);
        assert.equal(error.code, "SITE_CONFIG_HOSTS_INVALID");
        return true;
      },
    );
  } finally {
    restore();
  }
});

test("describeApiError translates known codes and falls back for unknown ones", () => {
  const known = new ApiError(409, "SITE_EXISTS", "SITE_EXISTS");
  assert.equal(describeApiError(known), "站点名已存在");
  const unknown = new ApiError(500, undefined, "boom");
  assert.equal(describeApiError(unknown), "boom");
});

test("a 401 response notifies every registered onUnauthorized listener", async () => {
  const { restore } = mockFetch(() => ({ status: 401, body: { authenticated: false } }));
  let notified = 0;
  const unsubscribe = onUnauthorized(() => {
    notified += 1;
  });
  try {
    await assert.rejects(() => api.session());
    assert.equal(notified, 1);
  } finally {
    unsubscribe();
    restore();
  }
});

test("a 204 response (delete) resolves without attempting to parse a body", async () => {
  const { restore } = mockFetch(() => ({ status: 204 }));
  try {
    await assert.doesNotReject(() => api.deleteSite("emr"));
  } finally {
    restore();
  }
});
