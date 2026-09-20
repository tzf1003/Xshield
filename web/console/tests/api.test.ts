import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { ApiError, ControlClient } from "../src/api.ts";
import { validateSearchPlan, searchPlanDigest } from "../src/search.ts";
import type { SearchPlan, SearchResponse } from "../src/search.ts";
import {
  BINDING_ID,
  GRANT_ID,
  OTHER_BINDING_ID,
  OTHER_GRANT_ID,
  bindingFixture,
  grantFixture,
} from "./ledger-fixtures.ts";
import {
  TOKEN,
  REQUEST_ID,
  OTHER_REQUEST_ID,
  ARTIFACT_ID,
  MODEL_CALL_ID,
  OTHER_MODEL_CALL_ID,
  EVENT_CURSOR,
  EVIDENCE_CURSOR,
  summaryFixture,
  eventsFixture,
  evidenceFixture,
  artifactFixture,
  errorFixture,
  modelCallFixture,
} from "./fixtures.ts";

const response = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
const errorIs = (code: string, status?: number) => (error: unknown) => {
  assert.ok(error instanceof ApiError);
  assert.equal(error.code, code);
  if (status !== undefined) assert.equal(error.status, status);
  assert.ok(!error.message.includes("Synthetic server detail"));
  assert.ok(!error.message.includes(TOKEN));
  return true;
};

test("fixed GET routes preserve wire semantics and safe display metadata", async (t) => {
  const fixtures = [
    summaryFixture(),
    eventsFixture(),
    evidenceFixture(),
    artifactFixture(),
    modelCallFixture(),
  ];
  const paths = [
    `/control/v1/requests/${REQUEST_ID}`,
    `/control/v1/requests/${REQUEST_ID}/events?cursor=${EVENT_CURSOR}`,
    `/control/v1/requests/${REQUEST_ID}/evidence?cursor=${EVIDENCE_CURSOR}`,
    `/control/v1/artifacts/${ARTIFACT_ID}`,
    `/control/v1/model-calls/${MODEL_CALL_ID}`,
  ];
  let index = 0;
  t.mock.method(
    globalThis,
    "fetch",
    async (path: string, options: RequestInit) => {
      assert.equal(path, paths[index]);
      assert.equal(options.method, "GET");
      assert.deepEqual(options.headers, {
        Authorization: `Bearer ${TOKEN}`,
        Accept: "application/json",
      });
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.redirect, "error");
      assert.equal(options.referrerPolicy, "no-referrer");
      assert.ok(options.signal instanceof AbortSignal);
      return response(fixtures[index++]);
    },
  );
  const client = new ControlClient(TOKEN);
  assert.ok(!JSON.stringify(client).includes(TOKEN));
  const summary = await client.summary(REQUEST_ID);
  assert.equal(summary.summary?.decision, "DENY");
  assert.equal(summary.summary?.stages[0]?.confidence, null);
  assert.equal(summary.completeness, "complete");
  assert.equal(summary.has_gaps, true);
  const events = await client.events(REQUEST_ID, EVENT_CURSOR);
  assert.equal(events.events[0]?.occurred_at, Date.parse(summary.as_of) * 1000);
  assert.equal(events.events[0]?.model_revision, "");
  assert.equal(events.next_cursor, EVENT_CURSOR);
  const evidence = await client.evidence(REQUEST_ID, EVIDENCE_CURSOR);
  const artifact = await client.artifact(ARTIFACT_ID);
  assert.equal(
    evidence.artifacts[0]?.artifact_id,
    artifact.artifact?.artifact_id,
  );
  for (const item of [evidence.artifacts[0], artifact.artifact]) {
    assert.ok(item);
    assert.ok(!("storage" in item));
    assert.ok(!("integrity" in item));
  }
  const model = await client.modelCall(MODEL_CALL_ID);
  assert.deepEqual(model, modelCallFixture());
  assert.equal(index, 5);
});

test("invalid IDs, opaque cursor transport and credentials fail before network use", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected network");
  });
  for (const token of [
    "",
    "x".repeat(31),
    "x".repeat(513),
    `${TOKEN}\n`,
    `${TOKEN} `,
    "界".repeat(32),
  ]) {
    assert.throws(
      () => new ControlClient(token),
      errorIs("INVALID_CREDENTIAL"),
    );
  }
  const client = new ControlClient(TOKEN);
  for (const request of [
    "https://example.invalid/",
    "../requests",
    REQUEST_ID.toUpperCase(),
    REQUEST_ID.replace("-7000-", "-4000-"),
    `${REQUEST_ID}?extra=1`,
    `${REQUEST_ID}\n`,
    `${REQUEST_ID}\r`,
    `${REQUEST_ID}\u2028`,
    `${REQUEST_ID}\u2029`,
  ]) {
    await assert.rejects(
      client.summary(request),
      errorIs("CONTROL_REQUEST_ID_INVALID"),
    );
    await assert.rejects(
      client.events(request),
      errorIs("CONTROL_REQUEST_ID_INVALID"),
    );
    await assert.rejects(
      client.evidence(request),
      errorIs("CONTROL_REQUEST_ID_INVALID"),
    );
  }
  await assert.rejects(
    client.artifact(REQUEST_ID),
    errorIs("CONTROL_ARTIFACT_ID_INVALID"),
  );
  for (const value of [
    REQUEST_ID,
    MODEL_CALL_ID.toUpperCase(),
    `${MODEL_CALL_ID}?extra=1`,
    MODEL_CALL_ID.replace("-7000-", "-4000-"),
    `${MODEL_CALL_ID}\n`,
    `${MODEL_CALL_ID}\u2028`,
  ])
    await assert.rejects(
      client.modelCall(value),
      errorIs("CONTROL_MODEL_CALL_ID_INVALID"),
    );
  for (const cursor of [
    "",
    "a".repeat(161),
    "foo&limit=100",
    "%76%31",
    "a/b",
    "a+b",
    "a\nb",
  ]) {
    await assert.rejects(
      client.events(REQUEST_ID, cursor),
      errorIs("CONTROL_CURSOR_INVALID"),
    );
    await assert.rejects(
      client.evidence(REQUEST_ID, cursor),
      errorIs("CONTROL_CURSOR_INVALID"),
    );
  }
  assert.equal(network.mock.callCount(), 0);
});

test("model call projection preserves lifecycle, missing history and Noul confidence", async (t) => {
  const client = new ControlClient(TOKEN);
  const value = modelCallFixture();
  t.mock.method(globalThis, "fetch", async () => response(value));
  assert.deepEqual(await client.modelCall(MODEL_CALL_ID), value);
  for (const item of [value.model_call, ...value.model_call.events])
    Object.assign(item, {
      provider: null,
      provider_model_id: null,
      question_type: "noul",
      confidence: null,
      confidence_status: "not_applicable",
    });
  value.model_call.events = value.model_call.events.slice(-1);
  value.model_call.lifecycle_complete = false;
  value.completeness = "partial";
  assert.deepEqual(await client.modelCall(MODEL_CALL_ID), value);
  const missing = {
    ...value,
    found: false,
    model_call: null,
    completeness: "not_indexed",
  };
  t.mock.method(globalThis, "fetch", async () => response(missing));
  assert.deepEqual(await client.modelCall(MODEL_CALL_ID), missing);
});

test("model call projection accepts pending prefixes and pre-send failure", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const length of [1, 2]) {
    const value = modelCallFixture();
    value.model_call.events = value.model_call.events.slice(0, length);
    Object.assign(value.model_call, value.model_call.events.at(-1), {
      lifecycle_complete: false,
    });
    value.completeness = "pending";
    t.mock.method(globalThis, "fetch", async () => response(value));
    const result = await client.modelCall(MODEL_CALL_ID);
    assert.equal(result.completeness, "pending");
    assert.equal(result.model_call?.events.length, length);
  }
  const value = modelCallFixture();
  const failure = {
    ...value.model_call.events[0]!,
    status: "error",
    event_type: "model.failed",
    reason_code: "MODEL_EVIDENCE_UNAVAILABLE",
    request_seq: 2,
    event_id: value.model_call.events[1]!.event_id,
    cause_event_ids: [value.model_call.events[0]!.event_id],
  };
  value.model_call.events = [value.model_call.events[0]!, failure];
  Object.assign(value.model_call, failure);
  t.mock.method(globalThis, "fetch", async () => response(value));
  const result = await client.modelCall(MODEL_CALL_ID);
  assert.equal(result.completeness, "complete");
  assert.equal(result.model_call?.status, "error");
  assert.equal(result.model_call?.input_artifact_id, null);
});

test("model call projection rejects contradictory lifecycle and malformed identity", async (t) => {
  const client = new ControlClient(TOKEN);
  const mutations: Array<(value: ReturnType<typeof modelCallFixture>) => void> =
    [
      (value) => {
        value.source_model_call_id = OTHER_MODEL_CALL_ID;
      },
      (value) => {
        value.model_call.model_call_id = OTHER_MODEL_CALL_ID;
      },
      (value) => {
        value.watermark_scope = "all_journals";
      },
      (value) => {
        value.found = false;
      },
      (value) => {
        value.completeness = "partial";
      },
      (value) => {
        value.model_call.lifecycle_complete = false;
      },
      (value) => {
        value.model_call.events = [];
      },
      (value) => {
        value.model_call.events.reverse();
      },
      (value) => {
        value.model_call.events[1]!.request_id = OTHER_REQUEST_ID;
      },
      (value) => {
        value.model_call.events[1]!.provider_model_id = "jev-1.13.0";
      },
      (value) => {
        Object.assign(value.model_call, { provider: null });
      },
      (value) => {
        Reflect.deleteProperty(value.model_call, "provider");
      },
      (value) => {
        value.model_call.confidence = 0.2;
      },
      (value) => {
        value.model_call.events[0]!.confidence = 0.2;
        value.model_call.events[0]!.confidence_status = "provided";
      },
      (value) => {
        value.model_call.events[2]!.question_type = "noul";
      },
      (value) => {
        value.model_call.events[2]!.event_type = "model.cancelled";
      },
      (value) => {
        value.model_call.events[2]!.evidence_refs = [];
      },
      (value) => {
        value.model_call.events[1]!.cause_event_ids = [];
      },
      (value) => {
        value.model_call.events[2]!.cause_event_ids = [
          value.model_call.events[0]!.event_id,
        ];
      },
      (value) => {
        value.model_call.events[1]!.request_seq = 1;
      },
      (value) => {
        value.model_call.events[2]!.occurred_at = "invalid";
      },
      (value) => {
        value.model_call.events[2]!.duration_us = Number.MAX_SAFE_INTEGER + 1;
      },
      (value) => {
        value.model_call.output_artifact_id = ARTIFACT_ID;
      },
      (value) => {
        value.model_call.events[0]!.input_artifact_id = ARTIFACT_ID;
        value.model_call.events[0]!.evidence_refs = [ARTIFACT_ID];
      },
      (value) => {
        value.model_call.events[2]!.cause_event_ids = [
          value.model_call.events[2]!.event_id,
        ];
      },
      (value) => {
        value.model_call.events.splice(0, 1);
        Object.assign(value.model_call.events[1]!, {
          ...value.model_call.events[0]!,
          event_id: "ev_018f2a3b-4c5d-7000-8000-000000000003",
          request_seq: 3,
          cause_event_ids: [value.model_call.events[0]!.event_id],
        });
        Object.assign(value.model_call, value.model_call.events[1], {
          lifecycle_complete: false,
        });
        value.completeness = "pending";
      },
    ];
  for (const mutate of mutations) {
    const value = modelCallFixture();
    mutate(value);
    t.mock.method(globalThis, "fetch", async () => response(value));
    await assert.rejects(
      client.modelCall(MODEL_CALL_ID),
      errorIs("INVALID_RESPONSE", 200),
    );
  }
  const value = modelCallFixture();
  Object.assign(value.model_call, {
    payload_json: "synthetic-secret-body",
    provider_response: "synthetic-raw-response",
  });
  t.mock.method(globalThis, "fetch", async () => response(value));
  const projected = await client.modelCall(MODEL_CALL_ID);
  assert.ok(!JSON.stringify(projected).includes("synthetic-secret-body"));
  assert.ok(!JSON.stringify(projected).includes("synthetic-raw-response"));
});

test("missing and pending results retain honest completeness and nullable fields", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const [pending, gaps, completeness] of [
    [0, false, "not_found"],
    [1, false, "pending_index"],
    [0, true, "pending_index"],
  ] as const) {
    const value = {
      ...summaryFixture(),
      found: false,
      summary: null,
      pending_segments: pending,
      has_gaps: gaps,
      completeness,
      index_watermark: null,
    };
    t.mock.method(globalThis, "fetch", async () => response(value));
    assert.deepEqual(await client.summary(REQUEST_ID), value);
  }
  const value = summaryFixture();
  Object.assign(value.summary, {
    method: null,
    operation_id: null,
    decision: null,
    reason_code: null,
    status: null,
    origin_state: null,
    duration_us: null,
    terminal: false,
  });
  value.completeness = "pending";
  t.mock.method(globalThis, "fetch", async () => response(value));
  assert.equal((await client.summary(REQUEST_ID)).completeness, "pending");
  const unavailable = { ...artifactFixture(), found: false, artifact: null };
  t.mock.method(globalThis, "fetch", async () => response(unavailable));
  assert.deepEqual(await client.artifact(ARTIFACT_ID), unavailable);
});

test("malformed summary facts are rejected instead of filling missing data", async (t) => {
  const client = new ControlClient(TOKEN);
  const mutations: Array<(value: ReturnType<typeof summaryFixture>) => void> = [
    (value) => {
      value.source_request_id = OTHER_REQUEST_ID;
    },
    (value) => {
      value.request_id = "invalid";
    },
    (value) => {
      value.tenant_id = "<script>";
    },
    (value) => {
      value.as_of = "invalid";
    },
    (value) => {
      value.as_of = "2026-02-30T08:10:30Z";
    },
    (value) => {
      value.summary.first_occurred_at = "2026-09-20T24:00:00Z";
    },
    (value) => {
      value.found = false;
    },
    (value) => {
      value.completeness = "not_found";
    },
    (value) => {
      value.summary.event_count = Number.MAX_SAFE_INTEGER + 1;
    },
    (value) => {
      value.pending_segments = -1;
    },
    (value) => {
      value.index_watermark.producer_sequence = 0;
    },
    (value) => {
      value.summary.status = 999;
    },
    (value) => {
      value.summary.business_result_confirmed = true;
    },
    (value) => {
      value.summary.terminal = false;
    },
    (value) => {
      value.summary.stages[0]!.last_request_seq = 0;
    },
    (value) => {
      value.summary.stages[0]!.proof_kind = "untrusted";
    },
    (value) => {
      value.summary.stages[0]!.confidence_status = "provided";
    },
    (value) => {
      value.summary.stages.push(value.summary.stages[0]!);
    },
  ];
  for (const mutate of mutations) {
    const value = summaryFixture();
    mutate(value);
    t.mock.method(globalThis, "fetch", async () => response(value));
    await assert.rejects(
      client.summary(REQUEST_ID),
      errorIs("INVALID_RESPONSE", 200),
    );
  }
});

test("timeline validates sequence, numeric precision, references and pagination", async (t) => {
  const client = new ControlClient(TOKEN);
  const mutations: Array<(value: ReturnType<typeof eventsFixture>) => void> = [
    (value) => {
      value.source_request_id = OTHER_REQUEST_ID;
    },
    (value) => {
      value.truncated = false;
    },
    (value) => {
      value.next_cursor = "cursor&target=other";
    },
    (value) => {
      value.events[0]!.occurred_at = Number.MAX_SAFE_INTEGER + 1;
    },
    (value) => {
      value.events[0]!.duration_us = -1;
    },
    (value) => {
      value.events[0]!.request_seq = 0;
    },
    (value) => {
      value.events[0]!.event_id = ARTIFACT_ID;
    },
    (value) => {
      value.events[0]!.evidence_refs = ["artifact_invalid"];
    },
    (value) => {
      Object.assign(value.events[0]!, { cause_event_ids: [ARTIFACT_ID] });
    },
    (value) => {
      value.events[0]!.evidence_refs = [ARTIFACT_ID, ARTIFACT_ID];
    },
    (value) => {
      value.events.reverse();
    },
    (value) => {
      value.events = [];
    },
    (value) => {
      value.events = Array.from({ length: 1001 }, () => value.events[0]!);
    },
  ];
  for (const mutate of mutations) {
    const value = eventsFixture();
    mutate(value);
    t.mock.method(globalThis, "fetch", async () => response(value));
    await assert.rejects(
      client.events(REQUEST_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
  const nullable = eventsFixture(REQUEST_ID, true);
  Object.assign(nullable.events[0]!, {
    stage: "",
    reason_code: "",
    outcome: "",
    proof_kind: "",
    confidence_status: "",
  });
  t.mock.method(globalThis, "fetch", async () => response(nullable));
  assert.equal((await client.events(REQUEST_ID)).events[0]?.stage, "");
  const model = eventsFixture(REQUEST_ID, true);
  Object.assign(model.events[0]!, {
    proof_kind: "model",
    model_revision: "model-r1",
    confidence: 0.83,
    confidence_status: "provided",
  });
  t.mock.method(globalThis, "fetch", async () => response(model));
  assert.equal((await client.events(REQUEST_ID)).events[0]?.confidence, 0.83);
  for (const confidence of [-0.1, 1.1, Infinity, NaN]) {
    Object.assign(model.events[0]!, { confidence });
    await assert.rejects(
      client.events(REQUEST_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
});

test("manifest projection validates exact scope, target, fidelity and page relationships", async (t) => {
  const client = new ControlClient(TOKEN);
  const mutations: Array<(value: ReturnType<typeof evidenceFixture>) => void> =
    [
      (value) => {
        value.source_request_id = OTHER_REQUEST_ID;
      },
      (value) => {
        value.artifacts[0]!.tenant_id = "tenant_other";
      },
      (value) => {
        value.artifacts[0]!.site_id = "site_other";
      },
      (value) => {
        value.artifacts[0]!.request_id = OTHER_REQUEST_ID;
      },
      (value) => {
        value.artifacts[0]!.schema_version = 4;
      },
      (value) => {
        value.artifacts[0]!.example_only = true;
      },
      (value) => {
        value.artifacts[0]!.bytes_saved = 257;
      },
      (value) => {
        value.artifacts[0]!.fidelity = "perfect";
      },
      (value) => {
        value.artifacts[0]!.classification = "PUBLIC";
      },
      (value) => {
        value.artifacts[0]!.content_type = "text/html\nLocation: evil";
      },
      (value) => {
        value.artifacts.push(value.artifacts[0]!);
      },
      (value) => {
        value.artifacts = [];
      },
    ];
  for (const mutate of mutations) {
    const value = evidenceFixture();
    mutate(value);
    t.mock.method(globalThis, "fetch", async () => response(value));
    await assert.rejects(
      client.evidence(REQUEST_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
  for (const value of [
    { ...artifactFixture(), source_artifact_id: REQUEST_ID },
    { ...artifactFixture(), found: false },
    {
      ...artifactFixture(),
      artifact: {
        ...artifactFixture().artifact,
        artifact_id: "artifact_018f2a3b-4c5d-7000-8000-000000000012",
      },
    },
  ]) {
    t.mock.method(globalThis, "fetch", async () => response(value));
    await assert.rejects(
      client.artifact(ARTIFACT_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
});

test("HTTP diagnostics preserve status and safe request ID while discarding server details", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const [status, code] of [
    [401, "CONTROL_AUTH_REQUIRED"],
    [403, "CONTROL_SCOPE_DENIED"],
    [429, "CONTROL_RATE_LIMITED"],
    [429, "CONTROL_QUERY_BUDGET_EXCEEDED"],
    [429, "CONTROL_QUERY_CAPACITY_EXHAUSTED"],
    [503, "CONTROL_QUERY_TIMEOUT"],
    [503, "AUDIT_DURABILITY_FAILED"],
  ] as const) {
    t.mock.method(globalThis, "fetch", async () =>
      response(errorFixture(code), status),
    );
    await assert.rejects(client.summary(REQUEST_ID), (error) => {
      errorIs(code, status)(error);
      assert.equal(
        (error as ApiError).requestId,
        errorFixture(code).request_id,
      );
      return true;
    });
  }
  t.mock.method(globalThis, "fetch", async () =>
    response(
      {
        error_code: "ATTACKER_DETAIL",
        request_id: "<script>",
        message_safe: TOKEN,
      },
      500,
    ),
  );
  await assert.rejects(client.summary(REQUEST_ID), (error) => {
    errorIs("HTTP_ERROR", 500)(error);
    assert.equal((error as ApiError).requestId, null);
    return true;
  });
  t.mock.method(globalThis, "fetch", async () => {
    throw new Error(TOKEN);
  });
  await assert.rejects(
    client.summary(REQUEST_ID),
    errorIs("NETWORK_UNAVAILABLE"),
  );
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response("<html>session expired</html>", {
        status: 401,
        headers: { "content-type": "text/html" },
      }),
  );
  await assert.rejects(
    client.summary(REQUEST_ID),
    errorIs("INVALID_RESPONSE", 401),
  );
});

test("bounded stream decoding rejects oversized, invalid UTF-8, HTML and invalid JSON bodies", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const [body, headers, code] of [
    [
      "<html>private</html>",
      { "content-type": "text/html" },
      "INVALID_RESPONSE",
    ],
    ["{bad}", { "content-type": "application/json" }, "INVALID_RESPONSE"],
    [
      "{}",
      {
        "content-type": "application/json",
        "content-length": String(16 * 1024 * 1024 + 1),
      },
      "RESPONSE_TOO_LARGE",
    ],
    [
      "{}",
      { "content-type": "application/json", "content-length": "-1" },
      "INVALID_RESPONSE",
    ],
  ] as const) {
    t.mock.method(
      globalThis,
      "fetch",
      async () => new Response(body, { headers }),
    );
    await assert.rejects(client.summary(REQUEST_ID), errorIs(code));
  }
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(new Uint8Array([0xff]), {
        headers: { "content-type": "application/json" },
      }),
  );
  await assert.rejects(client.summary(REQUEST_ID), errorIs("INVALID_RESPONSE"));
  let cancelled = false;
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(16 * 1024 * 1024 + 1));
          },
          cancel() {
            cancelled = true;
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  await assert.rejects(
    client.summary(REQUEST_ID),
    errorIs("RESPONSE_TOO_LARGE"),
  );
  assert.equal(cancelled, true);
  const encoded = new TextEncoder().encode(
    JSON.stringify({ ...summaryFixture(), ignored: "证据" }),
  );
  const boundary = encoded.length - 5;
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encoded.slice(0, boundary));
            controller.enqueue(encoded.slice(boundary));
            controller.close();
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  assert.equal((await client.summary(REQUEST_ID)).found, true);
});

test("external cancellation and 15-second deadline return sanitized terminal errors", async (t) => {
  const client = new ControlClient(TOKEN);
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    (_path: string, options: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        options.signal!.addEventListener(
          "abort",
          () => reject(new Error(TOKEN)),
          { once: true },
        );
      }),
  );
  const preAborted = new AbortController();
  preAborted.abort(TOKEN);
  await assert.rejects(
    client.summary(REQUEST_ID, preAborted.signal),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(fetch.mock.callCount(), 0);
  const cancelled = new AbortController();
  const inFlight = client.summary(REQUEST_ID, cancelled.signal);
  cancelled.abort(TOKEN);
  await assert.rejects(inFlight, errorIs("REQUEST_ABORTED"));
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const timedOut = client.summary(REQUEST_ID);
  t.mock.timers.tick(14_999);
  assert.equal(
    (fetch.mock.calls.at(-1)!.arguments[1] as RequestInit).signal!.aborted,
    false,
  );
  t.mock.timers.tick(1);
  await assert.rejects(timedOut, errorIs("REQUEST_TIMEOUT"));
});

test("deadline also covers a stalled response body after headers arrive", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let reading = false;
  t.mock.method(
    globalThis,
    "fetch",
    async (_path: string, options: RequestInit) =>
      new Response(
        new ReadableStream({
          start(controller) {
            options.signal!.addEventListener(
              "abort",
              () => controller.error(new Error(TOKEN)),
              { once: true },
            );
          },
          pull() {
            reading = true;
          },
        }),
        { headers: { "content-type": "application/json" } },
      ),
  );
  const pending = new ControlClient(TOKEN).summary(REQUEST_ID);
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(reading, true);
  t.mock.timers.tick(15_000);
  await assert.rejects(pending, errorIs("REQUEST_TIMEOUT", 200));
});

function searchPlan(): SearchPlan {
  return {
    schema_version: 3,
    start: "2026-09-20T00:00:00Z",
    end: "2026-09-21T00:00:00Z",
    filters: [],
    sort: "occurred_at_asc",
    limit: 2,
  };
}
function searchCursor(event: SearchResponse["events"][number]): string {
  const time =
    BigInt(Date.parse(event.occurred_at.slice(0, 19) + "Z")) * 1000n +
    BigInt(event.occurred_at.slice(20, 26));
  return `v1.${time}.${event.event_id}.${"a".repeat(64)}`;
}
async function searchResponse(plan = searchPlan()): Promise<SearchResponse> {
  const source = summaryFixture();
  const events = [2, 1].map((id, index) => ({
    request_id: null,
    event_id: `ev_018f2a3b-4c5d-7000-8000-${String(id).padStart(12, "0")}`,
    event_type: "origin.response",
    stage: null,
    outcome: null,
    reason_code: null,
    proof_kind: null,
    confidence: null,
    confidence_status: null,
    occurred_at: `2026-09-20T08:10:30.12345${index + 6}Z`,
    request_seq: index + 1,
    duration_us: 0,
    policy_revision: "policy-r1",
    model_revision: null,
    evidence_refs: [ARTIFACT_ID],
    cause_event_ids: [],
    sensitivity: "INTERNAL",
  }));
  if (plan.sort === "occurred_at_desc") events.reverse();
  return {
    schema_version: 3,
    request_id: source.request_id,
    tenant_id: source.tenant_id,
    site_id: source.site_id,
    as_of: source.as_of,
    index_watermark: source.index_watermark,
    has_gaps: true,
    pending_segments: 2,
    query_digest: await searchPlanDigest(plan),
    scanned_rows: null,
    scanned_bytes: 0,
    truncated: true,
    next_cursor: searchCursor(events.at(-1)!),
    events,
  };
}

test("search freezes a strict plan and posts only to its fixed audited read route", async (t) => {
  const plan = searchPlan();
  const original = structuredClone(plan);
  const fixture = await searchResponse();
  const fetch = t.mock.method(
    globalThis,
    "fetch",
    async (path: string, options: RequestInit) => {
      assert.equal(path, "/control/v1/search");
      assert.equal(options.method, "POST");
      assert.deepEqual(options.headers, {
        Authorization: `Bearer ${TOKEN}`,
        Accept: "application/json",
        "Content-Type": "application/json",
      });
      assert.deepEqual(JSON.parse(String(options.body)), original);
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.redirect, "error");
      assert.equal(options.referrerPolicy, "no-referrer");
      assert.ok(options.signal instanceof AbortSignal);
      return response({
        ...fixture,
        payload_json: TOKEN,
        events: fixture.events.map((event) => ({
          ...event,
          payload_json: TOKEN,
        })),
      });
    },
  );
  const pending = new ControlClient(TOKEN).search(plan);
  plan.filters.push({ kind: "request_id", value: OTHER_REQUEST_ID });
  plan.limit = 100;
  const actual = await pending;
  assert.deepEqual(actual, fixture);
  assert.ok(!JSON.stringify(actual).includes(TOKEN));
  assert.equal(fetch.mock.callCount(), 1);
});

test("search canonical digest covers every predicate and retained filter order", async () => {
  const plan = searchPlan();
  const suffix = "018f2a3b-4c5d-7000-8000-000000000001";
  plan.filters = [
    { kind: "request_id", value: REQUEST_ID },
    { kind: "event_id", value: `ev_${suffix}` },
    { kind: "grant_id", value: `grant_${suffix}` },
    { kind: "auth_binding_id", value: `auth_${suffix}` },
    { kind: "case_id", value: `case_${suffix}` },
    { kind: "artifact_id", value: ARTIFACT_ID },
    { kind: "text", field: "operation_id", value: "orders:read" },
    { kind: "confidence_at_most", basis_points: 1234 },
  ];
  const canonical = `1789862400|1789948800|asc|2|request_id=${REQUEST_ID}|event_id=ev_${suffix}|grant_id=grant_${suffix}|auth_binding_id=auth_${suffix}|case_id=case_${suffix}|artifact_id=${ARTIFACT_ID}|operation_id=orders:read|confidence<=1234`;
  const expected = createHash("sha256").update(canonical).digest("hex");
  assert.equal(await searchPlanDigest(validateSearchPlan(plan)), expected);
  plan.filters.reverse();
  assert.notEqual(await searchPlanDigest(plan), expected);
  plan.filters = [{ kind: "outcome", value: "DENY" }];
  assert.equal(
    await searchPlanDigest(plan),
    createHash("sha256")
      .update("1789862400|1789948800|asc|2|outcome=DENY")
      .digest("hex"),
  );
  const normalized = validateSearchPlan({
    ...plan,
    start: "2026-09-20T00:00:00.000+00:00",
  });
  assert.equal(normalized.start, plan.start);
  normalized.filters.length = 0;
  assert.equal(plan.filters.length, 1);
});

test("invalid search inputs fail before network and preserve strict query budgets", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected network");
  });
  const client = new ControlClient(TOKEN);
  const invalid = [
    { schema_version: 4 },
    { tenant_id: "tenant_other" },
    { sql: "SELECT 1" },
    { cursor: "cursor" },
    { start: "2026-02-30T00:00:00Z" },
    { start: "2026-09-20T00:00:00.000001Z" },
    { start: "2026-09-20T00:00:00+08:00" },
    { start: "1969-12-31T23:59:59Z" },
    { start: "2026-09-21T00:00:00Z" },
    { end: "2026-10-22T00:00:00Z" },
    { start: "2300-01-01T00:00:00Z", end: "2300-01-02T00:00:00Z" },
    { limit: 0 },
    { limit: 1001 },
    { limit: 1.5 },
    { sort: "duration_desc" },
    { filters: undefined },
    { filters: Array(9).fill({ kind: "outcome", value: "PASS" }) },
    { filters: [{ kind: "sql", value: "SELECT 1" }] },
    { filters: [{ kind: "outcome", value: "DENY", extra: true }] },
    { filters: [{ kind: "outcome", value: "allow" }] },
    { filters: [{ kind: "request_id", value: ARTIFACT_ID }] },
    { filters: [{ kind: "text", field: "payload_json", value: "anything" }] },
    { filters: [{ kind: "text", field: "stage", value: "a|b" }] },
    { filters: [{ kind: "text", field: "stage", value: "a".repeat(129) }] },
    { filters: [{ kind: "confidence_at_most", basis_points: 10001 }] },
    { filters: [{ kind: "confidence_at_most", basis_points: 1.1 }] },
  ];
  for (const changes of invalid) {
    await assert.rejects(
      client.search({ ...searchPlan(), ...changes } as SearchPlan),
      errorIs("CONTROL_QUERY_INVALID"),
    );
  }
  for (const cursor of [
    "",
    "a".repeat(161),
    "v1.0.ev_fake.signature",
    "cursor&scope=other",
  ]) {
    await assert.rejects(
      client.search(searchPlan(), cursor),
      errorIs("CONTROL_CURSOR_INVALID"),
    );
  }
  const cancelled = new AbortController();
  cancelled.abort(TOKEN);
  await assert.rejects(
    client.search(searchPlan(), undefined, cancelled.signal),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(network.mock.callCount(), 0);
});

test("search pagination preserves nullable facts, microsecond ordering and both sort directions", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const sort of ["occurred_at_asc", "occurred_at_desc"] as const) {
    const plan = { ...searchPlan(), sort };
    const first = await searchResponse(plan);
    t.mock.method(globalThis, "fetch", async () => response(first));
    assert.deepEqual(await client.search(plan), first);
    const next = structuredClone(first);
    next.events = [
      {
        ...first.events[0]!,
        event_id: "ev_018f2a3b-4c5d-7000-8000-000000000003",
        occurred_at:
          sort === "occurred_at_asc"
            ? "2026-09-20T08:10:30.123458Z"
            : "2026-09-20T08:10:30.123455Z",
        proof_kind: "model",
        model_revision: "model-r1",
        confidence: 0.1,
        confidence_status: "provided",
      },
    ];
    next.truncated = false;
    next.next_cursor = null;
    next.scanned_rows = 0;
    next.scanned_bytes = null;
    t.mock.method(
      globalThis,
      "fetch",
      async (_path: string, options: RequestInit) => {
        assert.equal(
          JSON.parse(String(options.body)).cursor,
          first.next_cursor,
        );
        return response(next);
      },
    );
    assert.deepEqual(await client.search(plan, first.next_cursor!), next);
    next.events = [];
    next.index_watermark = null;
    assert.deepEqual(await client.search(plan, first.next_cursor!), next);
  }
  const plan = {
    ...searchPlan(),
    start: "2299-12-31T00:00:00Z",
    end: "2300-01-01T00:00:00Z",
  };
  const future = await searchResponse(plan);
  future.events.forEach((event, index) => {
    event.occurred_at = `2299-12-31T23:59:59.99999${index + 8}Z`;
  });
  future.next_cursor = searchCursor(future.events.at(-1)!);
  t.mock.method(globalThis, "fetch", async () => response(future));
  assert.deepEqual(await client.search(plan), future);
});

test("search rejects contradictory digest, position, confidence and wire shapes", async (t) => {
  const client = new ControlClient(TOKEN);
  const mutations: Array<(value: SearchResponse) => void> = [
    (value) => {
      value.query_digest = "f".repeat(64);
    },
    (value) => {
      Object.assign(value, { schema_version: 4 });
    },
    (value) => {
      value.scanned_bytes = Number.MAX_SAFE_INTEGER + 1;
    },
    (value) => {
      value.pending_segments = -1;
    },
    (value) => {
      value.events[0]!.request_id = "unknown";
    },
    (value) => {
      value.events[0]!.stage = "";
    },
    (value) => {
      value.events[0]!.confidence = 0;
    },
    (value) => {
      value.events[0]!.proof_kind = "deterministic";
    },
    (value) => {
      value.events[0]!.model_revision = "jev-r1";
    },
    (value) => {
      value.events[0]!.event_type = "<script>";
    },
    (value) => {
      value.events[0]!.occurred_at = "2026-09-20T08:10:30.1234567Z";
    },
    (value) => {
      value.events[0]!.occurred_at = "2026-09-20T08:10:30.123456+08:00";
    },
    (value) => {
      value.events[0]!.occurred_at = "2026-02-30T08:10:30.123456Z";
    },
    (value) => {
      value.events[0]!.occurred_at = "2026-09-19T23:59:59.999999Z";
    },
    (value) => {
      value.events[1]!.occurred_at = "2026-09-21T00:00:00.000000Z";
    },
    (value) => {
      value.events[1]!.occurred_at = value.events[0]!.occurred_at;
    },
    (value) => {
      value.events.reverse();
    },
    (value) => {
      value.events[1]!.event_id = value.events[0]!.event_id;
    },
    (value) => {
      value.events.push(value.events[0]!);
    },
    (value) => {
      value.events.pop();
    },
    (value) => {
      value.truncated = false;
    },
    (value) => {
      value.next_cursor = searchCursor(value.events[0]!);
    },
    (value) => {
      value.next_cursor = "synthetic.cursor";
    },
  ];
  for (const mutate of mutations) {
    const value = await searchResponse();
    mutate(value);
    t.mock.method(globalThis, "fetch", async () => response(value));
    await assert.rejects(
      client.search(searchPlan()),
      errorIs("INVALID_RESPONSE", 200),
    );
  }
  const first = await searchResponse();
  t.mock.method(globalThis, "fetch", async () => response(first));
  await assert.rejects(
    client.search(searchPlan(), first.next_cursor!),
    errorIs("INVALID_RESPONSE", 200),
  );
});

test("search shares bounded errors and cancellation while distinguishing plan budget denial", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const [status, code] of [
    [422, "CONTROL_QUERY_INVALID"],
    [400, "CONTROL_CURSOR_INVALID"],
    [403, "CONTROL_SCOPE_DENIED"],
    [401, "CONTROL_AUTH_REQUIRED"],
    [429, "CONTROL_QUERY_BUDGET_EXCEEDED"],
    [429, "CONTROL_QUERY_CAPACITY_EXHAUSTED"],
    [503, "AUDIT_DURABILITY_FAILED"],
  ] as const) {
    t.mock.method(globalThis, "fetch", async () =>
      response(errorFixture(code), status),
    );
    await assert.rejects(client.search(searchPlan()), errorIs(code, status));
  }
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response("{}", {
        headers: {
          "content-type": "application/json",
          "content-length": String(16 * 1024 * 1024 + 1),
        },
      }),
  );
  await assert.rejects(
    client.search(searchPlan()),
    errorIs("RESPONSE_TOO_LARGE", 200),
  );
  let started!: () => void;
  const reachedFetch = new Promise<void>((resolve) => {
    started = resolve;
  });
  t.mock.method(
    globalThis,
    "fetch",
    (_path: string, options: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        options.signal!.addEventListener(
          "abort",
          () => reject(new Error(TOKEN)),
          { once: true },
        );
        started();
      }),
  );
  const abort = new AbortController();
  const pending = client.search(searchPlan(), undefined, abort.signal);
  await reachedFetch;
  abort.abort(TOKEN);
  await assert.rejects(pending, errorIs("REQUEST_ABORTED"));
  const stopped = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected network");
  });
  t.mock.method(globalThis.crypto.subtle, "digest", async () => {
    throw new Error(TOKEN);
  });
  await assert.rejects(
    client.search(searchPlan()),
    errorIs("QUERY_DIGEST_UNAVAILABLE"),
  );
  assert.equal(stopped.mock.callCount(), 0);
});

test("ledger reads bind targets, preserve observations and project only display fields", async (t) => {
  const grant = grantFixture();
  const binding = bindingFixture();
  const sent: string[] = [];
  t.mock.method(
    globalThis,
    "fetch",
    async (path: string, options: RequestInit) => {
      sent.push(path);
      assert.equal(options.method, "GET");
      assert.equal(options.body, undefined);
      assert.deepEqual(options.headers, {
        Authorization: `Bearer ${TOKEN}`,
        Accept: "application/json",
      });
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.redirect, "error");
      assert.equal(options.referrerPolicy, "no-referrer");
      assert.ok(options.signal instanceof AbortSignal);
      return response(
        path.includes("/grants/")
          ? {
              ...grant,
              private_snapshot: "synthetic-private",
              grant: {
                ...grant.grant,
                resource_key_hmac: "synthetic-private",
                constraints: { secret: true },
                binding: {
                  ...grant.grant!.binding,
                  principal_ref: "synthetic-private",
                  credential: TOKEN,
                },
              },
            }
          : {
              ...binding,
              private_snapshot: "synthetic-private",
              binding: {
                ...binding.binding,
                principal_ref: "synthetic-private",
                waf_sid_fingerprint: TOKEN,
              },
            },
      );
    },
  );
  const client = new ControlClient(TOKEN);
  assert.deepEqual(await client.grant(GRANT_ID), grant);
  assert.deepEqual(await client.binding(BINDING_ID), binding);
  assert.deepEqual(sent, [
    `/control/v1/grants/${GRANT_ID}`,
    `/control/v1/auth-bindings/${BINDING_ID}`,
  ]);

  for (const kind of ["grant", "binding"] as const) {
    const target = kind === "grant" ? GRANT_ID : BINDING_ID;
    const missing = {
      ...(kind === "grant" ? grant : binding),
      found: false,
      as_of: null,
      [kind]: null,
    };
    t.mock.method(globalThis, "fetch", async () => response(missing));
    assert.deepEqual(await client[kind](target), missing);
  }
});

test("ledger target validation rejects ambiguous IDs before any transport", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => {
    throw new Error("unexpected network");
  });
  const client = new ControlClient(TOKEN);
  for (const [kind, target, code] of [
    ["grant", GRANT_ID, "CONTROL_GRANT_ID_INVALID"],
    ["binding", BINDING_ID, "CONTROL_BINDING_ID_INVALID"],
  ] as const) {
    for (const value of [
      null,
      undefined,
      4,
      {},
      "",
      REQUEST_ID,
      target.toUpperCase(),
      target.replace("-7000-", "-4000-"),
      `${target}?tenant_id=other`,
      `../${target}`,
      ...["\n", "\r", "\r\n", "\u2028", "\u2029", " ", "/", "%0a"].map(
        (end) => target + end,
      ),
    ])
      await assert.rejects(client[kind](value as string), errorIs(code));
  }
  assert.equal(network.mock.callCount(), 0);
});

test("ledger expiry compares exact microseconds and stored states remain independent", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const asOf of [
    "2026-09-20T08:10:30.123456Z",
    "2299-09-20T08:10:30.123456Z",
  ]) {
    for (const [end, expired] of [
      ["123455", true],
      ["123456", true],
      ["123457", false],
    ] as const) {
      const grant = grantFixture();
      grant.as_of = asOf;
      grant.grant!.expires_at = asOf.replace("123456", end);
      grant.grant!.time_expired = expired;
      grant.grant!.binding.expires_at = asOf.replace("123456", end);
      grant.grant!.binding.time_expired = expired;
      grant.grant!.binding.current_auth_epoch = 5;
      grant.grant!.binding.epoch_matches_grant = false;
      const binding = bindingFixture();
      binding.as_of = asOf;
      binding.binding!.expires_at = asOf.replace("123456", end);
      binding.binding!.time_expired = expired;
      // An update after expiry or the observation is possible after clock rollback.
      binding.binding!.updated_at = "2299-12-31T23:59:59.999999Z";
      t.mock.method(globalThis, "fetch", async (path: string) =>
        response(path.includes("/grants/") ? grant : binding),
      );
      assert.deepEqual(await client.grant(GRANT_ID), grant);
      assert.deepEqual(await client.binding(BINDING_ID), binding);
    }
  }
  for (const state of ["anonymous", "active", "revoked", "expired"] as const) {
    for (const expired of [false, true]) {
      const binding = bindingFixture();
      binding.binding!.stored_status = state;
      binding.binding!.expires_at = expired
        ? binding.as_of!
        : "2026-09-20T09:00:00.000000Z";
      binding.binding!.time_expired = expired;
      if (state !== "active") {
        binding.binding!.current_auth_epoch = 0;
        binding.binding!.credential_generation = 0;
      }
      t.mock.method(globalThis, "fetch", async () => response(binding));
      assert.deepEqual(await client.binding(BINDING_ID), binding);
    }
  }
  for (const state of ["active", "revoked", "expired"] as const) {
    const grant = grantFixture();
    grant.grant!.stored_status = state;
    grant.grant!.binding.stored_status = state;
    grant.grant!.binding.expires_at = "2026-09-20T08:05:00.000000Z";
    grant.grant!.binding.time_expired = true;
    t.mock.method(globalThis, "fetch", async () => response(grant));
    assert.deepEqual(await client.grant(GRANT_ID), grant);
  }
});

test("ledger boundary rejects contradictory observations and malformed display facts", async (t) => {
  const client = new ControlClient(TOKEN);
  const grant = grantFixture();
  const binding = bindingFixture();
  for (const [kind, target, fixture, record] of [
    ["grant", GRANT_ID, grant, grant.grant],
    ["binding", BINDING_ID, binding, binding.binding],
  ] as const) {
    const malformed = [
      { ...fixture, schema_version: 2 },
      { ...fixture, schema_version: "3" },
      { ...fixture, found: "true" },
      { ...fixture, found: false },
      { ...fixture, as_of: null },
      { ...fixture, as_of: undefined },
      { ...fixture, [kind]: null },
      { ...fixture, [kind]: undefined },
      { ...fixture, [kind]: [] },
      {
        ...fixture,
        [`source_${kind}_id`]:
          kind === "grant" ? OTHER_GRANT_ID : OTHER_BINDING_ID,
      },
      {
        ...fixture,
        [kind]: {
          ...record,
          [kind === "grant" ? "grant_id" : "binding_id"]:
            kind === "grant" ? OTHER_GRANT_ID : OTHER_BINDING_ID,
        },
      },
      { ...fixture, request_id: REQUEST_ID + "\u2028" },
      { ...fixture, tenant_id: "tenant/other" },
    ];
    for (const value of ["unknown", null, 3])
      malformed.push({
        ...fixture,
        [kind]: { ...record, stored_status: value },
      });
    for (const value of ["false", null, 0, true])
      malformed.push({
        ...fixture,
        [kind]: { ...record, time_expired: value },
      });
    for (const field of [
      "as_of",
      "expires_at",
      kind === "grant" ? "issued_at" : "updated_at",
    ]) {
      for (const value of [
        null,
        "1969-12-31T23:59:59.999999Z",
        "2026-02-30T08:00:00.000000Z",
        "2026-09-20T24:00:00.000000Z",
        "2026-09-20T08:10:30.123456+00:00",
        "2026-09-20T08:10:30.123Z",
        "2026-09-20T08:10:30.1234567Z",
        "2026-09-20T08:10:30.123456Z\n",
      ]) {
        malformed.push(
          field === "as_of"
            ? { ...fixture, as_of: value }
            : { ...fixture, [kind]: { ...record, [field]: value } },
        );
      }
    }
    for (const bad of malformed) {
      t.mock.method(globalThis, "fetch", async () => response(bad));
      await assert.rejects(
        client[kind](target),
        errorIs("INVALID_RESPONSE", 200),
      );
    }
  }
  const grantBad = [
    { ...grant.grant, auth_epoch: 5 },
    { ...grant.grant, auth_epoch: -1 },
    { ...grant.grant, auth_epoch: Number.MAX_SAFE_INTEGER + 1 },
    { ...grant.grant, issued_at: grant.grant!.expires_at },
    { ...grant.grant, resource_type: "<svg/onload=alert(1)>" },
    { ...grant.grant, operation_id: "orders/read" },
    { ...grant.grant, view_id: "view\n" },
    { ...grant.grant, policy_revision: "x".repeat(129) },
    { ...grant.grant, source_event_id: GRANT_ID },
    { ...grant.grant, source_request_id: BINDING_ID },
    {
      ...grant.grant,
      binding: { ...grant.grant!.binding, epoch_matches_grant: false },
    },
    {
      ...grant.grant,
      binding: { ...grant.grant!.binding, current_auth_epoch: 3 },
    },
    {
      ...grant.grant,
      binding: { ...grant.grant!.binding, time_expired: true },
    },
    {
      ...grant.grant,
      binding: { ...grant.grant!.binding, binding_id: GRANT_ID },
    },
  ];
  for (const data of grantBad) {
    t.mock.method(globalThis, "fetch", async () =>
      response({ ...grant, grant: data }),
    );
    await assert.rejects(
      client.grant(GRANT_ID),
      errorIs("INVALID_RESPONSE", 200),
    );
  }
  for (const field of ["current_auth_epoch", "credential_generation"]) {
    for (const value of [-1, 0, 1.5, "4", Number.MAX_SAFE_INTEGER + 1, null]) {
      t.mock.method(globalThis, "fetch", async () =>
        response({
          ...binding,
          binding: { ...binding.binding, [field]: value },
        }),
      );
      await assert.rejects(
        client.binding(BINDING_ID),
        errorIs("INVALID_RESPONSE", 200),
      );
    }
  }
  t.mock.method(globalThis, "fetch", async () =>
    response({
      ...binding,
      binding: { ...binding.binding, stored_status: "anonymous" },
    }),
  );
  await assert.rejects(
    client.binding(BINDING_ID),
    errorIs("INVALID_RESPONSE", 200),
  );
});

test("ledger failures retain safe diagnostics and cancelled requests do not start", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const [kind, target, unavailable] of [
    ["grant", GRANT_ID, "CONTROL_GRANT_STORE_UNAVAILABLE"],
    ["binding", BINDING_ID, "CONTROL_BINDING_STORE_UNAVAILABLE"],
  ] as const) {
    for (const [status, code] of [
      [401, "CONTROL_AUTH_REQUIRED"],
      [403, "CONTROL_SCOPE_DENIED"],
      [429, "CONTROL_QUERY_CAPACITY_EXHAUSTED"],
      [503, unavailable],
      [503, "AUDIT_DURABILITY_FAILED"],
    ] as const) {
      t.mock.method(globalThis, "fetch", async () =>
        response(errorFixture(code), status),
      );
      await assert.rejects(client[kind](target), errorIs(code, status));
    }
    const network = t.mock.method(globalThis, "fetch", async () => {
      throw new Error("unexpected transport");
    });
    await assert.rejects(
      client[kind](target, AbortSignal.abort(TOKEN)),
      errorIs("REQUEST_ABORTED"),
    );
    assert.equal(network.mock.callCount(), 0);
  }
});

test("development proxy permits fixed reads and exact search/case POST routes", async () => {
  const { default: config } = await import("../vite.config.ts");
  const proxy = config.server?.proxy?.["/control/"];
  assert.ok(proxy && typeof proxy !== "string" && proxy.bypass);
  type Request = Parameters<typeof proxy.bypass>[0];
  type Response = Parameters<typeof proxy.bypass>[1];
  for (const [method, url, allowed] of [
    ["POST", "/control/v1/search", true],
    ["GET", `/control/v1/grants/${GRANT_ID}`, true],
    ["GET", `/control/v1/auth-bindings/${BINDING_ID}`, true],
    [
      "GET",
      `/control/v1/requests/${REQUEST_ID}/events?cursor=${EVENT_CURSOR}`,
      true,
    ],
    ["POST", "/control/v1/search?scope=other", false],
    ["POST", "/control/v1/search/", false],
    ["GET", "/control/v1/search", false],
    ["PUT", "/control/v1/search", false],
    ["POST", "/control/v1/cases", true],
    ["POST", `/control/v1/cases/${CASE_ID}/items`, true],
    ["POST", `/control/v1/cases/${CASE_ID}/close`, true],
    ["GET", `/control/v1/cases/${CASE_ID}/items?cursor=${CASE_CURSOR}`, true],
    ["GET", "/control/v1/cases", true],
    ["GET", `/control/v1/cases?cursor=${CASE_LIST_CURSOR}`, true],
    ["GET", "/control/v1/cases/", false],
    ["GET", `/control/v1/cases/${CASE_ID}`, false],
    ["DELETE", "/control/v1/cases", false],
    ["GET", `/control/v1/cases/${CASE_ID}/close`, false],
    ["POST", `/control/v1/cases/${CASE_ID}/holds`, false],
    ["POST", `/control/v1/cases/${CASE_ID}/close?reason=other`, false],
    ["POST", "/control/v1/cases?tenant=other", false],
    ["POST", "/control/v1/cases/", false],
    ["POST", `/control/v1/requests/${REQUEST_ID}`, false],
    ["GET", `/control/v1/artifacts/${ARTIFACT_ID}/content`, false],
    ["POST", `/control/v1/grants/${GRANT_ID}`, false],
    ["DELETE", `/control/v1/auth-bindings/${BINDING_ID}`, false],
    ["GET", `/control/v1/grants/${GRANT_ID}/revoke`, false],
    ["GET", `/control/v1/auth-bindings/${BINDING_ID}/credentials`, false],
  ] as const) {
    const state = {
      statusCode: 200,
      ended: false,
      end() {
        this.ended = true;
      },
    };
    const result: unknown = await proxy.bypass(
      { method, url } as Request,
      state as unknown as Response,
      proxy,
    );
    assert.equal(result, allowed ? undefined : false);
    assert.equal(state.statusCode, allowed ? 200 : 404);
    assert.equal(state.ended, !allowed);
  }
});

const CASE_ID = "case_018f2a3b-4c5d-7000-8000-000000000951";
const CASE_KEY = "synthetic-case-key-01";
const CASE_CURSOR = `v1.${ARTIFACT_ID}.${"a".repeat(64)}`;
const CASE_LIST_CURSOR = `v1.${CASE_ID}.${"b".repeat(64)}`;
const caseEnvelope = {
  request_id: REQUEST_ID,
  tenant_id: "tenant_a",
  site_id: "site_a",
};
const caseFacts = () => ({
  case_id: CASE_ID,
  status: "open",
  purpose: "调查合成事件",
  created_at: "2026-09-20T01:02:03.004Z",
});
const caseAdded = () => ({
  ...caseEnvelope,
  schema_version: 3,
  case_id: CASE_ID,
  artifact_id: ARTIFACT_ID,
  added_by: "operator-1",
  added_at: "2026-09-20T01:02:04.005Z",
  replayed: false,
});
const casePage = () => ({
  ...caseEnvelope,
  schema_version: 3,
  case: caseFacts(),
  as_of: "2026-09-20T01:02:05.006007Z",
  items: [
    {
      artifact_id: ARTIFACT_ID,
      added_by: "operator-1",
      added_at: "2026-09-20T01:02:04.005Z",
      catalog_status: "active",
    },
  ],
  truncated: true,
  next_cursor: CASE_CURSOR as string | null,
});
const caseListPage = () => ({
  ...caseEnvelope,
  schema_version: 3,
  as_of: casePage().as_of,
  items: [caseFacts()],
  truncated: true,
  next_cursor: CASE_LIST_CURSOR as string | null,
});

test("case list uses fixed GET pages and projects only owner case metadata", async (t) => {
  const first = caseListPage();
  const second = {
    ...first,
    as_of: "2026-09-20T01:03:00.000001Z",
    items: [
      {
        ...caseFacts(),
        case_id: CASE_ID.replace(/951$/, "950"),
        status: "closed",
        // Creation clocks can move independently of the UUID ordering.
        created_at: "2026-09-20T01:03:00.000Z",
      },
    ],
    truncated: false,
    next_cursor: null,
  };
  const pages = [first, second, { ...second, items: [] }];
  let count = 0;
  t.mock.method(
    globalThis,
    "fetch",
    async (path: string, options: RequestInit) => {
      assert.equal(
        path,
        `/control/v1/cases${count === 1 ? `?cursor=${CASE_LIST_CURSOR}` : ""}`,
      );
      assert.equal(options.method, "GET");
      assert.equal(options.body, undefined);
      assert.deepEqual(options.headers, {
        Authorization: `Bearer ${TOKEN}`,
        Accept: "application/json",
      });
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.redirect, "error");
      assert.equal(options.referrerPolicy, "no-referrer");
      assert.ok(options.signal instanceof AbortSignal);
      const page = pages[count++]!;
      return response({
        ...page,
        owner_subject: "private-owner",
        items: page.items.map((item) => ({
          ...item,
          content: "private-content",
          storage: { locator: "private-locator" },
          key_ref: "private-key",
          evidence_access: "private-capability",
        })),
      });
    },
  );
  const client = new ControlClient(TOKEN);
  assert.deepEqual(await client.cases(), first);
  assert.deepEqual(await client.cases(CASE_LIST_CURSOR), second);
  assert.deepEqual(await client.cases(), pages[2]);
  assert.equal(count, 3);
});

test("case list rejects malformed pages, oversized lists and unbound descending cursors", async (t) => {
  const page = caseListPage();
  const item = caseFacts();
  const earlier = { ...item, case_id: CASE_ID.replace(/951$/, "950") };
  const malformed = [
    { schema_version: 2 },
    { schema_version: "3" },
    { request_id: REQUEST_ID + "\n" },
    { tenant_id: "tenant/other" },
    { site_id: null },
    { as_of: null },
    { as_of: "2026-02-30T01:02:05.006007Z" },
    { as_of: "2026-09-20T01:02:05.006Z" },
    { as_of: "2026-09-20T01:02:05.006007+00:00" },
    { items: null },
    { items: [null] },
    {
      items: Array.from({ length: 129 }, (_, index) => ({
        ...item,
        case_id: CASE_ID.replace(/951$/, String(951 - index)),
      })),
      truncated: false,
      next_cursor: null,
    },
    { items: [{ ...item, case_id: ARTIFACT_ID }] },
    { items: [{ ...item, case_id: CASE_ID.toUpperCase() }] },
    { items: [{ ...item, case_id: CASE_ID.replace("-7000-", "-4000-") }] },
    { items: [{ ...item, status: "active" }] },
    { items: [{ ...item, purpose: "" }] },
    { items: [{ ...item, purpose: " padded" }] },
    { items: [{ ...item, purpose: "bad\u0085text" }] },
    { items: [{ ...item, purpose: "界".repeat(171) }] },
    { items: [{ ...item, created_at: "2026-09-20T01:02:03.004005Z" }] },
    { items: [{ ...item, created_at: "2026-02-30T01:02:03.004Z" }] },
    { items: [item, item] },
    { items: [earlier, item] },
    { items: [] },
    { truncated: false },
    { truncated: "true" },
    { next_cursor: null },
    { next_cursor: CASE_CURSOR },
    { next_cursor: CASE_LIST_CURSOR.replace(CASE_ID, earlier.case_id) },
    { next_cursor: CASE_LIST_CURSOR + "\n" },
    { next_cursor: CASE_LIST_CURSOR.toUpperCase() },
  ];
  const client = new ControlClient(TOKEN);
  for (const patch of malformed) {
    t.mock.method(globalThis, "fetch", async () =>
      response({ ...page, ...patch }),
    );
    await assert.rejects(client.cases(), errorIs("INVALID_RESPONSE", 200));
  }
  // A later page must begin strictly below the incoming position.
  for (const case_id of [CASE_ID, CASE_ID.replace(/951$/, "952")]) {
    t.mock.method(globalThis, "fetch", async () =>
      response({
        ...page,
        items: [{ ...item, case_id }],
        truncated: false,
        next_cursor: null,
      }),
    );
    await assert.rejects(
      client.cases(CASE_LIST_CURSOR),
      errorIs("INVALID_RESPONSE", 200),
    );
  }
  for (const status of [201, 202, 206]) {
    t.mock.method(globalThis, "fetch", async () => response(page, status));
    await assert.rejects(client.cases(), errorIs("INVALID_RESPONSE", status));
  }
});

test("case list validates cursor and cancellation before IO", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => response({}));
  const client = new ControlClient(TOKEN);
  for (const cursor of [
    "",
    "bad",
    "x".repeat(161),
    CASE_CURSOR,
    CASE_LIST_CURSOR.toUpperCase(),
    CASE_LIST_CURSOR.replace("-7000-", "-4000-"),
    CASE_LIST_CURSOR.replace("v1.", "v2."),
    CASE_LIST_CURSOR.slice(0, -1),
    `${CASE_LIST_CURSOR}\n`,
    `${CASE_LIST_CURSOR}\u2028`,
    `${CASE_LIST_CURSOR}&tenant_id=other`,
    `%76${CASE_LIST_CURSOR.slice(1)}`,
  ])
    await assert.rejects(
      client.cases(cursor),
      errorIs("CONTROL_CURSOR_INVALID"),
    );
  await assert.rejects(
    client.cases(undefined, AbortSignal.abort()),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(network.mock.callCount(), 0);
});

test("case list surfaces bounded service failures once for explicit retry", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const [status, code] of [
    [401, "CONTROL_AUTH_REQUIRED"],
    [403, "CONTROL_SCOPE_DENIED"],
    [429, "CONTROL_CASE_BUSY"],
    [503, "CONTROL_CASE_STORE_UNAVAILABLE"],
    [503, "AUDIT_DURABILITY_FAILED"],
  ] as const) {
    const network = t.mock.method(globalThis, "fetch", async () =>
      response(errorFixture(code), status),
    );
    await assert.rejects(client.cases(), errorIs(code, status));
    assert.equal(network.mock.callCount(), 1);
  }
});

test("case transport freezes exact mutation inputs, keys and fixed response correlations", async (t) => {
  const client = new ControlClient(TOKEN);
  const created = { ...caseEnvelope, ...caseFacts(), replayed: false };
  const closed = {
    ...caseEnvelope,
    schema_version: 3,
    case_id: CASE_ID,
    status: "closed",
    closed_at: "2026-09-20T01:02:06.007Z",
    replayed: false,
  };
  const calls: [string, unknown, unknown, number][] = [
    ["cases", { purpose: caseFacts().purpose }, created, 201],
    [`cases/${CASE_ID}/items`, { artifact_id: ARTIFACT_ID }, caseAdded(), 201],
    [`cases/${CASE_ID}/close`, { reason: "Review complete" }, closed, 200],
    [
      "cases",
      { purpose: caseFacts().purpose },
      { ...created, status: "closed", replayed: true },
      200,
    ],
    [
      `cases/${CASE_ID}/items`,
      { artifact_id: ARTIFACT_ID },
      { ...caseAdded(), replayed: true },
      200,
    ],
    [
      `cases/${CASE_ID}/close`,
      { reason: "Review complete" },
      { ...closed, replayed: true },
      200,
    ],
  ];
  let count = 0;
  t.mock.method(
    globalThis,
    "fetch",
    async (path: string, options: RequestInit) => {
      const [expectedPath, body, result, status] = calls[count++]!;
      assert.equal(path, `/control/v1/${expectedPath}`);
      assert.equal(options.method, "POST");
      assert.deepEqual(JSON.parse(String(options.body)), body);
      assert.deepEqual(options.headers, {
        Authorization: `Bearer ${TOKEN}`,
        Accept: "application/json",
        "Content-Type": "application/json",
        "Idempotency-Key": CASE_KEY,
      });
      assert.equal(options.credentials, "omit");
      assert.equal(options.cache, "no-store");
      assert.equal(options.redirect, "error");
      return response(
        {
          ...(result as object),
          content: "excluded",
          storage: { secret: "excluded" },
        },
        status,
      );
    },
  );
  for (const replayed of [false, true]) {
    assert.deepEqual(await client.createCase(caseFacts().purpose, CASE_KEY), {
      ...created,
      status: replayed ? "closed" : "open",
      replayed,
    });
    assert.deepEqual(await client.addCaseItem(CASE_ID, ARTIFACT_ID, CASE_KEY), {
      ...caseAdded(),
      replayed,
    });
    assert.deepEqual(
      await client.closeCase(CASE_ID, "Review complete", CASE_KEY),
      { ...closed, replayed },
    );
  }
  assert.equal(count, 6);
});

test("case input validates UTF-8, controls, exact identifiers and single canonical keys before IO", async (t) => {
  const network = t.mock.method(globalThis, "fetch", async () => response({}));
  const client = new ControlClient(TOKEN);
  for (const value of [
    "",
    " padded",
    "padded ",
    "x\n",
    "x\u0085y",
    "\u2000x",
    "界".repeat(171),
    "x".repeat(513),
    "x\ud800",
    "x\udc00",
  ]) {
    await assert.rejects(
      client.createCase(value, CASE_KEY),
      errorIs("CONTROL_CASE_REQUEST_INVALID"),
    );
    await assert.rejects(
      client.closeCase(CASE_ID, value, CASE_KEY),
      errorIs("CONTROL_CASE_CLOSE_REQUEST_INVALID"),
    );
  }
  for (const key of [
    "short",
    "x".repeat(129),
    `${CASE_KEY}\n`,
    `${CASE_KEY}\u2028`,
    `${CASE_KEY} `,
    "a".repeat(15) + "界",
    `${CASE_KEY}/path`,
  ]) {
    await assert.rejects(
      client.createCase("Review", key),
      errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
    );
    await assert.rejects(
      client.addCaseItem(CASE_ID, ARTIFACT_ID, key),
      errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
    );
    await assert.rejects(
      client.closeCase(CASE_ID, "Review", key),
      errorIs("CONTROL_IDEMPOTENCY_KEY_INVALID"),
    );
  }
  for (const target of [
    REQUEST_ID,
    `${CASE_ID}\n`,
    `${CASE_ID}\u2028`,
    `${CASE_ID}?scope=other`,
    CASE_ID.toUpperCase(),
    "../cases",
  ]) {
    await assert.rejects(
      client.caseItems(target),
      errorIs("CONTROL_CASE_ID_INVALID"),
    );
    await assert.rejects(
      client.addCaseItem(target, ARTIFACT_ID, CASE_KEY),
      errorIs("CONTROL_CASE_ID_INVALID"),
    );
    await assert.rejects(
      client.closeCase(target, "Review", CASE_KEY),
      errorIs("CONTROL_CASE_ID_INVALID"),
    );
  }
  for (const cursor of [
    "bad",
    `${CASE_CURSOR}\n`,
    `${CASE_CURSOR}&scope=other`,
    CASE_CURSOR.toUpperCase(),
  ])
    await assert.rejects(
      client.caseItems(CASE_ID, cursor),
      errorIs("CONTROL_CURSOR_INVALID"),
    );
  await assert.rejects(
    client.addCaseItem(CASE_ID, `${ARTIFACT_ID}\n`, CASE_KEY),
    errorIs("CONTROL_ARTIFACT_ID_INVALID"),
  );
  assert.equal(network.mock.callCount(), 0);
});

test("case collection keeps catalog status separate and binds ordered cursor pages", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const catalog_status of [
    "active",
    "expired",
    "deleted",
    "unavailable",
  ]) {
    const page = casePage();
    page.items[0]!.catalog_status = catalog_status;
    Object.assign(page.items[0]!, {
      content: "excluded",
      key_ref: "excluded",
      locator: "excluded",
    });
    t.mock.method(
      globalThis,
      "fetch",
      async (path: string, options: RequestInit) => {
        assert.equal(path, `/control/v1/cases/${CASE_ID}/items`);
        assert.equal(options.method, "GET");
        assert.equal(new Headers(options.headers).get("idempotency-key"), null);
        return response(page);
      },
    );
    const result = await client.caseItems(CASE_ID);
    assert.equal(result.items[0]?.catalog_status, catalog_status);
    assert.equal(result.as_of, page.as_of);
    assert.equal(result.next_cursor, CASE_CURSOR);
    assert.ok(!JSON.stringify(result).includes("excluded"));
  }
  const last = {
    ...casePage(),
    items: [],
    truncated: false,
    next_cursor: null,
  };
  t.mock.method(globalThis, "fetch", async (path: string) => {
    assert.equal(
      path,
      `/control/v1/cases/${CASE_ID}/items?cursor=${CASE_CURSOR}`,
    );
    return response(last);
  });
  assert.deepEqual(await client.caseItems(CASE_ID, CASE_CURSOR), last);
});

test("case decoders reject contradictory scope targets, replay statuses and pagination", async (t) => {
  const client = new ControlClient(TOKEN);
  for (const patch of [
    { schema_version: 2 },
    { case: { ...caseFacts(), case_id: REQUEST_ID } },
    { case: { ...caseFacts(), status: "active" } },
    { case: { ...caseFacts(), purpose: "\u0085bad" } },
    { case: { ...caseFacts(), created_at: "2026-02-30T01:00:00.000Z" } },
    { as_of: "2026-09-20T01:02:05.006Z" },
    { items: [...casePage().items, ...casePage().items] },
    { items: [{ ...casePage().items[0], added_by: "界".repeat(86) }] },
    { items: [{ ...casePage().items[0], catalog_status: "readable" }] },
    { items: [] },
    { truncated: false },
    { next_cursor: CASE_CURSOR.replace(ARTIFACT_ID, REQUEST_ID) },
  ]) {
    t.mock.method(globalThis, "fetch", async () =>
      response({ ...casePage(), ...patch }),
    );
    await assert.rejects(
      client.caseItems(CASE_ID),
      errorIs("INVALID_RESPONSE"),
    );
  }
  t.mock.method(globalThis, "fetch", async () => response(casePage()));
  await assert.rejects(
    client.caseItems(CASE_ID, CASE_CURSOR),
    errorIs("INVALID_RESPONSE"),
  );
  for (const [status, patch] of [
    [200, {}],
    [201, { replayed: true }],
    [201, { status: "closed" }],
    [201, { purpose: "changed" }],
    [201, { replayed: null }],
  ] as const) {
    t.mock.method(globalThis, "fetch", async () =>
      response(
        { ...caseEnvelope, ...caseFacts(), replayed: false, ...patch },
        status,
      ),
    );
    await assert.rejects(
      client.createCase(caseFacts().purpose, CASE_KEY),
      errorIs("INVALID_RESPONSE"),
    );
  }
  for (const patch of [
    { case_id: REQUEST_ID },
    { artifact_id: REQUEST_ID },
    { replayed: true },
    { schema_version: 1 },
  ]) {
    t.mock.method(globalThis, "fetch", async () =>
      response({ ...caseAdded(), ...patch }, 201),
    );
    await assert.rejects(
      client.addCaseItem(CASE_ID, ARTIFACT_ID, CASE_KEY),
      errorIs("INVALID_RESPONSE"),
    );
  }
  for (const patch of [
    { case_id: REQUEST_ID },
    { status: "open" },
    { schema_version: 2 },
    { closed_at: null },
  ]) {
    t.mock.method(globalThis, "fetch", async () =>
      response({
        ...caseEnvelope,
        schema_version: 3,
        case_id: CASE_ID,
        status: "closed",
        closed_at: caseFacts().created_at,
        replayed: false,
        ...patch,
      }),
    );
    await assert.rejects(
      client.closeCase(CASE_ID, "Review", CASE_KEY),
      errorIs("INVALID_RESPONSE"),
    );
  }
});

test("case write failures do not retry; explicit retry retains original key and body", async (t) => {
  const client = new ControlClient(TOKEN);
  const seen: string[] = [];
  let failed = true;
  t.mock.method(
    globalThis,
    "fetch",
    async (_path: string, options: RequestInit) => {
      seen.push(
        `${new Headers(options.headers).get("Idempotency-Key")}:${String(options.body)}`,
      );
      if (failed) throw new Error(TOKEN);
      return response({ ...caseEnvelope, ...caseFacts(), replayed: true });
    },
  );
  await assert.rejects(
    client.createCase(caseFacts().purpose, CASE_KEY),
    errorIs("NETWORK_UNAVAILABLE"),
  );
  assert.equal(seen.length, 1);
  failed = false;
  assert.equal(
    (await client.createCase(caseFacts().purpose, CASE_KEY)).replayed,
    true,
  );
  assert.equal(seen[0], seen[1]);
  for (const [status, code] of [
    [401, "CONTROL_AUTH_REQUIRED"],
    [403, "CONTROL_SCOPE_DENIED"],
    [409, "CONTROL_IDEMPOTENCY_CONFLICT"],
    [429, "CONTROL_CASE_BUSY"],
    [503, "CONTROL_CASE_STORE_UNAVAILABLE"],
    [503, "AUDIT_DURABILITY_FAILED"],
  ] as const) {
    const network = t.mock.method(globalThis, "fetch", async () =>
      response(errorFixture(code), status),
    );
    await assert.rejects(
      client.createCase(caseFacts().purpose, CASE_KEY),
      errorIs(code, status),
    );
    assert.equal(network.mock.callCount(), 1);
  }
  const network = t.mock.method(globalThis, "fetch", async () => response({}));
  await assert.rejects(
    client.createCase("Review", CASE_KEY, AbortSignal.abort()),
    errorIs("REQUEST_ABORTED"),
  );
  assert.equal(network.mock.callCount(), 0);
});
