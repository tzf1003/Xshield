import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
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
