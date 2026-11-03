// A saved version's settings read back into the form's types (lib/model-form.ts). The history stores the settings as
// the core's JSON, so a timeout is a number and a share flag a boolean: a restore must read them as those.

import assert from "node:assert/strict";
import { test } from "node:test";
import { formFromValues, modelValuesFromWire } from "../src/lib/model-form.ts";

test("a Jev version's settings read back as the form's types", () => {
  assert.deepEqual(
    modelValuesFromWire("jev", {
      route: "direct",
      endpoint: "https://api.typesafe.ai/v1/systemone",
      model: "typesafe-ai/jev",
      timeout_ms: 3000,
    }),
    {
      route: "direct",
      endpoint: "https://api.typesafe.ai/v1/systemone",
      model: "typesafe-ai/jev",
      timeout_ms: 3000,
    },
  );
});

test("a history response as the API sends it restores a shared agent with its share flag on", () => {
  // The shape GET /api/system/models/agent/history returns: the stored JSON, read the way the server writes it.
  const wire = JSON.parse(`{
    "provider": "gateway",
    "endpoint": "https://ai-gateway.vercel.sh/v1",
    "model": "openai/gpt-4.1-mini",
    "timeout_ms": 30000,
    "share_key_with_jev": true
  }`);
  const restored = modelValuesFromWire("agent", wire);
  assert.deepEqual(restored, {
    provider: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: 30000,
    share_key_with_jev: true,
  });
  assert.equal(formFromValues("agent", restored).shareKey, true);
});

test("an unshared agent version restores with its share flag off", () => {
  const restored = modelValuesFromWire("agent", {
    provider: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: 30000,
    share_key_with_jev: false,
  });
  assert.equal(formFromValues("agent", restored).shareKey, false);
});

test("an empty model reads as no model, and an unknown route reads as the gateway", () => {
  assert.deepEqual(
    modelValuesFromWire("jev", { route: "mystery", endpoint: "", model: null, timeout_ms: 2000 }),
    { route: "gateway", endpoint: null, model: null, timeout_ms: 2000 },
  );
  assert.deepEqual(
    modelValuesFromWire("agent", {
      provider: "custom",
      endpoint: "https://llm.example.com/v1",
      model: "",
      timeout_ms: 60000,
      share_key_with_jev: false,
    }),
    {
      provider: "custom",
      endpoint: "https://llm.example.com/v1",
      model: null,
      timeout_ms: 60000,
      share_key_with_jev: false,
    },
  );
});
