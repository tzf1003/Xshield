// A saved version's settings read back into the form's types (lib/model-form.ts). The API sends every value
// as text (xshield-core values()), so a restore must not read "false" as a set flag.

import assert from "node:assert/strict";
import { test } from "node:test";
import { formFromValues, modelValuesFromWire } from "../src/lib/model-form.ts";

test("a Jev version's text values read back as the form's types", () => {
  assert.deepEqual(
    modelValuesFromWire("jev", {
      route: "direct",
      endpoint: "https://api.typesafe.ai/v1/systemone",
      model: "typesafe-ai/jev",
      timeout_ms: "3000",
    }),
    {
      route: "direct",
      endpoint: "https://api.typesafe.ai/v1/systemone",
      model: "typesafe-ai/jev",
      timeout_ms: 3000,
    },
  );
});

test('the share flag is read from its text, so "false" leaves the key unshared when restored', () => {
  const saved = {
    provider: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: "30000",
  };
  const off = modelValuesFromWire("agent", { ...saved, share_key_with_jev: "false" });
  assert.deepEqual(off, {
    provider: "gateway",
    endpoint: "https://ai-gateway.vercel.sh/v1",
    model: "openai/gpt-4.1-mini",
    timeout_ms: 30000,
    share_key_with_jev: false,
  });
  assert.equal(formFromValues("agent", off).shareKey, false);
  const on = modelValuesFromWire("agent", { ...saved, share_key_with_jev: "true" });
  assert.equal(formFromValues("agent", on).shareKey, true);
});

test("an empty model reads as no model, and an unknown route reads as the gateway", () => {
  assert.deepEqual(
    modelValuesFromWire("jev", { route: "mystery", endpoint: "", model: "", timeout_ms: "2000" }),
    { route: "gateway", endpoint: null, model: null, timeout_ms: 2000 },
  );
  assert.deepEqual(
    modelValuesFromWire("agent", {
      provider: "custom",
      endpoint: "https://llm.example.com/v1",
      model: "",
      timeout_ms: "60000",
      share_key_with_jev: "false",
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
