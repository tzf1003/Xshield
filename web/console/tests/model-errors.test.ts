// The codes the control plane and the gateways send for a model configuration each have their own
// text, so a form never shows a bare code (lib/vocab.ts). The codes are the stable ones from
// xshield-core (ConfigError::code), the gateway's test refusals (JEV_CONFIG_*), and the codes a
// gateway reports for a version it could not load.

import assert from "node:assert/strict";
import { test } from "node:test";
import { errorText, MODEL_LOAD_ERROR_TEXT } from "../src/lib/vocab.ts";

const REFUSALS = [
  "MODEL_ROUTE_INVALID",
  "MODEL_PROVIDER_INVALID",
  "MODEL_ENDPOINT_INVALID",
  "MODEL_NAME_INVALID",
  "MODEL_TIMEOUT_INVALID",
  "MODEL_KEY_INVALID",
  "MODEL_KEY_SHARE_INVALID",
  "JEV_CONFIG_ROUTE_INVALID",
  "JEV_CONFIG_ENDPOINT_INVALID",
  "JEV_CONFIG_MODEL_INVALID",
  "JEV_CONFIG_TIMEOUT_INVALID",
  "JEV_CONFIG_KEY_INVALID",
];

const LOAD_ERRORS = [
  "MODEL_KEY_UNREADABLE",
  "MODEL_STORE_UNAVAILABLE",
  "JEV_CONFIG_ROUTE_INVALID",
  "JEV_CONFIG_ENDPOINT_INVALID",
];

test("every refusal the control plane or a gateway sends has its own text", () => {
  for (const code of REFUSALS) {
    const text = errorText(code);
    assert.ok(!text.includes(code), `${code} shows as a bare code`);
  }
});

test("every code a gateway reports for a version it could not load has its own text", () => {
  for (const code of LOAD_ERRORS) {
    assert.ok(MODEL_LOAD_ERROR_TEXT[code], `${code} has no text`);
  }
});
