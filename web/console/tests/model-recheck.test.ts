// When the Jev card re-reads the configuration (lib/model-status.ts). It re-reads every five seconds while a saved
// version is on its way to the gateways, and every thirty seconds while a gateway is still behind after the grace
// period, so a late load shows without a reload.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { JevModelsState, ModelLoad } from "../src/api/types.ts";
import { jevBehind, LOAD_POLL_MS, LOAD_RECHECK_MS } from "../src/lib/model-status.ts";

const OLD = "2026-11-01T12:40:00.000Z";

function load(edge: string, version: number | null, error: string | null = null): ModelLoad {
  return { edge, online: true, source: version === null ? null : "console", version, error };
}

function jev(overrides: Partial<JevModelsState> = {}): JevModelsState {
  return {
    configured: true,
    source: "console",
    version: 14,
    updated_at: OLD,
    route: "gateway",
    endpoint: null,
    endpoint_host: null,
    model: "typesafe-ai/jev",
    timeout_ms: 2000,
    key: { set: true, last4: "9f3a", updated_at: OLD, shared_with_jev: false },
    key_env: "AI_GATEWAY_API_KEY",
    env_available: true,
    env_overridden: [],
    loaded: [load("edge-1", 14), load("edge-2", 14)],
    impact: { sites: 2, fail_closed: [] },
    usage: { window_minutes: 5, calls: 0, failed: 0, p95_ms: null },
    ...overrides,
  };
}

test("the fast pace is five seconds and the slower pace for a gateway still behind is thirty", () => {
  assert.equal(LOAD_POLL_MS, 5_000);
  assert.equal(LOAD_RECHECK_MS, 30_000);
});

test("a gateway still behind is re-read, and a gateway with a load error counts as behind", () => {
  assert.equal(jevBehind(jev({ loaded: [load("edge-1", 14), load("edge-2", 13)] })), true);
  assert.equal(jevBehind(jev({ loaded: [load("edge-2", 13, "MODEL_KEY_UNREADABLE")] })), true);
});

test("nothing is re-read once every gateway runs the saved version, or while the environment is in use", () => {
  assert.equal(jevBehind(undefined), false);
  assert.equal(jevBehind(jev()), false);
  assert.equal(jevBehind(jev({ source: "env", loaded: [load("edge-2", null)] })), false);
  assert.equal(jevBehind(jev({ source: null, version: 0, loaded: [] })), false);
});
