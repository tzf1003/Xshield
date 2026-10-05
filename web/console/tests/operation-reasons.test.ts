import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ApiError, ControlClient } from "../src/api.ts";
import { messages } from "../src/api-contract.ts";
import { isKnownRejection } from "../src/security/errors.ts";
import { operationReason, operationReasons } from "../src/ui/operation-reasons.ts";
import { type ReasonTone, reasonDictionary, reasonText } from "../src/ui/reason-codes.ts";

const root = new URL("../../../", import.meta.url);
const read = (path: string) => readFileSync(new URL(path, root), "utf8");

/**
 * The sources behind the workbench, key administration, the browser session, the audit
 * publication read and case-analysis jobs, with the literal codes each one may emit. Only quoted
 * literals count, so constants and environment variable names never match.
 */
const sources: readonly (readonly [path: string, pattern: RegExp])[] = [
  ["crates/xshield-control/src/workbench.rs", /"((?:WORKBENCH|CONTROL)_[A-Z0-9_]+)"/g],
  ["crates/xshield-control/src/management_api_key.rs", /"(CONTROL_[A-Z0-9_]+)"/g],
  ["crates/xshield-control/src/api_key_authz.rs", /"(CONTROL_[A-Z0-9_]+)"/g],
  ["crates/xshield-control/src/identity.rs", /"(CONTROL_[A-Z0-9_]+)"/g],
  // lib.rs holds every route; only the audit-health and key-authentication codes are ours.
  ["crates/xshield-control/src/lib.rs", /"(CONTROL_(?:HEALTH|API_KEY)_[A-Z0-9_]+)"/g],
  ["crates/xshield-control/src/jobs.rs", /"(CONTROL_(?:JOB|CASE_ANALYSIS)_[A-Z0-9_]+)"/g],
  ["crates/xshield-postgres/src/control_job.rs", /"(CONTROL_(?:JOB|CASE_ANALYSIS)_[A-Z0-9_]+)"/g],
];

function scanned(): Map<string, string> {
  const found = new Map<string, string>();
  for (const [path, pattern] of sources) {
    for (const match of read(path).matchAll(pattern)) {
      const code = match[1];
      if (code && !found.has(code)) found.set(code, path);
    }
  }
  return found;
}

test("the scan still sees the codes these pages must explain", () => {
  const found = scanned();
  for (const code of [
    "WORKBENCH_UPSTREAM_LAST_OBSERVED",
    "WORKBENCH_UPSTREAM_NEVER_OBSERVED",
    "WORKBENCH_EDGE_NOT_CONFIGURED",
    "WORKBENCH_AUDIT_NOT_AUTHORIZED",
    "CONTROL_API_KEY_SCOPE_FORBIDDEN",
    "CONTROL_API_KEY_SCOPE_INVALID",
    "CONTROL_API_KEY_INVALID",
    "CONTROL_OIDC_MFA_REQUIRED",
    "CONTROL_HEALTH_UNAVAILABLE",
    "CONTROL_CASE_ANALYSIS_COMPLETE",
  ]) {
    assert.ok(found.has(code), `scan no longer sees ${code}: update the scan, not the assertion`);
  }
  const workbench = [...found.keys()].filter((code) => code.startsWith("WORKBENCH_"));
  assert.ok(workbench.length >= 12, `only ${workbench.length} workbench codes found`);
  assert.ok(found.size >= 60, `only ${found.size} codes found; the scan is probably broken`);
});

test("every WORKBENCH_* code has a Chinese label, explanation and next step", () => {
  const missing: string[] = [];
  for (const [code, path] of scanned()) {
    if (!code.startsWith("WORKBENCH_")) continue;
    const entry = operationReason(code);
    if (!entry) {
      missing.push(`${code} (${path})`);
      continue;
    }
    assert.match(entry.label, /[一-鿿]/, `${code}: label is Chinese`);
    assert.match(entry.text, /[一-鿿]/, `${code}: explanation is Chinese`);
    assert.match(entry.action, /[一-鿿]/, `${code}: next step is Chinese`);
    assert.ok(entry.label.length <= 8, `${code}: a label fits in a pill`);
  }
  assert.deepEqual(missing, [], "add these codes to src/ui/operation-reasons.ts");
});

test("every scanned code has wording: the site dictionary, this dictionary or a safe message", () => {
  const missing: string[] = [];
  for (const [code, path] of scanned()) {
    const known =
      Object.hasOwn(reasonDictionary, code) ||
      operationReason(code) !== null ||
      Object.hasOwn(messages, code);
    if (!known) missing.push(`${code} (${path})`);
  }
  assert.deepEqual(missing, [], "add these codes to src/ui/operation-reasons.ts");
  // Key administration codes always get the full explanation, never only the short message.
  for (const code of scanned().keys()) {
    if (code.startsWith("CONTROL_API_KEY")) assert.ok(operationReason(code), code);
  }
});

test("dictionary entries are complete, Chinese, alive in the sources and never repeated", () => {
  const tones: ReasonTone[] = ["success", "info", "warning", "danger", "neutral"];
  const everything = sources.map(([path]) => read(path)).join("\n");
  for (const [code, value] of Object.entries(operationReasons)) {
    assert.ok(value.label.trim().length > 0, `${code}: label`);
    assert.match(value.text, /[一-鿿]/, `${code}: text is Chinese`);
    assert.match(value.action, /[一-鿿]/, `${code}: action is Chinese`);
    assert.ok(tones.includes(value.tone), `${code}: tone`);
    assert.ok(
      everything.includes(`"${code}"`),
      `${code}: no longer emitted by the scanned sources`,
    );
    assert.ok(!Object.hasOwn(reasonDictionary, code), `${code}: also in the site dictionary`);
  }
});

test("reasonText reaches the operation codes after the site dictionary", () => {
  const view = reasonText("WORKBENCH_UPSTREAM_LAST_OBSERVED");
  assert.equal(view.known, true);
  assert.equal(view.code, "WORKBENCH_UPSTREAM_LAST_OBSERVED");
  assert.match(view.text, /最近一次持久化的健康读取/);
  assert.match(view.action, /刷新健康/);
  // Site codes keep their own wording, generic codes keep the API client's message.
  assert.equal(reasonText("CONTROL_SITE_PAUSED").text, reasonDictionary.CONTROL_SITE_PAUSED.text);
  assert.equal(reasonText("CONTROL_RATE_LIMITED").text, messages.CONTROL_RATE_LIMITED);
  assert.equal(operationReason("constructor"), null);
  assert.equal(operationReason("__proto__"), null);
  assert.equal(operationReason(""), null);
});

test("every key-administration refusal keeps its stable code through the client", async (t) => {
  const backend = [
    read("crates/xshield-control/src/management_api_key.rs"),
    read("crates/xshield-control/src/api_key_authz.rs"),
  ].join("\n");
  const statuses: Record<string, number> = {
    CONTROL_API_KEY_REQUEST_INVALID: 400,
    CONTROL_API_KEY_EXPIRY_INVALID: 400,
    CONTROL_API_KEY_SCOPE_INVALID: 400,
    CONTROL_API_KEY_SCOPE_FORBIDDEN: 403,
    CONTROL_API_KEY_NOT_FOUND: 404,
    CONTROL_API_KEY_SITE_EXISTS: 409,
    CONTROL_API_KEY_UNAVAILABLE: 503,
    CONTROL_API_KEY_INVALID: 401,
  };
  const successFacts = new Set([
    "CONTROL_API_KEY_CREATED",
    "CONTROL_API_KEY_REVOKED",
    "CONTROL_API_KEY_ROTATED_IN",
    "CONTROL_API_KEY_ROTATED_OUT",
  ]);
  const refusals = [...new Set([...backend.matchAll(/"(CONTROL_API_KEY_[A-Z_]+)"/g)])]
    .map((match) => match[1] ?? "")
    .filter((code) => !successFacts.has(code));
  for (const code of refusals) assert.ok(Object.hasOwn(statuses, code), `status of ${code}`);
  let current = "";
  t.mock.method(
    globalThis,
    "fetch",
    async () =>
      new Response(
        JSON.stringify({
          error_code: current,
          request_id: "req_018f2a3b-4c5d-7000-8000-000000000001",
          message_safe: "Synthetic server detail",
          retryable: false,
          next_action: "correct_request",
        }),
        { status: statuses[current], headers: { "Content-Type": "application/json" } },
      ),
  );
  const client = new ControlClient("synthetic-observer-token-for-browser-tests-000000000000");
  for (const code of Object.keys(statuses)) {
    current = code;
    assert.ok(Object.hasOwn(messages, code), `${code} has no safe message`);
    const status = statuses[code] ?? 0;
    await assert.rejects(client.managementApiKeys(), (error: unknown) => {
      assert.ok(error instanceof ApiError);
      assert.equal(error.code, code);
      assert.equal(error.status, status);
      assert.ok(!error.message.includes("Synthetic server detail"));
      return true;
    });
    // 4xx refusals are deterministic (nothing was written); 503 and 401 are not.
    assert.equal(
      isKnownRejection(new ApiError(code as keyof typeof messages, status)),
      status >= 400 && status < 500 && status !== 401,
      code,
    );
  }
});
