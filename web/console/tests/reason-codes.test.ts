import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { messages } from "../src/api-contract.ts";
import {
  type ReasonTone,
  reasonDictionary,
  reasonText,
  riskDictionary,
} from "../src/ui/reason-codes.ts";

const root = new URL("../../../", import.meta.url);
const read = (path: string) => readFileSync(new URL(path, root), "utf8");

/** The files whose string literals are site, apply, edge or health reason codes. */
const codeSources = [
  "crates/xshield-control/src/site_config.rs",
  "crates/xshield-control/src/workbench.rs",
  "crates/xshield-postgres/src/site_config.rs",
  "crates/xshield-gateway/src/apply_api.rs",
  "crates/xshield-core/src/site.rs",
  "crates/xshield-core/src/site/config.rs",
  "crates/xshield-core/src/site/upstream.rs",
];

/** Quoted literals only (Rust "..." and SQL '...'), so constants and env var names never match. */
const literal = /["']((?:CONTROL_SITES?|EDGE)_[A-Z0-9_]+)["']/g;

function scannedCodes(): Map<string, string> {
  const found = new Map<string, string>();
  for (const path of codeSources) {
    for (const match of read(path).matchAll(literal)) {
      const code = match[1];
      if (code && !found.has(code)) found.set(code, path);
    }
  }
  return found;
}

test("the scan finds the codes this console must label", () => {
  const found = scannedCodes();
  for (const code of [
    "CONTROL_SITE_APPROVAL_REVISION_MISMATCH",
    "CONTROL_SITE_DELETE_STEP_UP_REQUIRED",
    "CONTROL_SITE_SSRF_BLOCKED",
    "CONTROL_SITE_PAUSED",
    "CONTROL_SITE_APPLY_ACTIVE",
    "EDGE_APPLY_CONFIRMED",
    "EDGE_SNAPSHOT_PERSISTENCE_UNAVAILABLE",
    "EDGE_DIRECT_APPLY_NOT_CONFIRMED",
  ]) {
    assert.ok(found.has(code), `scan no longer sees ${code}: update the scan, not the assertion`);
  }
  assert.ok(found.size >= 50, `only ${found.size} codes found; the scan is probably broken`);
});

test("every site, apply, edge and health code in the Rust sources has text and a next action", () => {
  const missing: string[] = [];
  for (const [code, path] of scannedCodes()) {
    if (!Object.hasOwn(reasonDictionary, code)) missing.push(`${code} (${path})`);
  }
  assert.deepEqual(missing, [], "add these codes to src/ui/reason-codes.ts");
});

test("every dictionary entry is complete, Chinese and appears in the sources", () => {
  const tones: ReasonTone[] = ["success", "info", "warning", "danger", "neutral"];
  const everything = [
    ...codeSources,
    ...readdirSync(new URL("crates/xshield-control/src/", root))
      .filter((name) => name.endsWith(".rs"))
      .map((name) => `crates/xshield-control/src/${name}`),
  ]
    .map(read)
    .join("\n");
  for (const [code, value] of Object.entries(reasonDictionary)) {
    assert.ok(value.text.trim().length > 0, `${code}: text`);
    assert.ok(value.action.trim().length > 0, `${code}: action`);
    assert.match(value.text, /[一-鿿]/, `${code}: text is Chinese`);
    assert.match(value.action, /[一-鿿]/, `${code}: action is Chinese`);
    assert.ok(tones.includes(value.tone), `${code}: tone`);
    assert.ok(
      everything.includes(`"${code}"`) || everything.includes(`'${code}'`),
      `${code}: dead`,
    );
  }
});

test("every site error the API client maps has dictionary text as well", () => {
  for (const code of Object.keys(messages)) {
    if (!code.startsWith("CONTROL_SITE_")) continue;
    assert.ok(Object.hasOwn(reasonDictionary, code), `${code} has an error message but no entry`);
  }
});

test("risk tokens mirror assess_change_risk exactly", () => {
  const source = read("crates/xshield-core/src/site/risk.rs");
  const tokens = [...source.matchAll(/Self::[A-Za-z]+ => "([A-Z_]+)"/g)].map((match) => match[1]);
  assert.ok(tokens.length >= 17, "the risk token scan found too few tokens");
  assert.deepEqual([...tokens].sort(), Object.keys(riskDictionary).sort());
  for (const value of Object.values(riskDictionary)) {
    assert.ok(value.label.length > 0 && value.detail.length > 0);
  }
});

test("reasonText labels known codes and never invents text for unknown ones", () => {
  const known = reasonText("CONTROL_SITE_APPROVAL_REVISION_MISMATCH");
  assert.equal(known.known, true);
  assert.equal(known.code, "CONTROL_SITE_APPROVAL_REVISION_MISMATCH");
  assert.match(known.action, /重新读取/);
  // Generic control codes fall back to the API client's safe message.
  const generic = reasonText("CONTROL_RATE_LIMITED");
  assert.equal(generic.text, messages.CONTROL_RATE_LIMITED);
  assert.equal(generic.known, true);
  const unknown = reasonText("SOMETHING_NEW");
  assert.equal(unknown.known, false);
  assert.equal(unknown.code, "SOMETHING_NEW");
  assert.match(unknown.text, /尚未识别/);
  assert.equal(reasonText(null).code, "");
  assert.equal(reasonText(undefined).known, false);
  assert.equal(reasonText("").known, false);
  // Object.prototype members are not codes.
  assert.equal(reasonText("constructor").known, false);
  assert.equal(reasonText("__proto__").known, false);
});

test("the delete and approve step-up refusals tell the operator how to recover", () => {
  for (const code of ["CONTROL_SITE_DELETE_STEP_UP_REQUIRED", "CONTROL_STEP_UP_REQUIRED"]) {
    assert.match(reasonText(code).action, /重新验证高危操作/);
  }
  assert.match(reasonText("CONTROL_SITE_IDEMPOTENCY_KEY_SUPERSEDED").action, /不要原样重试/);
});
