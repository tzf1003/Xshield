import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  describedReasonCodes,
  describeReason,
  isKnownReason,
  UNDESCRIBED_EXPLAIN,
} from "../src/ui/request-reasons.ts";
import { reasonData } from "../src/ui/request-reasons-data.ts";

const repo = fileURLToPath(new URL("../../../", import.meta.url));

/**
 * Where reason codes are written. The three `src/*.rs` levels hold the request pipeline, the
 * audit contract and the worker; `model_eval` holds the model lifecycle codes. Test modules are
 * skipped: their fixtures are not part of the contract.
 */
const roots = [
  { dir: "crates/xshield-gateway/src", recursive: false },
  { dir: "crates/xshield-core/src", recursive: false },
  { dir: "crates/xshield-worker/src", recursive: false },
  { dir: "crates/xshield-worker/src/model_eval", recursive: true },
] as const;

/**
 * Uppercase string constants that are not reason codes. Anything else of the shape
 * `"[A-Z][A-Z0-9_]{5,}"` in those sources must be described in `request-reasons-data.ts`, so a
 * new code cannot ship without words. Adding a name here needs a one-line reason.
 */
const notReasonCodes: Readonly<Record<string, string>> = {
  AUTH_ENTRY: "site policy admission class",
  BUFFERED_JSON: "site policy response mode",
  COMPATIBILITY: "request-crypto coverage mode",
  DIRECT_ENCRYPT: "site policy crypto mode",
  ENFORCE: "request-crypto coverage mode",
  OBSERVE: "request-crypto coverage mode",
  PUBLIC: "admission class and sensitivity label",
  INTERNAL: "event sensitivity label",
  RESTRICTED: "event sensitivity label",
  SENSITIVE: "event sensitivity label",
  CANCELLED: "stage outcome label",
  SKIPPED: "stage outcome label",
  UNKNOWN: "decision and outcome label",
  DELETE: "HTTP method name",
  NOT_CONFIGURED:
    "final decision label of the in-process M0 audit; wire decisions are ALLOW/DENY/UNKNOWN",
  HEARTBEAT: "browser sensor event type",
  PAGE_READY: "browser sensor event type",
  VISIBILITY: "browser sensor event type",
  CARGO_PKG_VERSION: "cargo build environment variable",
  SCREAMING_SNAKE_CASE: "serde rename rule",
};
/** Environment variable names and API key names are configuration, not reasons. */
const notReasonPatterns: readonly RegExp[] = [/^XSHIELD_/, /_API_KEY$/];

const candidate = /"[A-Z][A-Z0-9_]{5,}"/g;

function* sourceFiles(dir: string, recursive: boolean): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : 1,
  )) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (recursive) yield* sourceFiles(path, true);
    } else if (entry.name.endsWith(".rs")) {
      yield path;
    }
  }
}

const isTestFile = (path: string) =>
  /(^|\/)tests?(\/|\.rs$)/.test(path) || /_tests?\.rs$/.test(path);

type Hit = { value: string; where: string };

function scan(): Hit[] {
  const hits: Hit[] = [];
  for (const root of roots) {
    for (const file of sourceFiles(join(repo, root.dir), root.recursive)) {
      const rel = relative(repo, file);
      if (isTestFile(rel)) continue;
      const text = readFileSync(file, "utf8");
      // Drop an inline `#[cfg(test)] mod tests { ... }`; out-of-line test modules are separate files.
      const inlineTests = /#\[cfg\(test\)\]\s*mod\s+\w+\s*\{/.exec(text);
      const code = inlineTests ? text.slice(0, inlineTests.index) : text;
      code.split("\n").forEach((line, index) => {
        for (const match of line.matchAll(candidate)) {
          hits.push({ value: match[0].slice(1, -1), where: `${rel}:${index + 1}` });
        }
      });
    }
  }
  return hits;
}

const hits = scan();
const isIgnored = (value: string) =>
  Object.hasOwn(notReasonCodes, value) || notReasonPatterns.some((pattern) => pattern.test(value));

test("the scan finds the Rust sources it is meant to guard", () => {
  assert.ok(hits.length > 300, `only ${hits.length} constants found; did the crates move?`);
  const files = new Set(hits.map((hit) => hit.where.split(":")[0]));
  for (const expected of [
    "crates/xshield-core/src/audit.rs",
    "crates/xshield-gateway/src/protected_identity.rs",
    "crates/xshield-worker/src/model_eval/mod.rs",
  ]) {
    assert.ok(files.has(expected), expected);
  }
});

test("every uppercase constant in the gateway, core and worker sources is described or classified", () => {
  const missing = new Map<string, string>();
  for (const hit of hits) {
    if (isIgnored(hit.value) || isKnownReason(hit.value)) continue;
    if (!missing.has(hit.value)) missing.set(hit.value, hit.where);
  }
  assert.deepEqual(
    [...missing].map(([value, where]) => `${value} (${where})`),
    [],
    "describe each code in src/ui/request-reasons-data.ts, or list it as a non-reason in this test",
  );
});

test("the non-reason list holds no stale entries", () => {
  const seen = new Set(hits.map((hit) => hit.value));
  const stale = Object.keys(notReasonCodes).filter((name) => !seen.has(name));
  assert.deepEqual(stale, []);
  // A described code is never also classified as a non-reason.
  assert.deepEqual(
    Object.keys(notReasonCodes).filter((name) => isKnownReason(name)),
    [],
  );
});

test("every ReasonCode of the audit contract has a description", () => {
  const source = readFileSync(join(repo, "crates/xshield-core/src/audit.rs"), "utf8");
  const start = source.indexOf("impl ReasonCode {");
  const block = source.slice(start, source.indexOf("\n}\n", start));
  const codes = [...block.matchAll(/=> "([A-Z0-9_]+)"/g)].map((match) => match[1] ?? "");
  assert.ok(codes.length > 80, `only ${codes.length} ReasonCode arms parsed`);
  assert.deepEqual(
    codes.filter((code) => !isKnownReason(code)),
    [],
  );
});

test("the codes the console fixtures and pages rely on are described", () => {
  for (const code of [
    "UI_ACTION_NOT_AVAILABLE",
    "AUTH_BINDING_VALID",
    "WAF_QUERY_BLOCKED",
    "REQUEST_ACCEPTED",
    "REQUEST_DENIED",
    "MODEL_EVALUATED",
    "MODEL_REQUESTED",
    "MODEL_EVALUATION_STARTED",
    "MODEL_PROVIDER_UNAVAILABLE",
    "ORIGIN_OUTCOME_UNKNOWN",
    "REQUEST_INCOMPLETE",
    "CONTROL_SCOPE_DENIED",
  ]) {
    assert.equal(describeReason(code).known, true, code);
  }
});

test("every description is complete, in Chinese and honest about its tone", () => {
  const tones = new Set(["allow", "deny", "observe", "error", "info", "unknown"]);
  const problems: string[] = [];
  for (const [code, tuple] of Object.entries(reasonData)) {
    const [tone, label, explain, next] = tuple;
    if (!tones.has(tone)) problems.push(`${code}: tone ${tone}`);
    if (!/[一-鿿]/.test(label) || label.length > 20) problems.push(`${code}: label`);
    if (label === code || /[A-Z]{2,}_[A-Z]{2,}/.test(label))
      problems.push(`${code}: raw code in label`);
    if (!explain.endsWith("。") || explain.length > 120) problems.push(`${code}: explanation`);
    if (next.trim() === "" || next.length > 100) problems.push(`${code}: next step`);
    // A hard failure that lands in the "allow" tone would read as good news.
    if (tone === "allow" && /失败|拒绝|无效|不匹配/.test(label))
      problems.push(`${code}: allow tone`);
  }
  assert.deepEqual(problems, []);
});

test("codes without a description are shown as received, never invented", () => {
  const unknown = describeReason("SOMETHING_NEW_FROM_A_NEWER_SERVER");
  assert.equal(unknown.known, false);
  assert.equal(unknown.code, "SOMETHING_NEW_FROM_A_NEWER_SERVER");
  assert.equal(unknown.label, "SOMETHING_NEW_FROM_A_NEWER_SERVER");
  assert.equal(unknown.explain, UNDESCRIBED_EXPLAIN);
  assert.equal(unknown.tone, "unknown");
  for (const missing of [null, undefined, ""]) {
    const description = describeReason(missing);
    assert.equal(description.known, false);
    assert.equal(description.code, "");
    assert.equal(description.label, "未记录原因");
  }
  const known = describeReason("UI_ACTION_NOT_AVAILABLE");
  assert.deepEqual([known.known, known.tone, known.label], [true, "deny", "界面动作不可用"]);
  assert.equal(describedReasonCodes().length, Object.keys(reasonData).length);
});
