import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { decodeRollout, type SiteRollout } from "../src/api.ts";
import {
  canonicalJson,
  configFromStored,
  type SiteConfigDraft,
} from "../src/sites/model/config.ts";
import {
  assessChangeRisk,
  explainApproval,
  needsIndependentApproval,
  needsStepUp,
  rolloutRelaxes,
} from "../src/sites/model/risk.ts";

const LOOP = readFileSync(
  new URL("../../../tests/site-config/browser-loop.json", import.meta.url),
  "utf8",
);

const observe = (until: number, enforced?: string[]): SiteRollout => ({
  mode: "observe",
  observe_until_unix: until,
  revision: "rollout-1",
  ...(enforced ? { enforced_operations: enforced } : {}),
});

function draft(rollout?: SiteRollout): SiteConfigDraft {
  const stored = JSON.parse(LOOP) as Record<string, unknown>;
  if (rollout) (stored.policy as Record<string, unknown>).rollout = rollout;
  const result = configFromStored(stored);
  assert.ok(result);
  return result;
}

test("the rollout block decodes strictly and enforce reads as absent", () => {
  assert.equal(decodeRollout(undefined), undefined);
  assert.equal(decodeRollout({}), undefined);
  assert.equal(decodeRollout({ mode: "enforce" }), undefined);
  assert.deepEqual(decodeRollout(observe(2_000_000_000, ["app.page"])), {
    mode: "observe",
    observe_until_unix: 2_000_000_000,
    revision: "rollout-1",
    enforced_operations: ["app.page"],
  });
  assert.deepEqual(decodeRollout({ ...observe(2_000_000_000), enforced_operations: [] }), {
    mode: "observe",
    observe_until_unix: 2_000_000_000,
    revision: "rollout-1",
  });
  for (const invalid of [
    { mode: "enforce", revision: "r1" },
    { mode: "enforce", observe_until_unix: 1 },
    { mode: "OBSERVE", observe_until_unix: 1, revision: "r1" },
    { mode: "observe", revision: "r1" },
    { mode: "observe", observe_until_unix: 0, revision: "r1" },
    { mode: "observe", observe_until_unix: 1, revision: "has space" },
    { ...observe(1), enforced_operations: ["a", "a"] },
    { ...observe(1), extra: true },
    null,
  ]) {
    assert.throws(() => decodeRollout(invalid), JSON.stringify(invalid));
  }
});

test("a stored rollout survives the draft and stays absent when enforced", () => {
  const observed = draft(observe(2_000_000_000, ["app.page"]));
  assert.deepEqual(observed.policy.rollout, observe(2_000_000_000, ["app.page"]));
  assert.ok(canonicalJson(observed.policy).includes('"rollout"'));
  const enforced = draft();
  assert.equal(enforced.policy.rollout, undefined);
  assert.ok(!canonicalJson(enforced.policy).includes("rollout"));
});

test("rollout reasons mirror assess_change_risk in each direction", () => {
  const enforced = draft();
  const observed = draft(observe(2_000_000_000));
  const extended = draft(observe(2_000_000_001));
  const tightened = draft(observe(2_000_000_000, ["app.page"]));
  const relabelled = draft({ ...observe(2_000_000_000), revision: "rollout-2" });
  assert.ok(assessChangeRisk(null, observed).includes("ROLLOUT_MODE_RELAXED"));
  assert.ok(!assessChangeRisk(null, enforced).some((token) => token.startsWith("ROLLOUT")));
  for (const [from, to, expected] of [
    [enforced, observed, "ROLLOUT_MODE_RELAXED"],
    [observed, extended, "ROLLOUT_MODE_RELAXED"],
    [tightened, observed, "ROLLOUT_MODE_RELAXED"],
    [observed, enforced, "ROLLOUT_MODE_TIGHTENED"],
    [extended, observed, "ROLLOUT_MODE_TIGHTENED"],
    [observed, tightened, "ROLLOUT_MODE_TIGHTENED"],
    [observed, relabelled, "ROLLOUT_MODE_TIGHTENED"],
  ] as const) {
    assert.deepEqual(assessChangeRisk(from, to), [expected]);
  }
  assert.deepEqual(assessChangeRisk(observed, observed), []);
  assert.equal(rolloutRelaxes(undefined, undefined), false);
  assert.equal(needsIndependentApproval("ROLLOUT_MODE_RELAXED"), true);
  assert.equal(needsIndependentApproval("ROLLOUT_MODE_TIGHTENED"), false);
  assert.equal(needsStepUp("ROLLOUT_MODE_RELAXED"), true);
  assert.equal(needsStepUp("AUTH_ENTRY_CHANGED"), false);
});

test("the approval explanation lists the rollout rows under the reason that applies", () => {
  const explanation = explainApproval(draft(), draft(observe(2_000_000_000)));
  assert.deepEqual(
    explanation.reasons.map((reason) => reason.token),
    ["ROLLOUT_MODE_RELAXED"],
  );
  const rows = explanation.reasons[0]?.changes.map((change) => change.id) ?? [];
  assert.deepEqual(rows, ["rollout.mode", "rollout.observe_until_unix", "rollout.revision"]);
  assert.ok(explanation.reasons[0]?.label.includes("观察"));
});
