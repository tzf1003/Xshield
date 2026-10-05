import assert from "node:assert/strict";
import { test } from "node:test";
import type { SiteRevision } from "../src/api.ts";
import { emptyDraft, type SiteConfigDraft } from "../src/sites/model/config.ts";
import {
  approvalNeed,
  planRollback,
  releaseGates,
  restoredFrom,
  reviewDigest,
} from "../src/sites/model/release.ts";
import { leaveListNotice, takeListNotice } from "../src/sites/state/list-flash.ts";

const A = "a".repeat(64);
const B = "b".repeat(64);

test("a rollback with a change pending cancels it by restoring the active revision", () => {
  const plan = planRollback(
    { desired_revision: 5, active_revision: 4, apply_state: "pending" },
    [5, 4, 3, 2, 1],
  );
  assert.deepEqual(plan, {
    available: true,
    cancelsPendingChange: true,
    target: 4,
    candidates: [],
  });
  // A failed apply is a change that did not complete.
  assert.equal(
    planRollback({ desired_revision: 4, active_revision: 4, apply_state: "failed" }, [4, 3]).target,
    4,
  );
});

test("with nothing pending the server picks the previously active revision, which the console cannot name", () => {
  const plan = planRollback(
    { desired_revision: 4, active_revision: 4, apply_state: "active" },
    [4, 3, 2, 1],
  );
  assert.equal(plan.available, true);
  assert.equal(plan.cancelsPendingChange, false);
  assert.equal(
    plan.target,
    null,
    "revision numbers below the active one may never have served traffic",
  );
  assert.deepEqual(plan.candidates, [3, 2, 1], "preview candidates, newest first");
  // A paused site with nothing pending behaves the same way.
  assert.equal(
    planRollback({ desired_revision: 4, active_revision: 4, apply_state: "paused" }, [4, 3])
      .cancelsPendingChange,
    false,
  );
});

test("without an active revision there is nothing to roll back to", () => {
  assert.deepEqual(
    planRollback({ desired_revision: 1, active_revision: null, apply_state: "pending" }, [1]),
    { available: false, cancelsPendingChange: false, target: null, candidates: [] },
  );
});

test("candidates are only older revisions, in any input order", () => {
  const plan = planRollback(
    { desired_revision: 6, active_revision: 6, apply_state: "active" },
    [2, 9, 6, 4, 1, 7],
  );
  assert.deepEqual(plan.candidates, [4, 2, 1]);
});

test("an approval is pinned to the configuration that was read, and a mismatch is stale", () => {
  assert.deepEqual(reviewDigest({ config_digest: A }, A), { digest: A, stale: false });
  assert.deepEqual(reviewDigest({ config_digest: A }, B), { digest: A, stale: true });
  assert.deepEqual(reviewDigest({ config_digest: A }, null), { digest: A, stale: false });
  // Without revisions the status digest is what there is.
  assert.deepEqual(reviewDigest(null, B), { digest: B, stale: false });
  assert.deepEqual(reviewDigest(null, null), { digest: null, stale: false });
});

test("a digest that is not 64 lowercase hex is never sent", () => {
  for (const bad of [
    "",
    "A".repeat(64),
    "a".repeat(63),
    "a".repeat(65),
    `${"a".repeat(63)}g`,
    ` ${"a".repeat(63)}`,
  ]) {
    assert.equal(reviewDigest(null, bad).digest, null, JSON.stringify(bad));
    assert.equal(reviewDigest({ config_digest: bad }, null).digest, null, JSON.stringify(bad));
  }
});

const live = (over: Partial<SiteConfigDraft> = {}): SiteConfigDraft => ({
  ...emptyDraft(),
  display_name: "Alpha",
  public_origin: "https://www.example.test",
  upstream_address: "8.8.8.8:443",
  upstream_server_name: "origin.example.test",
  listen_port: 6101,
  status: "active",
  ...over,
});

test("the release gates keep today's rules and say why an action is unavailable", () => {
  const facts = (over: Record<string, unknown> = {}) => ({
    desired_revision: 4,
    active_revision: 3,
    apply_state: "pending" as const,
    requires_approval: true,
    ...over,
  });
  // Awaiting approval: approve is the way forward, apply waits for it.
  let gates = releaseGates(facts(), true);
  assert.equal(gates.approve.enabled, true);
  assert.equal(gates.apply.enabled, false);
  assert.match(gates.apply.hint, /先批准/);
  assert.equal(gates.validate.enabled, true);
  assert.equal(gates.rollback.enabled, true);
  // No approval needed: nothing to approve, apply is offered.
  gates = releaseGates(facts({ requires_approval: false }), true);
  assert.equal(gates.approve.enabled, false);
  assert.match(gates.approve.hint, /不需要审批/);
  assert.equal(gates.apply.enabled, true);
  // A site the edge never served has nothing to roll back to.
  gates = releaseGates(facts({ active_revision: null, requires_approval: false }), true);
  assert.equal(gates.rollback.enabled, false);
  assert.match(gates.rollback.hint, /没有可回滚/);
  // Nothing staged: nothing to apply.
  assert.equal(releaseGates(facts({ desired_revision: null }), true).apply.enabled, false);
  // A role that cannot read the facts is offered everything and the server decides.
  const blind = releaseGates(
    { desired_revision: null, active_revision: null, apply_state: null, requires_approval: null },
    false,
  );
  assert.deepEqual(
    [blind.validate.enabled, blind.approve.enabled, blind.apply.enabled, blind.rollback.enabled],
    [true, true, true, true],
  );
  // Re-applying a confirmed revision stays possible (a re-push), as before.
  assert.equal(
    releaseGates(
      facts({ desired_revision: 3, apply_state: "active", requires_approval: false }),
      true,
    ).apply.enabled,
    true,
  );
});

test("the approval explanation names the changed fields under each reason", () => {
  const serving = live();
  const staged = live({ upstream_address: "9.9.9.9:443", display_name: "Alpha 新" });
  const need = approvalNeed({
    verdict: true,
    desired: 4,
    active: 3,
    readable: true,
    staged,
    serving,
  });
  assert.equal(need.limitation, null);
  assert.equal(need.disagrees, false);
  assert.deepEqual(
    need.explanation?.reasons.map((reason) => reason.token),
    ["UPSTREAM_CHANGED"],
  );
  assert.ok(
    need.explanation?.free.some((change) => change.label.includes("名称")),
    "the display name is free",
  );
});

test("a first activation is explained without a baseline", () => {
  const need = approvalNeed({
    verdict: true,
    desired: 1,
    active: null,
    readable: true,
    staged: live(),
    serving: null,
  });
  assert.deepEqual(
    need.explanation?.reasons.map((reason) => reason.token),
    ["ACTIVATION"],
  );
});

test("when the server and the reconstruction disagree the server's verdict stands and it is flagged", () => {
  const same = live();
  // The server says approval is needed but the console sees no field that requires it.
  const stricter = approvalNeed({
    verdict: true,
    desired: 4,
    active: 3,
    readable: true,
    staged: same,
    serving: same,
  });
  assert.equal(stricter.disagrees, true);
  assert.equal(stricter.verdict, true);
  // The server says it is not needed but the console would have asked for it.
  const laxer = approvalNeed({
    verdict: false,
    desired: 4,
    active: 3,
    readable: true,
    staged: live({ listen_port: 6200 }),
    serving: same,
  });
  assert.equal(laxer.disagrees, true);
});

test("without readable revisions there is a verdict and a stated limitation, never a guess", () => {
  const blind = approvalNeed({
    verdict: true,
    desired: 4,
    active: 3,
    readable: false,
    staged: null,
    serving: null,
  });
  assert.equal(blind.explanation, null);
  assert.match(blind.limitation ?? "", /observer/);
  assert.equal(blind.disagrees, false);
  // Readable, but the staged revision is not in the list that was read.
  const missing = approvalNeed({
    verdict: true,
    desired: 5,
    active: 3,
    readable: true,
    staged: null,
    serving: live(),
  });
  assert.equal(missing.explanation, null);
  assert.match(missing.limitation ?? "", /r5/);
  // Readable, staged present, but the serving revision is not in the list.
  const noServing = approvalNeed({
    verdict: true,
    desired: 4,
    active: 3,
    readable: true,
    staged: live(),
    serving: null,
  });
  assert.equal(noServing.explanation, null);
  assert.match(noServing.limitation ?? "", /r3/);
});

const stored = (revision: number, config: SiteConfigDraft): SiteRevision => ({
  revision,
  policy_revision: config.policy_revision,
  config_digest: String(revision)
    .padStart(64, "a")
    .replace(/[^0-9a-f]/g, "a"),
  config: structuredClone(config) as unknown as Record<string, unknown>,
  created_by: "author@example.test",
  created_at: "2026-09-20T08:10:30.000Z",
});

test("a revision that repeats an older one is recognised, a plain re-save is not", () => {
  const a = live();
  const b = live({ upstream_address: "9.9.9.9:443" });
  const items = [
    stored(1, a),
    stored(2, b),
    stored(3, b), // re-save of the revision right before it
    stored(4, a), // a rollback: stores r1's content as a new revision
    stored(5, live({ display_name: "新名称" })),
  ];
  assert.deepEqual([...restoredFrom(items)], [[4, 1]]);
  // Input order does not matter, and revisions that cannot be read are skipped.
  assert.deepEqual([...restoredFrom([...items].reverse())], [[4, 1]]);
  assert.deepEqual([...restoredFrom([{ ...stored(9, a), config: "garbage" as never }])], []);
});

test("a notice left for the list is read once and then gone", () => {
  assert.equal(takeListNotice(), null);
  const outcome = { tone: "success", title: "站点已删除，监听端口已释放。", detail: null } as const;
  leaveListNotice(outcome);
  assert.deepEqual(takeListNotice(), outcome);
  assert.equal(takeListNotice(), null, "reading it consumes it");
});
