import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  ObjectAcceptanceJudgement,
  ObjectSlotEntry,
  ObjectTierJudgement,
  ObjectsSpec,
} from "../src/api/types.ts";
import {
  hasJudgement,
  isAcceptance,
  judgementChoiceOf,
  judgementKey,
  judgementWords,
  proposalFigures,
  proposalWords,
  shareOfMille,
  unidentifiedNoteOfEntry,
  unidentifiedNoteOfProposal,
  withJudgement,
} from "../src/lib/judgement.ts";
import { checkObjects, objectChanges, parseObjects } from "../src/lib/objects-validate.ts";
import { DECLARE_TEXT } from "../src/lib/vocab.ts";

// The judgements a declared position carries (docs/07 7.9.15, 7.9.16): the words the object table and the request
// detail show, the figures of a proposal, the entry the drawer's choices make, and the checks the form runs before
// it saves. The gateway refuses the same shapes, so a form that shows one of them is a form that would not save.

const doctor: ObjectSlotEntry = { key: "GET /api/doctors [].id", class: "doctor", source: "admin" };

const acceptance: ObjectAcceptanceJudgement = {
  id: "p-1",
  key: "GET /doctor/{id} path[1]",
  reliability: "high",
  last_seen: null,
  accepts_public: false,
  votes: 1234,
  sessions: 56,
  public_per_mille: 4,
};

const tier: ObjectTierJudgement = {
  id: "p-2",
  key: "GET /api/doctors [].id",
  reliability: "medium",
  last_seen: null,
  tier: "public",
  units: 12,
  seen_values: 3,
  agreement_per_mille: 950,
};

test("a judgement reads in words: identity, tier, acceptance, then reliability", () => {
  assert.equal(judgementWords({ identity: "user" }), "身份 用户");
  assert.equal(judgementWords({ identity: "role" }), "身份 角色");
  assert.equal(judgementWords({ tier: "public", reliability: "high" }), "归属 公共 · 可靠性 高");
  assert.equal(judgementWords({ tier: "admin", reliability: "low" }), "归属 管理 · 可靠性 低");
  assert.equal(
    judgementWords({ accepts_public: false, reliability: "medium" }),
    "不接受公共来源 · 可靠性 中",
  );
  assert.equal(
    judgementWords({ accepts_public: true, reliability: "high" }),
    "接受公共来源 · 可靠性 高",
  );
  assert.equal(judgementWords({}), null);
});

test("a judgement's key tells whether it changed, and an absent field reads as none", () => {
  assert.equal(judgementKey({ tier: "self" }), judgementKey({ tier: "self" }));
  assert.notEqual(judgementKey({ tier: "self" }), judgementKey({ tier: "org" }));
  assert.notEqual(
    judgementKey({ tier: "self" }),
    judgementKey({ tier: "self", reliability: "high" }),
  );
  assert.equal(judgementKey({}), judgementKey({ identity: undefined }));
});

test("a judgement set as one choice keeps a reliability only when a tier or an acceptance qualifies it", () => {
  const judged: ObjectSlotEntry = { ...doctor, tier: "org", reliability: "high" };
  // An absent field is kept, a value replaces the old one.
  assert.deepEqual(withJudgement(judged, { reliability: "medium" }), {
    ...doctor,
    tier: "org",
    reliability: "medium",
  });
  // A null takes the field away; the reliability goes with the tier it qualified.
  assert.deepEqual(withJudgement(judged, { tier: null }), doctor);
  // A reliability with nothing to qualify is dropped, as the gateway would refuse it.
  assert.deepEqual(withJudgement(doctor, { reliability: "high" }), doctor);
  // An acceptance keeps its reliability, and an identity clears with null.
  assert.deepEqual(withJudgement(doctor, { accepts_public: true, reliability: "low" }), {
    ...doctor,
    accepts_public: true,
    reliability: "low",
  });
  assert.deepEqual(withJudgement({ ...doctor, identity: "role" }, { identity: null }), doctor);
});

test("a judgement choice never changes the entry it is given", () => {
  const judged: ObjectSlotEntry = { ...doctor, tier: "org", reliability: "high", paused: true };
  const before = structuredClone(judged);
  withJudgement(judged, { tier: null, reliability: null });
  assert.deepEqual(judged, before);
});

test("the choice of an entry's judgement copies it onto another entry and keeps that entry's own fields", () => {
  const source: ObjectSlotEntry = { ...doctor, tier: "org", reliability: "high" };
  const target: ObjectSlotEntry = {
    key: "GET /api/doctors [].id",
    class: "patient",
    source: "rule",
    paused: true,
  };
  assert.deepEqual(withJudgement(target, judgementChoiceOf(source)), {
    key: doctor.key,
    class: "patient",
    source: "rule",
    paused: true,
    tier: "org",
    reliability: "high",
  });
});

test("a proposal reads in words and in the figures it rests on", () => {
  assert.equal(proposalWords(acceptance), "不接受公共来源 · 可靠性 高");
  assert.deepEqual(proposalFigures(acceptance), ["票 1234", "会话 56", "公共票 0.4%"]);
  assert.equal(proposalWords(tier), "归属 公共 · 可靠性 中");
  assert.deepEqual(proposalFigures(tier), ["单位 12", "不同值 3", "一致 95%"]);
  assert.equal(isAcceptance(acceptance), true);
  assert.equal(isAcceptance(tier), false);
});

test("a share in thousandths reads as a percentage, to a tenth below one percent", () => {
  assert.equal(shareOfMille(0), "0.0%");
  assert.equal(shareOfMille(4), "0.4%");
  assert.equal(shareOfMille(9), "0.9%");
  assert.equal(shareOfMille(10), "1%");
  assert.equal(shareOfMille(950), "95%");
  assert.equal(shareOfMille(999), "100%");
});

test("an entry carries a judgement when one of its four fields is set", () => {
  assert.equal(hasJudgement({}), false);
  assert.equal(hasJudgement({ tier: "self" }), true);
  assert.equal(hasJudgement({ accepts_public: false }), true);
});

test("a position's judgement is read as the form reads it, and the same values come back", () => {
  const objects: ObjectsSpec = {
    classes: [{ id: "doctor", name: "医生" }],
    slots: [
      { ...doctor, identity: "user" },
      {
        key: "GET /doctor/{id} path[1]",
        class: "doctor",
        source: "rule",
        accepts_public: false,
        reliability: "high",
      },
    ],
  };
  const parsed = parseObjects(JSON.parse(JSON.stringify(objects)));
  if (!parsed.ok) assert.fail(parsed.message);
  assert.deepEqual(parsed.value, objects);
  assert.deepEqual(checkObjects(parsed.value), []);
});

test("the form refuses the two judgement shapes the gateway refuses", () => {
  const conflict = parseObjects({
    slots: [{ ...doctor, tier: "self", accepts_public: true }],
  });
  if (conflict.ok) assert.fail("a tier with an acceptance is refused");
  assert.equal(conflict.message, DECLARE_TEXT.judgementConflict(1));

  const alone = parseObjects({ slots: [{ ...doctor, reliability: "high" }] });
  if (alone.ok) assert.fail("a reliability with nothing to qualify is refused");
  assert.equal(alone.message, DECLARE_TEXT.reliabilityAlone(1));
});

test("a judgement outside the four values of its field is refused as a shape mistake", () => {
  const bad = parseObjects({ slots: [{ ...doctor, tier: "private" }] });
  if (bad.ok) assert.fail("a tier outside the four is refused");
  assert.equal(bad.message, DECLARE_TEXT.slotShape(1));

  const badIdentity = parseObjects({ slots: [{ ...doctor, identity: "guest" }] });
  if (badIdentity.ok) assert.fail("an identity outside the three is refused");
  assert.equal(badIdentity.message, DECLARE_TEXT.slotShape(1));
});

test("the object map's check reports a position that breaks a judgement rule", () => {
  const objects: ObjectsSpec = {
    classes: [{ id: "doctor", name: "医生" }],
    slots: [{ ...doctor, tier: "self", accepts_public: true }],
  };
  assert.deepEqual(checkObjects(objects), [DECLARE_TEXT.judgementConflict(1)]);
});

test("a change of a position's judgement is listed as the change it makes, both ways", () => {
  const classes = [{ id: "doctor", name: "医生" }];
  const before: ObjectsSpec = { classes, slots: [doctor] };
  const after: ObjectsSpec = { classes, slots: [{ ...doctor, identity: "user" }] };
  assert.deepEqual(objectChanges(before, after), ["GET /api/doctors [].id 判断 无 → 身份 用户"]);
  assert.deepEqual(objectChanges(after, before), ["GET /api/doctors [].id 判断 身份 用户 → 无"]);
});

test("an administrator's tier proposal says who got the data, in place of the counts of the ordinary units", () => {
  const admin: ObjectTierJudgement = { ...tier, tier: "admin", reliability: "high" };
  assert.deepEqual(proposalFigures(admin), ["只有管理员拿到了数据，其他用户被拒绝"]);
  // A tier of ordinary users keeps its counts.
  assert.deepEqual(proposalFigures(tier), ["单位 12", "不同值 3", "一致 95%"]);
});

test("a site that declares no user identity says that its acceptance judgements at medium are not tightened", () => {
  const note =
    "本站点没有声明用户身份，这一条不会自动收紧，需要收紧时请声明用户身份的位置，或手动把这个请求位置设为不接受公共来源。";
  // A proposal of public sources carries the note there; a tier proposal does not, and an identified site has none.
  assert.equal(unidentifiedNoteOfProposal(acceptance, false), note);
  assert.equal(unidentifiedNoteOfProposal(acceptance, true), null);
  assert.equal(unidentifiedNoteOfProposal(tier, false), null);
  // A declared position's acceptance at medium carries it; at high it does not, nor does a position with no acceptance.
  assert.equal(
    unidentifiedNoteOfEntry({ accepts_public: false, reliability: "medium" }, false),
    note,
  );
  assert.equal(
    unidentifiedNoteOfEntry({ accepts_public: false, reliability: "high" }, false),
    null,
  );
  assert.equal(unidentifiedNoteOfEntry({ reliability: "medium" }, false), null);
  assert.equal(
    unidentifiedNoteOfEntry({ accepts_public: false, reliability: "medium" }, true),
    null,
  );
});
