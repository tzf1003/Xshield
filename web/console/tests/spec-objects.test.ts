import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  FieldKindDeclaration,
  LearningSettings,
  ObjectSlotEntry,
  SiteSpec,
} from "../src/api/types.ts";
import { canonical, semanticChanges } from "../src/lib/diff.ts";
import { normalizeSpec, parseSpecText, rebaseSpec } from "../src/features/sites/spec-model.ts";
import { orderSpec, specToJson, specToYaml } from "../src/lib/yaml.ts";

// Regression: a site's object map must survive every path a save takes. Without it, saving a site from the console
// deleted its object map, because the spec model and the comparison did not carry the section. The field kinds a
// person declares are in `advanced.field_kinds` (the gateway reads them there); the learning settings are in `objects`,
// with the gateway's classes and slots, which the console keeps exactly as they are.

const learning: LearningSettings = {
  auto_learn: true,
  auto_tighten: false,
  agent: { enabled: true, daily_limit: 50 },
  thresholds: { uses: 30, sessions: 4 },
  auto_pause: true,
};

const declared: FieldKindDeclaration[] = [
  { field: "doc_id", kind: "document", in: ["/api/records/*"] },
];

const site: SiteSpec = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { cookie: "sid" },
  entries: ["/api/login"],
  bypass: ["/static/*"],
  advanced: { field_kinds: declared },
  objects: {
    learning,
    classes: [{ id: "doctor", name: "医生" }],
    slots: [{ key: "GET /api/doctors [].id", class: "doctor", source: "admin" }],
  },
};

test("the object map and the field kinds survive the normalisation of a saved configuration", () => {
  const back = normalizeSpec(JSON.parse(specToJson(site)));
  if (!back.ok) assert.fail(back.message);
  assert.deepEqual(back.value.objects, site.objects);
  assert.deepEqual(back.value.advanced, site.advanced);
});

test("the object map and the field kinds survive the key ordering that saves and comparisons use", () => {
  assert.deepEqual(orderSpec(site).objects, site.objects);
  assert.deepEqual(orderSpec(site).advanced, site.advanced);
});

test("the object map and the field kinds survive the YAML the editor shows and reads back", () => {
  const parsed = parseSpecText(specToYaml(site));
  if (!parsed.ok) assert.fail(parsed.message);
  assert.deepEqual(parsed.spec.objects, site.objects);
  assert.deepEqual(parsed.spec.advanced, site.advanced);
});

test("a change to the learning settings or to a field kind is a change to the configuration", () => {
  const learned: SiteSpec = {
    ...site,
    objects: { ...site.objects, learning: { ...learning, auto_tighten: true } },
  };
  assert.notEqual(canonical(site), canonical(learned));
  assert.deepEqual(semanticChanges(site, learned), ["学习设置 自动收紧 关 → 开"]);

  const reclassed: SiteSpec = {
    ...site,
    advanced: { field_kinds: [{ field: "doc_id", kind: "doctor", in: ["/api/records/*"] }] },
  };
  assert.deepEqual(semanticChanges(site, reclassed), ["响应 /api/records/* doc_id 从文档改为医生"]);
});

test("learning settings at their defaults are left out of a saved configuration", () => {
  const defaults: SiteSpec = {
    ...site,
    objects: {
      learning: {
        auto_learn: true,
        auto_tighten: true,
        agent: { enabled: false, daily_limit: 200 },
        thresholds: { uses: 20, sessions: 5 },
        auto_pause: true,
      },
    },
  };
  assert.equal(orderSpec(defaults).objects, undefined);
  assert.equal(JSON.parse(specToJson(defaults)).objects, undefined);
});

test("a save that rebases over a newer version keeps the object map and the field kinds", () => {
  const latest: SiteSpec = {
    ...site,
    entries: [...site.entries, "/api/new"],
    objects: {
      ...site.objects,
      slots: [{ key: "GET /api/docs [].id", class: "document", source: "rule" }],
    },
  };
  const mine: SiteSpec = { ...site, bypass: [...(site.bypass ?? []), "/static2/*"] };
  const { spec, conflicts } = rebaseSpec(site, mine, latest);
  assert.deepEqual(conflicts, []);
  assert.deepEqual(spec.objects?.learning, learning);
  assert.deepEqual(spec.objects?.classes, site.objects?.classes);
  // The gateway's slots come from the newer version, which is where they were changed.
  assert.deepEqual(spec.objects?.slots, latest.objects?.slots);
  assert.deepEqual(spec.advanced, site.advanced);
});

test("a field kind declared in a draft is added to the newer version", () => {
  const added: FieldKindDeclaration = { field: "visit", kind: "visit" };
  const mine: SiteSpec = { ...site, advanced: { field_kinds: [...declared, added] } };
  const latest: SiteSpec = { ...site, entries: [...site.entries, "/api/new"] };
  const { spec } = rebaseSpec(site, mine, latest);
  assert.deepEqual(spec.advanced?.field_kinds, [...declared, added]);
});

// A position's judgement is part of the position (docs/07 7.9.16). The learning task pauses positions on its own and
// writes a version of its own, so a save can rebase over a version that paused the position the draft gave a judgement.
const doctorPosition: ObjectSlotEntry = {
  key: "GET /api/doctors [].id",
  class: "doctor",
  source: "admin",
};

test("an identity the draft gave a position survives a newer version that paused the same position", () => {
  const mine: SiteSpec = {
    ...site,
    objects: { ...site.objects, slots: [{ ...doctorPosition, identity: "user" }] },
  };
  const latest: SiteSpec = {
    ...site,
    objects: { ...site.objects, slots: [{ ...doctorPosition, paused: true }] },
  };
  const { spec, conflicts } = rebaseSpec(site, mine, latest);
  assert.deepEqual(conflicts, []);
  assert.deepEqual(spec.objects?.slots, [{ ...doctorPosition, identity: "user", paused: true }]);
});

test("a judgement the draft gave a position is kept beside the newer version's other positions", () => {
  const judged: ObjectSlotEntry = { ...doctorPosition, tier: "org", reliability: "high" };
  const docs: ObjectSlotEntry = { key: "GET /api/docs [].id", class: "document", source: "rule" };
  const mine: SiteSpec = { ...site, objects: { ...site.objects, slots: [judged] } };
  const latest: SiteSpec = {
    ...site,
    objects: { ...site.objects, slots: [doctorPosition, docs] },
  };
  const { spec } = rebaseSpec(site, mine, latest);
  assert.deepEqual(spec.objects?.slots, [judged, docs]);
});

test("a judgement the draft cleared stays cleared when the newer version paused the position", () => {
  const judged: ObjectSlotEntry = { ...doctorPosition, identity: "user" };
  const base: SiteSpec = { ...site, objects: { ...site.objects, slots: [judged] } };
  const mine: SiteSpec = { ...site, objects: { ...site.objects, slots: [doctorPosition] } };
  const latest: SiteSpec = {
    ...site,
    objects: { ...site.objects, slots: [{ ...judged, paused: true }] },
  };
  const { spec } = rebaseSpec(base, mine, latest);
  assert.deepEqual(spec.objects?.slots, [{ ...doctorPosition, paused: true }]);
});

test("a pause the newer version wrote is kept when the draft did not touch the position", () => {
  const mine: SiteSpec = { ...site, entries: [...site.entries, "/api/draft"] };
  const latest: SiteSpec = {
    ...site,
    objects: { ...site.objects, slots: [{ ...doctorPosition, paused: true }] },
  };
  const { spec } = rebaseSpec(site, mine, latest);
  assert.deepEqual(spec.objects?.slots, [{ ...doctorPosition, paused: true }]);
});
