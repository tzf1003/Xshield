import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  BootstrapCandidate,
  FieldKindDeclaration,
  ObjectEvent,
  ObjectSlotRow,
  SiteSpec,
} from "../src/api/types.ts";
import {
  type BootstrapChoice,
  bannerGroups,
  declarationFor,
  fieldOfKey,
  flowSearch,
  migrateSynonyms,
  pathWordWarnings,
  planBootstrap,
  revertEvent,
  routeFilter,
  scopeOfKey,
  withDeclarations,
  withPlan,
} from "../src/features/sites/objects/objects-model.ts";
import {
  checkDeclarations,
  checkField,
  checkKind,
  checkScope,
  declarationChanges,
  declarationProblem,
  declarationsOf,
  fieldKey,
  inScope,
  kindKey,
  objectChanges,
  parseObjects,
  patternsOverlap,
  scopesOverlap,
} from "../src/lib/objects-validate.ts";

const decl = (field: string, kind: string, scope?: string[]): FieldKindDeclaration =>
  scope === undefined ? { field, kind } : { field, kind, in: scope };

test("a field name ignores case, underscores and dashes", () => {
  assert.equal(fieldKey("doc_id"), "docid");
  assert.equal(fieldKey("docId"), "docid");
  assert.equal(fieldKey("DocID"), "docid");
  assert.equal(fieldKey("doc-id"), "docid");
});

test("a field name is 1 to 32 letters, digits, underscores or dashes", () => {
  assert.equal(checkField("doc_id"), null);
  assert.equal(checkField("a-1"), null);
  assert.equal(checkField("a".repeat(32)), null);
  assert.match(checkField("") ?? "", /不能为空/);
  assert.match(checkField("a".repeat(33)) ?? "", /最多 32 个字符/);
  assert.match(checkField("doc id") ?? "", /只能用字母、数字/);
  assert.match(checkField("doc.id") ?? "", /只能用字母、数字/);
});

test("a kind is 3 to 24 lowercase letters, and a trailing s does not count", () => {
  assert.equal(checkKind("doctor"), null);
  assert.equal(checkKind("abc"), null);
  assert.equal(checkKind("a".repeat(24)), null);
  assert.match(checkKind("ab") ?? "", /3 到 24 个小写字母/);
  assert.match(checkKind("Doctor") ?? "", /小写字母/);
  assert.match(checkKind("a".repeat(25)) ?? "", /小写字母/);
  assert.match(checkKind("doc_1") ?? "", /小写字母/);
  assert.equal(kindKey("doctors"), "doctor");
  assert.equal(kindKey("doctor"), "doctor");
  assert.equal(kindKey("bus"), "bus");
});

test("a scope takes at most 8 path patterns written like entries, none repeated", () => {
  assert.equal(checkScope(["/api/appointments*", "/api/schedule"]), null);
  assert.equal(checkScope([]), null);
  assert.match(checkScope(Array.from({ length: 9 }, (_, i) => `/a${i}`)) ?? "", /最多 8 个/);
  assert.match(checkScope(["/api/x", "/api/x"]) ?? "", /重复/);
  assert.notEqual(checkScope(["api/x"]), null);
  assert.notEqual(checkScope(["/api/*/x"]), null);
});

test("two patterns overlap when some path can match both", () => {
  assert.equal(patternsOverlap("/api/appointments*", "/api/appointments/7"), true);
  assert.equal(patternsOverlap("/api/*", "/api/records"), true);
  assert.equal(patternsOverlap("/api/docs*", "/api/appointments*"), false);
  assert.equal(patternsOverlap("/api/a", "/api/b"), false);
  assert.equal(patternsOverlap("/api/a", "/api/a"), true);
});

test("a missing scope is the whole site and overlaps everything", () => {
  assert.equal(scopesOverlap(undefined, ["/api/a*"]), true);
  assert.equal(scopesOverlap([], ["/api/a*"]), true);
  assert.equal(scopesOverlap(["/api/a*"], ["/api/b*"]), false);
});

test("a scope matches a request path by its prefix, and a whole site matches any path", () => {
  assert.equal(inScope(undefined, "/anything"), true);
  assert.equal(inScope(["/api/appointments*"], "/api/appointments"), true);
  assert.equal(inScope(["/api/appointments*"], "/api/appointments/7"), true);
  assert.equal(inScope(["/api/appointments"], "/api/appointments/7"), false);
  assert.equal(inScope(["/api/appointments"], "/api/appointments"), true);
  assert.equal(inScope(["/api/appointments*"], "/api/schedule"), false);
});

test("the same name in an overlapping scope is a duplicate or a conflict, by kind", () => {
  const list = [decl("doc_id", "doctor", ["/api/appointments*"])];
  assert.deepEqual(declarationProblem(list, decl("docId", "doctor", ["/api/appointments/7"])), {
    kind: "duplicate",
    with: list[0],
  });
  assert.equal(
    declarationProblem(list, decl("doc_id", "document", ["/api/appointments*"]))?.kind,
    "conflict",
  );
  assert.equal(declarationProblem(list, decl("doc_id", "doctor", ["/api/docs*"])), null);
  assert.equal(declarationProblem(list, decl("doc_id", "document", ["/api/docs*"])), null);
  // A declaration for the whole site overlaps the scoped one.
  assert.equal(declarationProblem(list, decl("doc_id", "document"))?.kind, "conflict");
});

test("a whole list is checked: each entry, then the clashes between entries", () => {
  assert.deepEqual(checkDeclarations([decl("doc_id", "doctor", ["/api/a*"])]), []);
  const clash = checkDeclarations([
    decl("doc_id", "doctor"),
    decl("doc_id", "document", ["/api/a*"]),
  ]);
  assert.equal(clash.length, 1);
  assert.match(clash[0] ?? "", /doc_id 在重叠的范围里已归为 doctor/);
  const bad = checkDeclarations([decl("doc id", "Doctor")]);
  assert.equal(bad.length, 1);
  assert.match(bad[0] ?? "", /第 1 条/);
  const many = Array.from({ length: 33 }, (_, i) => decl(`f${i}`, "doctor"));
  assert.match(checkDeclarations(many)[0] ?? "", /最多 32 条/);
});

test("the save dialog reads declarations and learning changes in words", () => {
  const before: SiteSpec["objects"] = undefined;
  const after: SiteSpec["objects"] = {
    learning: {
      auto_learn: true,
      auto_tighten: false,
      agent: { enabled: false, daily_limit: 200 },
      thresholds: { uses: 20, sessions: 5 },
      auto_pause: true,
    },
  };
  assert.deepEqual(objectChanges(before, after), ["学习设置 自动收紧 开 → 关"]);
  assert.deepEqual(objectChanges(after, before), ["学习设置 自动收紧 关 → 开"]);
  assert.deepEqual(objectChanges(undefined, undefined), []);
  assert.deepEqual(objectChanges({}, { learning: undefined }), []);

  const declared = [decl("doc_id", "doctor", ["/api/appointments*"])];
  assert.deepEqual(declarationChanges(undefined, declared), [
    "对象表 ＋ 字段 doc_id 归为医生（仅 /api/appointments*）",
  ]);
  assert.deepEqual(declarationChanges(declared, undefined), [
    "对象表 －1：字段 doc_id 归为医生（仅 /api/appointments*）",
  ]);
  assert.deepEqual(declarationChanges(undefined, [decl("doc", "doctor")]), [
    "对象表 ＋ 字段 doc 归为医生（全站）",
  ]);
  // The same field under the same scope with another class is a change of class, read as the move.
  const changed = [decl("doc_id", "document", ["/api/appointments*"])];
  assert.deepEqual(declarationChanges(declared, changed), [
    "响应 /api/appointments* doc_id 从医生改为文档",
  ]);
});

test("the objects section of a configuration is read strictly", () => {
  assert.deepEqual(parseObjects(undefined), { ok: true, value: undefined });
  assert.equal(parseObjects("x").ok, false);
  assert.equal(parseObjects({ learnng: {} }).ok, false);
  // Field kinds belong to the advanced section, so the objects section refuses them.
  assert.equal(parseObjects({ field_kinds: [] }).ok, false);
  // The gateway's classes and slots come through exactly as they are.
  assert.deepEqual(parseObjects({ classes: [{ id: "doctor", name: "医生" }], slots: [] }), {
    ok: true,
    value: { classes: [{ id: "doctor", name: "医生" }], slots: [] },
  });
  // Field kinds are read item by item, the way the form reads one.
  assert.deepEqual(
    declarationsOf([{ field: "doc_id", kind: "doctor", in: ["/api/appointments*"] }]),
    {
      ok: true,
      value: [{ field: "doc_id", kind: "doctor", in: ["/api/appointments*"] }],
    },
  );
  assert.equal(declarationsOf("doc_id").ok, false);
  assert.equal(declarationsOf([{ field: "doc_id" }]).ok, false);
  assert.equal(declarationsOf([{ field: "doc_id", kind: "doctor", in: [1] }]).ok, false);
  const learning = parseObjects({
    learning: {
      auto_learn: true,
      auto_tighten: true,
      agent: { enabled: true, daily_limit: "10" },
      thresholds: { uses: 20, sessions: 5 },
      auto_pause: true,
    },
  });
  assert.equal(learning.ok, false);
});

test("a position key reads as its field and scope, and a path position has no field", () => {
  assert.equal(fieldOfKey("GET /api/appointments [].doc_id"), "doc_id");
  assert.equal(fieldOfKey("GET /api/schedule query.doc"), "doc");
  assert.equal(fieldOfKey("GET /api/records/{id} attachments[].doc_id"), "doc_id");
  assert.equal(fieldOfKey("GET /doctor/{id} path[1]"), null);
  assert.equal(fieldOfKey("POST /api/x body.who#2"), null);
  assert.equal(scopeOfKey("GET /api/appointments [].doc_id"), "/api/appointments*");
  assert.equal(scopeOfKey("GET /api/records/{id} attachments[].doc_id"), "/api/records/*");
  assert.equal(routeFilter("/doctor/{id}/files/{id}"), "/doctor/*");
  assert.equal(routeFilter("/docs"), "/docs");
});

test("a confirmed position becomes one declaration, and a path position cannot", () => {
  const slot: ObjectSlotRow = {
    id: "s1",
    side: "response",
    key: "GET /api/appointments [].doc_id",
    class: "doctor",
    state: "proposed",
    source: "rule",
    basis: "流向 87%",
    last_seen: null,
    dismissed: false,
    in_effect: true,
    suspension: null,
  };
  assert.deepEqual(declarationFor(slot), {
    field: "doc_id",
    kind: "doctor",
    in: ["/api/appointments*"],
  });
  assert.equal(declarationFor({ ...slot, class: null }), null);
  assert.equal(declarationFor({ ...slot, key: "GET /doctor/{id} path[1]" }), null);
});

const base: SiteSpec = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { header: "Authorization" },
  entries: ["/login", "/api/docs"],
};

const candidate = (key: string, kind: string, name: string): BootstrapCandidate => ({
  id: key,
  key,
  side: "response",
  kind,
  name,
  reason: { code: "field_name", word: null, field: null },
  uses: 10,
  sessions: 3,
  note: null,
  conflict: null,
});

/** An automatic change for the tests: a pause of a path position unless `over` says otherwise. */
function eventOf(
  id: string,
  kind: ObjectEvent["kind"],
  at: string,
  over: Partial<ObjectEvent>,
): ObjectEvent {
  return {
    id,
    kind,
    at,
    version: 17,
    slot_id: "s1",
    key: "GET /doctor/{id} path[1]",
    side: "request",
    before: {
      class: "doctor",
      entry: { key: "GET /doctor/{id} path[1]", class: "doctor", source: "admin" },
    },
    after: null,
    reason: null,
    impact: [],
    examples: [],
    status: "open",
    handled: null,
    note: null,
    ...over,
  };
}

test("a cold start writes named fields as declarations, path positions as slots, and the classes it needs", () => {
  const choices: BootstrapChoice[] = [
    {
      candidate: candidate("GET /api/doctors [].id", "doctor", "医生"),
      kind: "doctor",
      name: "医生",
      changed: false,
    },
    {
      candidate: candidate("GET /doctor/{id} path[1]", "doctor", "医生"),
      kind: "doctor",
      name: "医生",
      changed: true,
    },
    {
      candidate: candidate("GET /api/doctors [].id", "doctor", "医生"),
      kind: "doctor",
      name: "医生",
      changed: false,
    },
  ];
  const plan = planBootstrap(choices, [], undefined);
  assert.deepEqual(plan.declarations, [{ field: "id", kind: "doctor", in: ["/api/doctors*"] }]);
  assert.deepEqual(plan.slots, [
    { key: "GET /doctor/{id} path[1]", class: "doctor", source: "admin" },
  ]);
  assert.deepEqual(plan.classes, [{ id: "doctor", name: "医生" }]);
  const written = withPlan(base, plan);
  assert.deepEqual(written.advanced?.field_kinds, [
    { field: "id", kind: "doctor", in: ["/api/doctors*"] },
  ]);
  assert.deepEqual(written.objects?.slots, [
    { key: "GET /doctor/{id} path[1]", class: "doctor", source: "admin" },
  ]);
  assert.deepEqual(written.objects?.classes, [{ id: "doctor", name: "医生" }]);
});

test("an automatic pause is undone by putting back the entry from before it, without the pause", () => {
  const before = { key: "GET /doctor/{id} path[1]", class: "doctor", source: "admin" as const };
  const paused: SiteSpec = {
    ...base,
    objects: { classes: [{ id: "doctor", name: "医生" }], slots: [{ ...before, paused: true }] },
  };
  const undone = revertEvent(paused, eventOf("e1", "auto_pause", "2026-11-03T05:00:00Z", {}));
  assert.deepEqual(undone?.objects?.slots, [before]);
  assert.equal(revertEvent(paused, eventOf("e2", "anomaly", "2026-11-03T05:00:00Z", {})), null);
});

test("the banner groups open events: pauses and anomalies apart, and the tightenings of one pass together", () => {
  const groups = bannerGroups([
    eventOf("a", "auto_pause", "2026-11-03T05:00:00Z", {}),
    eventOf("b", "auto_tighten", "2026-11-03T06:00:00Z", {}),
    eventOf("c", "auto_tighten", "2026-11-03T06:00:00Z", {}),
    eventOf("d", "auto_tighten", "2026-11-03T03:00:00Z", {}),
  ]);
  assert.deepEqual(
    groups.paused.map((item) => item.id),
    ["a"],
  );
  assert.deepEqual(groups.anomaly, []);
  assert.deepEqual(
    groups.tightened.map((group) => [group.at, group.events.map((item) => item.id)]),
    [
      ["2026-11-03T06:00:00Z", ["b", "c"]],
      ["2026-11-03T03:00:00Z", ["d"]],
    ],
  );
});

test("declarations are added once, and a migrated synonym group leaves the synonyms", () => {
  const spec: SiteSpec = {
    name: "emr",
    hosts: ["emr.example.com"],
    origin: "http://10.0.0.5:8080",
    session: { header: "Authorization" },
    entries: ["/login", "/api/docs"],
    advanced: {
      synonyms: [
        ["doc", "doctor"],
        ["payment", "card"],
      ],
    },
  };
  const once = withDeclarations(spec, [decl("doc_id", "doctor", ["/api/appointments*"])]);
  const twice = withDeclarations(once, [decl("docId", "doctor", ["/api/appointments*"])]);
  assert.equal(twice.advanced?.field_kinds?.length, 1);
  const migrated = migrateSynonyms(
    spec,
    [["doc", "doctor"]],
    [decl("doc_id", "doctor", ["/api/a*"])],
  );
  assert.deepEqual(migrated.advanced?.synonyms, [["payment", "card"]]);
  assert.deepEqual(migrated.advanced?.field_kinds, [decl("doc_id", "doctor", ["/api/a*"])]);
  assert.deepEqual(spec.advanced?.synonyms, [
    ["doc", "doctor"],
    ["payment", "card"],
  ]);
  const emptied = migrateSynonyms(
    spec,
    [
      ["doc", "doctor"],
      ["payment", "card"],
    ],
    [],
  );
  assert.equal(emptied.advanced?.synonyms, undefined);
});

test("a path word that a synonym also names is warned about, with the other word", () => {
  const spec: SiteSpec = {
    name: "emr",
    hosts: ["emr.example.com"],
    origin: "http://10.0.0.5:8080",
    session: { header: "Authorization" },
    entries: ["/login", "/api/docs"],
    advanced: { synonyms: [["doc", "doctor"]] },
  };
  const warnings = pathWordWarnings(
    spec,
    ["doc", "doctor"],
    (word, other) => `会让路径里的 ${word} 也算成 ${other}`,
  );
  assert.deepEqual(warnings, ["会让路径里的 docs 也算成 doctor"]);
});

test("the request list condition of a flow names its class and route", () => {
  const flow = {
    key: "GET /doctor/{id} path[1]",
    side: "request" as const,
    share: 0.87,
    uses: 140,
    sessions: 23,
    jev_allow: 140,
    jev_deny: 0,
    method: "GET",
    route: "/doctor/{id}",
  };
  assert.equal(flowSearch(flow, "doctor"), "object:doctor path:/doctor/*");
  assert.equal(flowSearch(flow, null), "path:/doctor/*");
});
