import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  BootstrapCandidate,
  FieldKindDeclaration,
  ObjectEvent,
  ObjectFunctionEntry,
  ObjectSlotEntry,
  ObjectSlotRow,
  ObjectsSpec,
  SiteSpec,
} from "../src/api/types.ts";
import {
  type BootstrapChoice,
  bannerGroups,
  candidateName,
  declarationFor,
  fieldOfKey,
  flowSearch,
  migrateSynonyms,
  pathWordWarnings,
  planBootstrap,
  revertEvent,
  routeFilter,
  scopeOfKey,
  withClasses,
  withDeclarations,
  withPlan,
  withSlot,
  withoutSlot,
} from "../src/features/sites/objects/objects-model.ts";
import {
  checkDeclarations,
  checkField,
  checkKind,
  checkObjects,
  checkScope,
  declarationChanges,
  declarationProblem,
  declarationsOf,
  fieldKey,
  functionRefusalWords,
  inScope,
  kindKey,
  objectChanges,
  parseObjects,
  patternsOverlap,
  scopesOverlap,
} from "../src/lib/objects-validate.ts";
import { DECLARE_TEXT } from "../src/lib/vocab.ts";

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
  // The default is off, so an absent setting and a turned-on one differ by tightening.
  const after: SiteSpec["objects"] = {
    learning: {
      auto_learn: true,
      auto_tighten: true,
      agent: { enabled: false, daily_limit: 200 },
      thresholds: { uses: 20, sessions: 5 },
      auto_pause: true,
    },
  };
  assert.deepEqual(objectChanges(before, after), ["学习设置 自动收紧 关 → 开"]);
  assert.deepEqual(objectChanges(after, before), ["学习设置 自动收紧 开 → 关"]);
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
    agent_status: null,
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

test("a candidate with no class yet is named by its kind", () => {
  const unnamed = { ...candidate("GET /api/docs [].id", "doc", "文档"), name: null };
  assert.equal(candidateName(unnamed), "doc");
  assert.equal(candidateName(candidate("GET /api/docs [].id", "doc", "文档")), "文档");
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

test("a cold start writes every chosen position as a slot under its key, and the classes it needs", () => {
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
  assert.deepEqual(plan.slots, [
    { key: "GET /api/doctors [].id", class: "doctor", source: "rule" },
    { key: "GET /doctor/{id} path[1]", class: "doctor", source: "admin" },
  ]);
  assert.deepEqual(plan.classes, [{ id: "doctor", name: "医生" }]);
  const written = withPlan(base, plan);
  assert.equal(written.advanced, undefined);
  assert.deepEqual(written.objects?.slots, [
    { key: "GET /api/doctors [].id", class: "doctor", source: "rule" },
    { key: "GET /doctor/{id} path[1]", class: "doctor", source: "admin" },
  ]);
  assert.deepEqual(written.objects?.classes, [{ id: "doctor", name: "医生" }]);
});

test("confirming a named response field writes one slot, and leaves the field kinds and the sibling fields of its path alone", () => {
  const declared: FieldKindDeclaration = { field: "doc", kind: "doctor", in: ["/api/records*"] };
  const sibling: ObjectSlotEntry = {
    key: "GET /api/patients/{id} prescriptions[].id",
    class: "prescription",
    source: "rule",
  };
  const start: SiteSpec = {
    ...base,
    objects: { classes: [{ id: "prescription", name: "处方" }], slots: [sibling] },
    advanced: { field_kinds: [declared] },
  };
  const plan = planBootstrap(
    [
      {
        candidate: candidate("GET /api/patients/{id} id", "patient", "患者"),
        kind: "patient",
        name: "患者",
        changed: false,
      },
    ],
    [],
    start.objects,
  );
  const written = withPlan(start, plan);
  assert.deepEqual(written.advanced?.field_kinds, [declared]);
  assert.deepEqual(written.objects?.slots, [
    sibling,
    { key: "GET /api/patients/{id} id", class: "patient", source: "rule" },
  ]);
  assert.deepEqual(written.objects?.classes, [
    { id: "prescription", name: "处方" },
    { id: "patient", name: "患者" },
  ]);
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

// ------------------------------------------------------------------ the function table (objects.functions)

const fn = (
  key: string,
  source: ObjectFunctionEntry["source"],
  over: Partial<ObjectFunctionEntry> = {},
): ObjectFunctionEntry => ({ key, source, ...over });

test("the function table is read item by item, and its entries come through as they are", () => {
  const functions: ObjectFunctionEntry[] = [
    fn("POST /api/admin/export", "rule", { tier: "admin", reliability: "high" }),
    fn("GET /api/patients/{id}", "admin"),
  ];
  assert.deepEqual(parseObjects({ functions }), { ok: true, value: { functions } });
  assert.deepEqual(parseObjects({ functions: [] }), { ok: true, value: { functions: [] } });
});

test("a function entry is read strictly, and a wrong one is refused with its place in the table", () => {
  assert.deepEqual(parseObjects({ functions: "POST /api/admin/export" }), {
    ok: false,
    message: DECLARE_TEXT.functionsShape,
  });
  assert.deepEqual(
    parseObjects({
      functions: [
        { key: "GET /api/a", source: "admin" },
        { key: "GET /api/b", source: "nobody" },
      ],
    }),
    { ok: false, message: DECLARE_TEXT.functionShape(2) },
  );
  assert.deepEqual(parseObjects({ functions: [{ key: "GET /api/a" }] }), {
    ok: false,
    message: DECLARE_TEXT.functionShape(1),
  });
  assert.deepEqual(
    parseObjects({ functions: [{ key: "GET /api/a", source: "admin", note: "x" }] }),
    { ok: false, message: DECLARE_TEXT.unknownKey("note") },
  );
  assert.deepEqual(
    parseObjects({
      functions: [{ key: "GET /api/a", source: "admin", tier: "admin", reliability: "huge" }],
    }),
    { ok: false, message: DECLARE_TEXT.functionShape(1) },
  );
  assert.deepEqual(
    parseObjects({ functions: [{ key: "GET /api/a", source: "admin", tier: "public" }] }),
    { ok: false, message: DECLARE_TEXT.functionTier(1) },
  );
  assert.deepEqual(
    parseObjects({ functions: [{ key: "GET /api/a", source: "admin", reliability: "high" }] }),
    { ok: false, message: DECLARE_TEXT.functionReliabilityAlone(1) },
  );
});

test("the function table is checked as the gateway checks it: count, key, duplicates, tier and reliability", () => {
  const exported = fn("POST /api/admin/export", "rule", { tier: "admin", reliability: "high" });
  assert.deepEqual(
    checkObjects({ functions: [exported, fn("GET /api/patients/{id}", "admin")] }),
    [],
  );

  const many = Array.from({ length: 2049 }, (_, i) => fn(`GET /api/items/${i}`, "admin"));
  assert.deepEqual(checkObjects({ functions: many }), [DECLARE_TEXT.functionCountMax]);

  // The method is three to seven capitals, the key is two parts with one space, the template starts with a slash,
  // and the key is 256 bytes at most.
  const badKeys = [
    "get /api/a",
    "GET api/a",
    "GET /api/a b",
    "GE /api/a",
    `GET /${"a".repeat(260)}`,
  ];
  for (const key of badKeys) {
    assert.deepEqual(
      checkObjects({ functions: [fn(key, "admin")] }),
      [DECLARE_TEXT.functionShape(1)],
      key,
    );
  }

  // Two keys that differ only in the letters of the template are the same function; the later one is the duplicate.
  assert.deepEqual(
    checkObjects({
      functions: [fn("GET /api/patients/{id}", "admin"), fn("GET /api/patients/{ID}", "rule")],
    }),
    [DECLARE_TEXT.functionDuplicate("GET /api/patients/{ID}")],
  );

  const openTierButPublic = {
    key: "POST /api/x",
    source: "admin",
    tier: "public",
  } as unknown as ObjectFunctionEntry;
  assert.deepEqual(checkObjects({ functions: [openTierButPublic] }), [
    DECLARE_TEXT.functionTier(1),
  ]);

  const reliabilityOnly = {
    key: "POST /api/x",
    source: "admin",
    reliability: "high",
  } as ObjectFunctionEntry;
  assert.deepEqual(checkObjects({ functions: [reliabilityOnly] }), [
    DECLARE_TEXT.functionReliabilityAlone(1),
  ]);
});

test("a gateway refusal of one function entry reads as the check's words for that entry", () => {
  const objects: ObjectsSpec = {
    functions: [
      fn("POST /api/admin/export", "rule", { tier: "admin" }),
      fn("POST /api/admin/export", "rule"),
    ],
  };
  assert.equal(
    functionRefusalWords("objects.functions[0]", "function_tier_unsupported", objects),
    DECLARE_TEXT.functionTier(1),
  );
  assert.equal(
    functionRefusalWords("objects.functions[0]", "reliability_without_judgement", objects),
    DECLARE_TEXT.functionReliabilityAlone(1),
  );
  assert.equal(
    functionRefusalWords("objects.functions[1]", "duplicate_key", objects),
    DECLARE_TEXT.functionDuplicate("POST /api/admin/export"),
  );
  assert.equal(
    functionRefusalWords("objects.functions[2]", "key_invalid", objects),
    DECLARE_TEXT.functionShape(3),
  );
  assert.equal(
    functionRefusalWords("objects.functions", "too_many", objects),
    DECLARE_TEXT.functionCountMax,
  );
  // A refusal about another place, or one with no reason the console knows, is left to the error code.
  assert.equal(functionRefusalWords("objects.slots[3]", "class_unknown", objects), null);
  assert.equal(functionRefusalWords("objects.functions[0]", undefined, objects), null);
  assert.equal(functionRefusalWords("objects.functions[0]", "class_unknown", objects), null);
});

test("the function table's changes are listed one line each: an entry added or removed, and its tier, reliability or source", () => {
  const exported = fn("POST /api/admin/export", "rule");
  assert.deepEqual(objectChanges(undefined, { functions: [exported] }), [
    "对象表 ＋ 功能 POST /api/admin/export",
  ]);
  assert.deepEqual(
    objectChanges(undefined, { functions: [fn(exported.key, "rule", { tier: "admin" })] }),
    ["对象表 ＋ 功能 POST /api/admin/export"],
  );
  assert.deepEqual(objectChanges({ functions: [exported] }, undefined), [
    "对象表 －1：功能 POST /api/admin/export",
  ]);
  assert.deepEqual(
    objectChanges(
      { functions: [exported] },
      { functions: [fn(exported.key, "rule", { tier: "admin" })] },
    ),
    ["功能 POST /api/admin/export 档位 对所有会话开放 → 仅管理员"],
  );
  const admin = fn(exported.key, "rule", { tier: "admin", reliability: "high" });
  assert.deepEqual(
    objectChanges({ functions: [admin] }, { functions: [{ ...admin, reliability: "medium" }] }),
    ["功能 POST /api/admin/export 可靠性 高 → 中"],
  );
  assert.deepEqual(
    objectChanges({ functions: [exported] }, { functions: [{ ...exported, source: "admin" }] }),
    ["功能 POST /api/admin/export 来源 规则 → 管理员声明"],
  );
});

test("the object map's own edits keep the function table", () => {
  const exported = fn("POST /api/admin/export", "rule", { tier: "admin" });
  const slot: ObjectSlotEntry = { key: "GET /api/doctors [].id", class: "doctor", source: "admin" };
  const spec: SiteSpec = { ...base, objects: { functions: [exported] } };
  assert.deepEqual(withSlot(spec, slot).objects, { functions: [exported], slots: [slot] });
  assert.deepEqual(withClasses(spec, [{ id: "doctor", name: "医生" }]).objects, {
    functions: [exported],
    classes: [{ id: "doctor", name: "医生" }],
  });
  assert.deepEqual(withoutSlot(withSlot(spec, slot), slot.key).objects, { functions: [exported] });
});

// ------------------------------------------------------------------ the switch (objects.ask_unknown_functions)

test("the switch is read as a boolean, and anything else is refused", () => {
  const functions = [fn("GET /api/patients", "rule")];
  assert.deepEqual(parseObjects({ functions, ask_unknown_functions: true }), {
    ok: true,
    value: { functions, ask_unknown_functions: true },
  });
  assert.deepEqual(parseObjects({ functions, ask_unknown_functions: false }), {
    ok: true,
    value: { functions, ask_unknown_functions: false },
  });
  assert.deepEqual(parseObjects({ functions, ask_unknown_functions: "yes" }), {
    ok: false,
    message: DECLARE_TEXT.askShape,
  });
});

test("the switch on an empty table is a local error, as the gateway would refuse it", () => {
  assert.deepEqual(checkObjects({ ask_unknown_functions: true }), [
    DECLARE_TEXT.askWithoutFunctions,
  ]);
  assert.deepEqual(checkObjects({ functions: [], ask_unknown_functions: true }), [
    DECLARE_TEXT.askWithoutFunctions,
  ]);
  assert.deepEqual(
    checkObjects({ functions: [fn("GET /api/patients", "rule")], ask_unknown_functions: true }),
    [],
  );
  assert.deepEqual(checkObjects({ ask_unknown_functions: false }), []);
  // The gateway's refusal names the switch's own place, and only its own reason.
  assert.equal(
    functionRefusalWords("objects.ask_unknown_functions", "ask_without_functions", {}),
    DECLARE_TEXT.askWithoutFunctions,
  );
  assert.equal(functionRefusalWords("objects.ask_unknown_functions", "class_unknown", {}), null);
  assert.equal(functionRefusalWords("objects.ask_unknown_functions", undefined, {}), null);
});

test("the switch's change is one line in the change list, turned on or off", () => {
  const functions = [fn("GET /api/patients", "rule")];
  assert.deepEqual(objectChanges({ functions }, { functions, ask_unknown_functions: true }), [
    "功能表 未知功能送 Jev 判定 关 → 开",
  ]);
  assert.deepEqual(objectChanges({ functions, ask_unknown_functions: true }, { functions }), [
    "功能表 未知功能送 Jev 判定 开 → 关",
  ]);
  assert.deepEqual(objectChanges({ functions }, { functions, ask_unknown_functions: false }), []);
});
