import assert from "node:assert/strict";
import { test } from "node:test";
import type {
  FieldKindDeclaration,
  LearningSettings,
  ObjectFunctionEntry,
  ObjectSlotEntry,
  SiteSpec,
} from "../src/api/types.ts";
import { ApiError } from "../src/api/client.ts";
import { canonical, semanticChanges } from "../src/lib/diff.ts";
import { normalizeSpec, parseSpecText, rebaseSpec } from "../src/features/sites/spec-model.ts";
import { requestProblem, serverProblem } from "../src/features/sites/site-messages.ts";
import { orderSpec, specToJson, specToYaml } from "../src/lib/yaml.ts";
import { DECLARE_TEXT, errorText } from "../src/lib/vocab.ts";

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
        auto_tighten: false,
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

// ------------------------------------------------------------------ the function table (objects.functions)

const exported: ObjectFunctionEntry = {
  key: "POST /api/admin/export",
  source: "rule",
  tier: "admin",
  reliability: "high",
};
const listed: ObjectFunctionEntry = { key: "GET /api/patients/{id}", source: "admin" };

test("the function table survives the YAML and the JSON the editor shows and reads back", () => {
  const spec: SiteSpec = { ...site, objects: { ...site.objects, functions: [exported, listed] } };
  const parsed = parseSpecText(specToYaml(spec));
  if (!parsed.ok) assert.fail(parsed.message);
  assert.deepEqual(parsed.spec.objects, spec.objects);
  const back = normalizeSpec(JSON.parse(specToJson(spec)));
  if (!back.ok) assert.fail(back.message);
  assert.deepEqual(back.value.objects, spec.objects);
});

test("a function's keys are written in a fixed order, and an empty table is not written", () => {
  const reordered: ObjectFunctionEntry = {
    reliability: "high",
    tier: "admin",
    source: "rule",
    key: "POST /api/admin/export",
  };
  const spec: SiteSpec = { ...site, objects: { functions: [reordered, listed] } };
  assert.deepEqual(Object.keys(orderSpec(spec).objects?.functions?.[0] ?? {}), [
    "key",
    "source",
    "tier",
    "reliability",
  ]);
  assert.deepEqual(Object.keys(orderSpec(spec).objects?.functions?.[1] ?? {}), ["key", "source"]);
  const empty: SiteSpec = { ...site, objects: { functions: [] } };
  assert.equal(orderSpec(empty).objects, undefined);
  assert.doesNotMatch(specToYaml(empty), /functions/);
  assert.doesNotMatch(specToJson(empty), /functions/);
});

test("a save over a newer version keeps the function entries both sides added", () => {
  const started: SiteSpec = { ...site, objects: { ...site.objects, functions: [exported] } };
  const added = { key: "DELETE /api/records/{id}", source: "agent" } as const;
  const mine: SiteSpec = {
    ...started,
    objects: { ...started.objects, functions: [exported, listed] },
  };
  const latest: SiteSpec = {
    ...started,
    objects: { ...started.objects, functions: [exported, added] },
  };
  const { spec, conflicts } = rebaseSpec(started, mine, latest);
  assert.deepEqual(conflicts, []);
  assert.deepEqual(spec.objects?.functions, [exported, added, listed]);
});

test("a function the newer version removed stays removed when the draft did not change it", () => {
  const started: SiteSpec = {
    ...site,
    objects: { ...site.objects, functions: [exported, listed] },
  };
  const mine: SiteSpec = { ...started, entries: [...started.entries, "/api/draft"] };
  const latest: SiteSpec = { ...started, objects: { ...started.objects, functions: [exported] } };
  const { spec } = rebaseSpec(started, mine, latest);
  assert.deepEqual(spec.objects?.functions, [exported]);
});

test("the switch survives the YAML, the JSON and a save over a newer version, and is written only when on", () => {
  const on: SiteSpec = { ...site, objects: { functions: [exported], ask_unknown_functions: true } };
  const parsed = parseSpecText(specToYaml(on));
  if (!parsed.ok) assert.fail(parsed.message);
  assert.deepEqual(parsed.spec.objects, on.objects);
  const back = normalizeSpec(JSON.parse(specToJson(on)));
  if (!back.ok) assert.fail(back.message);
  assert.deepEqual(back.value.objects, on.objects);
  // The switch is written after the table it needs.
  assert.match(specToYaml(on), /functions:[\s\S]*ask_unknown_functions: true/);
  const off: SiteSpec = {
    ...site,
    objects: { functions: [exported], ask_unknown_functions: false },
  };
  assert.doesNotMatch(specToYaml(off), /ask_unknown_functions/);
  assert.doesNotMatch(specToJson(off), /ask_unknown_functions/);
  // A save over a newer version keeps the switch this draft turned on.
  const started: SiteSpec = { ...site, objects: { functions: [exported] } };
  const mine: SiteSpec = {
    ...started,
    objects: { functions: [exported], ask_unknown_functions: true },
  };
  const latest: SiteSpec = { ...started, entries: [...started.entries, "/api/newer"] };
  const { spec, conflicts } = rebaseSpec(started, mine, latest);
  assert.deepEqual(conflicts, []);
  assert.equal(spec.objects?.ask_unknown_functions, true);
});

// The text of configurations with no function table, as the console wrote them before the table existed. The table is
// new, so these must still come out of the editor byte for byte the same (the YAML and the JSON both).
const emrPlain: SiteSpec = {
  name: "emr",
  hosts: ["emr.example.com"],
  origin: "http://10.0.0.5:8080",
  session: { cookie: "sid" },
  entries: ["/api/login"],
  bypass: ["/static/*"],
  advanced: {
    field_kinds: [{ field: "doc_id", kind: "document", in: ["/api/records/*"] }],
  },
  objects: {
    learning: {
      auto_learn: true,
      auto_tighten: false,
      agent: { enabled: true, daily_limit: 50 },
      thresholds: { uses: 30, sessions: 4 },
      auto_pause: true,
    },
    classes: [{ id: "doctor", name: "医生" }],
    slots: [
      { key: "GET /api/doctors [].id", class: "doctor", source: "admin" },
      {
        key: "GET /doctor/{id} path[1]",
        class: "doctor",
        source: "agent",
        paused: true,
        identity: "user",
        reliability: "high",
        tier: "self",
      },
      {
        key: "POST /api/x body.who",
        class: "doctor",
        source: "rule",
        accepts_public: false,
        reliability: "low",
      },
    ],
  },
};

const judgedPlain: SiteSpec = {
  name: "juice",
  hosts: ["juice.example.com", "b.example.com"],
  origin: "https://10.0.0.9",
  session: { header: "Authorization" },
  entries: ["/rest/user/login", "/rest/admin/*"],
  bypass: ["/static/*"],
  routes: [{ path: "/weixin/wx/gateway", name_from: [["body.method"], ["header.X-Service-Id"]] }],
  mode: "enforce",
  on_jev_unavailable: "allow",
  advanced: {
    jev_timeout_ms: 3000,
    secret_fields: ["idcard", "ssn"],
    synonyms: [["payment", "card"]],
    field_kinds: [{ field: "owner", kind: "doctor" }],
  },
};

const defaultsPlain: SiteSpec = {
  name: "plain",
  hosts: ["plain.example.com"],
  origin: "http://10.0.0.7:80",
  session: { cookie: "JSESSIONID" },
  entries: ["/login"],
  objects: {
    learning: {
      auto_learn: true,
      auto_tighten: false,
      agent: { enabled: false, daily_limit: 200 },
      thresholds: { uses: 20, sessions: 5 },
      auto_pause: true,
    },
  },
};

test("a configuration without a function table is written byte for byte as before", () => {
  assert.equal(specToYaml(emrPlain), EMR_YAML);
  assert.equal(specToJson(emrPlain), EMR_JSON);
  assert.equal(specToYaml(judgedPlain), JUDGED_YAML);
  assert.equal(specToJson(judgedPlain), JUDGED_JSON);
  assert.equal(specToYaml(defaultsPlain), DEFAULTS_YAML);
  assert.equal(specToJson(defaultsPlain), DEFAULTS_JSON);
});

const EMR_YAML = [
  "name: emr",
  "hosts:",
  "  - emr.example.com",
  "origin: http://10.0.0.5:8080",
  "session:",
  "  cookie: sid",
  "entries:",
  "  - /api/login",
  "bypass:",
  "  - /static/*",
  "advanced:",
  "  field_kinds:",
  "    - field: doc_id",
  "      kind: document",
  "      in:",
  "        - /api/records/*",
  "objects:",
  "  learning:",
  "    auto_learn: true",
  "    auto_tighten: false",
  "    agent:",
  "      enabled: true",
  "      daily_limit: 50",
  "    thresholds:",
  "      uses: 30",
  "      sessions: 4",
  "    auto_pause: true",
  "  classes:",
  "    - id: doctor",
  "      name: 医生",
  "  slots:",
  "    - key: GET /api/doctors [].id",
  "      class: doctor",
  "      source: admin",
  "    - key: GET /doctor/{id} path[1]",
  "      class: doctor",
  "      source: agent",
  "      paused: true",
  "      identity: user",
  "      reliability: high",
  "      tier: self",
  "    - key: POST /api/x body.who",
  "      class: doctor",
  "      source: rule",
  "      accepts_public: false",
  "      reliability: low",
  "",
].join("\n");

const EMR_JSON = [
  "{",
  '  "name": "emr",',
  '  "hosts": [',
  '    "emr.example.com"',
  "  ],",
  '  "origin": "http://10.0.0.5:8080",',
  '  "session": {',
  '    "cookie": "sid"',
  "  },",
  '  "entries": [',
  '    "/api/login"',
  "  ],",
  '  "bypass": [',
  '    "/static/*"',
  "  ],",
  '  "advanced": {',
  '    "field_kinds": [',
  "      {",
  '        "field": "doc_id",',
  '        "kind": "document",',
  '        "in": [',
  '          "/api/records/*"',
  "        ]",
  "      }",
  "    ]",
  "  },",
  '  "objects": {',
  '    "learning": {',
  '      "auto_learn": true,',
  '      "auto_tighten": false,',
  '      "agent": {',
  '        "enabled": true,',
  '        "daily_limit": 50',
  "      },",
  '      "thresholds": {',
  '        "uses": 30,',
  '        "sessions": 4',
  "      },",
  '      "auto_pause": true',
  "    },",
  '    "classes": [',
  "      {",
  '        "id": "doctor",',
  '        "name": "医生"',
  "      }",
  "    ],",
  '    "slots": [',
  "      {",
  '        "key": "GET /api/doctors [].id",',
  '        "class": "doctor",',
  '        "source": "admin"',
  "      },",
  "      {",
  '        "key": "GET /doctor/{id} path[1]",',
  '        "class": "doctor",',
  '        "source": "agent",',
  '        "paused": true,',
  '        "identity": "user",',
  '        "reliability": "high",',
  '        "tier": "self"',
  "      },",
  "      {",
  '        "key": "POST /api/x body.who",',
  '        "class": "doctor",',
  '        "source": "rule",',
  '        "accepts_public": false,',
  '        "reliability": "low"',
  "      }",
  "    ]",
  "  }",
  "}",
  "",
].join("\n");

const JUDGED_YAML = [
  "name: juice",
  "hosts:",
  "  - juice.example.com",
  "  - b.example.com",
  "origin: https://10.0.0.9",
  "session:",
  "  header: Authorization",
  "routes:",
  "  - path: /weixin/wx/gateway",
  "    name_from:",
  "      - - body.method",
  "      - - header.X-Service-Id",
  "entries:",
  "  - /rest/user/login",
  "  - /rest/admin/*",
  "bypass:",
  "  - /static/*",
  "mode: enforce",
  "on_jev_unavailable: allow",
  "advanced:",
  "  jev_timeout_ms: 3000",
  "  secret_fields:",
  "    - idcard",
  "    - ssn",
  "  synonyms:",
  "    - - payment",
  "      - card",
  "  field_kinds:",
  "    - field: owner",
  "      kind: doctor",
  "",
].join("\n");

const JUDGED_JSON = [
  "{",
  '  "name": "juice",',
  '  "hosts": [',
  '    "juice.example.com",',
  '    "b.example.com"',
  "  ],",
  '  "origin": "https://10.0.0.9",',
  '  "session": {',
  '    "header": "Authorization"',
  "  },",
  '  "routes": [',
  "    {",
  '      "path": "/weixin/wx/gateway",',
  '      "name_from": [',
  "        [",
  '          "body.method"',
  "        ],",
  "        [",
  '          "header.X-Service-Id"',
  "        ]",
  "      ]",
  "    }",
  "  ],",
  '  "entries": [',
  '    "/rest/user/login",',
  '    "/rest/admin/*"',
  "  ],",
  '  "bypass": [',
  '    "/static/*"',
  "  ],",
  '  "mode": "enforce",',
  '  "on_jev_unavailable": "allow",',
  '  "advanced": {',
  '    "jev_timeout_ms": 3000,',
  '    "secret_fields": [',
  '      "idcard",',
  '      "ssn"',
  "    ],",
  '    "synonyms": [',
  "      [",
  '        "payment",',
  '        "card"',
  "      ]",
  "    ],",
  '    "field_kinds": [',
  "      {",
  '        "field": "owner",',
  '        "kind": "doctor"',
  "      }",
  "    ]",
  "  }",
  "}",
  "",
].join("\n");

const DEFAULTS_YAML = [
  "name: plain",
  "hosts:",
  "  - plain.example.com",
  "origin: http://10.0.0.7:80",
  "session:",
  "  cookie: JSESSIONID",
  "entries:",
  "  - /login",
  "",
].join("\n");

const DEFAULTS_JSON = [
  "{",
  '  "name": "plain",',
  '  "hosts": [',
  '    "plain.example.com"',
  "  ],",
  '  "origin": "http://10.0.0.7:80",',
  '  "session": {',
  '    "cookie": "JSESSIONID"',
  "  },",
  '  "entries": [',
  '    "/login"',
  "  ]",
  "}",
  "",
].join("\n");

test("a refused function entry is named in the words of its check, and other refusals of the map read from their code", () => {
  const spec: SiteSpec = { ...site, objects: { functions: [listed, exported] } };
  const refusal = new ApiError(400, {
    error: "SITE_CONFIG_OBJECTS_INVALID",
    field: "objects.functions[1]",
    reason: "function_tier_unsupported",
  });
  assert.equal(requestProblem(refusal, spec), DECLARE_TEXT.functionTier(2));
  assert.equal(
    serverProblem(
      "SITE_CONFIG_OBJECTS_INVALID",
      "objects.functions[1]",
      spec,
      "function_tier_unsupported",
    ),
    DECLARE_TEXT.functionTier(2),
  );
  assert.equal(
    serverProblem("SITE_CONFIG_OBJECTS_INVALID", "objects.slots[3]", spec, "class_unknown"),
    errorText("SITE_CONFIG_OBJECTS_INVALID"),
  );
});
