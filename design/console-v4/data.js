// Mock data for the Xshield v4 console prototype.
// Shapes follow docs/07 section 7.9 (control-plane API) and the real gateway:
// `jev.state` is the compact JSON string build_state() produces (keys sorted, no
// whitespace), the provider response has the {model, answers, usage} shape, and
// `trace.values[].sources[]` lines up with `state.request.values[].seen_as[]`.
// This is sample data for a static click-through, not real records. Two sites:
// emr (enforce, customised advanced params) and juice (observe, all defaults).
// Attack payloads in request values are short neutered placeholders; the real
// console renders them as escaped text nodes.
'use strict';
(function () {
  const NOW = Date.parse('2026-11-01T21:17:04+08:00');
  const MIN = 60000;
  const enc = new TextEncoder();
  const utf8 = (s) => enc.encode(s).length;

  // req_ + 12 hex digits of Unix ms + 20 hex digits (UUIDv7 without dashes).
  const idTime = (id) => parseInt(id.slice(4, 16), 16);
  const rid = (offsetMs, tail) => 'req_' + (NOW - offsetMs).toString(16).padStart(12, '0') + tail;

  const ID = {
    // juice, session 7c1e9a40d2b35f61 (logged in 18 minutes ago)
    j_login: rid(18 * MIN, '5f0a2b7700112233f0a2'),
    j_whoami: rid(18 * MIN - 1000, '8c1d0e4f2a6b9c3d5e7f'),
    j_products: rid(18 * MIN - 2000, '620133aa001122334455'),
    j_deliv: rid(13 * MIN, '4a9c7e1b3d5f60822c8e'), // falls inside the log gap: never written
    j_search1: rid(6 * MIN, '3d7a91c2e4f60b8a1d35'),
    j_search2: rid(4 * MIN, 'b41e6c0f9a2d7385c1e6'),
    j_basket1: 'req_01a197410a1b2c3d4e5f60718293a4b5',
    j_basket6: 'req_01a19741107477ff9224781077354552',
    j_cards3: rid(20000, '9e5b2a7c1d4f08e36a91'),
    j_admin: 'req_01a197410c41d2e90011223344556677',
    j_bypass: 'req_01a19740e5100a0b0c0d0e0f10111213',
    // emr, sessions a913ee40771c2b05 and b0ffee1234567890
    e_login: rid(40 * MIN, 'a2d9f4c1e7b30586d1f4'),
    e_home: rid(40 * MIN - 5000, '41b7e0a93c5d8f2617ab'),
    e_patients: rid(31 * MIN, 'd83c1f5a07e9b264c3d8'),
    e_p7: rid(30 * MIN, '0b6e4d2c9f1a83570e4c'),
    e_p8: 'req_01a19740aa73f00e0d0c0b0a09080706',
    e_atk: 'req_01a197402f1e0d0c0b0a090807060504',
    e_p12: 'req_01a197400d0e0f101112131415161718',
    e_import: rid(20 * MIN, '7f2a5c8e1b4d90a3e6c5'),
    e_limit: rid(5 * MIN, 'c59d3b7f1e2a60845d9b'),
    u_scan: rid(3 * MIN, '16e8a4f0d2c7b95a3e41'),
  };
  const T = (key) => idTime(ID[key]);

  const SESSION_LABEL = { juice: '7c1e9a40d2b35f61', emr: 'a913ee40771c2b05', emr2: 'b0ffee1234567890' };

  // ---------------------------------------------------------------- sites
  const SPEC = {
    emr: {
      name: 'emr', hosts: ['emr.example.com'], origin: 'http://10.0.0.5:8080',
      session: { header: 'Authorization' },
      entries: ['/login', '/api/home', '/api/patients'],
      bypass: ['/static/*', '/favicon.ico'],
      mode: 'enforce', on_jev_unavailable: 'deny',
      advanced: { jev_timeout_ms: 3000, secret_fields: ['idcard', 'ssn'] },
    },
    juice: {
      name: 'juice', hosts: ['juice.example.com'], origin: 'http://10.0.0.9:3000',
      session: { header: 'Authorization' },
      entries: ['/rest/user/login', '/api/Products', '/rest/products/search'],
      bypass: ['/assets/*', '/favicon.ico'],
      mode: 'observe', on_jev_unavailable: 'deny', advanced: {},
    },
  };
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const without = (spec, patch) => Object.assign(clone(spec), patch);

  const SITES = [
    {
      name: 'emr', mode: 'enforce', hosts: ['emr.example.com'], origin: 'http://10.0.0.5:8080',
      version: 12, saved_at: NOW - 140 * MIN, observing_since: null,
      requests_24h: 9812, blocked_24h: 21, would_block_24h: 0, jev_calls_24h: 412, suggestions: 0,
      spec: clone(SPEC.emr),
      versions: [
        { version: 12, at: NOW - 140 * MIN, change: 'update', note: '慢链路：把 Jev 超时调到 3 秒，追加身份证号脱敏词', spec: clone(SPEC.emr) },
        { version: 11, at: NOW - 3 * 86400000, change: 'update', note: '登记入口 /api/patients', spec: without(SPEC.emr, { advanced: {} }) },
        { version: 10, at: NOW - 5 * 86400000, change: 'update', note: '', spec: without(SPEC.emr, { advanced: {}, entries: ['/login', '/api/home'], bypass: ['/static/*'] }) },
      ],
    },
    {
      name: 'juice', mode: 'observe', hosts: ['juice.example.com'], origin: 'http://10.0.0.9:3000',
      version: 7, saved_at: NOW - 9 * MIN, observing_since: NOW - (6 * 24 * 60 + 4 * 60) * MIN,
      requests_24h: 8392, blocked_24h: 0, would_block_24h: 14, jev_calls_24h: 66, suggestions: 2,
      spec: clone(SPEC.juice),
      versions: [
        { version: 7, at: NOW - 9 * MIN, change: 'update', note: '加入绕过 /favicon.ico', spec: clone(SPEC.juice) },
        { version: 6, at: NOW - 2 * 86400000, change: 'update', note: '登记入口 /rest/products/search', spec: without(SPEC.juice, { bypass: ['/assets/*'] }) },
        { version: 5, at: NOW - 4 * 86400000, change: 'update', note: '', spec: without(SPEC.juice, { bypass: ['/assets/*'], entries: ['/rest/user/login', '/api/Products'] }) },
      ],
    },
  ];

  // ---------------------------------------------------------------- Jev prompts
  const PROMPT_NOW = 'jq_5c2e81d07a4b9f13';
  const PROMPT_OLD = 'jq_91b3d6e20c4a7f58';
  const QUESTIONS = window.MOCK_QUESTIONS;
  const OLD_QUESTIONS = clone(QUESTIONS);
  OLD_QUESTIONS.access.instructions = OLD_QUESTIONS.access.instructions.replace(/ A value with verified true was already matched[^.]*\.[^.]*\./, '');
  const PROMPTS = {
    [PROMPT_NOW]: { id: PROMPT_NOW, first_seen: '2026-11-01T11:52:00Z', questions: QUESTIONS },
    [PROMPT_OLD]: { id: PROMPT_OLD, first_seen: '2026-10-30T09:20:00Z', questions: OLD_QUESTIONS },
  };

  // ---------------------------------------------------------------- builders
  const argmax = (o) => Object.keys(o).reduce((a, b) => (o[a] >= o[b] ? a : b));
  const sortKeys = (o) => Object.keys(o).sort().reduce((acc, k) => { acc[k] = o[k]; return acc; }, {});

  // One value spec drives both trace.values[] and state.request.values[], so the
  // two always line up the way docs/07 7.5.2 requires.
  const src = (field, request, refId) => ({ field, request, request_id: refId || null, at_millis: refId ? idTime(refId) : null });
  const V = (at, value, o = {}) => Object.assign({ at, key: null, value, kind: 'reference', inert: false, seen: false, verified: false, sources: [] }, o);
  const ROUTE = (at, value) => V(at, value, { kind: 'route', inert: true });

  const stateValue = (v) => {
    const o = { at: v.at, kind: v.kind, seen_as: v.sources.map((s) => `${s.field} @ ${s.request}`), value: v.value };
    if (v.verified) o.verified = true;
    return o;
  };
  // Mirrors state.rs render(): serde_json sorts object keys, output is compact.
  function mkState(s) {
    return JSON.stringify({
      entry: { matched: !!s.entry },
      recent: (s.recent || []).slice(-(s.recentKeep == null ? 10 : s.recentKeep)).map((r) => ({ method: r.method, path: r.path, status: r.status })),
      request: { method: s.method, path: s.path, truncated: !!s.truncated, values: s.values.filter((v) => !v.inert).map(stateValue) },
      session: { age_seconds: s.age, entries_passed: (s.entries || []).map((e) => e.path) },
    });
  }
  const buildBody = (model, stateStr, questions) => JSON.stringify({ model, questions: questions || QUESTIONS, state: JSON.parse(stateStr) });
  function mkResponse(model, access, attack, usage) {
    const choice = (o) => ({ choice: argmax(o), probabilities: sortKeys(o), type: 'choice' });
    return JSON.stringify({ answers: { access: choice(access), attack: choice(attack) }, model, usage });
  }
  const MODEL = 'typesafe-ai/jev';

  // Jev exchange as stored in decision_log.jev (docs/07 7.5.1).
  function mkJev(o) {
    const model = o.model || MODEL;
    const prompt = o.prompt || PROMPT_NOW;
    const q = PROMPTS[prompt].questions;
    const state = o.state ? mkState(o.state) : null;
    const j = {
      state, prompt, model, route: 'gateway', timeout_ms: o.timeout_ms || 2000, trim: o.trim || 0,
      request_bytes: state ? utf8(buildBody(model, state, q)) : 0,
      http_status: o.http_status === undefined ? (o.failure ? null : 200) : o.http_status,
      response: null, usage: o.usage || null, access: o.access || null, attack: o.attack || null,
      conclusion: 'unknown', millis: o.millis, failure: o.failure || null,
    };
    if (!o.failure) {
      j.response = mkResponse('jev-1.13.0', o.access, o.attack, o.usage);
      j.conclusion = (argmax(o.access) === 'DENY' || argmax(o.attack) === 'ATTACK') ? 'deny'
        : (argmax(o.access) === 'UNKNOWN' || argmax(o.attack) === 'UNKNOWN') ? 'unknown' : 'allow';
    }
    return j;
  }
  function summarizeJev(j) {
    if (!j) return null;
    if (j.failure) return { access: null, attack: null, confidence: null, ms: j.millis, failure: j.failure };
    const a = argmax(j.access); const t = argmax(j.attack);
    return { access: a, attack: t, confidence: Math.min(j.access[a], j.attack[t]), ms: j.millis, failure: null };
  }

  const timing = (total, judge, origin) => ({ total_ms: total, judge_ms: judge, origin_ms: origin });
  const RESP_NONE = { content_type: null, bytes: 0, observed: 'skipped', skip: 'not_forwarded', values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false };
  const resp = (o) => Object.assign({ content_type: 'application/json', bytes: 600, observed: 'json', skip: null, values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false }, o);
  const ref = (key, method, path, status) => ({ method, path, status: status || 200, request_id: ID[key], at_millis: T(key) });
  const passed = (key, path) => ({ path, at_millis: T(key), request_id: ID[key] });

  // decision_log row + detail, with sensible defaults.
  function rec(o) {
    const base = {
      id: 0, request_id: '', at_millis: idTime(o.request_id), site: 'juice', site_version: 7, edge: 'edge-1',
      method: 'GET', host: 'juice.example.com', path: '/', query: null, status: 200,
      decision_path: 'fast_allow', outcome: 'allowed', session: '', context: 'session',
      client: '192.168.1.20', total_ms: 12, jev: null, trace: { v: 1 }, jevFull: null,
    };
    const r = Object.assign(base, o);
    if (r.jevFull && !o.jev) r.jev = summarizeJev(r.jevFull);
    if (r.trace.timing) r.total_ms = r.trace.timing.total_ms;
    return r;
  }

  // ---------------------------------------------------------------- records
  const RECORDS = [];
  let nextId = 91300;
  const add = (o) => { o.id = nextId--; const r = rec(o); RECORDS.push(r); return r; };

  // ---- juice / session 7c1e9a40d2b35f61 -------------------------------------
  const S1 = SESSION_LABEL.juice;
  const S1_AGE = (key) => Math.round((T(key) - T('j_login')) / 1000);
  const loginRef = ref('j_login', 'POST', '/rest/user/login');
  const whoamiRef = ref('j_whoami', 'GET', '/rest/user/whoami');
  const productsRef = ref('j_products', 'GET', '/api/Products');
  const search1Ref = ref('j_search1', 'GET', '/rest/products/search');
  const search2Ref = ref('j_search2', 'GET', '/rest/products/search');
  const basket1Ref = ref('j_basket1', 'GET', '/rest/basket/1');
  const basket6Ref = ref('j_basket6', 'GET', '/rest/basket/6');
  const S1_ENTRIES = [passed('j_login', '/rest/user/login'), passed('j_products', '/api/Products')];

  // 1. login: entry request, no credential yet, so the context is the client address
  (function () {
    const values = [ROUTE('path[0]', 'rest'), ROUTE('path[1]', 'user'), ROUTE('path[2]', 'login'),
      V('body.email', 'user@example.com', { key: 'email', kind: 'input' }),
      V('body.password', '<redacted>', { key: 'password', kind: 'input', len: 12, redacted: true })];
    add({
      request_id: ID.j_login, method: 'POST', path: '/rest/user/login', decision_path: 'jev_allow', outcome: 'allowed',
      session: 'ad57c3e1902b4f68', context: 'address',
      trace: {
        v: 1, entry: '/rest/user/login', bypass: null, refused: null, values_truncated: false, values,
        session: { age_seconds: 0, known_values: 0, entries_passed: [], recent: [] }, cache_source: null,
        timing: timing(640, 412, 225),
        response: resp({ bytes: 320, values: 6, new_values: 6, fields: [['token', 1], ['bid', 1], ['umail', 1]], issued_session: S1, entry_passed: true }),
        upstream_error: null,
      },
      jevFull: mkJev({
        state: { entry: true, age: 0, entries: [], recent: [], method: 'POST', path: '/rest/user/login', values },
        access: { ALLOW: 0.9712, DENY: 0.021, UNKNOWN: 0.0078 }, attack: { ATTACK: 0.015, BENIGN: 0.981, UNKNOWN: 0.004 },
        usage: { input_tokens: 540, output_tokens: 12 }, millis: 410,
      }),
    });
  }());

  // 2. whoami: no values at all
  add({
    request_id: ID.j_whoami, path: '/rest/user/whoami', session: S1, decision_path: 'fast_allow',
    trace: {
      v: 1, entry: null, bypass: null, refused: null, values_truncated: false,
      values: [ROUTE('path[0]', 'rest'), ROUTE('path[1]', 'user'), ROUTE('path[2]', 'whoami')],
      session: { age_seconds: S1_AGE('j_whoami'), known_values: 6 }, cache_source: null, timing: timing(11, 1, 9),
      response: resp({ bytes: 210, values: 4, new_values: 4, fields: [['id', 1], ['basketId', 1], ['email', 1]] }), upstream_error: null,
    },
  });

  // 3. entry /api/Products: a collection name that never needs to have been shown
  (function () {
    const values = [ROUTE('path[0]', 'api'), V('path[1]', 'Products', { kind: 'route' })];
    const recent = [loginRef, whoamiRef];
    add({
      request_id: ID.j_products, path: '/api/Products', session: S1, decision_path: 'jev_allow', total_ms: 402,
      trace: {
        v: 1, entry: '/api/Products', bypass: null, refused: null, values_truncated: false, values,
        session: { age_seconds: S1_AGE('j_products'), known_values: 10, entries_passed: [passed('j_login', '/rest/user/login')], recent }, cache_source: null,
        timing: timing(402, 388, 11),
        response: resp({ bytes: 48211, values: 291, new_values: 291, fields: [['id', 38], ['name', 38], ['price', 38], ['description', 38]], entry_passed: true }), upstream_error: null,
      },
      jevFull: mkJev({
        state: { entry: true, age: S1_AGE('j_products'), entries: [passed('j_login', '/rest/user/login')], recent, method: 'GET', path: '/api/Products', values },
        access: { ALLOW: 0.988, DENY: 0.0072, UNKNOWN: 0.0048 }, attack: { ATTACK: 0.003, BENIGN: 0.99, UNKNOWN: 0.007 },
        usage: { input_tokens: 612, output_tokens: 12 }, millis: 388,
      }),
    });
  }());

  // 4. search (entry, free text) judged by Jev; 5. the same request again is served from the cache
  (function () {
    const q1 = V('query.q', 'apple', { key: 'q', kind: 'input' });
    const values = [ROUTE('path[0]', 'rest'), ROUTE('path[1]', 'products'), ROUTE('path[2]', 'search'), q1];
    const recent = [loginRef, whoamiRef, productsRef];
    add({
      request_id: ID.j_search1, path: '/rest/products/search', query: 'q=apple', session: S1, decision_path: 'jev_allow', total_ms: 470,
      trace: {
        v: 1, entry: '/rest/products/search', bypass: null, refused: null, values_truncated: false, values,
        session: { age_seconds: S1_AGE('j_search1'), known_values: 301, entries_passed: S1_ENTRIES, recent }, cache_source: null,
        timing: timing(470, 455, 9),
        response: resp({ bytes: 3120, values: 8, new_values: 8, fields: [['id', 2], ['name', 2], ['price', 2]] }), upstream_error: null,
      },
      jevFull: mkJev({
        state: { entry: true, age: S1_AGE('j_search1'), entries: S1_ENTRIES, recent, method: 'GET', path: '/rest/products/search', values },
        access: { ALLOW: 0.965, DENY: 0.0212, UNKNOWN: 0.0138 }, attack: { ATTACK: 0.0041, BENIGN: 0.993, UNKNOWN: 0.0029 },
        usage: { input_tokens: 655, output_tokens: 12 }, millis: 455,
      }),
    });
    add({
      request_id: ID.j_search2, path: '/rest/products/search', query: 'q=apple', session: S1, decision_path: 'cached_allow',
      trace: {
        v: 1, entry: '/rest/products/search', bypass: null, refused: null, values_truncated: false, values: values.map((v) => Object.assign({}, v)),
        session: { age_seconds: S1_AGE('j_search2'), known_values: 309 }, cache_source: ID.j_search1, timing: timing(17, 2, 12),
        response: resp({ bytes: 3120, values: 8, new_values: 0, fields: [['id', 2], ['name', 2], ['price', 2]] }), upstream_error: null,
      },
    });
  }());

  // 6. basket/1: value 1 was shown as basketId by whoami, so the gateway verifies it itself
  add({
    request_id: ID.j_basket1, path: '/rest/basket/1', session: S1, decision_path: 'fast_allow',
    trace: {
      v: 1, entry: null, bypass: null, refused: null, values_truncated: false,
      values: [ROUTE('path[0]', 'rest'), ROUTE('path[1]', 'basket'),
        V('path[2]', '1', { seen: true, verified: true, sources: [src('basketId', 'GET /rest/user/whoami', ID.j_whoami)] })],
      session: { age_seconds: S1_AGE('j_basket1'), known_values: 309 }, cache_source: null, timing: timing(14, 2, 11),
      response: resp({ bytes: 540, values: 9, new_values: 9, fields: [['id', 1], ['quantity', 3], ['ProductId', 3]] }), upstream_error: null,
    },
  });

  // 7. basket/6: 6 only appeared as a quantity -> Jev says DENY, observe mode lets it through
  (function () {
    const values = [ROUTE('path[0]', 'rest'), ROUTE('path[1]', 'basket'),
      V('path[2]', '6', { seen: true, verified: false, sources: [src('quantity', 'GET /rest/basket/1', ID.j_basket1)] })];
    const recent = [loginRef, whoamiRef, productsRef, search1Ref, search2Ref, basket1Ref];
    add({
      request_id: ID.j_basket6, path: '/rest/basket/6', session: S1, decision_path: 'jev_deny', outcome: 'would_block', total_ms: 812,
      trace: {
        v: 1, entry: null, bypass: null, refused: null, values_truncated: false, values,
        session: { age_seconds: S1_AGE('j_basket6'), known_values: 318, entries_passed: S1_ENTRIES, recent }, cache_source: null,
        timing: timing(812, 515, 290),
        response: resp({ bytes: 1832, values: 14, new_values: 9, fields: [['id', 3], ['name', 3], ['price', 3]], after_would_block: true }), upstream_error: null,
      },
      jevFull: mkJev({
        state: { entry: false, age: S1_AGE('j_basket6'), entries: S1_ENTRIES, recent, method: 'GET', path: '/rest/basket/6', values },
        access: { ALLOW: 0.1203, DENY: 0.8612, UNKNOWN: 0.0185 }, attack: { ATTACK: 0.0071, BENIGN: 0.9901, UNKNOWN: 0.0028 },
        usage: { input_tokens: 1021, output_tokens: 12 }, millis: 512,
      }),
    });
  }());

  // 8. Cards/3: a low-confidence DENY, one of its sources fell into the log gap
  (function () {
    const values = [ROUTE('path[0]', 'api'), V('path[1]', 'Cards', { kind: 'route' }),
      V('path[2]', '3', {
        seen: true, verified: false,
        sources: [src('quantity', 'GET /rest/basket/1', ID.j_basket1), src('deliveryMethodId', 'GET /api/Deliverys', ID.j_deliv)],
      })];
    const recent = [whoamiRef, productsRef, search1Ref, search2Ref, basket1Ref, basket6Ref];
    add({
      request_id: ID.j_cards3, path: '/api/Cards/3', session: S1, decision_path: 'jev_deny', outcome: 'would_block', total_ms: 655, edge: 'edge-2',
      trace: {
        v: 1, entry: null, bypass: null, refused: null, values_truncated: false, values,
        session: { age_seconds: S1_AGE('j_cards3'), known_values: 327, entries_passed: S1_ENTRIES, recent }, cache_source: null,
        timing: timing(655, 502, 144),
        response: resp({ bytes: 388, values: 5, new_values: 2, fields: [['id', 1], ['cardNum', 1]], after_would_block: true }), upstream_error: null,
      },
      jevFull: mkJev({
        state: { entry: false, age: S1_AGE('j_cards3'), entries: S1_ENTRIES, recent, method: 'GET', path: '/api/Cards/3', values },
        access: { ALLOW: 0.36, DENY: 0.58, UNKNOWN: 0.06 }, attack: { ATTACK: 0.012, BENIGN: 0.97, UNKNOWN: 0.018 },
        usage: { input_tokens: 1090, output_tokens: 12 }, millis: 497,
      }),
    });
  }());

  // 9. no session, not an entry: observe mode forwards it
  add({
    request_id: ID.j_admin, path: '/rest/admin/application-configuration', decision_path: 'no_session', outcome: 'would_block', context: null,
    trace: {
      v: 1, entry: null, bypass: null, refused: 'unauthenticated', values_truncated: false,
      values: [ROUTE('path[0]', 'rest'), ROUTE('path[1]', 'admin'), ROUTE('path[2]', 'application-configuration')],
      session: null, cache_source: null, timing: timing(9, 1, 7),
      response: resp({ bytes: 2100, observed: 'skipped', skip: 'status' }), upstream_error: null,
    },
  });
  RECORDS[RECORDS.length - 1].trace.response = resp({ bytes: 2100, values: 0, new_values: 0, fields: [] });

  // 10. bypass stub
  add({
    request_id: ID.j_bypass, path: '/assets/public/images/products/apple_juice.jpg', decision_path: 'bypass', outcome: 'allowed', context: null,
    trace: { v: 1, bypass: '/assets/*', timing: timing(6, 0, 5) },
  });

  // ---- emr / sessions a913ee40771c2b05 and b0ffee1234567890 -----------------
  const S2 = SESSION_LABEL.emr;
  const E_AGE = (key) => Math.round((T(key) - T('e_login')) / 1000);
  const eLoginRef = ref('e_login', 'POST', '/login');
  const eHomeRef = ref('e_home', 'GET', '/api/home');
  const ePatientsRef = ref('e_patients', 'GET', '/api/patients');
  const eP7Ref = ref('e_p7', 'GET', '/api/patients/7');
  const EMR = { site: 'emr', site_version: 12, host: 'emr.example.com', client: '10.2.0.44' };

  (function () {
    const values = [ROUTE('path[0]', 'login'),
      V('body.username', 'dr.chen', { key: 'username', kind: 'input' }),
      V('body.password', '<redacted>', { key: 'password', kind: 'input', len: 14, redacted: true })];
    add(Object.assign({}, EMR, {
      request_id: ID.e_login, method: 'POST', path: '/login', decision_path: 'jev_allow', outcome: 'allowed', session: 'f20c8d51be3a9047', context: 'address',
      trace: {
        v: 1, entry: '/login', bypass: null, refused: null, values_truncated: false, values,
        session: { age_seconds: 0, known_values: 0, entries_passed: [], recent: [] }, cache_source: null, timing: timing(571, 402, 160),
        response: resp({ bytes: 290, values: 3, new_values: 3, fields: [['token', 1], ['role', 1]], issued_session: S2, entry_passed: true }), upstream_error: null,
      },
      jevFull: mkJev({
        prompt: PROMPT_OLD, timeout_ms: 3000,
        state: { entry: true, age: 0, entries: [], recent: [], method: 'POST', path: '/login', values },
        access: { ALLOW: 0.972, DENY: 0.018, UNKNOWN: 0.01 }, attack: { ATTACK: 0.011, BENIGN: 0.985, UNKNOWN: 0.004 },
        usage: { input_tokens: 498, output_tokens: 12 }, millis: 402,
      }),
    }));
    add(Object.assign({}, EMR, {
      request_id: ID.e_home, path: '/api/home', session: S2, decision_path: 'fast_allow',
      trace: {
        v: 1, entry: '/api/home', bypass: null, refused: null, values_truncated: false, values: [ROUTE('path[0]', 'api'), ROUTE('path[1]', 'home')],
        session: { age_seconds: E_AGE('e_home'), known_values: 3 }, cache_source: null, timing: timing(18, 2, 15),
        response: resp({ bytes: 1204, values: 5, new_values: 5, fields: [['title', 2]], entry_passed: true }), upstream_error: null,
      },
    }));
    add(Object.assign({}, EMR, {
      request_id: ID.e_patients, path: '/api/patients', session: S2, decision_path: 'fast_allow',
      trace: {
        v: 1, entry: '/api/patients', bypass: null, refused: null, values_truncated: false, values: [ROUTE('path[0]', 'api'), ROUTE('path[1]', 'patients')],
        session: { age_seconds: E_AGE('e_patients'), known_values: 8 }, cache_source: null, timing: timing(41, 2, 37),
        response: resp({ bytes: 6420, values: 120, new_values: 120, fields: [['id', 20], ['name', 20], ['ward', 20]], entry_passed: true }), upstream_error: null,
      },
    }));
    add(Object.assign({}, EMR, {
      request_id: ID.e_p7, path: '/api/patients/7', session: S2, decision_path: 'fast_allow',
      trace: {
        v: 1, entry: null, bypass: null, refused: null, values_truncated: false,
        values: [ROUTE('path[0]', 'api'), ROUTE('path[1]', 'patients'), V('path[2]', '7', { seen: true, verified: true, sources: [src('id', 'GET /api/patients', ID.e_patients)] })],
        session: { age_seconds: E_AGE('e_p7'), known_values: 128 }, cache_source: null, timing: timing(22, 2, 18),
        response: resp({ bytes: 880, values: 12, new_values: 6, fields: [['id', 1], ['name', 1], ['age', 1]] }), upstream_error: null,
      },
    }));
  }());

  // 14. patients/8: 8 only appeared as an age -> blocked in enforce mode
  (function () {
    const values = [ROUTE('path[0]', 'api'), ROUTE('path[1]', 'patients'),
      V('path[2]', '8', { seen: true, verified: false, sources: [src('age', 'GET /api/patients/7', ID.e_p7)] })];
    const recent = [eLoginRef, eHomeRef, ePatientsRef, eP7Ref];
    const entries = [passed('e_login', '/login'), passed('e_home', '/api/home'), passed('e_patients', '/api/patients')];
    add(Object.assign({}, EMR, {
      request_id: ID.e_p8, path: '/api/patients/8', status: 403, session: S2, decision_path: 'jev_deny', outcome: 'blocked', edge: 'edge-2',
      trace: {
        v: 1, entry: null, bypass: null, refused: 'forbidden', values_truncated: false, values,
        session: { age_seconds: Math.round((T('e_p8') - T('e_login')) / 1000), known_values: 134, entries_passed: entries, recent }, cache_source: null,
        timing: timing(690, 560, null), response: RESP_NONE, upstream_error: null,
      },
      jevFull: mkJev({
        timeout_ms: 3000,
        state: { entry: false, age: Math.round((T('e_p8') - T('e_login')) / 1000), entries, recent, method: 'GET', path: '/api/patients/8', values },
        access: { ALLOW: 0.0601, DENY: 0.931, UNKNOWN: 0.0089 }, attack: { ATTACK: 0.005, BENIGN: 0.992, UNKNOWN: 0.003 },
        usage: { input_tokens: 880, output_tokens: 12 }, millis: 548,
      }),
    }));
    // 15. a search with an injection payload: the gateway denies on the attack answer
    const atkValues = [ROUTE('path[0]', 'api'), ROUTE('path[1]', 'patients'), ROUTE('path[2]', 'search'),
      V('body.q', "x' OR sleep(5)=0 --", { key: 'q', kind: 'input' })];
    const atkRecent = [eLoginRef, eHomeRef, ePatientsRef, eP7Ref];
    add(Object.assign({}, EMR, {
      request_id: ID.e_atk, method: 'POST', path: '/api/patients/search', status: 403, session: S2, decision_path: 'jev_deny', outcome: 'blocked',
      trace: {
        v: 1, entry: null, bypass: null, refused: 'forbidden', values_truncated: false, values: atkValues,
        session: { age_seconds: Math.round((T('e_atk') - T('e_login')) / 1000), known_values: 134, entries_passed: entries, recent: atkRecent }, cache_source: null,
        timing: timing(540, 480, null), response: RESP_NONE, upstream_error: null,
      },
      jevFull: mkJev({
        timeout_ms: 3000,
        state: { entry: false, age: Math.round((T('e_atk') - T('e_login')) / 1000), entries, recent: atkRecent, method: 'POST', path: '/api/patients/search', values: atkValues },
        access: { ALLOW: 0.88, DENY: 0.11, UNKNOWN: 0.01 }, attack: { ATTACK: 0.95, BENIGN: 0.04, UNKNOWN: 0.01 },
        usage: { input_tokens: 760, output_tokens: 12 }, millis: 470,
      }),
    }));
  }());

  // 16. Jev timeout -> deny by site setting
  (function () {
    const values = [ROUTE('path[0]', 'api'), ROUTE('path[1]', 'patients'), V('path[2]', '12', { seen: false })];
    add(Object.assign({}, EMR, {
      request_id: ID.e_p12, path: '/api/patients/12', status: 403, session: SESSION_LABEL.emr2, client: '10.2.0.51', decision_path: 'jev_unavailable', outcome: 'blocked',
      trace: {
        v: 1, entry: null, bypass: null, refused: 'forbidden', values_truncated: false, values,
        session: { age_seconds: 300, known_values: 44, entries_passed: [], recent: [] }, cache_source: null,
        timing: timing(3010, 3005, null), response: RESP_NONE, upstream_error: null,
      },
      jevFull: mkJev({
        timeout_ms: 3000, failure: 'JEV_TIMEOUT', millis: 3002,
        state: { entry: false, age: 300, entries: [], recent: [], method: 'GET', path: '/api/patients/12', values },
      }),
    }));
  }());

  // 17. 413 stub, 18. call limit without a call, 19. unknown host
  add(Object.assign({}, EMR, {
    request_id: ID.e_import, method: 'POST', path: '/api/patients/import', status: 413, decision_path: 'body_not_inspectable', outcome: 'blocked', context: null, client: '10.2.0.44',
    trace: { v: 1, refused: 'body_not_inspectable', timing: timing(4, 0, null) },
  }));
  add(Object.assign({}, EMR, {
    request_id: ID.e_limit, method: 'POST', path: '/login', status: 403, session: 'c7a1f93e5d2084b6', context: 'address', client: '10.2.0.77',
    decision_path: 'jev_unavailable', outcome: 'blocked', edge: 'edge-2',
    trace: {
      v: 1, entry: '/login', bypass: null, refused: 'forbidden', values_truncated: false,
      values: [ROUTE('path[0]', 'login'), V('body.username', 'nurse01', { key: 'username', kind: 'input' }), V('body.password', '<redacted>', { key: 'password', kind: 'input', len: 9, redacted: true })],
      session: { age_seconds: 0, known_values: 0, entries_passed: [], recent: [] }, cache_source: null, timing: timing(3, 1, null), response: RESP_NONE, upstream_error: null,
    },
    jevFull: mkJev({ failure: 'JEV_CALL_LIMIT', millis: 0, timeout_ms: 3000, http_status: null }),
  }));
  add({
    request_id: ID.u_scan, site: null, site_version: null, host: 'scanner.example.net', path: '/wp-login.php', status: 404, client: '203.0.113.9',
    decision_path: 'unknown_site', outcome: 'blocked', context: null, edge: 'edge-2',
    trace: { v: 1, refused: 'unknown_site', timing: timing(1, 0, null) },
  });

  RECORDS.sort((a, b) => b.at_millis - a.at_millis);
  const RECORD_BY_ID = {};
  RECORDS.forEach((r) => { RECORD_BY_ID[r.request_id] = r; });

  // ---------------------------------------------------------------- sessions
  const SESSIONS = [
    { label: S1, context: 'session', site: 'juice', first_at: T('j_login'), last_at: T('j_cards3'), requests: 46, jev_calls: 4, blocked: 0, would_block: 2, issued_by: ID.j_login },
    { label: S2, context: 'session', site: 'emr', first_at: T('e_login'), last_at: T('e_p8'), requests: 61, jev_calls: 8, blocked: 2, would_block: 0, issued_by: ID.e_login },
    { label: SESSION_LABEL.emr2, context: 'session', site: 'emr', first_at: NOW - 8 * MIN, last_at: T('e_p12'), requests: 12, jev_calls: 1, blocked: 1, would_block: 0, issued_by: null },
  ];

  // ---------------------------------------------------------------- system
  const JEV_CONFIG = { route: 'gateway', endpoint_host: 'ai-gateway.vercel.sh', model: MODEL, default_timeout_ms: 2000, prompt: PROMPT_NOW };
  const JEV_STATUS = {
    health: 'ok', window_minutes: 5, calls: 42, ok: 42, failures: {}, p50_ms: 540, p95_ms: 910,
    last_ok_at: '2026-11-01T13:17:24Z', last_failure: { at: '2026-11-01T13:02:00Z', failure: 'JEV_TIMEOUT', site: 'emr' }, config: JEV_CONFIG,
  };
  const mkEdge = (edge, o) => Object.assign({
    edge, online: true, started_at: NOW - 20 * 60 * MIN, seen_at: NOW - 5000, build: 'v4.0.0-rc1', listen: ':8443', tls: true, sessions: 0, queue: 0,
    written: 0, dropped: 0, dropped_bypass: 0, write_errors: 0, gaps: [], sites: { emr: { version: 12 }, juice: { version: 7 } }, jev: JEV_CONFIG,
  }, o);
  const SYSTEM = {
    control_build: 'v4.0.0-rc1', postgres: '16.4',
    edges: [
      mkEdge('edge-1', {
        sessions: 1841, queue: 3, written: 1820422, dropped: 37, dropped_bypass: 1204,
        gaps: [
          { from_ms: NOW - 15 * MIN, to_ms: NOW - 12 * MIN, dropped: 37, dropped_bypass: 0, write_errors: 0 },
          { from_ms: NOW - 3 * 60 * MIN, to_ms: NOW - 178 * MIN, dropped: 0, dropped_bypass: 1204, write_errors: 0 },
        ],
      }),
      mkEdge('edge-2', { started_at: NOW - 6 * 60 * MIN, seen_at: NOW - 7000, sessions: 1203, queue: 1, written: 604511 }),
      mkEdge('edge-3', { online: false, started_at: NOW - 30 * 60 * MIN, seen_at: NOW - 3 * 60 * MIN, sessions: 0, written: 90211, sites: { emr: { version: 11 }, juice: { version: 7 } } }),
    ],
    storage: {
      retention_days: 7, earliest_at: NOW - 6.5 * 86400000,
      partitions: [
        { name: 'decision_log_p20261108', from: '2026-11-08', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261107', from: '2026-11-07', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261106', from: '2026-11-06', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261105', from: '2026-11-05', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261104', from: '2026-11-04', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261103', from: '2026-11-03', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261102', from: '2026-11-02', rows: 0, bytes: 0, future: true },
        { name: 'decision_log_p20261101', from: '2026-11-01', rows: 1402233, bytes: 1181116006 },
        { name: 'decision_log_p20261031', from: '2026-10-31', rows: 1988010, bytes: 1620000000 },
        { name: 'decision_log_p20261030', from: '2026-10-30', rows: 1904221, bytes: 1551000000 },
      ],
    },
    params: {
      site_overridable: {
        jev_timeout_ms: 2000, session_calls_per_minute: 60, address_calls_per_minute: 30, allow_cache_minutes: 10,
        secret_fields: ['authorization', 'credential', 'cvv', 'otp', 'passwd', 'password', 'pwd', 'secret', 'token'], synonyms: [['card', 'payment']],
      },
      fixed: {
        seen_max: 5000, sources_max: 6, recent_max: 50, idle_hours: 24, sessions_max: 20000, long_value_chars: 8, state_bytes_max: 8192,
        request_body_max: 49152, response_parse_max: 1048576, request_values_max: 200, queue_capacity: 10000,
      },
    },
  };

  // ---------------------------------------------------------------- insights, evidence, charts
  const INSIGHTS = {
    juice: {
      window_hours: 24,
      suggestions: [
        { id: 's1', kind: 'entry_candidate', method: 'GET', path: '/rest/admin/application-configuration', count: 312, sample: ID.j_admin, action: { add_entry: '/rest/admin/application-configuration' }, reason: '未登录时前端就会请求这个接口，目前全部按“无会话”记为本应拦截。' },
        { id: 's2', kind: 'bypass_candidate', method: 'GET', path: '/assets/i18n/en.json', count: 401, sample: ID.j_bypass, action: { add_bypass: '/assets/*' }, reason: '国际化资源文件，属于静态资源，不需要判定。' },
      ],
      readiness: { observing_since: SITES[1].observing_since, would_block: { jev_deny: 11, no_session: 3 }, open_suggestions: 2, jev_health: 'ok', after_would_block_refs: 5 },
    },
    emr: { window_hours: 24, suggestions: [], readiness: null },
  };

  // Log-normal call-duration histogram, 100 ms buckets, the last bucket holds timeouts.
  function durationHist(total, medianMs, sigma, buckets, timeouts) {
    const w = 100; const out = []; let sum = 0;
    for (let i = 0; i < buckets; i++) {
      const x = (i + 0.5) * w;
      const p = Math.exp(-Math.pow(Math.log(x / medianMs), 2) / (2 * sigma * sigma)) / x;
      out.push(p); sum += p;
    }
    const counts = out.map((p) => Math.round((p / sum) * (total - timeouts)));
    counts[buckets - 1] += timeouts;
    return counts;
  }
  const EVIDENCE = {
    emr: { window_hours: 24, jev: { p50_ms: 540, p95_ms: 1820, p99_ms: 2410, timeouts: 3, calls: 412, timeout_ms_used: 3000 }, call_limit: { session_peak: 22, address_peak: 41, session_hits: 0, address_hits: 11 }, cache: { cached_allows: 86 }, histogram: durationHist(412, 540, 0.55, 30, 3) },
    juice: { window_hours: 24, jev: { p50_ms: 460, p95_ms: 760, p99_ms: 910, timeouts: 0, calls: 66, timeout_ms_used: 2000 }, call_limit: { session_peak: 8, address_peak: 12, session_hits: 0, address_hits: 0 }, cache: { cached_allows: 12 }, histogram: durationHist(66, 460, 0.4, 20, 0) },
  };
  const TIMESERIES = Array.from({ length: 24 }, (_, i) => {
    const base = 220 + Math.round(120 * Math.sin((i / 24) * Math.PI * 2 - 1));
    return { hour: i, fast: base, jev: Math.round(base * 0.08), no_session: Math.round(base * 0.03) };
  });

  window.MOCK = {
    NOW, MIN, ID, SITES, SPEC, PROMPTS, PROMPT_NOW, QUESTIONS, RECORDS, RECORD_BY_ID, SESSIONS, JEV_STATUS, SYSTEM, INSIGHTS, EVIDENCE,
    TIMESERIES, idTime, argmax, utf8, buildBody, mkState, BUILTIN_SECRET: ['password', 'passwd', 'pwd', 'secret', 'token', 'otp', 'credential', 'authorization', 'cvv'],
  };
}());
