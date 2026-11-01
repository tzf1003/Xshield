// Mock data for the Xshield v4 console prototype.
// Shapes follow docs/07 section 7.9 (control-plane API). This is sample data
// for a static click-through, not real records. Two sites: emr (enforce,
// customised advanced params) and juice (observe, all defaults).
// Request values that would carry attack payloads are shown as short neutered
// placeholders; the real console renders them as escaped text nodes.

const NOW = Date.parse('2026-11-01T21:17:04+08:00');
const min = (n) => n * 60000;

// Decode the Unix-ms timestamp from a req_ id's first 12 hex digits.
function idTime(id) { return parseInt(id.slice(4, 16), 16); }

const SITES = [
  {
    name: 'emr', mode: 'enforce', hosts: ['emr.example.com'], origin: 'http://10.0.0.5:8080',
    session: { header: 'Authorization' }, version: 12, loaded_version: 12, loaded_at: NOW - min(140),
    observing_since: null, requests_24h: 9812, blocked_24h: 21, would_block_24h: 0, jev_calls_24h: 412,
    suggestions: 0,
    spec: {
      name: 'emr', hosts: ['emr.example.com'], origin: 'http://10.0.0.5:8080',
      session: { header: 'Authorization' },
      entries: ['/login', '/api/home', '/api/patients'],
      bypass: ['/static/*', '/favicon.ico'],
      mode: 'enforce', on_jev_unavailable: 'deny',
      advanced: { jev_timeout_ms: 3000, secret_fields: ['idcard', 'ssn'] },
    },
  },
  {
    name: 'juice', mode: 'observe', hosts: ['juice.example.com'], origin: 'http://10.0.0.9:3000',
    session: { header: 'Authorization' }, version: 7, loaded_version: 7, loaded_at: NOW - min(9),
    observing_since: NOW - min(60 * 24 * 6 + 60 * 4), requests_24h: 8392, blocked_24h: 0,
    would_block_24h: 14, jev_calls_24h: 66, suggestions: 2,
    spec: {
      name: 'juice', hosts: ['juice.example.com'], origin: 'http://10.0.0.9:3000',
      session: { header: 'Authorization' },
      entries: ['/rest/user/login', '/api/Products', '/rest/products/search'],
      bypass: ['/assets/*', '/favicon.ico'],
      mode: 'observe', on_jev_unavailable: 'deny', advanced: {},
    },
  },
];

const PROMPTS = {
  jq_5c2e81d07a4b9f13: {
    id: 'jq_5c2e81d07a4b9f13', first_seen: '2026-11-01T05:12:00Z',
    questions: {
      access: {
        instructions: 'You are a web application firewall. state.request is one HTTP request from a logged-in browser session. state.session and state.recent describe what the origin server already showed this session. For every value in state.request.values that selects or names an existing business object (record id, account, owner, file, order), check state.request.values[].seen_as. Answer ALLOW only if every object-selecting value was shown earlier as that kind of object, or if state.entry.matched is true and the values are only the input that entry needs.',
        choices: ['ALLOW', 'DENY', 'UNKNOWN'],
      },
      attack: {
        instructions: 'You are a web application firewall. Inspect every value in state.request.values and the request path for attack content. Values marked <redacted> are secrets and are not attack content. Answer ATTACK if any value carries attack content, BENIGN if none does, UNKNOWN only if the evidence is insufficient.',
        choices: ['BENIGN', 'ATTACK', 'UNKNOWN'],
      },
    },
  },
};

// Build a decision record. Overrides merge onto sensible defaults.
function rec(o) {
  const at = idTime(o.request_id);
  const base = {
    id: 0, request_id: '', at_millis: at, site: 'juice', site_version: 7, edge: 'edge-1',
    method: 'GET', host: 'juice.example.com', path: '/', query: null, status: 200,
    decision_path: 'fast_allow', outcome: 'allowed', session: '', context: 'session',
    client: '192.168.1.20', total_ms: 12, jev: null,
    trace: { v: 1 }, jevFull: null,
  };
  return Object.assign(base, o);
}

const V = (at, value, extra = {}) => Object.assign({ at, key: null, value, kind: 'reference', inert: false, seen: false, verified: false, sources: [] }, extra);

const RECORDS = [
  rec({
    id: 91242, request_id: 'req_01a19741107477ff9224781077354552', site: 'juice', site_version: 7,
    method: 'GET', path: '/rest/basket/6', status: 200, decision_path: 'jev_deny', outcome: 'would_block',
    session: '7c1e9a40d2b35f61', total_ms: 812,
    jev: { access: 'DENY', attack: 'BENIGN', confidence: 0.86, ms: 512, failure: null },
    trace: {
      v: 1, entry: null, bypass: null, refused: null, values_truncated: false,
      values: [
        V('path[0]', 'rest', { kind: 'route', inert: true }),
        V('path[1]', 'basket', { kind: 'route', inert: true }),
        V('path[2]', '6', { kind: 'reference', seen: true, verified: false,
          sources: [{ field: 'quantity', request: 'GET /rest/basket/1', request_id: 'req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4', at_millis: idTime('req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4') }] }),
      ],
      session: {
        age_seconds: 674, known_values: 318,
        entries_passed: [
          { path: '/rest/user/login', at_millis: NOW - min(12), request_id: 'req_01a197405f0a2b7700112233f0a2b77c' },
          { path: '/api/Products', at_millis: NOW - min(12) + 600, request_id: 'req_01a19740620133aa0011223344556677' },
        ],
        recent: [
          { method: 'GET', path: '/rest/user/whoami', status: 200, request_id: 'req_01a197405f0a2b7700112233f0a2b77c', at_millis: NOW - min(12) },
          { method: 'GET', path: '/api/Products', status: 200, request_id: 'req_01a19740620133aa0011223344556677', at_millis: NOW - min(12) + 600 },
          { method: 'GET', path: '/rest/basket/1', status: 200, request_id: 'req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4', at_millis: idTime('req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4') },
        ],
      },
      cache_source: null,
      timing: { total_ms: 812, judge_ms: 515, origin_ms: 290 },
      response: { content_type: 'application/json', bytes: 1832, observed: 'json', skip: null, values: 14, new_values: 9, fields: [['id', 3], ['name', 3], ['price', 3]], issued_session: null, entry_passed: false, after_would_block: true },
      upstream_error: null,
    },
    jevFull: {
      state: JSON.stringify({
        entry: { matched: false, pattern: null },
        session: { age_seconds: 674, entries_passed: ['/rest/user/login', '/api/Products'] },
        recent: [
          { method: 'GET', path: '/rest/user/whoami', status: 200 },
          { method: 'GET', path: '/api/Products', status: 200 },
          { method: 'GET', path: '/rest/basket/1', status: 200 },
        ],
        request: { method: 'GET', path: '/rest/basket/6', values: [{ at: 'path[2]', kind: 'reference', value: '6', seen_as: ['quantity @ GET /rest/basket/1'] }] },
      }, null, 2),
      prompt: 'jq_5c2e81d07a4b9f13', model: 'typesafe-ai/jev', route: 'gateway',
      timeout_ms: 2000, trim: 0, request_bytes: 3412, http_status: 200,
      response: '{"access":{"ALLOW":0.1203,"DENY":0.8612,"UNKNOWN":0.0185},"attack":{"BENIGN":0.9901,"ATTACK":0.0071,"UNKNOWN":0.0028}}',
      usage: { input_tokens: 1021, output_tokens: 12 },
      access: { ALLOW: 0.1203, DENY: 0.8612, UNKNOWN: 0.0185 },
      attack: { BENIGN: 0.9901, ATTACK: 0.0071, UNKNOWN: 0.0028 },
      conclusion: 'deny', millis: 512, failure: null,
    },
  }),
  rec({
    id: 91241, request_id: 'req_01a197410a1b2c3d4e5f60718293a4b5', site: 'juice',
    method: 'GET', path: '/rest/basket/1', status: 200, decision_path: 'fast_allow', outcome: 'allowed',
    session: '7c1e9a40d2b35f61', total_ms: 14,
    trace: {
      v: 1, entry: null, bypass: null, refused: null, values_truncated: false,
      values: [
        V('path[0]', 'rest', { kind: 'route', inert: true }),
        V('path[1]', 'basket', { kind: 'route', inert: true }),
        V('path[2]', '1', { kind: 'reference', seen: true, verified: true,
          sources: [{ field: 'basketId', request: 'GET /rest/user/whoami', request_id: 'req_01a197405f0a2b7700112233f0a2b77c', at_millis: NOW - min(12) }] }),
      ],
      session: { age_seconds: 660, known_values: 309, entries_passed: [], recent: [] },
      cache_source: null,
      timing: { total_ms: 14, judge_ms: 2, origin_ms: 11 },
      response: { content_type: 'application/json', bytes: 540, observed: 'json', skip: null, values: 9, new_values: 2, fields: [['id', 1], ['quantity', 2]], issued_session: null, entry_passed: false, after_would_block: false },
      upstream_error: null,
    },
  }),
  rec({
    id: 91240, request_id: 'req_01a197410c41d2e90011223344556677', site: 'juice',
    method: 'GET', path: '/rest/admin/application-configuration', status: 200,
    decision_path: 'no_session', outcome: 'would_block', session: '', context: null, total_ms: 9,
    trace: {
      v: 1, entry: null, bypass: null, refused: 'unauthenticated', values_truncated: false,
      values: [], session: null, cache_source: null,
      timing: { total_ms: 9, judge_ms: 1, origin_ms: 7 },
      response: { content_type: 'application/json', bytes: 2100, observed: 'json', skip: null, values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false },
      upstream_error: null,
    },
  }),
  rec({
    id: 91239, request_id: 'req_01a197405f0a2b7700112233f0a2b77c', site: 'juice',
    method: 'POST', path: '/rest/user/login', status: 200, decision_path: 'jev_allow', outcome: 'allowed',
    session: '7c1e9a40d2b35f61', total_ms: 640,
    jev: { access: 'ALLOW', attack: 'BENIGN', confidence: 0.97, ms: 410, failure: null },
    trace: {
      v: 1, entry: '/rest/user/login', bypass: null, refused: null, values_truncated: false,
      values: [
        V('path[0]', 'rest', { kind: 'route', inert: true }),
        V('body.email', 'user@example.com', { key: 'email', kind: 'input' }),
        V('body.password', '<redacted>', { key: 'password', kind: 'input', seen: false }),
      ],
      session: { age_seconds: 0, known_values: 0, entries_passed: [{ path: '/rest/user/login', at_millis: NOW - min(12), request_id: 'req_01a197405f0a2b7700112233f0a2b77c' }], recent: [] },
      cache_source: null,
      timing: { total_ms: 640, judge_ms: 412, origin_ms: 225 },
      response: { content_type: 'application/json', bytes: 320, observed: 'json', skip: null, values: 4, new_values: 4, fields: [['token', 1]], issued_session: '7c1e9a40d2b35f61', entry_passed: true, after_would_block: false },
      upstream_error: null,
    },
    jevFull: {
      state: JSON.stringify({ entry: { matched: true, pattern: '/rest/user/login' }, session: { age_seconds: 0, entries_passed: [] }, recent: [], request: { method: 'POST', path: '/rest/user/login', values: [{ at: 'body.email', kind: 'input', value: 'user@example.com', seen_as: [] }, { at: 'body.password', kind: 'input', value: '<redacted>', seen_as: [] }] } }, null, 2),
      prompt: 'jq_5c2e81d07a4b9f13', model: 'typesafe-ai/jev', route: 'gateway', timeout_ms: 2000, trim: 0,
      request_bytes: 2210, http_status: 200,
      response: '{"access":{"ALLOW":0.9712,"DENY":0.0210,"UNKNOWN":0.0078},"attack":{"BENIGN":0.9810,"ATTACK":0.0150,"UNKNOWN":0.0040}}',
      usage: { input_tokens: 540, output_tokens: 12 },
      access: { ALLOW: 0.9712, DENY: 0.0210, UNKNOWN: 0.0078 },
      attack: { BENIGN: 0.9810, ATTACK: 0.0150, UNKNOWN: 0.0040 },
      conclusion: 'allow', millis: 410, failure: null,
    },
  }),
  rec({
    id: 91238, request_id: 'req_01a19740e5100a0b0c0d0e0f10111213', site: 'juice',
    method: 'GET', path: '/assets/public/images/products/apple_juice.jpg', status: 200,
    decision_path: 'bypass', outcome: 'allowed', session: '', context: null, total_ms: 6,
    trace: { v: 1, bypass: '/assets/*', timing: { total_ms: 6, judge_ms: 0, origin_ms: 5 } },
  }),
  rec({
    id: 91230, request_id: 'req_01a19740aa73f00e0d0c0b0a09080706', site: 'emr', site_version: 12,
    host: 'emr.example.com', method: 'GET', path: '/api/patients/8', status: 403,
    decision_path: 'jev_deny', outcome: 'blocked', session: 'a913ee40771c2b05', client: '10.2.0.44', total_ms: 690,
    jev: { access: 'DENY', attack: 'BENIGN', confidence: 0.93, ms: 548, failure: null },
    trace: {
      v: 1, entry: null, bypass: null, refused: 'forbidden', values_truncated: false,
      values: [
        V('path[0]', 'api', { kind: 'route', inert: true }),
        V('path[1]', 'patients', { kind: 'route', inert: true }),
        V('path[2]', '8', { kind: 'reference', seen: true, verified: false,
          sources: [{ field: 'age', request: 'GET /api/patients/7', request_id: 'req_01a19740a0b1c2d3e4f5061728394a5b', at_millis: NOW - min(30) }] }),
      ],
      session: {
        age_seconds: 1920, known_values: 142,
        entries_passed: [{ path: '/login', at_millis: NOW - min(40), request_id: 'req_01a197400102030405060708090a0b0c' }],
        recent: [
          { method: 'GET', path: '/api/patients', status: 200, request_id: 'req_01a197409fa0b1c2d3e4f50617283940', at_millis: NOW - min(31) },
          { method: 'GET', path: '/api/patients/7', status: 200, request_id: 'req_01a19740a0b1c2d3e4f5061728394a5b', at_millis: NOW - min(30) },
        ],
      },
      cache_source: null,
      timing: { total_ms: 690, judge_ms: 560, origin_ms: null },
      response: { content_type: null, bytes: 0, observed: 'skipped', skip: 'not_forwarded', values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false },
      upstream_error: null,
    },
    jevFull: {
      state: JSON.stringify({ entry: { matched: false, pattern: null }, session: { age_seconds: 1920, entries_passed: ['/login'] }, recent: [{ method: 'GET', path: '/api/patients', status: 200 }, { method: 'GET', path: '/api/patients/7', status: 200 }], request: { method: 'GET', path: '/api/patients/8', values: [{ at: 'path[2]', kind: 'reference', value: '8', seen_as: ['age @ GET /api/patients/7'] }] } }, null, 2),
      prompt: 'jq_5c2e81d07a4b9f13', model: 'typesafe-ai/jev', route: 'gateway', timeout_ms: 3000, trim: 0,
      request_bytes: 1980, http_status: 200,
      response: '{"access":{"ALLOW":0.0601,"DENY":0.9310,"UNKNOWN":0.0089},"attack":{"BENIGN":0.9920,"ATTACK":0.0050,"UNKNOWN":0.0030}}',
      usage: { input_tokens: 880, output_tokens: 12 },
      access: { ALLOW: 0.0601, DENY: 0.9310, UNKNOWN: 0.0089 },
      attack: { BENIGN: 0.9920, ATTACK: 0.0050, UNKNOWN: 0.0030 },
      conclusion: 'deny', millis: 548, failure: null,
    },
  }),
  rec({
    id: 91225, request_id: 'req_01a197402f1e0d0c0b0a090807060504', site: 'emr', site_version: 12,
    host: 'emr.example.com', method: 'POST', path: '/api/patients/search', status: 403,
    decision_path: 'jev_deny', outcome: 'blocked', session: 'a913ee40771c2b05', client: '10.2.0.44', total_ms: 540,
    jev: { access: 'ALLOW', attack: 'ATTACK', confidence: 0.95, ms: 470, failure: null },
    trace: {
      v: 1, entry: null, bypass: null, refused: 'forbidden', values_truncated: false,
      values: [
        V('path[0]', 'api', { kind: 'route', inert: true }),
        V('body.q', "x' OR sleep(5)=0 --", { key: 'q', kind: 'input', seen: false }),
      ],
      session: { age_seconds: 1900, known_values: 140, entries_passed: [], recent: [] },
      cache_source: null,
      timing: { total_ms: 540, judge_ms: 480, origin_ms: null },
      response: { content_type: null, bytes: 0, observed: 'skipped', skip: 'not_forwarded', values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false },
      upstream_error: null,
    },
    jevFull: {
      state: JSON.stringify({ entry: { matched: false, pattern: null }, session: { age_seconds: 1900, entries_passed: ['/login'] }, recent: [], request: { method: 'POST', path: '/api/patients/search', values: [{ at: 'body.q', kind: 'input', value: "x' OR sleep(5)=0 --", seen_as: [] }] } }, null, 2),
      prompt: 'jq_5c2e81d07a4b9f13', model: 'typesafe-ai/jev', route: 'gateway', timeout_ms: 3000, trim: 0,
      request_bytes: 1700, http_status: 200,
      response: '{"access":{"ALLOW":0.8800,"DENY":0.1100,"UNKNOWN":0.0100},"attack":{"BENIGN":0.0400,"ATTACK":0.9500,"UNKNOWN":0.0100}}',
      usage: { input_tokens: 760, output_tokens: 12 },
      access: { ALLOW: 0.88, DENY: 0.11, UNKNOWN: 0.01 },
      attack: { BENIGN: 0.04, ATTACK: 0.95, UNKNOWN: 0.01 },
      conclusion: 'deny', millis: 470, failure: null,
    },
  }),
  rec({
    id: 91210, request_id: 'req_01a197400d0e0f101112131415161718', site: 'emr', site_version: 12,
    host: 'emr.example.com', method: 'GET', path: '/api/patients/12', status: 504,
    decision_path: 'jev_unavailable', outcome: 'blocked', session: 'b0ffee1234567890', client: '10.2.0.51', total_ms: 3010,
    jev: { access: null, attack: null, confidence: null, ms: 3002, failure: 'JEV_TIMEOUT' },
    trace: {
      v: 1, entry: null, bypass: null, refused: 'forbidden', values_truncated: false,
      values: [V('path[0]', 'api', { kind: 'route', inert: true }), V('path[2]', '12', { kind: 'reference', seen: false })],
      session: { age_seconds: 300, known_values: 44, entries_passed: [], recent: [] },
      cache_source: null,
      timing: { total_ms: 3010, judge_ms: 3005, origin_ms: null },
      response: { content_type: null, bytes: 0, observed: 'skipped', skip: 'not_forwarded', values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false },
      upstream_error: null,
    },
    jevFull: {
      state: JSON.stringify({ entry: { matched: false, pattern: null }, session: { age_seconds: 300, entries_passed: ['/login'] }, recent: [], request: { method: 'GET', path: '/api/patients/12', values: [{ at: 'path[2]', kind: 'reference', value: '12', seen_as: [] }] } }, null, 2),
      prompt: 'jq_5c2e81d07a4b9f13', model: 'typesafe-ai/jev', route: 'gateway', timeout_ms: 3000, trim: 0,
      request_bytes: 1600, http_status: null, response: null, usage: null,
      access: null, attack: null, conclusion: 'unknown', millis: 3002, failure: 'JEV_TIMEOUT',
    },
  }),
];

// index records by id for cross-links
const RECORD_BY_ID = {};
RECORDS.forEach((r) => { RECORD_BY_ID[r.request_id] = r; });

// A couple of referenced source requests that aren't in the main list.
[
  rec({ id: 90010, request_id: 'req_01a1973f5b2a7c41a0d3e7f6b1c2d3e4', site: 'juice', method: 'GET', path: '/rest/basket/1', status: 200, decision_path: 'fast_allow', outcome: 'allowed', session: '7c1e9a40d2b35f61' }),
  rec({ id: 90008, request_id: 'req_01a19740a0b1c2d3e4f5061728394a5b', site: 'emr', host: 'emr.example.com', method: 'GET', path: '/api/patients/7', status: 200, decision_path: 'jev_allow', outcome: 'allowed', session: 'a913ee40771c2b05', client: '10.2.0.44', jev: { access: 'ALLOW', attack: 'BENIGN', confidence: 0.94, ms: 430, failure: null } }),
  rec({ id: 90005, request_id: 'req_01a19740620133aa0011223344556677', site: 'juice', method: 'GET', path: '/api/Products', status: 200, decision_path: 'fast_allow', outcome: 'allowed', session: '7c1e9a40d2b35f61' }),
].forEach((r) => { if (!RECORD_BY_ID[r.request_id]) { RECORD_BY_ID[r.request_id] = r; } });

const SESSIONS = [
  { label: '7c1e9a40d2b35f61', context: 'session', site: 'juice', first_at: NOW - min(12), last_at: NOW - min(1), requests: 46, jev_calls: 3, blocked: 0, would_block: 1, issued_by: 'req_01a197405f0a2b7700112233f0a2b77c' },
  { label: 'a913ee40771c2b05', context: 'session', site: 'emr', first_at: NOW - min(40), last_at: NOW - min(5), requests: 61, jev_calls: 8, blocked: 2, would_block: 0, issued_by: 'req_01a197400102030405060708090a0b0c' },
  { label: 'b0ffee1234567890', context: 'session', site: 'emr', first_at: NOW - min(8), last_at: NOW - min(2), requests: 12, jev_calls: 1, blocked: 1, would_block: 0, issued_by: null },
];

const JEV_STATUS = {
  health: 'ok', window_minutes: 5, calls: 42, ok: 42, failures: {},
  p50_ms: 540, p95_ms: 910, last_ok_at: '2026-11-01T13:17:24Z',
  last_failure: { at: '2026-11-01T13:02:00Z', failure: 'JEV_TIMEOUT', site: 'emr' },
  config: { route: 'gateway', endpoint_host: 'ai-gateway.vercel.sh', model: 'typesafe-ai/jev', default_timeout_ms: 2000, prompt: 'jq_5c2e81d07a4b9f13' },
};

const SYSTEM = {
  control_build: 'v4.0.0-rc1', postgres: '16.4',
  edges: [
    { edge: 'edge-1', online: true, started_at: NOW - min(60 * 20), seen_at: NOW - min(0.2), build: 'v4.0.0-rc1', listen: ':8443', tls: true, sessions: 1841, queue: 3, written: 1820422, dropped: 37, write_errors: 0, sites: { emr: { version: 12 }, juice: { version: 7 } }, jev: { route: 'gateway', endpoint_host: 'ai-gateway.vercel.sh', model: 'typesafe-ai/jev', default_timeout_ms: 2000, prompt: 'jq_5c2e81d07a4b9f13' } },
  ],
  storage: {
    retention_days: 7, earliest_at: NOW - min(60 * 24 * 6.5),
    partitions: [
      { name: 'decision_log_p20261101', rows: 1402233, bytes: 1181116006 },
      { name: 'decision_log_p20261031', rows: 1988010, bytes: 1620000000 },
      { name: 'decision_log_p20261030', rows: 1904221, bytes: 1551000000 },
    ],
    gaps: [{ edge: 'edge-1', from: NOW - min(15), to: NOW - min(12), rows: 37 }],
  },
  params: {
    site_overridable: { jev_timeout_ms: 2000, session_calls_per_minute: 60, address_calls_per_minute: 30, allow_cache_minutes: 10, secret_fields: ['authorization', 'credential', 'cvv', 'otp', 'passwd', 'password', 'pwd', 'secret', 'token'], synonyms: [['card', 'payment']] },
    fixed: { seen_max: 5000, sources_max: 6, recent_max: 50, idle_hours: 24, sessions_max: 20000, long_value_chars: 8, state_bytes_max: 8192, request_body_max: 49152, response_parse_max: 1048576, request_values_max: 200 },
  },
};

const INSIGHTS = {
  juice: {
    window_hours: 24,
    suggestions: [
      { id: 's1', kind: 'entry_candidate', method: 'GET', path: '/rest/admin/application-configuration', count: 312, sample: 'req_01a197410c41d2e90011223344556677', action: { add_entry: '/rest/admin/application-configuration' }, reason: '未登录时前端就会请求这个接口，目前全部按“无会话”记为本应拦截。' },
      { id: 's2', kind: 'bypass_candidate', method: 'GET', path: '/assets/i18n/en.json', count: 401, sample: 'req_01a19740e5100a0b0c0d0e0f10111213', action: { add_bypass: '/assets/*' }, reason: '国际化资源文件，属于静态资源，不需要判定。' },
    ],
    readiness: { observing_since: SITES[1].observing_since, would_block: { jev_deny: 11, no_session: 3 }, open_suggestions: 2, jev_health: 'ok', after_would_block_refs: 5 },
  },
  emr: { window_hours: 24, suggestions: [], readiness: null },
};

const EVIDENCE = {
  emr: { window_hours: 24, jev: { p50_ms: 540, p95_ms: 1820, p99_ms: 2410, timeouts: 3, calls: 412, timeout_ms_used: 3000 }, call_limit: { session_peak: 22, address_peak: 41, session_hits: 0, address_hits: 11 }, cache: { cached_allows: 86 }, histogram: [20, 60, 120, 180, 60, 30, 14, 8, 6, 3, 3] },
  juice: { window_hours: 24, jev: { p50_ms: 460, p95_ms: 760, p99_ms: 910, timeouts: 0, calls: 66, timeout_ms_used: 2000 }, call_limit: { session_peak: 8, address_peak: 12, session_hits: 0, address_hits: 0 }, cache: { cached_allows: 12 }, histogram: [8, 22, 18, 10, 5, 2, 1] },
};

// Hourly stacked series for the overview (24 buckets): fast=no-call allow, jev, no_session.
const TIMESERIES = Array.from({ length: 24 }, (_, i) => {
  const base = 220 + Math.round(120 * Math.sin((i / 24) * Math.PI * 2 - 1));
  return { hour: i, fast: base, jev: Math.round(base * 0.08), no_session: Math.round(base * 0.03) };
});

const SUMMARY = {
  judged: 6204, blocked: 23, would_block: 14, unjudged: 0, jev_calls: 412, jev_pct: 6.6, jev_p95_ms: 910, jev_timeouts: 3,
};

window.MOCK = { NOW, SITES, PROMPTS, RECORDS, RECORD_BY_ID, SESSIONS, JEV_STATUS, SYSTEM, INSIGHTS, EVIDENCE, TIMESERIES, SUMMARY, idTime };
