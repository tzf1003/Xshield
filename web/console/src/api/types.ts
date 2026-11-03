// Wire types of the control-plane API (docs/07 section 7.9) and of the decision record it serves
// (7.4, 7.5). Every field is snake_case JSON exactly as the server sends it; times named
// `*_millis` are Unix milliseconds, the rest RFC 3339 UTC strings (7.9.1).
//
// The sample responses in tests/fixtures/*.json are typed by these definitions (tests/contract),
// and the Rust side round-trips the same files, so a change here is a change to the contract.

// ------------------------------------------------------------------ vocabulary of the records

/** `req_` plus 32 lowercase hex digits (UUIDv7); the first 12 digits are the millisecond clock. */
export type RequestId = string;

export type DecisionPath =
  | "bypass"
  | "fast_allow"
  | "cached_allow"
  | "jev_allow"
  | "jev_deny"
  | "jev_unavailable"
  | "no_session"
  | "body_not_inspectable"
  | "unknown_site";

export type Outcome = "allowed" | "blocked" | "would_block" | "unjudged";

/** Where the context came from: a session credential, or the client address (entry requests). */
export type ContextKind = "session" | "address";

export type SiteMode = "observe" | "enforce";
export type OnJevUnavailable = "deny" | "allow";

export type JevAccess = "ALLOW" | "DENY" | "UNKNOWN";
export type JevAttack = "BENIGN" | "ATTACK" | "UNKNOWN";
export type JevConclusion = "allow" | "deny" | "unknown";
export type JevRoute = "gateway" | "direct" | "custom";

export type JevFailure =
  | "JEV_TIMEOUT"
  | "JEV_RATE_LIMITED"
  | "JEV_TRANSPORT"
  | "JEV_HTTP_ERROR"
  | "JEV_RESPONSE_TOO_LARGE"
  | "JEV_RESPONSE_INVALID"
  | "JEV_UNKNOWN"
  | "JEV_STATE_TOO_LARGE"
  | "JEV_CALL_LIMIT";

export type ValueKind = "reference" | "route" | "input";

export type RefusedReason =
  | "unauthenticated"
  | "forbidden"
  | "body_not_inspectable"
  | "unknown_site";

export type UpstreamError =
  | "connect_refused"
  | "connect_timeout"
  | "read_timeout"
  | "tls"
  | "other";

export type ResponseSkip =
  | "status"
  | "content_type"
  | "compressed"
  | "too_large"
  | "head"
  | "not_forwarded";

// ------------------------------------------------------------------ request list (7.9.3)

/** The two answers a call produced, reduced to what the list needs. Null when the call failed. */
export interface JevSummary {
  access: JevAccess | null;
  attack: JevAttack | null;
  /** The smaller of the two top probabilities (0 to 1). */
  confidence: number | null;
  /** Round trip of the call, in milliseconds. */
  ms: number | null;
  failure: JevFailure | null;
}

// The interface name of a request (docs/console-design-objects-routes.md 4.1, 7; header-routes-design.md 2).
/** Read by a route rule: the segments joined with `/`, and where each one came from. */
export interface ApiName {
  /** e.g. `bus.buriedPointService/saveBuriedPointList`. */
  name: string;
  /** One entry per segment, e.g. `header.X-Service-Id`, `path`. */
  from: string[];
}

/** A route rule covered the path, but the name could not be read. Treated as an unknown interface. */
export interface ApiUnknown {
  /** Why the name could not be read; mapped to words in vocab. */
  unknown: UnknownApiReason;
  /** The source that went wrong, e.g. `header.X-Service-Method`; absent for `route_subpath`. */
  source?: string;
}

/** Reason codes agreed with the interface-name backend (8 codes; body encryption counts as `body_not_json`). */
export type UnknownApiReason =
  | "missing"
  | "repeated"
  | "conflict"
  | "invalid_name"
  | "body_unsupported"
  | "body_not_json"
  | "body_too_large"
  | "route_subpath";

export type ApiInfo = ApiName | ApiUnknown;

export interface RequestRow {
  /** Row number inside the log (cursor and live-mode ordering). */
  id: number;
  request_id: RequestId;
  at_millis: number;
  site: string | null;
  site_version: number | null;
  method: string;
  host: string;
  path: string;
  /** The path the rules judge: `path` plus the interface name, or `path` itself without a rule. */
  logical_path: string;
  /** Interface name from the site's route rules; null when no rule covers the path. */
  api: ApiInfo | null;
  /** Header names of the request, lowercase, no values, at most 64. */
  request_headers?: string[];
  /** Redacted query string, at most 2 KiB. */
  query: string | null;
  status: number | null;
  decision_path: DecisionPath;
  outcome: Outcome;
  /** 16-hex session label, or an empty string when there is no context. */
  session: string;
  context: ContextKind | null;
  client: string;
  total_ms: number | null;
  jev: JevSummary | null;
}

export interface RequestListResponse {
  rows: RequestRow[];
  next_cursor: string | null;
}

/**
 * `GET /api/requests/counts` (docs/07 7.9.3): the same filters as the list, counted in one pass for
 * the quick filter chips. Every count is over judged rows except `bypass` and `unknown_site`.
 * `scanned` is served only when `complete` is false: the scan stopped at the 2-million-row limit.
 */
export interface RequestCounts {
  judged: number;
  attention: number;
  blocked: number;
  would_block: number;
  unjudged: number;
  jev: number;
  no_session: number;
  bypass: number;
  unknown_site: number;
  complete: boolean;
  scanned?: number;
}

// ------------------------------------------------------------------ the trace (7.4.3)

export interface TraceSource {
  /** Field the origin showed the value under, e.g. `quantity`. */
  field: string;
  /** `METHOD /path` of the response that showed it. */
  request: string;
  /** Null for values learned before the gateway restarted. */
  request_id: RequestId | null;
  at_millis: number | null;
  /** Position key of the origin on the response side, e.g. `GET /api/appointments [].doc_id`. */
  slot?: string;
  /** Class of the origin value from the object map, e.g. `doctor`; absent when no confirmed entry applies. */
  object?: string;
  /** `map` when `object` comes from a confirmed object-map entry; absent when name inference was used. */
  object_from?: "map";
}

export interface TraceValue {
  /** Location: `path[2]`, `query.q`, `body.items[].id`. */
  at: string;
  /** The key the value travels under, when it has one. */
  key: string | null;
  /** Value text; `<redacted>` for secrets (the original length is in `len`). */
  value: string;
  kind: ValueKind;
  inert: boolean;
  seen: boolean;
  verified: boolean;
  sources: TraceSource[];
  /** Original length, kept for redacted and clipped values. */
  len?: number;
  /** The value was cut to 256 characters. */
  clipped?: boolean;
  /** Position key on the request side, e.g. `GET /doctor/{id} path[1]`. */
  slot?: string;
  /** Class of the value from the object map, e.g. `doctor`; absent when name inference was used. */
  object?: string;
  /** `map` when `object` comes from a confirmed object-map entry; absent otherwise. */
  object_from?: "map";
  /** Composite value (a split value, e.g. `body.who#2` in `body.who`): the parts, each checked on its own. Later PR. */
  parts?: TraceValue[];
  /** How this value was split into parts, e.g. `按 # 拆成 3 段`. Later PR. */
  format?: string;
}

export interface EntryPass {
  path: string;
  at_millis: number | null;
  request_id: RequestId | null;
}

export interface RecentAccess {
  method: string;
  path: string;
  status: number | null;
  request_id: RequestId | null;
  at_millis: number | null;
}

export interface TraceSession {
  age_seconds: number;
  known_values: number;
  /**
   * Up to 16, written for Jev records only (aligned with `state.session.entries_passed`). Absent on a
   * record that made no Jev call, such as a fast or cached allow (trace.rs `TraceSession`).
   */
  entries_passed?: EntryPass[];
  /**
   * Up to 10, written for Jev records only (aligned with the tail of `state.recent`). Absent on a record
   * that made no Jev call.
   */
  recent?: RecentAccess[];
}

export interface TraceTiming {
  total_ms: number | null;
  judge_ms: number | null;
  origin_ms: number | null;
}

export interface TraceResponse {
  content_type: string | null;
  bytes: number;
  observed: "json" | "html" | "skipped";
  skip: ResponseSkip | null;
  values: number;
  new_values: number;
  /** The 12 most frequent field names with their counts; never the values themselves. */
  fields: Array<{ field: string; count: number }>;
  /** Label of the session this response created (a login). */
  issued_session: string | null;
  /** The response made the session pass an entry for the first time. */
  entry_passed: boolean;
  /** The request was "would block" but forwarded, and its response was still learned (7.4.6). */
  after_would_block: boolean;
  /**
   * Response structure (field paths and types, never values). Present only when the route's
   * structure is first seen or changes; the object map learns from it (object-map design 3).
   */
  shape?: ResponseShapeField[];
}

export interface ResponseShapeField {
  /** e.g. `[].doc_id`. */
  path: string;
  type: "string" | "number" | "boolean" | "null";
}

/**
 * Everything the gateway wrote about why a request got its outcome. Stub records (bypass, 413,
 * unknown site) carry only a few of these fields, and records imported from the old format are
 * `{ v: 0 }`.
 */
export interface Trace {
  v: number;
  entry?: string | null;
  bypass?: string | null;
  refused?: RefusedReason | null;
  values_truncated?: boolean;
  values?: TraceValue[];
  session?: TraceSession | null;
  cache_source?: RequestId | null;
  timing?: TraceTiming;
  response?: TraceResponse;
  upstream_error?: UpstreamError | null;
  /** The trace was cut to its 16 KiB limit. */
  trimmed?: boolean;
}

// ------------------------------------------------------------------ Jev exchange (7.5.1)

export type AccessProbabilities = Partial<Record<JevAccess, number>>;
export type AttackProbabilities = Partial<Record<JevAttack, number>>;

export interface JevRecord {
  /** The exact `state` text sent to Jev (redacted, at most 8 KiB). Null when no call was made. */
  state: string | null;
  /** Instruction version, `jq_` plus 16 hex digits; the text is at `/api/jev/prompts/{id}`. */
  prompt: string;
  model: string;
  route: JevRoute;
  /** Timeout this call actually used (site setting or deployment default). */
  timeout_ms: number;
  /** Trim level 0 to 4 (7.5.3). */
  trim: number;
  request_bytes: number | null;
  http_status: number | null;
  /** Raw provider response, at most 8 KiB; null on timeout and connection failure. */
  response: string | null;
  usage: Record<string, unknown> | null;
  access: AccessProbabilities | null;
  attack: AttackProbabilities | null;
  conclusion: JevConclusion | null;
  millis: number | null;
  failure: JevFailure | null;
}

/** The Jev request document as parsed from `JevRecord.state` (docs/02 2.2). */
export interface JevStateValue {
  at: string;
  kind?: ValueKind;
  /** Class from the object map (`object`); a value shown only as another class is judged against it (object-map design 2). */
  object?: string;
  value: string;
  seen_as: string[];
  verified?: boolean;
}

export interface JevState {
  entry: { matched: boolean };
  session: { age_seconds: number; entries_passed: string[] };
  recent: Array<{ method: string; path: string; status: number | null }>;
  request: {
    method: string;
    path: string;
    values: JevStateValue[];
    truncated?: boolean;
  };
}

export interface PromptQuestion {
  type: "choice";
  instructions: string;
  /** Option name to its meaning. */
  criteria: Record<string, string>;
}

/** `GET /api/jev/prompts/{id}` */
export interface JevPrompt {
  id: string;
  first_seen: string;
  questions: { access: PromptQuestion; attack: PromptQuestion };
  /** Calls inside the retention window that used this version, when the server counts them. */
  calls?: number;
}

// ------------------------------------------------------------------ request detail (7.9.4)

export interface SourceSummary {
  method: string;
  path: string;
  status: number | null;
  decision_path: DecisionPath;
  at_millis: number;
}

export interface RequestDetail {
  summary: RequestRow;
  /** Gateway instance that handled the request. */
  edge: string;
  trace: Trace;
  jev: JevRecord | null;
  /** Previous and next request of the same session. */
  neighbors: { prev: RequestId | null; next: RequestId | null };
  /** Summaries of every request id the trace links to; ids past retention are missing. */
  sources: Record<RequestId, SourceSummary>;
}

// ------------------------------------------------------------------ batch lookup (7.9.5)

export interface LookupRow {
  request_id: RequestId;
  found: boolean;
  summary?: RequestRow;
}

export interface LookupResponse {
  rows: LookupRow[];
}

// ------------------------------------------------------------------ statistics

export interface StatsSummary {
  since_millis: number;
  until_millis: number;
  /** Decided requests, without bypass and unknown-site stubs. */
  judged: number;
  blocked: number;
  would_block: number;
  unjudged: number;
  jev_calls: number;
  jev_timeouts: number;
  jev_p95_ms: number | null;
  /** The same figures for the equally long window before this one, when available. */
  previous: {
    judged: number;
    blocked: number;
    would_block: number;
    unjudged: number;
    jev_calls: number;
    jev_p95_ms: number | null;
  } | null;
  /** Twelve evenly spaced points per figure for the mini trend. */
  spark: {
    judged: number[];
    blocked: number[];
    would_block: number[];
    unjudged: number[];
    jev_calls: number[];
    jev_p95_ms: number[];
  };
  complete: boolean;
  /** Rows the scan read. Served only when `complete` is false (docs/07 section 7.9.1). */
  scanned?: number;
}

export interface TimeseriesBucket {
  at_millis: number;
  /** Request count by decision path inside the bucket. */
  counts: Partial<Record<DecisionPath, number>>;
}

export interface Timeseries {
  bucket_ms: number;
  since_millis: number;
  until_millis: number;
  buckets: TimeseriesBucket[];
  complete: boolean;
  /** Rows the scan read. Served only when `complete` is false (docs/07 section 7.9.1). */
  scanned?: number;
}

// ------------------------------------------------------------------ sessions (7.9.6)

export interface SessionRow {
  label: string;
  context: ContextKind;
  site: string | null;
  first_at_millis: number;
  last_at_millis: number;
  requests: number;
  jev_calls: number;
  blocked: number;
  would_block: number;
  /** Request that created the session (a login), when it is inside the retention window. */
  issued_by: RequestId | null;
}

export interface SessionListResponse {
  rows: SessionRow[];
}

export interface TimelineRow extends RequestRow {
  /** New values the response taught the session (`trace.response.new_values`). */
  learned: number | null;
  entry_passed: boolean;
  issued_session: string | null;
  after_would_block: boolean;
}

export interface SessionTimeline {
  summary: SessionRow;
  rows: TimelineRow[];
  next_cursor: string | null;
}

// ------------------------------------------------------------------ Jev status and statistics (7.9.7)

export type JevHealth = "ok" | "idle" | "degraded" | "down";

export interface JevStatus {
  health: JevHealth;
  window_minutes: number;
  calls: number;
  ok: number;
  failures: Partial<Record<JevFailure, number>>;
  p50_ms: number | null;
  p95_ms: number | null;
  last_ok_at: string | null;
  last_failure: { at: string; failure: JevFailure; site: string | null } | null;
  config: JevConfig | null;
}

export interface JevConfig {
  route: JevRoute;
  endpoint_host: string;
  model: string;
  default_timeout_ms: number;
  prompt: string;
  /** Where the instance's Jev configuration comes from (design agent-model-ui 2.1). Absent before models existed. */
  config_source?: ModelSource;
  /** The console version the instance runs; null when it runs the environment's configuration. */
  config_version?: number | null;
  /** A stable error code when the instance refused the console version it was sent. */
  config_error?: string | null;
}

export interface JevStats {
  since_millis: number;
  until_millis: number;
  calls: number;
  by_conclusion: Partial<Record<JevConclusion, number>>;
  by_failure: Partial<Record<JevFailure, number>>;
  p50_ms: number | null;
  p95_ms: number | null;
  /** Calls per 100 ms bucket, up to and including the timeout bucket. */
  latency_histogram: { bucket_ms: number; counts: number[]; timeout_ms: number };
  /** Calls per 0.1 confidence bucket (ten entries). */
  confidence_histogram: { counts: number[] };
  /**
   * Calls per hour for the stacked bars of the Jev page (docs/06 6.4.6). `allow` and `deny` count
   * the calls Jev answered ALLOW or DENY. `unavailable` is every other call: a timeout, an error,
   * an exhausted call limit, or an UNKNOWN answer, so allow + deny + unavailable equals the calls.
   * Added for the console v4 page; the gateway side fills it from the same window.
   */
  hourly: Array<{ at_millis: number; allow: number; deny: number; unavailable: number }>;
  complete: boolean;
}

// ------------------------------------------------------------------ site configuration

export interface SessionCredential {
  cookie?: string;
  header?: string;
}

/** Per-site overrides of the judging parameters (docs/07 7.6.1). Every field is optional. */
export interface Advanced {
  jev_timeout_ms?: number;
  session_calls_per_minute?: number;
  address_calls_per_minute?: number;
  allow_cache_minutes?: number;
  secret_fields?: string[];
  synonyms?: Array<[string, string]>;
  /** Field kinds declared by hand: the kind of object a field or parameter holds (field-kinds design 3). */
  field_kinds?: FieldKindDeclaration[];
}

/** Route rule (接口名规则, header-routes-design 2): the interface name sits outside the URL path. */
export interface RouteRule {
  /** Exact path, or a prefix ending in `*` (the same syntax as entries and bypass); never ends with `/`. */
  path: string;
  /** One group per segment of the name, joined with `/`. Every location in a group must agree (or the name is unknown). */
  name_from: string[][];
}

/** Object map settings (object-map design 1, 3.5; the console's settings sheet). Shape to be confirmed by the backend. */
export interface LearningSettings {
  /** Off: only hand-declared and confirmed slots apply. */
  auto_learn: boolean;
  /** Tightening changes apply on their own; off sends them to the proposal queue too. */
  auto_tighten: boolean;
  /** Ask the agent about slots the rules cannot decide, with a daily cap. */
  agent: { enabled: boolean; daily_limit: number };
  /** A slot must reach `uses` requests from `sessions` sessions before it is learned. */
  thresholds: { uses: number; sessions: number };
  /** Confirmed slots that turn abnormal are paused automatically. */
  auto_pause: boolean;
}

/** Hand declaration of a field's class (field-kinds design 3; the object map's manual entry). */
export interface FieldKindDeclaration {
  /** Field or parameter name; case and `_`, `-` are ignored when matching. */
  field: string;
  /** Class id, e.g. `doctor`. */
  kind: string;
  /** Path patterns the declaration is limited to; omitted means the whole site. */
  in?: string[];
}

/** A class of the object map (`objects.classes`): its id and the name the console shows. */
export interface ObjectClassEntry {
  id: string;
  name: string;
  description?: string;
}

/**
 * A confirmed position (`objects.slots`): the class the judge uses for it. The learning task sets `paused` when it
 * pauses the position: the judge stops using the class, and a save keeps the flag. A confirmation writes a plain entry
 * without it, which restores the position (console design 4.3, 6 C1).
 */
export interface ObjectSlotEntry {
  key: string;
  class: string;
  source: ObjectSource;
  paused?: boolean;
}

/**
 * The object map section (object-map design 1). The learning settings, the classes and the confirmed positions are
 * written by the console: a save writes what the draft holds (console design 4.3).
 */
export interface ObjectsSpec {
  learning?: LearningSettings;
  classes?: ObjectClassEntry[];
  slots?: ObjectSlotEntry[];
}

export interface SiteSpec {
  name: string;
  hosts: string[];
  origin: string;
  session: SessionCredential;
  entries: string[];
  bypass?: string[];
  mode?: SiteMode;
  on_jev_unavailable?: OnJevUnavailable;
  advanced?: Advanced;
  /** Route rules, in order; the first matching rule names the request (header-routes-design 2). */
  routes?: RouteRule[];
  /** Object map settings (object-map design 1). Hand-declared field kinds are in `advanced.field_kinds`. */
  objects?: ObjectsSpec;
}

export interface EdgeLoad {
  edge: string;
  /** Version the instance has loaded, null while it has none. */
  version: number | null;
  /** Error code when the instance rejected the site (e.g. SITE_CONFIG_ORIGIN_INVALID). */
  error: string | null;
  loaded_at_millis: number | null;
}

export interface SiteSummary {
  name: string;
  hosts: string[];
  origin: string;
  mode: SiteMode;
  version: number;
  updated_at: string;
  /** When the site was created or last switched to observe mode; null in enforce mode. */
  observing_since_millis: number | null;
  /** Lowest version loaded by the online gateways, null when none has loaded the site. */
  loaded_version: number | null;
  edges: EdgeLoad[];
  /** How far the online gateways have loaded `version` (docs/07 7.9.13). */
  rollout: Rollout;
  requests_24h: number;
  blocked_24h: number;
  would_block_24h: number;
  jev_calls_24h: number;
  /** Requests forwarded without a judgement in the last 24 hours (docs/07 7.9.13). */
  unjudged_24h: number;
  /** Jev calls that timed out in the last 24 hours. */
  jev_timeouts_24h: number;
  /** Jev calls refused by the per-session call limit in the last 24 hours. */
  call_limits_24h: number;
  suggestions: number;
}

export interface SiteListResponse {
  sites: SiteSummary[];
}

export interface SiteDetail extends SiteSummary {
  spec: SiteSpec;
  created_at: string;
}

/** `auto_tighten` and `auto_pause` are written by the learning task and can be undone (docs 5). */
export type ChangeKind =
  | "create"
  | "update"
  | "rollback"
  | "delete"
  | "import"
  | "auto_tighten"
  | "auto_pause";

export interface SiteVersion {
  version: number;
  change: ChangeKind;
  rollback_of: number | null;
  note: string | null;
  changed_at: string;
  /** Full configuration after the change; null for a delete. */
  spec: SiteSpec | null;
}

export interface SiteVersionsResponse {
  versions: SiteVersion[];
}

export interface SiteWriteBody {
  spec: SiteSpec;
  /** Required on update; the server answers 409 VERSION_CONFLICT when it is stale. */
  expected_version?: number;
  note?: string;
  /** The automatic change this save undoes or re-confirms (console design 6 A3). */
  object_event?: string;
}

export interface SiteRollbackBody {
  to_version: number;
  expected_version: number;
  note?: string;
}

export type ValidateResult = { valid: true } | { valid: false; error: string; field?: string };

// ------------------------------------------------------------------ impact preview (7.9.10)

export type ImpactKind =
  | "no_session_to_entry"
  | "entry_to_no_session"
  | "judged_to_bypass"
  | "bypass_to_judged"
  | "would_block_to_blocked"
  | "blocked_to_would_block"
  | "jev_timeout"
  | "call_limit"
  | "cache"
  | "secret_fields"
  | "api_split"
  | "entry_unreachable"
  | "new_fast_allow"
  | "back_to_jev"
  | "cache_by_api";

export interface ImpactChange {
  kind: ImpactKind;
  count: number;
  /** Requests among `count` that were "would block" (judged_to_bypass, bypass_to_judged). */
  would_block?: number;
  /** Method, path and count of the biggest contributors. */
  top?: Array<[string, string, number]>;
  sample?: RequestId;
  detail?: Record<string, unknown>;
}

export type ImpactWarning =
  | "SESSION_CHANGED"
  | "HOSTS_CHANGED"
  | "SYNONYMS_CHANGED"
  | "CACHE_RAISED"
  | "INTERFACE_UNVERIFIED";

export interface ImpactPreview {
  window_hours: number;
  rows: number;
  groups: number;
  complete: boolean;
  changes: ImpactChange[];
  /** 24 h hits of every entry and bypass rule of the draft. */
  patterns: { entries: Record<string, number>; bypass: Record<string, number> };
  warnings: ImpactWarning[];
}

// ------------------------------------------------------------------ insights (7.9.11)

export type SuggestionKind =
  | "entry_candidate"
  | "bypass_candidate"
  | "upload_candidate"
  | "raise_jev_timeout"
  | "raise_call_limit"
  | "secret_field_candidate"
  | "hot_would_block"
  | "object_proposals"
  | "route_rule_candidate";

/** A change to the configuration that applying a suggestion makes. */
export interface SuggestionAction {
  /** `exact` or `prefix` options of the same suggestion. */
  label?: "exact" | "prefix";
  add_entry?: string;
  add_bypass?: string;
  add_secret_field?: string;
  /** Route rule to add (`route_rule_candidate`, docs 5). */
  add_route?: RouteRule;
  set_advanced?: Advanced;
  /** Requests of the window this rule would match. */
  matches?: number;
}

export interface Suggestion {
  id: string;
  kind: SuggestionKind;
  method: string | null;
  path: string | null;
  count: number;
  /** Example request. */
  sample: RequestId | null;
  /** One or more alternatives; empty for `hot_would_block`. */
  actions: SuggestionAction[];
  reason: string;
  /**
   * Figures the card of `object_proposals` and `route_rule_candidate` can show (the console falls back to the
   * count alone when they are absent). Same shape as `ImpactChange.detail`.
   */
  detail?: Record<string, unknown>;
}

export interface Readiness {
  observing_since_millis: number | null;
  /** "Would block" requests of the window by decision path. */
  would_block: Partial<Record<DecisionPath, number>>;
  open_suggestions: number;
  jev_health: JevHealth;
  jev_p95_ms: number | null;
  jev_timeout_ratio: number | null;
  /** Requests that cited a value learned from a "would block" response (7.4.6). */
  after_would_block_refs: number;
  on_jev_unavailable: OnJevUnavailable;
}

export interface Insights {
  window_hours: number;
  suggestions: Suggestion[];
  readiness: Readiness | null;
  complete: boolean;
}

export interface Evidence {
  window_hours: number;
  jev: {
    calls: number;
    p50_ms: number | null;
    p95_ms: number | null;
    p99_ms: number | null;
    timeouts: number;
    timeout_ms_used: number;
  };
  call_limit: {
    session_peak: number;
    address_peak: number;
    session_hits: number;
    address_hits: number;
  };
  cache: { cached_allows: number };
  /** Jev latency, calls per 100 ms bucket. */
  histogram: number[];
  histogram_bucket_ms: number;
}

// ------------------------------------------------------------------ system (7.9.8)

export interface EdgeStatus {
  edge: string;
  online: boolean;
  started_at: string;
  seen_at: string;
  build: string;
  listen: string;
  tls: boolean;
  sessions: number;
  queue: number;
  written: number;
  dropped: number;
  /** Bypass rows dropped under queue pressure (docs/07 7.7.4). */
  dropped_bypass: number;
  write_errors: number;
  /** Loss history: merged minutes with lost records, the newest 50 (docs/07 7.7.4). */
  gaps: LogGap[];
  /** Per site: the version it loaded, or the error code that made it refuse the site. */
  sites: Record<string, { version?: number; error?: string; loaded_at_millis?: number }>;
  jev: JevConfig;
}

export interface Partition {
  name: string;
  rows: number;
  bytes: number;
}

/** One loss window of a gateway: consecutive minutes with lost records, merged (docs/07 7.7.4). */
export interface LogGap {
  from_ms: number;
  to_ms: number;
  dropped: number;
  dropped_bypass: number;
  write_errors: number;
}

export interface FixedParams {
  seen_max: number;
  sources_max: number;
  recent_max: number;
  idle_hours: number;
  sessions_max: number;
  long_value_chars: number;
  state_bytes_max: number;
  request_body_max: number;
  response_parse_max: number;
  request_values_max: number;
}

export interface SystemInfo {
  control_build: string;
  postgres: string;
  edges: EdgeStatus[];
  storage: {
    retention_days: number;
    earliest_millis: number | null;
    partitions: Partition[];
  };
  params: {
    site_overridable: Required<
      Pick<
        Advanced,
        | "jev_timeout_ms"
        | "session_calls_per_minute"
        | "address_calls_per_minute"
        | "allow_cache_minutes"
      >
    > & {
      secret_fields: string[];
      synonyms: Array<[string, string]>;
    };
    fixed: FixedParams;
  };
}

// ------------------------------------------------------------------ models (系统 · 模型; design agent-model-ui 2, 5.1)

/** Which configuration is in use: the console's saved version, or the environment the gateways read. */
export type ModelSource = "console" | "env";
/** The learning agent's provider: the Vercel AI Gateway (OpenAI-compatible) or any OpenAI-compatible address. */
export type AgentProvider = "gateway" | "custom";
/** A failure code of a call or a test: a JEV_* code, or `dns`, `tls`, `answer_invalid` (design 7). */
export type ModelFailure = string;
export type ModelKind = "jev" | "agent";

/** The key is write-only: the API says whether one is set, its last four characters and when it changed. */
export interface ModelKey {
  set: boolean;
  last4: string | null;
  updated_at: string | null;
  /** The learning agent uses Jev's key. Always false for the Jev group. */
  shared_with_jev: boolean;
}

/** One online gateway and the Jev configuration it loaded. Only online gateways are listed. */
export interface ModelLoad {
  edge: string;
  online: boolean;
  /** `console` or `env`; null while the gateway has nothing loaded. */
  source: ModelSource | null;
  /** The console version the gateway runs; null for the environment or when nothing is loaded. */
  version: number | null;
  /** A stable error code when the gateway refused the version it was sent (e.g. the key cannot be read). */
  error: string | null;
}

/** The Jev values a form sends. A preset route takes its address and model from the route. */
export interface JevModelValues {
  route: JevRoute;
  endpoint: string | null;
  model: string | null;
  timeout_ms: number;
}

/** The learning agent's values a form sends. */
export interface AgentModelValues {
  provider: AgentProvider;
  endpoint: string;
  model: string | null;
  timeout_ms: number;
  share_key_with_jev: boolean;
}

export type ModelValues = JevModelValues | AgentModelValues;

/** The Jev group. Fields that need a gateway or a saved version are null while nothing provides them. */
export interface JevModelsState {
  /** A key is in place: saved in the console, or in the environment of an online gateway. */
  configured: boolean;
  /** `console` while the console holds a configuration, `env` while the gateways read the environment, null when neither. */
  source: ModelSource | null;
  /** The console's version counter: 0 before the first save. It keeps its number when the environment takes over. */
  version: number;
  /** When the last version was saved. */
  updated_at: string | null;
  /** The saved route, or the one an online gateway reports from its environment. */
  route: JevRoute | null;
  /** The saved address; null for a preset route, or while the gateways read their environment. */
  endpoint: string | null;
  /** The host an online gateway reports, given while the gateways read their environment. */
  endpoint_host: string | null;
  model: string | null;
  timeout_ms: number | null;
  key: ModelKey;
  /** The environment variable the gateways read the key from, by name only. */
  key_env: string | null;
  /** Whether an online gateway's environment holds a usable configuration. */
  env_available: boolean;
  /** Environment variables that the console configuration overrides (names only, never values). */
  env_overridden: string[];
  loaded: ModelLoad[];
  impact: {
    /** Every site: all of them judge through Jev. */
    sites: number;
    /** Sites in enforce mode whose requests are refused when Jev fails. */
    fail_closed: string[];
  };
  /** The Jev calls of the health window. */
  usage: { window_minutes: number; calls: number; failed: number; p95_ms: number | null };
}

/** The learning agent's group. */
export interface AgentModelsState extends AgentModelValues {
  configured: boolean;
  /** `console` once something has been saved; null before that. */
  source: "console" | null;
  /** The console's version counter: 0 before the first save. */
  version: number;
  updated_at: string | null;
  key: ModelKey;
}

/** `GET /api/system/models`. */
export interface ModelsState {
  jev: JevModelsState;
  agent: AgentModelsState;
}

/** A save's answer: the group and the version it now has. The page reads the group again for the rest. */
export interface SavedModel {
  group: ModelKind;
  version: number;
}

/** A save: the form's values, the key only when it is replaced, and the version the form was read at. */
export type ModelWrite<V extends ModelValues> = V & {
  /** Omitted or null keeps the saved key; a string replaces it. */
  key?: string | null;
  /** The version the page was read at: 0 before the first save. */
  expected_version: number;
  /** Empty means no note. */
  note: string;
  /** Whether this exact configuration tested successfully before it was saved. Recorded, not enforced. */
  tested: boolean;
};

/** A test: the form's values; without a key, the saved one is used. */
export type ModelTestBody = Partial<ModelValues> & { key?: string | null };

/** The outcome of a test call. The server keeps no time for it; the page records when the answer arrived. */
export interface ModelTestResult {
  ok: boolean;
  latency_ms: number;
  /** The HTTP status the model service answered with; null when it did not answer. */
  status: number | null;
  failure: ModelFailure | null;
  /** The start of the error body the model service returned: at most 300 characters, untrusted text. */
  detail: string | null;
  answer_valid: boolean | null;
  /** A short reason made by the server when the answer did not parse. It is not model output. */
  answer_reason: string | null;
}

/** One changed field of a saved version. Values are the strings the history keeps; a key shows its last four. */
export interface ModelChange {
  field: string;
  old: string;
  new: string;
}

/** One saved version as the API sends it, newest first. Every value of `config` is text (the core's values()). */
export interface ModelVersionWire {
  version: number;
  at: string | null;
  /** `save`, or `revert_to_env` for the Jev group given back to the environment. */
  change: "save" | "revert_to_env";
  /** The settings of that version, without the key. Values are text: "2000", "false". */
  config: Record<string, string>;
  changes: ModelChange[];
  /** Null when the note is empty. */
  note: string | null;
  tested: boolean;
  /** `replaced`, `cleared`, or null when the key was kept. The page reads the key change from `changes`. */
  key_change?: string | null;
  /** The last four characters of a key this version set; null when it set none. */
  key_last4?: string | null;
}

/** One saved version as the page holds it: `config` read back into the types of the form (lib/model-form.ts). */
export interface ModelVersion extends Omit<ModelVersionWire, "config"> {
  config: ModelValues;
}

// ------------------------------------------------------------------ import (7.9.9)

export interface ImportResult {
  imported: number;
  skipped: number;
  errors: number;
  /** Line numbers of the first 20 rows that could not be read. */
  error_lines: number[];
  /** Rows dated outside the stored window (docs/07 7.9.9): not stored and not counted as errors. */
  out_of_range?: number;
}

// ------------------------------------------------------------------ errors and session

export interface ApiErrorBody {
  error: string;
  field?: string;
  current_version?: number;
}

export interface SessionState {
  authenticated: boolean;
}

/** Query parameters of `GET /api/requests`, `/counts` and `/export` (7.9.3). */
export interface RequestFilters {
  site?: string;
  since_millis?: number;
  until_millis?: number;
  outcome?: string;
  decision_path?: string;
  method?: string;
  status?: string;
  /** Matches the logical path (`path:` in the filter bar); without route rules it is the URL path. */
  path?: string;
  /** Case-sensitive substring of the interface name (`api:`). */
  api?: string;
  /** Requests whose interface name could not be read: a reason code, or `any` (`api:unknown`). */
  api_unknown?: UnknownApiReason | "any";
  /** Requests with a value of this object class (`object:`). */
  object?: string;
  session?: string;
  client?: string;
  request_id?: string;
  jev_access?: string;
  jev_attack?: string;
  jev_failure?: string;
  max_confidence?: number;
  min_ms?: number;
  site_version?: number;
  entry?: "true" | "false";
  /** Rows that carry a Jev exchange only (the Jev calls page). */
  has_jev?: "true";
  jev_trimmed?: "true" | "false";
  min_jev_ms?: number;
  /** `all` also returns bypass and unknown-site rows; the default leaves them out (7.9.3). */
  scope?: "all";
  cursor?: string;
  limit?: number;
}

// ------------------------------------------------------------------ Status and rollout (7.9.13)

export type GatewayLight = "ok" | "warn" | "down";

/** One line of the gateway problem list. `kind` says what is wrong; the other fields say where. */
export type GatewayProblem =
  | { kind: "site_load_failed"; edge: string; site: string; error: string }
  | {
      kind: "version_behind";
      edge: string;
      site: string;
      expected: number;
      loaded: number;
      saved_at_millis: number;
    }
  | {
      kind: "log_gap";
      edge: string;
      from_ms: number;
      to_ms: number;
      dropped: number;
      dropped_bypass: number;
      write_errors: number;
    }
  | { kind: "queue_pressure"; edge: string; queue: number; capacity: number }
  | { kind: "partition_missing"; days_ahead: number }
  | { kind: "heartbeat_late"; edge: string }
  | {
      kind: "jev_config_not_loaded";
      edge: string;
      /** The console version the gateway should run. */
      wanted: number;
      /** The version it runs; null when it runs none from the console. */
      loaded: number | null;
      error: string | null;
      saved_at_millis: number;
    }
  | { kind: "edge_offline"; edge: string; last_seen_ms: number; loaded: Record<string, number> };

/** GET /api/status: the top bar lights and the overview's attention list (every 15 seconds). */
export interface StatusResponse {
  gateway: {
    light: GatewayLight;
    /** `total` counts every instance that sent a heartbeat in the last day; `online` those in the last 30 s. */
    edges: { online: number; total: number };
    problems: GatewayProblem[];
  };
  jev: Omit<JevStatus, "config">;
}

export interface EdgeRollout {
  edge: string;
  online: boolean;
  loaded_version: number | null;
  /** An error code (for example SITE_CONFIG_ORIGIN_INVALID), or null. */
  error: string | null;
}

/** How far the online gateways have loaded a site's current version (docs/07 7.9.13). */
export interface Rollout {
  version: number;
  edges_online: number;
  edges_loaded: number;
  edges: EdgeRollout[];
}

// ------------------------------------------------------------------ 对象表（接口）
// The objects endpoints (console design 6). Times follow the file's rule: RFC 3339 UTC strings, and `*_millis` for
// Unix milliseconds. The shapes follow console design 6; a field the backend has not shipped yet is still typed here,
// and the backend's batches say which endpoint starts to fill it.

/** Learning state of a position (object-map design 1). */
export type ObjectState =
  | "pending"
  | "proposed"
  | "confirmed"
  | "ambiguous"
  | "suspended"
  | "retired";

/** Where a class or a position's class came from: a hand declaration, a rule, or the agent. */
export type ObjectSource = "admin" | "rule" | "agent";

/** The side of a request a position sits on. */
export type ObjectSide = "request" | "response";

/** Query of `GET /api/sites/{name}/objects`; the server filters the slots and counts the whole map. */
export type ObjectsFilter = {
  state?: ObjectState;
  class?: string;
  q?: string;
};

export interface ObjectCounts {
  classes: number;
  pending: number;
  proposed: number;
  confirmed: number;
  ambiguous: number;
  suspended: number;
}

export interface ObjectClass {
  /** Stable id, e.g. `doctor`; a rename changes the name only. */
  id: string;
  name: string;
  description: string;
  origin: ObjectSource;
  /** Sibling fields the class is usually seen with, e.g. `name`, `title`. */
  fields: string[];
  slot_count: number;
  uses_24h: number;
  /** Route templates the class is used in, e.g. `/doctor/{id}`. */
  routes: string[];
  /** Positions of the class that are paused; the class list marks them with ▲ (console design 3.2). Read as 0 when absent. */
  suspended_count?: number;
}

/** The name rule that named a class from a position: the same words the judge uses (console design 6 B). */
export type NameReasonCode = "field_name" | "parent_name" | "endpoint_name" | "route_word";

/** The evidence of an automatic change or a pause (console design 6 C2). Only the fields its code names are set. */
export type ObjectReasonCode = "evidence_drift" | "origin_4xx_rise" | "jev_deny_rise" | "split";

export interface ObjectReason {
  code: ObjectReasonCode;
  /** The days of evidence the reason counts over. Each field the gateway does not send is absent, not null. */
  days?: number | null;
  /** Before and after the change: shares from 0 to 1 for evidence drift, counts for the others. */
  before?: number | null;
  after?: number | null;
  /** The status counted by origin_4xx_rise: 403 or 404. */
  status?: number | null;
  total?: number | null;
  hits?: number | null;
  /** The position the evidence moved to, and the one it was before (evidence drift). */
  key?: string | null;
  key_before?: string | null;
  /** The two classes a split took apart. */
  classes?: string[] | null;
}

/** One row of the position table. */
export interface ObjectSlotRow {
  id: string;
  side: ObjectSide;
  /** The position, e.g. `GET /api/appointments [].doc_id` or `GET /doctor/{id} path[1]`. */
  key: string;
  /** Class id, or null while the position has none. */
  class: string | null;
  state: ObjectState;
  source: ObjectSource;
  /** One line of evidence, e.g. `流向 87% · 23 会话 · 0 拒绝`. */
  basis: string;
  /** RFC 3339 UTC, or null when the position was never seen. */
  last_seen: string | null;
  /** The proposal was ignored: the position stays listed, and the learning task does not propose it again. */
  dismissed: boolean;
  /** Whether the saved configuration still has this position's entry, so the judge still uses it (console design 6 D). */
  in_effect: boolean;
  /** Only while the position is suspended (state `suspended`); null otherwise. */
  suspension: ObjectSuspension | null;
}

/** Why a position is paused, and what the judge does with it now (console design 3.2, 6 D). */
export interface ObjectSuspension {
  /** RFC 3339 UTC: when it was paused. */
  at: string;
  /** Paused by the learning task (true) or by an administrator (false). */
  auto: boolean;
  version: number | null;
  event_id: string | null;
  reason: ObjectReason | null;
  /** The confirmed entry before the pause. */
  previous: {
    class: string | null;
    source: ObjectSource;
    confirmed_at: string | null;
    confirmed_by: string | null;
  } | null;
  /** What name inference gives now. `kind` is null and `basis` `none` when no name is left. */
  fallback: { kind: string | null; basis: NameReasonCode | "none"; word: string | null };
  /** The classes the position's values belong to now, by share (0 to 1). */
  evidence_now: Array<{ class: string; share: number }>;
  acknowledged: boolean;
}

/** A position's entry in the configuration: a field declaration (`advanced.field_kinds`) or an object slot. */
export type ObjectConfigEntry = FieldKindDeclaration | ObjectSlotEntry;

export type ObjectEventKind = "auto_tighten" | "auto_pause" | "anomaly";

export type ObjectEventStatus = "open" | "acknowledged" | "undone" | "superseded";

/** One automatic change or anomaly of the learning task (console design 2.3, 6 C2). */
export interface ObjectEvent {
  id: string;
  kind: ObjectEventKind;
  /** RFC 3339 UTC: the learning pass that made it. */
  at: string;
  /** The version the change made; null for an anomaly, which changes nothing. */
  version: number | null;
  slot_id: string | null;
  key: string;
  side: ObjectSide;
  /** The class and the entry before the change; null when there was none. */
  before: { class: string | null; entry: ObjectConfigEntry | null } | null;
  /** The class and the entry after the change. A pause keeps its entry, which then carries `paused: true`. */
  after: { class: string | null; entry: ObjectConfigEntry | null } | null;
  reason: ObjectReason | null;
  impact: ImpactChange[];
  /** Sample request ids, at most three. */
  examples: RequestId[];
  status: ObjectEventStatus;
  handled: { by: string; at: string; version: number | null } | null;
  /** The note of the version the change made, as the history shows it. */
  note: string | null;
}

/** `GET /api/sites/{name}/objects/events`: the events of the window, newest first. */
export interface ObjectEventsResponse {
  events: ObjectEvent[];
}

/** Query of `GET /api/sites/{name}/objects/events`: open or all events, one kind, and the days they span. */
export type ObjectEventsFilter = {
  status?: "open" | "all";
  kind?: ObjectEventKind;
  days?: number;
};

/** What the gateway runs now, so the console says what is in effect; a false flag is a part it does not run yet. */
export interface ObjectFeatures {
  auto_tighten: boolean;
  auto_pause: boolean;
  path_confirm: boolean;
}

/** When the learning task last ran, and how often it tightened or paused in the last 7 days. */
export interface LearningStatus {
  last_pass_at: string | null;
  auto_tighten_7d: number;
  auto_pause_7d: number;
}

/** `GET /api/sites/{name}/objects`: counts of the whole map, the classes, and the slots the filter matches. */
export interface ObjectsResponse {
  counts: ObjectCounts;
  /** False when no model is configured: the agent switch of the learning settings is then greyed out. */
  agent_configured: boolean;
  classes: ObjectClass[];
  slots: ObjectSlotRow[];
  /** The automatic changes of the last 30 days, newest first; the banner and the list show the open ones. */
  events: ObjectEvent[];
  features: ObjectFeatures;
  learning_status: LearningStatus;
}

/** Where a position's values travel: the other end of each flow, with its share and evidence. */
export interface ObjectFlow {
  /** The position at the other end, e.g. `GET /doctor/{id} path[1]`. */
  key: string;
  side: ObjectSide;
  /** Share of the position's uses that go this way, 0 to 1. */
  share: number;
  uses: number;
  sessions: number;
  jev_allow: number;
  jev_deny: number;
  /** Method and route template at the other end, for the link to the request list. */
  method: string;
  route: string;
}

/** A composite value split into parts (later PR; the section shows only when present). */
export interface ObjectFormat {
  /** e.g. `按 # 拆成 3 段（98% 的值符合）`. */
  summary: string;
  /** One line per part. */
  parts: string[];
  /** What happens to values that do not fit, e.g. `不符合格式的 2% 整体交给 Jev`. */
  rest: string | null;
}

/** The agent's conclusion for a position; its reason is model output and is rendered as text only. */
export interface ObjectAgentVerdict {
  /** A class id, `new` or `ambiguous`. */
  choice: string;
  /** 0 to 1. */
  confidence: number;
  /** The evidence the verdict cites, e.g. `f1`, `endpoint_shape`. */
  cites: string[];
  reason: string;
}

export interface ObjectHistoryEntry {
  /** RFC 3339 UTC. */
  at: string;
  /** e.g. `规则提议`, `证据更新`. */
  text: string;
}

/** `GET /api/sites/{name}/objects/slots/{id}`: the drawer of one position. Never contains values. */
export interface ObjectSlotDetail extends ObjectSlotRow {
  /** Flows of the values: request positions for a response position, response positions for a request one. */
  flows_in: ObjectFlow[];
  /** Sample request ids, at most three. */
  examples: RequestId[];
  /** Response structure: field paths and types only. */
  shape: ResponseShapeField[];
  /** Only when the position takes a composite value (later PR). */
  format?: ObjectFormat;
  /** Only when the class depends on a condition (later PR), e.g. `由 query.by 决定：id 为患者`. */
  condition?: string;
  /** Only when the agent was asked about this position. */
  agent?: ObjectAgentVerdict;
  history: ObjectHistoryEntry[];
  /** Effects of confirming the proposal, in the impact preview's shape. */
  impact: ImpactChange[];
}

/** A candidate of the cold start: one named position and the class the rules read from it (console design 6 B). */
export interface BootstrapCandidate {
  /** Stable within one response. */
  id: string;
  /** Position key, e.g. `GET /doctor/{id} path[1]`. */
  key: string;
  side: ObjectSide;
  /** Proposed class id, e.g. `doctor`. */
  kind: string;
  /** Proposed name in words, e.g. `医生`. */
  name: string;
  reason: { code: NameReasonCode; word: string | null; field: string | null };
  /** Requests and sessions of the position in the window. */
  uses: number;
  sessions: number;
  /** Why the candidate needs a look, e.g. the name is an abbreviation; null when it is clear. */
  note: string | null;
  /** The class the saved configuration already gives this position, when it is not `kind`; null otherwise. */
  conflict: string | null;
}

/** `GET /api/sites/{name}/objects/bootstrap`: the candidates from the last `window_hours` of requests. */
export interface BootstrapResponse {
  window_hours: number;
  /** The decision records of the site in the window: tells "no traffic" from "no candidates". */
  records: number;
  candidates: BootstrapCandidate[];
}
