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

export type ChangeKind = "create" | "update" | "rollback" | "delete" | "import";

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
  | "secret_fields";

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
  | "CACHE_RAISED";

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
  | "hot_would_block";

/** A change to the configuration that applying a suggestion makes. */
export interface SuggestionAction {
  /** `exact` or `prefix` options of the same suggestion. */
  label?: "exact" | "prefix";
  add_entry?: string;
  add_bypass?: string;
  add_secret_field?: string;
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
  path?: string;
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
