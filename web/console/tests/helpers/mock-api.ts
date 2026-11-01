// Serves the fixtures to the console through page.route, so a spec runs without a backend (docs/07
// 7.10.8). Lists are filtered and paged like the control plane (7.9.3), versions are checked (409),
// and every call is recorded: read them back with servedRequests(page) to assert on query strings.
//
// Call mockApi(page) before the first navigation. Inside one call the sites live in memory, so a
// save shows up in the next read; a new mockApi call starts again from the fixtures.

import type { Page } from "@playwright/test";
import type {
  DecisionPath,
  EdgeLoad,
  EdgeRollout,
  ImpactPreview,
  Insights,
  JevAccess,
  JevAttack,
  JevConclusion,
  JevRecord,
  Outcome,
  RequestDetail,
  RequestId,
  RequestRow,
  SessionRow,
  SiteDetail,
  SiteSpec,
  SiteSummary,
  SiteVersion,
  TimelineRow,
  ValidateResult,
} from "../../src/api/types.ts";
import {
  DAY_MS,
  evidence,
  FIXTURE_NOW_MS,
  insights,
  jevStats,
  jevStatus,
  preview,
  prompt,
  requestDetails,
  requestList,
  session,
  sessionList,
  sessionTimeline,
  siteEmr,
  siteJuice,
  status,
  summary,
  system,
  timeseries,
  versionsEmr,
} from "./fixtures.ts";

export { DAY_MS, FIXTURE_NOW_MS };

/** One call the console made, as the mock answered it. `body` is parsed JSON, or the raw text. */
export type ServedRequest = {
  method: string;
  /** Path with the /api prefix, e.g. `/api/requests/counts`. */
  path: string;
  /** Query string without the `?`. */
  query: string;
  body: unknown;
  status: number;
};

export type MockOptions = {
  /**
   * Replaces responses. Keys are `/api/path` (any method) or `METHOD /api/path`; a plain value is
   * sent with status 200, `reply(status, body)` sends that status. Applied before the built-in answers.
   */
  overrides?: Record<string, unknown>;
  /** false starts signed out: every call except session, login and logout answers 401. */
  signedIn?: boolean;
  /** The only password login accepts; any other answers 401 INVALID_PASSWORD. Unset accepts any. */
  password?: string;
  /** false keeps a saved version pending on the gateways, so the rollout stays partial. Default true. */
  gatewaysLoadSaved?: boolean;
};

const REPLY = Symbol("reply");

/** Overrides one response with a status: `reply(409, { error: "VERSION_CONFLICT", current_version: 14 })`. */
export function reply(
  status: number,
  body?: unknown,
): { [REPLY]: true; status: number; body: unknown } {
  return { [REPLY]: true, status, body };
}

const servedByPage = new WeakMap<Page, ServedRequest[]>();

/** Every call the mock answered for this page since its last mockApi call. */
export function servedRequests(page: Page): ServedRequest[] {
  return servedByPage.get(page) ?? [];
}

/** Only the control plane's calls: a glob like `**\/api/**` also matches the app's own modules under
 *  src/api/, and answering those with 404 leaves the page blank. */
function isApiCall(url: URL): boolean {
  return url.pathname.startsWith("/api/");
}

/** Routes every /api call of the page to the fixtures. */
export async function mockApi(page: Page, options: MockOptions = {}): Promise<void> {
  const state = freshState(options);
  const served: ServedRequest[] = [];
  servedByPage.set(page, served);
  await page.unroute(isApiCall);
  await page.route(isApiCall, async (route, request) => {
    const url = new URL(request.url());
    const raw = request.postData();
    const call: Call = {
      method: request.method(),
      path: url.pathname,
      params: url.searchParams,
      body: parseBody(raw),
      raw: raw ?? "",
    };
    const answer = answerFor(call, state, options);
    served.push({
      method: call.method,
      path: call.path,
      query: url.search.slice(1),
      body: call.body,
      status: answer.status,
    });
    await route.fulfill({
      status: answer.status,
      contentType: answer.type ?? "application/json",
      headers: answer.headers,
      body: answer.text ?? (answer.body === undefined ? "" : JSON.stringify(answer.body)),
    });
  });
}

// ------------------------------------------------------------------ answers and failures

type Call = { method: string; path: string; params: URLSearchParams; body: unknown; raw: string };
type Answer = {
  status: number;
  body?: unknown;
  text?: string;
  type?: string;
  headers?: Record<string, string>;
};

/** A failure the real API would answer with a status and an error code. */
class ApiFailure extends Error {
  readonly status: number;
  readonly code: string;
  readonly extra: Record<string, unknown>;

  constructor(status: number, code: string, extra: Record<string, unknown> = {}) {
    super(code);
    this.name = "ApiFailure";
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const ok = (body: unknown): Answer => ({ status: 200, body });
const empty = (status = 204): Answer => ({ status });

function parseBody(raw: string | null): unknown {
  if (raw === null || raw.length === 0) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

function answerFor(call: Call, state: State, options: MockOptions): Answer {
  const override =
    options.overrides?.[`${call.method} ${call.path}`] ?? options.overrides?.[call.path];
  if (override !== undefined)
    return isReply(override) ? { status: override.status, body: override.body } : ok(override);
  if (!state.signedIn && !AUTH_FREE.has(call.path))
    return { status: 401, body: { error: "UNAUTHENTICATED" } };
  try {
    return dispatch(call, state, options);
  } catch (error) {
    if (error instanceof ApiFailure)
      return { status: error.status, body: { error: error.code, ...error.extra } };
    throw error;
  }
}

function isReply(value: unknown): value is { status: number; body: unknown } {
  return typeof value === "object" && value !== null && REPLY in value;
}

const AUTH_FREE = new Set(["/api/session", "/api/login", "/api/logout"]);

// ------------------------------------------------------------------ state of one mock

type State = {
  signedIn: boolean;
  sites: Map<string, SiteDetail>;
  versions: Map<string, SiteVersion[]>;
};

function freshState(options: MockOptions): State {
  const emr = structuredClone(siteEmr);
  const juice = structuredClone(siteJuice);
  // juice has no version file: its only history entry is the configuration it was created with.
  const juiceVersions: SiteVersion[] = [
    {
      version: juice.version,
      change: "create",
      rollback_of: null,
      note: null,
      changed_at: juice.created_at,
      spec: structuredClone(juice.spec),
    },
  ];
  return {
    signedIn: options.signedIn ?? true,
    sites: new Map([
      [emr.name, emr],
      [juice.name, juice],
    ]),
    versions: new Map([
      [emr.name, structuredClone(versionsEmr.versions)],
      [juice.name, juiceVersions],
    ]),
  };
}

// ------------------------------------------------------------------ routing

type Handler = (match: RegExpMatchArray, call: Call, state: State, options: MockOptions) => Answer;

const ROUTES: Array<[method: string, pattern: RegExp, handler: Handler]> = [
  ["GET", /^\/api\/session$/, (_m, _c, s) => ok(s.signedIn ? session : { authenticated: false })],
  ["POST", /^\/api\/login$/, (_m, c, s, o) => login(c, s, o)],
  ["POST", /^\/api\/logout$/, (_m, _c, s) => logout(s)],
  ["GET", /^\/api\/requests$/, (_m, c) => listRequests(c)],
  ["GET", /^\/api\/requests\/counts$/, (_m, c) => countRequests(c)],
  ["GET", /^\/api\/requests\/export$/, (_m, c) => exportRequests(c)],
  ["POST", /^\/api\/requests\/lookup$/, (_m, c) => lookupRequests(c)],
  ["GET", /^\/api\/requests\/(req_[0-9a-f]{32})$/, (m) => requestDetail(m[1] ?? "")],
  ["POST", /^\/api\/import$/, (_m, c) => importLines(c)],
  ["GET", /^\/api\/stats\/summary$/, () => ok(summary)],
  ["GET", /^\/api\/stats\/timeseries$/, () => ok(timeseries)],
  ["GET", /^\/api\/sessions$/, (_m, c) => listSessions(c)],
  ["GET", /^\/api\/sessions\/([0-9a-f]{16})$/, (m) => sessionDetail(m[1] ?? "")],
  ["GET", /^\/api\/jev\/status$/, () => ok(jevStatus)],
  ["GET", /^\/api\/jev\/stats$/, () => ok(jevStats)],
  ["GET", /^\/api\/jev\/prompts\/([^/]+)$/, (m) => (m[1] === prompt.id ? ok(prompt) : notFound())],
  ["GET", /^\/api\/sites$/, (_m, _c, s) => ok({ sites: [...s.sites.values()].map(summaryOf) })],
  ["POST", /^\/api\/sites$/, (_m, c, s, o) => createSite(c, s, o)],
  ["POST", /^\/api\/sites\/validate$/, (_m, c) => ok(validateSpec(specOf(c)))],
  ["GET", /^\/api\/sites\/([^/]+)$/, (m, _c, s) => siteOr(s, m, (site) => ok(site))],
  ["PUT", /^\/api\/sites\/([^/]+)$/, (m, c, s, o) => saveSite(m, c, s, o)],
  ["DELETE", /^\/api\/sites\/([^/]+)$/, (m, _c, s) => deleteSite(m, s)],
  ["GET", /^\/api\/sites\/([^/]+)\/versions$/, (m, _c, s) => versionList(m, s)],
  ["GET", /^\/api\/sites\/([^/]+)\/versions\/(\d+)$/, (m, _c, s) => versionOne(m, s)],
  ["POST", /^\/api\/sites\/([^/]+)\/rollback$/, (m, c, s, o) => rollbackSite(m, c, s, o)],
  [
    "POST",
    /^\/api\/sites\/([^/]+)\/preview$/,
    (m, _c, s) => siteOr(s, m, (): Answer => ok(preview as ImpactPreview)),
  ],
  [
    "GET",
    /^\/api\/sites\/([^/]+)\/insights$/,
    (m, _c, s) => siteOr(s, m, (site) => ok(insightsFor(site))),
  ],
  ["GET", /^\/api\/sites\/([^/]+)\/evidence$/, (m, _c, s) => siteOr(s, m, () => ok(evidence))],
  ["GET", /^\/api\/status$/, () => ok(status)],
  ["GET", /^\/api\/system$/, () => ok(system)],
];

function dispatch(call: Call, state: State, options: MockOptions): Answer {
  for (const [method, pattern, handler] of ROUTES) {
    if (method !== call.method) continue;
    const match = call.path.match(pattern);
    if (match) return handler(match, call, state, options);
  }
  return notFound();
}

function notFound(): Answer {
  return { status: 404, body: { error: "NOT_FOUND" } };
}

// ------------------------------------------------------------------ session

function login(call: Call, state: State, options: MockOptions): Answer {
  const password = (call.body as { password?: unknown } | undefined)?.password;
  if (options.password !== undefined && password !== options.password) {
    return { status: 401, body: { error: "INVALID_PASSWORD" } };
  }
  state.signedIn = true;
  return empty();
}

function logout(state: State): Answer {
  state.signedIn = false;
  return empty();
}

// ------------------------------------------------------------------ request list

/** Rows in the order the server returns them: newest first, then by row number. */
const ALL_ROWS: RequestRow[] = [...requestList.rows].sort(
  (a, b) => b.at_millis - a.at_millis || b.id - a.id,
);
const ROWS_BY_ID = new Map(ALL_ROWS.map((row) => [row.request_id, row]));
const HIDDEN_PATHS = new Set(["bypass", "unknown_site"]);

function numberParam(params: URLSearchParams, key: string): number | undefined {
  const raw = params.get(key);
  if (raw === null || raw === "") return undefined;
  const value = Number(raw);
  if (!Number.isFinite(value)) throw new ApiFailure(400, "INVALID_FILTER", { field: key });
  return value;
}

function listParam(params: URLSearchParams, key: string): string[] {
  return (params.get(key) ?? "").split(",").filter((value) => value.length > 0);
}

/**
 * The rows the filters keep. Bypass and unknown-site rows are hidden unless scope=all or the caller
 * names one of those decision paths; the counts endpoint always counts them (7.9.3).
 */
function matchRows(params: URLSearchParams, includeHidden: boolean): RequestRow[] {
  const decisions = listParam(params, "decision_path");
  const outcomes = listParam(params, "outcome");
  const showHidden =
    includeHidden ||
    params.get("scope") === "all" ||
    decisions.some((path) => HIDDEN_PATHS.has(path));
  const since = numberParam(params, "since_millis") ?? FIXTURE_NOW_MS - DAY_MS;
  const until = numberParam(params, "until_millis") ?? FIXTURE_NOW_MS;
  if (until - since > 7 * DAY_MS) throw new ApiFailure(400, "WINDOW_TOO_LARGE");
  const site = params.get("site");
  const session = params.get("session");
  const requestId = params.get("request_id");
  const client = params.get("client");
  const method = params.get("method");
  const path = params.get("path");
  const status = params.get("status");
  const hasJev = params.get("has_jev") === "true";
  const jevAccess = params.get("jev_access");
  const jevAttack = params.get("jev_attack");
  const jevFailure = params.get("jev_failure");
  const maxConfidence = numberParam(params, "max_confidence");
  const minMs = numberParam(params, "min_ms");

  return ALL_ROWS.filter((row) => {
    if (!showHidden && HIDDEN_PATHS.has(row.decision_path)) return false;
    if (site !== null && row.site !== site) return false;
    if (row.at_millis < since || row.at_millis > until) return false;
    if (outcomes.length > 0 && !outcomes.includes(row.outcome)) return false;
    if (decisions.length > 0 && !decisions.includes(row.decision_path)) return false;
    if (session !== null && row.session !== session) return false;
    if (requestId !== null && row.request_id !== requestId) return false;
    if (client !== null && row.client !== client) return false;
    if (method !== null && row.method !== method) return false;
    if (path !== null && !pathMatches(row.path, path)) return false;
    if (status !== null && !statusMatches(row.status, status)) return false;
    if (hasJev && row.jev === null) return false;
    if (jevAccess !== null && row.jev?.access !== jevAccess) return false;
    if (jevAttack !== null && row.jev?.attack !== jevAttack) return false;
    if (jevFailure !== null && row.jev?.failure !== jevFailure) return false;
    if (
      maxConfidence !== undefined &&
      (row.jev?.confidence ?? Number.POSITIVE_INFINITY) > maxConfidence
    ) {
      return false;
    }
    if (minMs !== undefined && !(row.total_ms !== null && row.total_ms >= minMs)) return false;
    return true;
  });
}

/** `path` is exact, or a prefix when it ends with `*` (7.9.3). */
function pathMatches(actual: string, pattern: string): boolean {
  return pattern.endsWith("*") ? actual.startsWith(pattern.slice(0, -1)) : actual === pattern;
}

function statusMatches(actual: number | null, pattern: string): boolean {
  if (actual === null) return false;
  if (pattern === "4xx") return actual >= 400 && actual < 500;
  return String(actual) === pattern;
}

function listRequests(call: Call): Answer {
  const rows = matchRows(call.params, false);
  const limit = numberParam(call.params, "limit") ?? 100;
  if (limit < 1 || limit > 500) throw new ApiFailure(400, "INVALID_FILTER", { field: "limit" });
  let rest = rows;
  const cursor = call.params.get("cursor");
  if (cursor !== null) {
    const [atText = "", idText = ""] = cursor.split(".");
    const at = Number(atText);
    const id = Number(idText);
    if (!Number.isFinite(at) || !Number.isFinite(id))
      throw new ApiFailure(400, "INVALID_FILTER", { field: "cursor" });
    rest = rows.filter((row) => row.at_millis < at || (row.at_millis === at && row.id < id));
  }
  const page = rest.slice(0, limit);
  const last = page[page.length - 1];
  return ok({
    rows: page,
    next_cursor: rest.length > limit && last !== undefined ? `${last.at_millis}.${last.id}` : null,
  });
}

/** RequestCounts (types.ts): every count is over judged rows, except bypass and unknown-site, counted apart. */
function countRequests(call: Call): Answer {
  const rows = matchRows(call.params, true);
  const judged = rows.filter((row) => !HIDDEN_PATHS.has(row.decision_path));
  const outcomeCount = (outcome: Outcome): number =>
    judged.filter((row) => row.outcome === outcome).length;
  const pathCount = (path: DecisionPath): number =>
    rows.filter((row) => row.decision_path === path).length;
  const blocked = outcomeCount("blocked");
  const wouldBlock = outcomeCount("would_block");
  const unjudged = outcomeCount("unjudged");
  return ok({
    judged: judged.length,
    attention: blocked + wouldBlock + unjudged,
    blocked,
    would_block: wouldBlock,
    unjudged,
    jev: judged.filter((row) => row.jev !== null).length,
    no_session: pathCount("no_session"),
    bypass: pathCount("bypass"),
    unknown_site: pathCount("unknown_site"),
    complete: true,
  });
}

const CSV_COLUMNS = [
  "request_id",
  "at_millis",
  "site",
  "method",
  "host",
  "path",
  "status",
  "decision_path",
  "outcome",
  "session",
  "context",
  "client",
  "total_ms",
] as const;

/** Text cells that start with a formula character get a quote in front (7.9.9). */
function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  const safe = /^[=+\-@]/.test(text) ? `'${text}` : text;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

function exportRequests(call: Call): Answer {
  const format = call.params.get("format") ?? "jsonl";
  if (format !== "jsonl" && format !== "csv")
    throw new ApiFailure(400, "INVALID_FILTER", { field: "format" });
  const rows = matchRows(call.params, false).slice(0, 100_000);
  if (format === "jsonl") {
    return {
      status: 200,
      type: "application/x-ndjson",
      headers: { "content-disposition": 'attachment; filename="requests.jsonl"' },
      text: rows.map((row) => JSON.stringify(row)).join("\n") + (rows.length > 0 ? "\n" : ""),
    };
  }
  const lines = rows.map((row) => CSV_COLUMNS.map((column) => csvCell(row[column])).join(","));
  return {
    status: 200,
    type: "text/csv; charset=utf-8",
    headers: { "content-disposition": 'attachment; filename="requests.csv"' },
    text: `${[CSV_COLUMNS.join(","), ...lines].join("\r\n")}\r\n`,
  };
}

function lookupRequests(call: Call): Answer {
  const ids = (call.body as { ids?: unknown } | undefined)?.ids;
  if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string")) {
    throw new ApiFailure(400, "INVALID_FILTER", { field: "ids" });
  }
  if (ids.length > 1000) throw new ApiFailure(400, "TOO_MANY_IDS");
  const unique = [...new Set(ids as string[])];
  return ok({
    rows: unique.map((id) => {
      const row = ROWS_BY_ID.get(id);
      return row === undefined
        ? { request_id: id, found: false }
        : { request_id: id, found: true, summary: row };
    }),
  });
}

// ------------------------------------------------------------------ request detail

const FIXTURE_DETAILS = new Map(
  requestDetails.map((detail) => [detail.summary.request_id, detail]),
);

function requestDetail(id: string): Answer {
  const fixture = FIXTURE_DETAILS.get(id as RequestId);
  if (fixture !== undefined) return ok(fixture);
  const row = ROWS_BY_ID.get(id);
  if (row === undefined) throw new ApiFailure(404, "REQUEST_NOT_FOUND");
  // Rows without a sample record get the summary and a Jev record built from the list columns.
  const detail: RequestDetail = {
    summary: row,
    edge: "edge-1",
    trace: { v: 1, timing: { total_ms: row.total_ms, judge_ms: null, origin_ms: null } },
    jev: jevFromSummary(row),
    neighbors: neighboursOf(row),
    sources: {},
  };
  return ok(detail);
}

function neighboursOf(row: RequestRow): { prev: RequestId | null; next: RequestId | null } {
  if (row.session === "") return { prev: null, next: null };
  const list = ALL_ROWS.filter((item) => item.session === row.session).reverse(); // oldest first
  const index = list.findIndex((item) => item.id === row.id);
  return { prev: list[index - 1]?.request_id ?? null, next: list[index + 1]?.request_id ?? null };
}

function jevFromSummary(row: RequestRow): JevRecord | null {
  const jev = row.jev;
  if (jev === null) return null;
  const access = jev.access;
  const attack = jev.attack;
  const conclusion: JevConclusion | null =
    jev.failure === "JEV_CALL_LIMIT"
      ? null
      : access === null
        ? "unknown"
        : access === "DENY" || attack === "ATTACK"
          ? "deny"
          : access === "ALLOW"
            ? "allow"
            : "unknown";
  return {
    state:
      jev.failure === "JEV_CALL_LIMIT"
        ? null
        : JSON.stringify({
            entry: { matched: false },
            session: { age_seconds: 0, entries_passed: [] },
            recent: [],
            request: { method: row.method, path: row.path, values: [] },
          }),
    prompt: prompt.id,
    model: "typesafe-ai/jev",
    route: "gateway",
    timeout_ms: 2000,
    trim: 0,
    request_bytes: null,
    http_status: jev.failure === null ? 200 : null,
    response: null,
    usage: null,
    access:
      access === null
        ? null
        : ({ [access]: jev.confidence ?? 0 } as Partial<Record<JevAccess, number>>),
    attack:
      attack === null
        ? null
        : ({ [attack]: jev.confidence ?? 0 } as Partial<Record<JevAttack, number>>),
    conclusion,
    millis: jev.ms,
    failure: jev.failure,
  };
}

// ------------------------------------------------------------------ sessions

function listSessions(call: Call): Answer {
  const site = call.params.get("site");
  const flag = call.params.get("flag");
  const since = numberParam(call.params, "since_millis") ?? FIXTURE_NOW_MS - DAY_MS;
  const until = numberParam(call.params, "until_millis") ?? FIXTURE_NOW_MS;
  const limit = numberParam(call.params, "limit") ?? 200;
  let rows = sessionList.rows.filter(
    (row) =>
      (site === null || row.site === site) &&
      row.last_at_millis >= since &&
      row.first_at_millis <= until,
  );
  if (flag === "blocked") rows = rows.filter((row) => row.blocked > 0);
  if (flag === "jev") rows = rows.filter((row) => row.jev_calls > 0);
  return ok({ rows: rows.slice(0, limit) });
}

function sessionDetail(label: string): Answer {
  const summaryRow: SessionRow | undefined = sessionList.rows.find((row) => row.label === label);
  if (summaryRow === undefined) throw new ApiFailure(404, "SESSION_NOT_FOUND");
  if (label === sessionTimeline.summary.label) return ok(sessionTimeline);
  // Other sessions are built from the request list; the trace-only columns stay empty.
  const rows: TimelineRow[] = ALL_ROWS.filter((row) => row.session === label)
    .reverse()
    .map((row) => ({
      ...row,
      learned: null,
      entry_passed: false,
      issued_session: null,
      after_would_block: false,
    }));
  return ok({ summary: summaryRow, rows, next_cursor: null });
}

// ------------------------------------------------------------------ sites

function summaryOf(detail: SiteDetail): SiteSummary {
  const { spec, created_at, ...summary } = detail;
  void spec;
  void created_at;
  return summary;
}

function specOf(call: Call): SiteSpec {
  const spec = (call.body as { spec?: SiteSpec } | undefined)?.spec;
  if (spec === undefined || typeof spec !== "object")
    throw new ApiFailure(400, "SITE_CONFIG_MALFORMED");
  return spec;
}

function siteOr(
  state: State,
  match: RegExpMatchArray,
  found: (site: SiteDetail) => Answer,
): Answer {
  const site = state.sites.get(decodeURIComponent(match[1] ?? ""));
  return site === undefined ? { status: 404, body: { error: "SITE_NOT_FOUND" } } : found(site);
}

/** Juice carries the tuning suggestions; the other sites have nothing to suggest. */
function insightsFor(site: SiteDetail): Insights {
  if (site.name === "juice") return insights;
  return { window_hours: 24, suggestions: [], readiness: null, complete: true };
}

function hostClash(name: string, hosts: string[], state: State): string | null {
  for (const host of hosts) {
    for (const other of state.sites.values()) {
      if (other.name !== name && other.hosts.includes(host)) return host;
    }
  }
  return null;
}

/** The rollout after a save: online gateways load the new version at once unless the mock says not. */
function applyLoad(detail: SiteDetail, version: number, load: boolean): SiteDetail {
  const now = Date.now();
  const edges: EdgeRollout[] = detail.rollout.edges.map((edge) =>
    edge.online && load ? { ...edge, loaded_version: version } : edge,
  );
  const loads: EdgeLoad[] = detail.edges.map((edge) => {
    const rollout = edges.find((item) => item.edge === edge.edge);
    return rollout?.online && load ? { ...edge, version, loaded_at_millis: now } : edge;
  });
  const onlineLoaded = edges.filter((edge) => edge.online).map((edge) => edge.loaded_version);
  const lowest = onlineLoaded.every((value) => value !== null)
    ? Math.min(...(onlineLoaded as number[]))
    : null;
  return {
    ...detail,
    version,
    loaded_version: onlineLoaded.length === 0 ? detail.loaded_version : lowest,
    edges: loads,
    rollout: {
      version,
      edges_online: edges.filter((edge) => edge.online).length,
      edges_loaded: edges.filter((edge) => edge.online && edge.loaded_version === version).length,
      edges,
    },
  };
}

/** Records a new version of a site and returns the detail the server answers with. */
function commit(
  state: State,
  current: SiteDetail,
  spec: SiteSpec,
  change: SiteVersion["change"],
  note: string | null,
  rollbackOf: number | null,
  options: MockOptions,
): SiteDetail {
  const version = current.version + 1;
  const changedAt = new Date().toISOString().replace(".000Z", "Z");
  const mode = spec.mode ?? "observe";
  const observing =
    mode === "observe"
      ? current.mode === "observe"
        ? current.observing_since_millis
        : Date.now()
      : null;
  const next = applyLoad(
    {
      ...current,
      spec,
      hosts: spec.hosts,
      origin: spec.origin,
      mode,
      updated_at: changedAt,
      observing_since_millis: observing,
    },
    version,
    options.gatewaysLoadSaved ?? true,
  );
  state.sites.set(next.name, next);
  state.versions.set(next.name, [
    ...(state.versions.get(next.name) ?? []),
    { version, change, rollback_of: rollbackOf, note, changed_at: changedAt, spec },
  ]);
  return next;
}

function checkExpected(current: SiteDetail, expected: number | undefined): void {
  if (expected !== undefined && expected !== current.version) {
    throw new ApiFailure(409, "VERSION_CONFLICT", { current_version: current.version });
  }
}

function createSite(call: Call, state: State, options: MockOptions): Answer {
  const spec = specOf(call);
  const note = (call.body as { note?: string } | undefined)?.note ?? null;
  if (state.sites.has(spec.name)) throw new ApiFailure(409, "SITE_EXISTS");
  const clash = hostClash(spec.name, spec.hosts, state);
  if (clash !== null)
    throw new ApiFailure(409, "SITE_HOST_TAKEN", { field: `hosts[${spec.hosts.indexOf(clash)}]` });
  const now = new Date().toISOString().replace(".000Z", "Z");
  const base: SiteDetail = {
    name: spec.name,
    hosts: spec.hosts,
    origin: spec.origin,
    mode: spec.mode ?? "observe",
    version: 0,
    updated_at: now,
    observing_since_millis: Date.now(),
    loaded_version: null,
    edges: siteEdges(),
    rollout: { version: 0, edges_online: 0, edges_loaded: 0, edges: siteRollout() },
    requests_24h: 0,
    blocked_24h: 0,
    would_block_24h: 0,
    jev_calls_24h: 0,
    suggestions: 0,
    spec,
    created_at: now,
  };
  state.sites.set(spec.name, base);
  state.versions.set(spec.name, []);
  const created = commit(state, { ...base, version: 0 }, spec, "create", note, null, options);
  return { status: 201, body: created };
}

/** Edge rows of a new site, one per gateway on the system page, none loaded yet. */
function siteEdges(): EdgeLoad[] {
  return system.edges.map((edge) => ({
    edge: edge.edge,
    version: null,
    error: null,
    loaded_at_millis: null,
  }));
}

function siteRollout(): EdgeRollout[] {
  return system.edges.map((edge) => ({
    edge: edge.edge,
    online: edge.online,
    loaded_version: null,
    error: null,
  }));
}

function saveSite(match: RegExpMatchArray, call: Call, state: State, options: MockOptions): Answer {
  const name = decodeURIComponent(match[1] ?? "");
  const current = state.sites.get(name);
  if (current === undefined) return { status: 404, body: { error: "SITE_NOT_FOUND" } };
  const spec = specOf(call);
  if (spec.name !== name) return { status: 400, body: { error: "SITE_NAME_MISMATCH" } };
  const write = call.body as { expected_version?: number; note?: string };
  checkExpected(current, write.expected_version);
  const clash = hostClash(name, spec.hosts, state);
  if (clash !== null)
    throw new ApiFailure(409, "SITE_HOST_TAKEN", { field: `hosts[${spec.hosts.indexOf(clash)}]` });
  return ok(commit(state, current, spec, "update", write.note ?? null, null, options));
}

function deleteSite(match: RegExpMatchArray, state: State): Answer {
  const name = decodeURIComponent(match[1] ?? "");
  if (!state.sites.delete(name)) return { status: 404, body: { error: "SITE_NOT_FOUND" } };
  state.versions.delete(name);
  return empty();
}

function versionList(match: RegExpMatchArray, state: State): Answer {
  const name = decodeURIComponent(match[1] ?? "");
  const list = state.versions.get(name);
  if (list === undefined) return { status: 404, body: { error: "SITE_NOT_FOUND" } };
  return ok({ versions: [...list].sort((a, b) => b.version - a.version) });
}

function versionOne(match: RegExpMatchArray, state: State): Answer {
  const name = decodeURIComponent(match[1] ?? "");
  const found = state.versions.get(name)?.find((item) => item.version === Number(match[2]));
  return found === undefined ? notFound() : ok(found);
}

function rollbackSite(
  match: RegExpMatchArray,
  call: Call,
  state: State,
  options: MockOptions,
): Answer {
  const name = decodeURIComponent(match[1] ?? "");
  const current = state.sites.get(name);
  if (current === undefined) return { status: 404, body: { error: "SITE_NOT_FOUND" } };
  const body = call.body as { to_version: number; expected_version?: number; note?: string };
  checkExpected(current, body.expected_version);
  const target = state.versions.get(name)?.find((item) => item.version === body.to_version);
  if (target === undefined) return notFound();
  if (target.spec === null) throw new ApiFailure(409, "ROLLBACK_TARGET_DELETED");
  return ok(
    commit(state, current, target.spec, "rollback", body.note ?? null, body.to_version, options),
  );
}

/** The checks a draft gets before it is saved (the server rules, 7.9.12, in short form). */
function validateSpec(spec: SiteSpec): ValidateResult {
  if (!/^[a-z0-9_-]{1,64}$/.test(spec.name)) {
    return { valid: false, error: "SITE_CONFIG_NAME_INVALID", field: "name" };
  }
  if (spec.hosts.length === 0 || spec.hosts.length > 16) {
    return { valid: false, error: "SITE_CONFIG_HOSTS_INVALID", field: "hosts" };
  }
  if (!/^https?:\/\/[^/\s]+$/.test(spec.origin)) {
    return { valid: false, error: "SITE_CONFIG_ORIGIN_INVALID", field: "origin" };
  }
  if (spec.entries.length === 0 || spec.entries.length > 64) {
    return { valid: false, error: "SITE_CONFIG_ENTRIES_INVALID", field: "entries" };
  }
  const badEntry = spec.entries.findIndex((entry) => !entry.startsWith("/") || entry.includes("?"));
  if (badEntry >= 0)
    return { valid: false, error: "SITE_CONFIG_ENTRIES_INVALID", field: `entries[${badEntry}]` };
  const timeout = spec.advanced?.jev_timeout_ms;
  if (timeout !== undefined && (timeout < 100 || timeout > 30_000)) {
    return {
      valid: false,
      error: "SITE_CONFIG_ADVANCED_INVALID",
      field: "advanced.jev_timeout_ms",
    };
  }
  return { valid: true };
}

function importLines(call: Call): Answer {
  const lines = call.raw.split(/\r?\n/).filter((line) => line.trim().length > 0);
  let imported = 0;
  const errorLines: number[] = [];
  lines.forEach((line, index) => {
    try {
      JSON.parse(line);
      imported++;
    } catch {
      errorLines.push(index + 1);
    }
  });
  return ok({
    imported,
    skipped: 0,
    errors: errorLines.length,
    error_lines: errorLines.slice(0, 20),
  });
}
