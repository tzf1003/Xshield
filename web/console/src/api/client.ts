// Fetch wrapper for the control-plane API (docs/07 7.9). Errors carry the server's code and the
// field it names; codes are turned into text by lib/vocab.ts, never shown raw as data.

import type {
  Evidence,
  ImpactPreview,
  ImportResult,
  Insights,
  JevPrompt,
  JevStats,
  JevStatus,
  LookupResponse,
  RequestCounts,
  RequestDetail,
  RequestListResponse,
  SessionListResponse,
  SessionState,
  SessionTimeline,
  SiteDetail,
  SiteListResponse,
  SiteRollbackBody,
  SiteSpec,
  SiteVersionsResponse,
  SiteWriteBody,
  StatsSummary,
  StatusResponse,
  SystemInfo,
  Timeseries,
  ValidateResult,
} from "./types.ts";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly field: string | undefined;
  readonly currentVersion: number | undefined;

  constructor(status: number, body: { error?: string; field?: string; current_version?: number }) {
    super(body.error ?? `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.code = body.error;
    this.field = body.field;
    this.currentVersion = body.current_version;
  }
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

/** Called on every 401 so the shell can ask for the password without leaving the page. */
export function onUnauthorized(listener: Listener): () => void {
  unauthorizedListeners.add(listener);
  return () => {
    unauthorizedListeners.delete(listener);
  };
}

async function call<T>(
  method: string,
  path: string,
  body?: string,
  contentType?: string,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (contentType) headers["Content-Type"] = contentType;
  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 401) {
    for (const listener of unauthorizedListeners) listener();
  }
  if (!response.ok) {
    let parsed: { error?: string; field?: string; current_version?: number } = {};
    try {
      parsed = (await response.json()) as typeof parsed;
    } catch {
      parsed = { error: response.status >= 500 ? "INTERNAL" : `HTTP_${response.status}` };
    }
    throw new ApiError(response.status, parsed);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const get = <T>(path: string) => call<T>("GET", path);
const post = <T>(path: string, json?: unknown) =>
  call<T>("POST", path, json === undefined ? undefined : JSON.stringify(json), "application/json");
const put = <T>(path: string, json: unknown) =>
  call<T>("PUT", path, JSON.stringify(json), "application/json");
const del = <T>(path: string) => call<T>("DELETE", path);

const name = (site: string) => encodeURIComponent(site);

export const api = {
  session: () => get<SessionState>("/session"),
  login: (password: string) => post<void>("/login", { password }),
  logout: () => post<void>("/logout"),

  requests: (query: string) => get<RequestListResponse>(`/requests${query}`),
  requestCounts: (query: string) => get<RequestCounts>(`/requests/counts${query}`),
  requestDetail: (id: string) => get<RequestDetail>(`/requests/${encodeURIComponent(id)}`),
  lookup: (ids: string[]) => post<LookupResponse>("/requests/lookup", { ids }),
  importLog: (text: string) => call<ImportResult>("POST", "/import", text, "application/x-ndjson"),

  summary: (query: string) => get<StatsSummary>(`/stats/summary${query}`),
  timeseries: (query: string) => get<Timeseries>(`/stats/timeseries${query}`),

  sessions: (query: string) => get<SessionListResponse>(`/sessions${query}`),
  sessionTimeline: (label: string, query: string) =>
    get<SessionTimeline>(`/sessions/${encodeURIComponent(label)}${query}`),

  jevStatus: () => get<JevStatus>("/jev/status"),
  jevStats: (query: string) => get<JevStats>(`/jev/stats${query}`),
  prompt: (id: string) => get<JevPrompt>(`/jev/prompts/${encodeURIComponent(id)}`),

  sites: () => get<SiteListResponse>("/sites"),
  site: (site: string) => get<SiteDetail>(`/sites/${name(site)}`),
  createSite: (spec: SiteSpec, note?: string) =>
    post<SiteDetail>("/sites", note ? { spec, note } : { spec }),
  updateSite: (site: string, body: SiteWriteBody) => put<SiteDetail>(`/sites/${name(site)}`, body),
  deleteSite: (site: string) => del<void>(`/sites/${name(site)}`),
  versions: (site: string) => get<SiteVersionsResponse>(`/sites/${name(site)}/versions`),
  rollback: (site: string, body: SiteRollbackBody) =>
    post<SiteDetail>(`/sites/${name(site)}/rollback`, body),
  validate: (spec: SiteSpec) => post<ValidateResult>("/sites/validate", { spec }),
  preview: (site: string, spec: SiteSpec) =>
    post<ImpactPreview>(`/sites/${name(site)}/preview`, { spec }),
  insights: (site: string, hours = 24) =>
    get<Insights>(`/sites/${name(site)}/insights?window_hours=${hours}`),
  evidence: (site: string) => get<Evidence>(`/sites/${name(site)}/evidence`),

  status: () => get<StatusResponse>("/status"),
  system: () => get<SystemInfo>("/system"),
};

/** Builds a query string from defined values only. */
export function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text.length > 0 ? `?${text}` : "";
}
