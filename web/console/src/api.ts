import type { DecisionLogRow, HistoryEntry, JevStatus, SiteRecord, SiteSpecJson } from "./types.ts";

/** Thrown by every API call that gets a non-2xx response. `status` lets callers special-case 401/400/404/409. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;

  constructor(status: number, code: string | undefined, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

/** Fired on every 401 response so a single listener can redirect to /login regardless of which call failed. */
export type UnauthorizedListener = () => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

export function onUnauthorized(listener: UnauthorizedListener): () => void {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 401) {
    for (const listener of unauthorizedListeners) listener();
  }
  if (!response.ok) {
    let code: string | undefined;
    let message = `请求失败（${response.status}）`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body?.error) {
        code = body.error;
        message = body.error;
      }
    } catch {
      // No JSON body (e.g. a plain 404 from the proxy): keep the generic message.
    }
    throw new ApiError(response.status, code, message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  login(password: string): Promise<void> {
    return request("/login", { method: "POST", body: JSON.stringify({ password }) });
  },
  logout(): Promise<void> {
    return request("/logout", { method: "POST" });
  },
  session(): Promise<{ authenticated: boolean }> {
    return request("/session");
  },
  listSites(): Promise<SiteRecord[]> {
    return request("/sites");
  },
  createSite(spec: SiteSpecJson): Promise<SiteRecord> {
    return request("/sites", { method: "POST", body: JSON.stringify(spec) });
  },
  getSite(name: string): Promise<SiteRecord> {
    return request(`/sites/${encodeURIComponent(name)}`);
  },
  updateSite(name: string, spec: SiteSpecJson): Promise<SiteRecord> {
    return request(`/sites/${encodeURIComponent(name)}`, {
      method: "PUT",
      body: JSON.stringify(spec),
    });
  },
  deleteSite(name: string): Promise<void> {
    return request(`/sites/${encodeURIComponent(name)}`, { method: "DELETE" });
  },
  siteHistory(name: string, limit = 50): Promise<HistoryEntry[]> {
    return request(`/sites/${encodeURIComponent(name)}/history?limit=${limit}`);
  },
  rollbackSite(name: string, id: number): Promise<SiteRecord> {
    return request(`/sites/${encodeURIComponent(name)}/history/${id}/rollback`, {
      method: "POST",
    });
  },
  decisions(query: Record<string, string | number | undefined>): Promise<DecisionLogRow[]> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== "") params.set(key, String(value));
    }
    const qs = params.toString();
    return request(`/decisions${qs ? `?${qs}` : ""}`);
  },
  decision(id: number): Promise<DecisionLogRow> {
    return request(`/decisions/${id}`);
  },
  jevStatus(): Promise<JevStatus> {
    return request("/jev/status");
  },
};

/** Short Chinese messages for the SiteConfig validation error codes the server may return on 400. */
export const SITE_CONFIG_ERROR_MESSAGES: Record<string, string> = {
  SITE_CONFIG_MALFORMED: "配置格式不正确",
  SITE_CONFIG_NAME_INVALID: "站点名不合法（仅允许小写字母、数字、下划线、短横线）",
  SITE_CONFIG_HOSTS_INVALID: "域名列表不合法",
  SITE_CONFIG_ORIGIN_INVALID: "源站地址不合法",
  SITE_CONFIG_SESSION_INVALID: "会话凭证配置不合法",
  SITE_CONFIG_ENTRIES_INVALID: "入口路径不合法",
  SITE_CONFIG_BYPASS_INVALID: "跳过路径不合法",
  SITE_EXISTS: "站点名已存在",
  SITE_NOT_FOUND: "站点不存在",
  SITE_NAME_MISMATCH: "站点名与地址不一致",
  ROLLBACK_TARGET_DELETED: "该历史版本对应“已删除”，无法回滚",
  INVALID_PASSWORD: "口令不正确",
};

export function describeApiError(error: unknown): string {
  if (error instanceof ApiError) {
    return SITE_CONFIG_ERROR_MESSAGES[error.code ?? ""] ?? error.message;
  }
  if (error instanceof Error) return error.message;
  return "发生未知错误";
}
