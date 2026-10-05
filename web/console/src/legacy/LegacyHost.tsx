import type { FormEvent } from "react";
import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { routeQueryKind, routeTarget } from "../admin-routes";
import { ApiError } from "../api";
import type { AuditHealthResponse, ControlClient, JobResponse } from "../api";
import { AuditHealthPanel } from "../panels";
import { useSession } from "../security/SessionProvider";
import { unauthorizedNotice } from "../security/session-store.ts";

// The panel loads the first time its page is opened.
const ManagementApiKeyPanel = lazy(() =>
  import("../ManagementApiKeyPanel").then((module) => ({ default: module.ManagementApiKeyPanel })),
);

function Deferred({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<p className="empty">正在加载页面…</p>}>{children}</Suspense>;
}

type Problem = { message: string; code: string; requestId?: string | null; status?: number };
type Channel = "query" | "health";

function Failure({ problem }: { problem: Problem | null }) {
  return (
    problem && (
      <div className="notice danger" role="alert">
        <div>
          {problem.message}
          <small className="mono">
            {problem.code}
            {problem.status ? " · HTTP " + problem.status : ""}
            {problem.requestId ? ` · ${problem.requestId}` : ""}
          </small>
        </div>
      </div>
    )
  );
}

export type LegacyHostProps = {
  /** Current router pathname; the host keeps no routing state of its own. */
  pathname: string;
  navigate: (path: string, options?: { completed?: boolean }) => void;
};

/**
 * The pages that are not rebuilt yet: the job lookup, the audit publication snapshot and the
 * management API-key panel. Every other page is a routed page with its own data layer. The shell
 * renders this host once and keeps it mounted so an unconfirmed key operation survives navigation.
 */
export default function LegacyHost({ pathname }: LegacyHostProps) {
  // The session layer owns the ControlClient, the confirmed scope, roles, idle expiry and the
  // epoch shared with every TanStack query. This host keeps only per-view state.
  const session = useSession();
  const { store } = session.runtime;
  const connected = session.state.status === "connected";
  const client = session.state.client;
  const scope = session.state.scope;
  // `null` is the explicitly enabled local machine-login mode. Browser
  // sessions always carry the server-provided role list.
  const managementRoles = session.state.roles as string[] | null;
  // View generation: bumped whenever the visible view changes, so a response of an earlier view
  // cannot repaint. Distinct from the session epoch, which only moves on connect/disconnect.
  const lifetime = useRef(new AbortController());
  const viewGeneration = useRef(0);
  // Declared before every effect that issues a request: React replays effects in order on a
  // StrictMode remount, so the request signal must be renewed before a loader runs again.
  useEffect(() => {
    // StrictMode replays setup/cleanup; a new mount needs a live request signal.
    if (lifetime.current.signal.aborted) lifetime.current = new AbortController();
    return () => lifetime.current.abort();
  }, []);
  const operations = useRef<Record<Channel, number>>({ query: 0, health: 0 });
  const [jobId, setJobId] = useState("");
  const queryKind = routeQueryKind(pathname);
  const [job, setJob] = useState<JobResponse | null>(null);
  const [health, setHealth] = useState<AuditHealthResponse | null>(null);
  const [busy, setBusy] = useState<Partial<Record<Channel, boolean>>>({});
  const [problems, setProblems] = useState<Partial<Record<Channel, Problem>>>({});
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  const clearResults = useCallback(() => {
    lifetime.current.abort();
    lifetime.current = new AbortController();
    viewGeneration.current += 1;
    setHealth(null);
    setJob(null);
    setProblems({});
    setBusy({});
  }, []);

  // Whatever ends the session (idle, logout, 401, scope violation, pagehide, or a TanStack
  // query noticing one of those) also clears this host's per-view state, and the other way
  // round: `disconnect` below ends the shared session and with it the query cache.
  useEffect(
    () =>
      store.onDisconnect(() => {
        clearResults();
        setJobId("");
        setSessionNotice(null);
      }),
    [store, clearResults],
  );
  const disconnect = session.disconnect;

  // Leaving the page invalidates every in-flight response before another view can render.
  const previousPath = useRef(pathname);
  useLayoutEffect(() => {
    const before = previousPath.current;
    if (before === pathname) return;
    previousPath.current = pathname;
    clearResults();
    setJobId("");
  }, [pathname, clearResults]);

  useEffect(() => {
    const target = routeTarget(pathname, queryKind);
    if (target) setJobId(target);
  }, [pathname, queryKind]);

  // Every response belongs to a view generation, a session epoch and one authenticated scope.
  // Abort alone cannot stop already-resolved promises from repainting old data.
  async function run<T extends { tenant_id: string; site_id: string }>(
    channel: Channel,
    fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
    apply: (response: T) => void,
    fail?: (error: unknown) => void,
    expectedSiteId?: string,
  ): Promise<boolean> {
    const start = store.getState();
    const api = start.client;
    if (!api || start.status !== "connected") return false;
    const generation = viewGeneration.current;
    const sessionEpoch = start.epoch;
    const operation = ++operations.current[channel];
    const signal = AbortSignal.any([lifetime.current.signal, store.signal]);
    const current = () =>
      viewGeneration.current === generation &&
      store.isCurrent(sessionEpoch) &&
      operations.current[channel] === operation &&
      !signal.aborted;
    setBusy((value) => ({ ...value, [channel]: true }));
    setProblems((value) => ({ ...value, [channel]: undefined }));
    try {
      const response = await fetcher(api, signal);
      if (!current()) return false;
      const verdict = store.verifyScope(response, expectedSiteId);
      if (verdict === "wrong_site") throw new ApiError("INVALID_RESPONSE");
      // A cross-tenant or cross-site reply has already ended the session (and cleared this host).
      if (verdict === "mismatch") return false;
      apply(response);
      return true;
    } catch (error) {
      if (!current()) return false;
      if (error instanceof ApiError && error.status === 401) {
        disconnect(unauthorizedNotice);
      } else {
        fail?.(error);
        const problem =
          error instanceof ApiError
            ? {
                message: error.message,
                code: error.code,
                requestId: error.requestId,
                status: error.status,
              }
            : {
                message: "查询未完成，请稍后重试。",
                code: "CONSOLE_REQUEST_FAILED",
              };
        setProblems((value) => ({ ...value, [channel]: problem }));
      }
      return false;
    } finally {
      if (current()) setBusy((value) => ({ ...value, [channel]: false }));
    }
  }

  function queryJob(event: FormEvent) {
    event.preventDefault();
    clearResults();
    const target = jobId.trim();
    setJobId(target);
    void run(
      "query",
      (api, signal) => api.job(target, signal),
      (response) => setJob(response),
    );
  }
  function loadHealth() {
    void run(
      "health",
      (api, signal) => api.health(signal),
      (response) => setHealth(response),
    );
  }
  // While connected, in-session notices are local; once the session ended, why it ended.
  const notice = connected ? sessionNotice : (sessionNotice ?? session.state.notice);

  return (
    <div className="legacy">
      {notice && (
        <div className="notice" role="status">
          {notice}
        </div>
      )}
      <>
        {queryKind === "jobs" && job && (
          <section className="panel" aria-label="后台任务详情">
            <h2>任务状态</h2>
            {job.job ? (
              <dl className="session-grid">
                <div>
                  <dt>任务</dt>
                  <dd>{job.job.job_id}</dd>
                </div>
                <div>
                  <dt>案件</dt>
                  <dd>{job.job.case_id}</dd>
                </div>
                <div>
                  <dt>状态</dt>
                  <dd>{job.job.status}</dd>
                </div>
                <div>
                  <dt>原因</dt>
                  <dd>{job.job.reason_code}</dd>
                </div>
                <div>
                  <dt>证据数量</dt>
                  <dd>{job.job.artifact_count}</dd>
                </div>
              </dl>
            ) : (
              <p>当前主体范围内未找到该任务。</p>
            )}
          </section>
        )}
        {queryKind === "jobs" && (
          <form className="panel query-form" onSubmit={queryJob}>
            <label htmlFor="job-id">任务 ID</label>
            <input
              id="job-id"
              className="mono"
              placeholder="job_…"
              value={jobId}
              onChange={(e) => {
                clearResults();
                setJobId(e.target.value);
              }}
              autoComplete="off"
              spellCheck={false}
              maxLength={40}
              required
              pattern="job_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
              title="请输入规范的 job_ 前缀 UUIDv7"
            />
            <button type="submit" disabled={busy.query}>
              {busy.query ? "查询中…" : "查询"}
            </button>
          </form>
        )}
        <Failure problem={problems.query ?? null} />
        <Failure problem={problems.health ?? null} />
        {queryKind === "api-keys" &&
          client &&
          scope &&
          (managementRoles?.includes("system_admin") ||
            managementRoles?.includes("key_administrator")) && (
            <Deferred>
              <ManagementApiKeyPanel
                client={client}
                tenantId={scope.tenant_id}
                onNotice={setSessionNotice}
              />
            </Deferred>
          )}
        {queryKind === "audit-health" ? (
          <AuditHealthPanel response={health} busy={Boolean(busy.health)} onRefresh={loadHealth} />
        ) : (
          queryKind === "jobs" &&
          !job &&
          !busy.query &&
          !problems.query && (
            <section className="panel empty-state">
              <h2>查询后台任务</h2>
              <p className="muted">输入任务 ID，读取后台任务的当前状态与原因码。</p>
            </section>
          )
        )}
      </>
    </div>
  );
}
