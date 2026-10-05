import type { FormEvent } from "react";
import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiError, validateModelCallListPlan } from "../api";
import type {
  AgentRunResponse,
  ArtifactResponse,
  AuditHealthResponse,
  CalibrationReportResponse,
  ControlClient,
  JobResponse,
  ModelCallListPlan,
  ModelCallListResponse,
  ModelCallResponse,
} from "../api";
import { routeQueryKind, routeTarget } from "../admin-routes";
import type { SearchPreset } from "../investigation/search-preset.ts";
import { useInvestigationNavigate } from "../investigation/navigation.ts";
import type { BindingResponse, GrantResponse } from "../ledger";
import {
  AgentRunOverview,
  ArtifactDetail,
  AuditHealthPanel,
  CalibrationReportPanel,
  ModelCallListPanel,
  ModelCallOverview,
} from "../panels";
import { useSession } from "../security/SessionProvider";
import { unauthorizedNotice } from "../security/session-store.ts";

// Heavy panels load the first time their page is opened. The four workbenches below keep their
// unconfirmed-write state across navigation, so once mounted they stay mounted (hidden).
const LedgerPanel = lazy(() =>
  import("../LedgerPanel").then((module) => ({ default: module.LedgerPanel })),
);
const ManagementApiKeyPanel = lazy(() =>
  import("../ManagementApiKeyPanel").then((module) => ({ default: module.ManagementApiKeyPanel })),
);

function Deferred({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<p className="empty">正在加载页面…</p>}>{children}</Suspense>;
}

type Problem = { message: string; code: string; requestId?: string | null; status?: number };
type Channel = "query" | "events" | "evidence" | "artifact" | "health";
const queryLabels = {
  request: "请求 ID",
  model: "模型调用 ID",
  agent: "Agent 运行 ID",
  "calibration-report": "校准报告 ID",
  grant: "资格 ID",
  binding: "身份绑定 ID",
  jobs: "任务 ID",
};
const queryPrefixes = {
  request: "req",
  model: "mdl",
  agent: "agt",
  "calibration-report": "calr",
  grant: "grant",
  binding: "auth",
  jobs: "job",
};
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

/** Kinds whose content is a routed page now; the host renders nothing of its own for them. */
const routedKinds: ReadonlySet<string> = new Set(["request", "search"]);

/**
 * The pre-redesign pages, kept working while they are rebuilt one by one on the routed data
 * layer. The shell renders it once and keeps it mounted so unconfirmed writes survive navigation.
 */
export default function LegacyHost({ pathname, navigate: go }: LegacyHostProps) {
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
  const operations = useRef<Record<Channel, number>>({
    query: 0,
    events: 0,
    evidence: 0,
    artifact: 0,
    health: 0,
  });
  const [requestId, setRequestId] = useState("");
  const queryKind = routeQueryKind(pathname);
  const [ledger, setLedger] = useState<GrantResponse | BindingResponse | null>(null);
  const [model, setModel] = useState<ModelCallResponse | null>(null);
  const [agentRun, setAgentRun] = useState<AgentRunResponse | null>(null);
  const [modelListPlan, setModelListPlan] = useState<ModelCallListPlan | null>(null);
  const [modelList, setModelList] = useState<ModelCallListResponse | null>(null);
  const [job, setJob] = useState<JobResponse | null>(null);
  const [health, setHealth] = useState<AuditHealthResponse | null>(null);
  const [calibrationReport, setCalibrationReport] = useState<CalibrationReportResponse | null>(
    null,
  );
  const [artifact, setArtifact] = useState<ArtifactResponse | null>(null);
  const [busy, setBusy] = useState<Partial<Record<Channel, boolean>>>({});
  const [problems, setProblems] = useState<Partial<Record<Channel, Problem>>>({});
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  const clearResults = useCallback(() => {
    lifetime.current.abort();
    lifetime.current = new AbortController();
    viewGeneration.current += 1;
    setModel(null);
    setAgentRun(null);
    setModelListPlan(null);
    setModelList(null);
    setHealth(null);
    setJob(null);
    setCalibrationReport(null);
    setLedger(null);
    setArtifact(null);
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
        setRequestId("");
        setSessionNotice(null);
      }),
    [store, clearResults],
  );
  const disconnect = session.disconnect;

  const navigate = useCallback((path: string, completed = false) => go(path, { completed }), [go]);
  const investigation = useInvestigationNavigate();

  // Leaving the page invalidates every in-flight response before another view can render.
  const previousPath = useRef(pathname);
  useLayoutEffect(() => {
    const before = previousPath.current;
    if (before === pathname) return;
    previousPath.current = pathname;
    clearResults();
    setRequestId("");
  }, [pathname, clearResults]);

  useEffect(() => {
    const target = routeTarget(pathname, queryKind);
    if (target) setRequestId(target);
  }, [pathname, queryKind]);

  useEffect(() => {
    if (!connected) return;
    const target = routeTarget(pathname, queryKind);
    if (!target) return;
    if (queryKind === "model")
      void run(
        "query",
        (api, signal) => api.modelCall(target, signal),
        (response) => setModel(response),
      );
    else if (queryKind === "agent")
      void run(
        "query",
        (api, signal) => api.agentRun(target, signal),
        (response) => setAgentRun(response),
      );
    else if (queryKind === "grant")
      void run(
        "query",
        (api, signal) => api.grant(target, signal),
        (response) => setLedger(response),
      );
    else if (queryKind === "binding") loadBinding(target);
    else if (queryKind === "calibration-report") loadCalibrationReport(target);
  }, [connected, pathname, queryKind]);

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

  function clearArtifact() {
    operations.current.artifact += 1;
    setArtifact(null);
    setBusy((value) => ({ ...value, artifact: false }));
    setProblems((value) => ({ ...value, artifact: undefined }));
  }
  function query(event: FormEvent) {
    event.preventDefault();
    if (queryKind === "model-list" || queryKind === "audit-health") return;
    clearResults();
    const target = requestId.trim();
    setRequestId(target);
    if (queryKind === "model") {
      void run(
        "query",
        (api, signal) => api.modelCall(target, signal),
        (response) => setModel(response),
      );
      return;
    }
    if (queryKind === "jobs") {
      void run(
        "query",
        (api, signal) => api.job(target, signal),
        (response) => setJob(response),
      );
      return;
    }
    if (queryKind === "agent") {
      void run(
        "query",
        (api, signal) => api.agentRun(target, signal),
        (response) => setAgentRun(response),
      );
      return;
    }
    if (queryKind === "calibration-report") {
      void run(
        "query",
        (api, signal) => api.calibrationReport(target, signal),
        (response) => setCalibrationReport(response),
      );
      return;
    }
    if (queryKind === "grant") {
      void run(
        "query",
        (api, signal) => api.grant(target, signal),
        (response) => setLedger(response),
      );
      return;
    }
    if (queryKind === "binding") {
      loadBinding(target);
      return;
    }
  }
  function loadBinding(target: string) {
    void run(
      "query",
      (api, signal) => api.binding(target, signal),
      (response) => setLedger(response),
    );
  }
  function loadModelCalls(value: unknown, cursor?: string) {
    let plan: ModelCallListPlan;
    try {
      plan = validateModelCallListPlan(value);
    } catch {
      clearResults();
      void run(
        "query",
        (api, signal) => api.modelCalls(value, cursor, signal),
        () => {},
      );
      return;
    }
    clearResults();
    void run(
      "query",
      (api, signal) => api.modelCalls(plan, cursor, signal),
      (response) => {
        setModelListPlan(plan);
        setModelList(response);
      },
    );
  }
  function loadHealth() {
    void run(
      "health",
      (api, signal) => api.health(signal),
      (response) => setHealth(response),
    );
  }
  function loadCalibrationReport(target = requestId.trim()) {
    clearResults();
    setRequestId(target);
    void run(
      "query",
      (api, signal) => api.calibrationReport(target, signal),
      (response) => setCalibrationReport(response),
    );
  }
  function openTarget(kind: "request" | "binding" | "model" | "agent", id: string) {
    clearResults();
    const route =
      kind === "request"
        ? `/investigation/requests/${id}`
        : kind === "model"
          ? `/investigation/models/${id}`
          : kind === "agent"
            ? `/investigation/agents/${id}`
            : `/investigation/bindings/${id}`;
    navigate(route);
  }
  /** Opens the search page with one condition filled in; nothing is queried until you submit. */
  function prepareSearchHistory(preset: SearchPreset) {
    clearResults();
    investigation.openSearch(preset);
  }
  function openArtifact(id: string) {
    setArtifact(null);
    void run(
      "artifact",
      (api, signal) => api.artifact(id, signal),
      (response) => setArtifact(response),
    );
  }
  // While connected, in-session notices are local; once the session ended, why it ended.
  const notice = connected ? sessionNotice : (sessionNotice ?? session.state.notice);

  // Routed pages render their own content. The host stays mounted (and hidden by the shell) on
  // them so that the workbenches below keep their frozen, unconfirmed writes across navigation.
  const routed = routedKinds.has(queryKind);

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
        {["model", "agent", "calibration-report", "grant", "binding", "jobs"].includes(
          queryKind,
        ) && (
          <form className="panel query-form" onSubmit={query}>
            <label htmlFor="request-id">{queryLabels[queryKind as keyof typeof queryLabels]}</label>
            <input
              id="request-id"
              className="mono"
              placeholder={`${queryPrefixes[queryKind as keyof typeof queryPrefixes]}_…`}
              value={requestId}
              onChange={(e) => {
                clearResults();
                setRequestId(e.target.value);
              }}
              autoComplete="off"
              spellCheck={false}
              maxLength={
                (queryPrefixes[queryKind as keyof typeof queryPrefixes] ?? "req").length + 37
              }
              required
              pattern={`${queryPrefixes[queryKind as keyof typeof queryPrefixes]}_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}`}
              title={`请输入规范的 ${queryPrefixes[queryKind as keyof typeof queryPrefixes]}_ 前缀 UUIDv7`}
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
        {queryKind === "model-list" ? (
          <ModelCallListPanel
            response={modelList}
            plan={modelListPlan}
            busy={Boolean(busy.query)}
            onEdit={clearResults}
            onSubmit={(value) => loadModelCalls(value)}
            onNext={() => {
              if (modelListPlan && modelList?.next_cursor)
                loadModelCalls(modelListPlan, modelList.next_cursor);
            }}
            onOpen={(id) => openTarget("model", id)}
          />
        ) : queryKind === "audit-health" ? (
          <AuditHealthPanel response={health} busy={Boolean(busy.query)} onRefresh={loadHealth} />
        ) : queryKind === "calibration-report" ? (
          <CalibrationReportPanel
            response={calibrationReport}
            busy={Boolean(busy.query)}
            onRefresh={() => loadCalibrationReport()}
            onHistory={(reportId) => {
              prepareSearchHistory({
                kind: "calibration_report_id",
                value: reportId,
              });
            }}
          />
        ) : ledger ? (
          <Deferred>
            <LedgerPanel
              response={ledger}
              onBinding={(id) => openTarget("binding", id)}
              onRequest={(id) => openTarget("request", id)}
              onHistory={(preset) => {
                prepareSearchHistory(preset);
              }}
            />
          </Deferred>
        ) : model ? (
          <>
            <ModelCallOverview
              response={model}
              onOpen={openArtifact}
              onHistory={(modelCallId) => {
                prepareSearchHistory({
                  kind: "model_call_id",
                  value: modelCallId,
                });
              }}
              onPreviousEvent={(id) => prepareSearchHistory({ kind: "event_id", value: id })}
              onFollowEvent={(id) =>
                prepareSearchHistory({ kind: "caused_by_event_id", value: id })
              }
            />
            {(artifact || busy.artifact || problems.artifact) && (
              <section className="panel detail-panel" aria-label="模型证据详情" aria-live="polite">
                <div className="panel-heading">
                  <h2>证据详情</h2>
                  <button className="text-button" onClick={clearArtifact}>
                    关闭详情
                  </button>
                </div>
                <Failure problem={problems.artifact ?? null} />
                {busy.artifact ? (
                  <p className="empty" role="status">
                    正在读取证据元数据…
                  </p>
                ) : (
                  artifact && <ArtifactDetail response={artifact} />
                )}
              </section>
            )}
          </>
        ) : agentRun ? (
          <>
            <AgentRunOverview
              response={agentRun}
              onOpen={openArtifact}
              onRequest={(id) => openTarget("request", id)}
              onHistory={(agentRunId) => {
                prepareSearchHistory({
                  kind: "agent_run_id",
                  value: agentRunId,
                });
              }}
            />
            {(artifact || busy.artifact || problems.artifact) && (
              <section
                className="panel detail-panel"
                aria-label="Agent 证据详情"
                aria-live="polite"
              >
                <div className="panel-heading">
                  <h2>证据详情</h2>
                  <button className="text-button" onClick={clearArtifact}>
                    关闭详情
                  </button>
                </div>
                <Failure problem={problems.artifact ?? null} />
                {busy.artifact ? (
                  <p className="empty" role="status">
                    正在读取证据元数据…
                  </p>
                ) : (
                  artifact && <ArtifactDetail response={artifact} />
                )}
              </section>
            )}
          </>
        ) : (
          queryKind !== "api-keys" &&
          !routed &&
          !busy.query &&
          !problems.query && (
            <section className="panel empty-state">
              <h2>
                {queryKind === "model"
                  ? "查询模型调用"
                  : queryKind === "agent"
                    ? "查询 Agent 运行"
                    : "查询账本记录"}
              </h2>
              <p className="muted">
                {queryKind === "model"
                  ? "输入模型调用 ID，读取生命周期与输入、输出、调用记录的证据引用。"
                  : queryKind === "agent"
                    ? "输入 Agent 运行 ID，读取脱敏生命周期与固定事件引用。"
                    : `输入${queryLabels[queryKind as keyof typeof queryLabels] ?? "目标 ID"}，读取当前状态、代际与期限。`}
              </p>
            </section>
          )
        )}
      </>
    </div>
  );
}
