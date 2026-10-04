import { useBlocker } from "@tanstack/react-router";
import type { FormEvent, KeyboardEvent } from "react";
import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiError, validateModelCallListPlan } from "../api";
import type {
  AgentRunResponse,
  ArtifactResponse,
  AuditHealthResponse,
  CalibrationReportResponse,
  ControlClient,
  EventsResponse,
  EvidenceResponse,
  JobResponse,
  ModelCallListPlan,
  ModelCallListResponse,
  ModelCallResponse,
  SiteApplyResponse,
  SiteConfigResponse,
  SiteListItem,
  SiteRevision,
  SummaryResponse,
} from "../api";
import { routeQueryKind, routeTarget, siteRoute } from "../admin-routes";
import type { BindingResponse, GrantResponse } from "../ledger";
import {
  AgentRunOverview,
  ArtifactDetail,
  AuditHealthPanel,
  CalibrationReportPanel,
  EventDetail,
  EventTable,
  EvidenceTable,
  ModelCallListPanel,
  ModelCallOverview,
  RequestOverview,
  WatermarkNotice,
} from "../panels";
import { validateCausalityPlan, validateSearchPlan } from "../search";
import type { CausalityResponse, SearchPlan, SearchResponse } from "../search";
import type { SearchPreset } from "../SearchPanel";
import { useSession } from "../security/SessionProvider";
import { unauthorizedNotice } from "../security/session-store.ts";

// Heavy panels load the first time their page is opened. The four workbenches below keep their
// unconfirmed-write state across navigation, so once mounted they stay mounted (hidden).
const SearchPanel = lazy(() =>
  import("../SearchPanel").then((module) => ({ default: module.SearchPanel })),
);
const LedgerPanel = lazy(() =>
  import("../LedgerPanel").then((module) => ({ default: module.LedgerPanel })),
);
const CasePanel = lazy(() =>
  import("../CasePanel").then((module) => ({ default: module.CasePanel })),
);
const EvidenceAccessPanel = lazy(() =>
  import("../EvidenceAccessPanel").then((module) => ({ default: module.EvidenceAccessPanel })),
);
const EvidenceHoldPanel = lazy(() =>
  import("../EvidenceHoldPanel").then((module) => ({ default: module.EvidenceHoldPanel })),
);
const ExportPanel = lazy(() =>
  import("../ExportPanel").then((module) => ({ default: module.ExportPanel })),
);
const SiteOperationsPanel = lazy(() =>
  import("../SiteOperationsPanel").then((module) => ({ default: module.SiteOperationsPanel })),
);
const SiteConfigPanel = lazy(() =>
  import("../SiteConfigPanel").then((module) => ({ default: module.SiteConfigPanel })),
);
const ManagementApiKeyPanel = lazy(() =>
  import("../ManagementApiKeyPanel").then((module) => ({ default: module.ManagementApiKeyPanel })),
);

/** Mounts its children the first time the page is opened and keeps them (hidden) afterwards. */
function Workbench({ active, children }: { active: boolean; children: React.ReactNode }) {
  const [mounted, setMounted] = useState(active);
  if (active && !mounted) setMounted(true);
  if (!mounted) return null;
  return (
    <div hidden={!active}>
      <Deferred>{children}</Deferred>
    </div>
  );
}

function Deferred({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<p className="empty">正在加载页面…</p>}>{children}</Suspense>;
}

type Problem = { message: string; code: string; requestId?: string | null; status?: number };
type Channel =
  | "query"
  | "events"
  | "evidence"
  | "artifact"
  | "case"
  | "access"
  | "hold"
  | "export"
  | "sites"
  | "health";
const queryLabels = {
  request: "请求 ID",
  model: "模型调用 ID",
  agent: "Agent 运行 ID",
  "calibration-report": "校准报告 ID",
  grant: "资格 ID",
  binding: "身份绑定 ID",
  export: "导出 ID",
  jobs: "任务 ID",
};
const queryPrefixes = {
  request: "req",
  model: "mdl",
  agent: "agt",
  "calibration-report": "calr",
  grant: "grant",
  binding: "auth",
  export: "export",
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
  /** Event search requested from outside the host (the command palette). */
  searchIntent: { preset: SearchPreset; nonce: number } | null;
  onSearchIntentConsumed: () => void;
};

/**
 * The pre-redesign pages, kept working while they are rebuilt one by one on the routed data
 * layer. The shell renders it once and keeps it mounted so unconfirmed writes survive navigation.
 */
export default function LegacyHost({
  pathname,
  navigate: go,
  searchIntent,
  onSearchIntentConsumed,
}: LegacyHostProps) {
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
    case: 0,
    access: 0,
    hold: 0,
    export: 0,
    sites: 0,
    health: 0,
  });
  const [requestId, setRequestId] = useState("");
  const queryKind = routeQueryKind(pathname);
  const currentSite = siteRoute(pathname);
  const [ledger, setLedger] = useState<GrantResponse | BindingResponse | null>(null);
  const [searchPreset, setSearchPreset] = useState<SearchPreset | null>(null);
  const [searchPresetVersion, setSearchPresetVersion] = useState(0);
  const [searchPlan, setSearchPlan] = useState<SearchPlan | null>(null);
  const [search, setSearch] = useState<SearchResponse | null>(null);
  const [causality, setCausality] = useState<CausalityResponse | null>(null);
  const [model, setModel] = useState<ModelCallResponse | null>(null);
  const [agentRun, setAgentRun] = useState<AgentRunResponse | null>(null);
  const [modelListPlan, setModelListPlan] = useState<ModelCallListPlan | null>(null);
  const [modelList, setModelList] = useState<ModelCallListResponse | null>(null);
  const [job, setJob] = useState<JobResponse | null>(null);
  const [health, setHealth] = useState<AuditHealthResponse | null>(null);
  const [calibrationReport, setCalibrationReport] = useState<CalibrationReportResponse | null>(
    null,
  );
  const [siteConfig, setSiteConfig] = useState<SiteConfigResponse | null>(null);
  const [siteStatus, setSiteStatus] = useState<SiteApplyResponse | null>(null);
  const [siteHealth, setSiteHealth] = useState<SiteApplyResponse | null>(null);
  const [siteRevisions, setSiteRevisions] = useState<SiteRevision[]>([]);
  const [siteList, setSiteList] = useState<SiteListItem[]>([]);
  const [siteListCursor, setSiteListCursor] = useState<string | null>(null);
  const selectedSiteId = currentSite?.siteId ?? "";
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [events, setEvents] = useState<EventsResponse | null>(null);
  const [evidence, setEvidence] = useState<EvidenceResponse | null>(null);
  const [artifact, setArtifact] = useState<ArtifactResponse | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<"events" | "evidence">("events");
  const [busy, setBusy] = useState<Partial<Record<Channel, boolean>>>({});
  const [problems, setProblems] = useState<Partial<Record<Channel, Problem>>>({});
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  const clearResults = useCallback(() => {
    lifetime.current.abort();
    lifetime.current = new AbortController();
    viewGeneration.current += 1;
    setSummary(null);
    setModel(null);
    setAgentRun(null);
    setModelListPlan(null);
    setModelList(null);
    setHealth(null);
    setJob(null);
    setCalibrationReport(null);
    setSiteConfig(null);
    setSiteHealth(null);
    setSiteStatus(null);
    setSiteRevisions([]);
    setLedger(null);
    setSearchPlan(null);
    setSearch(null);
    setCausality(null);
    setEvents(null);
    setEvidence(null);
    setArtifact(null);
    setSelected(null);
    setTab("events");
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
        setSiteList([]);
        setSiteListCursor(null);
        setSearchPreset(null);
        setSessionNotice(null);
      }),
    [store, clearResults],
  );
  const disconnect = session.disconnect;

  const siteUnsaved = useRef(false);
  const pendingPreset = useRef<SearchPreset | null>(null);
  const setSiteUnsaved = useCallback((value: boolean) => {
    siteUnsaved.current = value;
  }, []);
  const navigate = useCallback((path: string, completed = false) => go(path, { completed }), [go]);

  // Leaving the page invalidates every in-flight response before another view can render;
  // the categories of one site editing session are the exception.
  const previousPath = useRef(pathname);
  useLayoutEffect(() => {
    const before = previousPath.current;
    if (before === pathname) return;
    previousPath.current = pathname;
    const previous = siteRoute(before);
    const next = siteRoute(pathname);
    if (!previous || !next || previous.siteId !== next.siteId) {
      clearResults();
      siteUnsaved.current = false;
    }
    setRequestId("");
    const preset = pendingPreset.current;
    pendingPreset.current = null;
    if (preset && routeQueryKind(pathname) === "search") {
      setSearchPreset(preset);
      setSearchPresetVersion((version) => version + 1);
    } else {
      setSearchPreset(null);
    }
  }, [pathname, clearResults]);

  // An unsaved site draft or unconfirmed operation asks before the page is left. The router
  // consults this for links, programmatic navigation and back/forward alike; the panels
  // install their own beforeunload warning for reloads.
  useBlocker({
    shouldBlockFn: ({ current, next }) => {
      const before = siteRoute(current.pathname);
      const after = siteRoute(next.pathname);
      if (!siteUnsaved.current || (before && after && before.siteId === after.siteId)) {
        return false;
      }
      return !window.confirm("当前站点有未保存草稿或待确认操作。确定离开？");
    },
    enableBeforeUnload: false,
  });

  // A search requested from outside (the command palette) is applied once the session is live.
  useEffect(() => {
    if (!searchIntent || !connected) return;
    prepareSearchHistory(searchIntent.preset);
    onSearchIntentConsumed();
  }, [searchIntent, connected]);
  useEffect(() => {
    const target = routeTarget(pathname, queryKind);
    if (target) setRequestId(target);
  }, [pathname, queryKind]);

  useEffect(() => {
    if (!connected) return;
    const target = routeTarget(pathname, queryKind);
    if (!target) return;
    if (queryKind === "request") loadRequest(target);
    else if (queryKind === "model")
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

  useEffect(() => {
    if (connected && queryKind === "site-config") loadSiteConfig();
  }, [connected, queryKind, selectedSiteId]);

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
  function loadEvents(target: string, cursor?: string) {
    setEvents(null);
    setSelected(null);
    clearArtifact();
    void run(
      "events",
      (api, signal) => api.events(target, cursor, signal),
      (response) => {
        setEvents(response);
        setSelected(response.events.at(-1)?.event_id ?? null);
      },
    );
  }
  function query(event: FormEvent) {
    event.preventDefault();
    if (
      queryKind === "search" ||
      queryKind === "case" ||
      queryKind === "access" ||
      queryKind === "hold" ||
      queryKind === "export" ||
      queryKind === "model-list" ||
      queryKind === "audit-health" ||
      queryKind === "site-config"
    )
      return;
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
    loadRequest(target);
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
  function loadSiteConfig(cursor?: string, append = false) {
    if (currentSite) {
      if (!currentSite.creating) loadSiteDetails(currentSite.siteId);
      return;
    }
    void run(
      "sites",
      (api, signal) => api.siteList(signal, cursor),
      (response) => {
        setSiteList((current) => {
          if (!append) return response.sites;
          const seen = new Set(current.map((site) => site.site_id));
          return [...current, ...response.sites.filter((site) => !seen.has(site.site_id))];
        });
        setSiteListCursor(response.next_cursor);
      },
    );
  }
  function loadSiteDetails(siteId: string) {
    if (managementRoles !== null && !managementRoles.includes("system_admin")) {
      if (managementRoles.includes("observer")) {
        void run(
          "query",
          (api, signal) => api.siteStatus(siteId, signal),
          (response) => setSiteStatus(response),
          undefined,
          siteId,
        );
        void run(
          "sites",
          (api, signal) => api.siteRevisions(siteId, signal),
          (response) => setSiteRevisions(response.revisions),
          undefined,
          siteId,
        );
      }
      return;
    }
    void run(
      "query",
      async (api, signal) => {
        const config = await api.siteConfig(siteId, signal);
        // Each response is checked before combining projections. A revision
        // response from another tenant/site must never be silently merged.
        if (config.site_id !== siteId) throw new ApiError("INVALID_RESPONSE");
        return config;
      },
      (response) => setSiteConfig(response),
      undefined,
      siteId,
    );
    if (managementRoles === null || managementRoles.includes("observer")) {
      void run(
        "sites",
        async (api, signal) => {
          const response = await api.siteRevisions(siteId, signal);
          if (response.site_id !== siteId) throw new ApiError("INVALID_RESPONSE");
          return response;
        },
        (response) => setSiteRevisions(response.revisions),
        undefined,
        siteId,
      );
    }
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
    setSearchPreset(null);
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
  function prepareSearchHistory(preset: SearchPreset) {
    clearResults();
    if (routeQueryKind(pathname) === "search") {
      setSearchPreset(preset);
      setSearchPresetVersion((version) => version + 1);
      setRequestId("");
      return;
    }
    pendingPreset.current = preset;
    navigate("/investigation/search");
  }
  function loadRequest(target: string) {
    void run(
      "query",
      (api, signal) => api.summary(target, signal),
      (response) => {
        setSummary(response);
        loadEvents(target);
      },
    );
  }
  function searchEvents(value: unknown, cursor?: string) {
    clearResults();
    void run(
      "query",
      (api, signal) => {
        const plan = validateSearchPlan(value);
        setSearchPlan(plan);
        return api.search(plan, cursor, signal);
      },
      (response) => {
        setSearch(response);
        setSelected(response.events[0]?.event_id ?? null);
      },
    );
  }
  function loadCausality(value: unknown) {
    setCausality(null);
    void run(
      "query",
      (api, signal) => {
        const plan = validateCausalityPlan(value);
        return api.causality(plan, signal);
      },
      (response) => setCausality(response),
    );
  }
  function invalidateCausality() {
    operations.current.query += 1;
    setCausality(null);
    setBusy((value) => ({ ...value, query: false }));
    setProblems((value) => ({ ...value, query: undefined }));
  }
  function loadEvidence(cursor?: string) {
    if (!summary) return;
    setEvidence(null);
    clearArtifact();
    void run(
      "evidence",
      (api, signal) => api.evidence(summary.source_request_id, cursor, signal),
      (response) => setEvidence(response),
    );
  }
  function openArtifact(id: string) {
    setArtifact(null);
    void run(
      "artifact",
      (api, signal) => api.artifact(id, signal),
      (response) => setArtifact(response),
    );
  }
  function switchTab(next: "events" | "evidence") {
    clearArtifact();
    setTab(next);
    if (next === "evidence" && !evidence && !busy.evidence) loadEvidence();
  }
  function tabKey(event: KeyboardEvent<HTMLDivElement>) {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const next =
      event.key === "Home"
        ? "events"
        : event.key === "End"
          ? "evidence"
          : tab === "events"
            ? "evidence"
            : "events";
    switchTab(next);
    document.getElementById(`${next}-tab`)?.focus();
  }
  const event = (search?.events ?? events?.events)?.find((value) => value.event_id === selected);
  const relatedEvents = search?.events ?? events?.events ?? (event ? [event] : []);
  const eventDetails = (
    <aside className="panel detail-panel" aria-live="polite">
      <div className="panel-heading">
        <h2>{artifact || busy.artifact || problems.artifact ? "证据详情" : "事件详情"}</h2>
        {(artifact || problems.artifact || busy.artifact) && (
          <button className="text-button" onClick={clearArtifact}>
            {queryKind === "case" ? "关闭详情" : "返回事件"}
          </button>
        )}
      </div>
      <Failure problem={problems.artifact ?? null} />
      {busy.artifact ? (
        <p className="empty" role="status">
          正在读取证据元数据…
        </p>
      ) : artifact ? (
        <ArtifactDetail response={artifact} />
      ) : (
        !problems.artifact &&
        (event ? (
          <EventDetail
            event={event}
            relatedEvents={relatedEvents}
            onOpen={openArtifact}
            onRequest={(id) => openTarget("request", id)}
            onModelCall={(id) => openTarget("model", id)}
            onPreviousEvent={(id) => prepareSearchHistory({ kind: "event_id", value: id })}
            onFollowEvent={(id) => prepareSearchHistory({ kind: "caused_by_event_id", value: id })}
            onCausalEvent={(id) => {
              clearArtifact();
              invalidateCausality();
              if (relatedEvents.some((item) => item.event_id === id)) {
                setSelected(id);
              } else {
                prepareSearchHistory({ kind: "event_id", value: id });
              }
            }}
            onTraceId={(traceId) => prepareSearchHistory({ kind: "trace_id", value: traceId })}
            causality={causality}
            causalityBusy={Boolean(busy.query)}
            causalityProblem={problems.query ?? null}
            onCausalityEdit={() => {
              invalidateCausality();
            }}
            onCausalitySubmit={loadCausality}
          />
        ) : (
          <p className="empty">选择一条事件或证据查看详情。</p>
        ))
      )}
    </aside>
  );

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
        {["request", "model", "agent", "calibration-report", "grant", "binding", "jobs"].includes(
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
        <Failure problem={problems.sites ?? null} />
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
        <Workbench active={queryKind === "case"}>
          <CasePanel
            active={queryKind === "case"}
            busy={Boolean(busy.case)}
            onInvalidate={clearResults}
            onRun={(fetcher, apply, fail) => run("case", fetcher, apply, fail)}
            onHistory={(jobId) => {
              prepareSearchHistory({ kind: "job_id", value: jobId });
            }}
            onArtifact={openArtifact}
            artifactDetails={
              queryKind === "case" &&
              (artifact || busy.artifact || problems.artifact) &&
              eventDetails
            }
          />
        </Workbench>
        <Workbench active={queryKind === "access"}>
          <EvidenceAccessPanel
            active={queryKind === "access"}
            busy={Boolean(busy.access)}
            onInvalidate={clearResults}
            onHistory={(accessRequestId) => {
              prepareSearchHistory({
                kind: "evidence_access_request_id",
                value: accessRequestId,
              });
            }}
            onRun={(fetcher, apply, fail) => run("access", fetcher, apply, fail)}
          />
        </Workbench>
        <Workbench active={queryKind === "hold"}>
          <EvidenceHoldPanel
            active={queryKind === "hold"}
            busy={Boolean(busy.hold)}
            onInvalidate={clearResults}
            onHistory={(holdId) => {
              prepareSearchHistory({ kind: "evidence_hold_id", value: holdId });
            }}
            onRun={(fetcher, apply, fail) => run("hold", fetcher, apply, fail)}
          />
        </Workbench>
        <Workbench active={queryKind === "export"}>
          <ExportPanel
            active={queryKind === "export"}
            busy={Boolean(busy.export)}
            onInvalidate={clearResults}
            onRun={(fetcher, apply, fail) => run("export", fetcher, apply, fail)}
          />
        </Workbench>
        {queryKind === "site-config" &&
        currentSite &&
        managementRoles !== null &&
        !managementRoles.includes("system_admin") ? (
          <Deferred>
            <SiteOperationsPanel
              key={selectedSiteId}
              siteId={selectedSiteId}
              section={currentSite.section}
              roles={managementRoles}
              status={siteStatus}
              health={siteHealth}
              revisions={siteRevisions}
              busy={Boolean(busy.query || busy.sites || busy.health)}
              failed={Boolean(problems.query || problems.sites)}
              onRefresh={() => loadSiteDetails(selectedSiteId)}
              onNavigate={navigate}
              onUnsavedChange={setSiteUnsaved}
              onHealth={() => {
                setSiteHealth(null);
                void run(
                  "health",
                  (api, signal) => api.siteHealth(selectedSiteId, signal),
                  (response) => setSiteHealth(response),
                  undefined,
                  selectedSiteId,
                );
              }}
              onValidate={() =>
                run(
                  "query",
                  (api, signal) => api.validateSite(selectedSiteId, signal),
                  (response) =>
                    setSessionNotice(
                      response.valid ? "配置验证通过。" : "配置验证未通过：" + response.reason_code,
                    ),
                  undefined,
                  selectedSiteId,
                )
              }
              onApply={(key) =>
                run(
                  "query",
                  (api, signal) => api.applySite(selectedSiteId, key, signal),
                  () => loadSiteDetails(selectedSiteId),
                  undefined,
                  selectedSiteId,
                )
              }
              onApprove={(key) =>
                run(
                  "query",
                  (api, signal) => api.approveSite(selectedSiteId, key, signal),
                  () => loadSiteDetails(selectedSiteId),
                  undefined,
                  selectedSiteId,
                )
              }
              onRollback={(key) =>
                run(
                  "query",
                  (api, signal) => api.rollbackSite(selectedSiteId, key, signal),
                  () => loadSiteDetails(selectedSiteId),
                  undefined,
                  selectedSiteId,
                )
              }
            />
          </Deferred>
        ) : queryKind === "site-config" ? (
          <Deferred>
            <SiteConfigPanel
              roles={managementRoles}
              onUnsavedChange={setSiteUnsaved}
              health={siteHealth}
              healthBusy={Boolean(busy.health)}
              onHealth={() => {
                setSiteHealth(null);
                void run(
                  "health",
                  (api, signal) => api.siteHealth(selectedSiteId, signal),
                  (response) => setSiteHealth(response),
                  undefined,
                  selectedSiteId,
                );
              }}
              response={siteConfig}
              sites={siteList}
              nextCursor={siteListCursor}
              key={selectedSiteId || "list"}
              selectedSiteId={currentSite?.creating ? "" : selectedSiteId}
              creating={currentSite?.creating ?? false}
              onNavigate={navigate}
              busy={Boolean(busy.query || busy.sites)}
              failed={Boolean(problems.query || problems.sites)}
              onRefresh={() => loadSiteConfig()}
              onLoadMore={() => {
                if (siteListCursor) void loadSiteConfig(siteListCursor, true);
              }}
              listView={pathname === "/sites"}
              section={currentSite?.section ?? "overview"}
              onSelectSite={(siteId) => {
                navigate(`/sites/${siteId}/overview`);
              }}
              onSave={(siteId, draft, key) => {
                const creating = currentSite?.creating === true;
                return run(
                  "query",
                  (api, signal) =>
                    creating
                      ? api.createSite(siteId, draft, key, signal)
                      : api.saveSiteConfig(siteId, draft, key, signal),
                  (response) => {
                    setSiteConfig(response);
                    if (creating) navigate("/sites/" + siteId + "/overview", true);
                  },
                  undefined,
                  siteId,
                );
              }}
              onValidate={(siteId) => {
                return run(
                  "query",
                  (api, signal) => api.validateSite(siteId, signal),
                  (result) => {
                    setSessionNotice(
                      result.valid ? "配置验证通过。" : "配置验证未通过：" + result.reason_code,
                    );
                  },
                  undefined,
                  siteId,
                );
              }}
              onApply={(siteId, key) =>
                run(
                  "query",
                  (api, signal) => api.applySite(siteId, key, signal),
                  () => loadSiteDetails(siteId),
                  undefined,
                  siteId,
                )
              }
              onApprove={(siteId, key) =>
                run(
                  "query",
                  (api, signal) => api.approveSite(siteId, key, signal),
                  () => loadSiteDetails(siteId),
                  undefined,
                  siteId,
                )
              }
              revisions={siteRevisions}
              onRollback={(siteId, key) =>
                run(
                  "query",
                  (api, signal) => api.rollbackSite(siteId, key, signal),
                  () => loadSiteDetails(siteId),
                  undefined,
                  siteId,
                )
              }
              onOpenInvestigation={() => {
                navigate("/investigation/requests");
              }}
            />
          </Deferred>
        ) : queryKind === "case" ||
          queryKind === "hold" ||
          queryKind === "access" ||
          queryKind === "export" ? null : queryKind === "search" ? (
          <Deferred>
            <SearchPanel
              key={searchPresetVersion}
              response={search}
              initialFilter={searchPreset}
              plan={searchPlan}
              busy={Boolean(busy.query)}
              selected={selected}
              details={eventDetails}
              onEdit={clearResults}
              onSubmit={searchEvents}
              onNext={() => {
                if (searchPlan && search?.next_cursor) searchEvents(searchPlan, search.next_cursor);
              }}
              onSelect={(id) => {
                clearArtifact();
                invalidateCausality();
                setSelected(id);
              }}
            />
          </Deferred>
        ) : queryKind === "model-list" ? (
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
        ) : summary ? (
          <>
            <WatermarkNotice summary={summary} events={events} />
            <RequestOverview response={summary} />
            <div className="tabs" role="tablist" aria-label="调查内容" onKeyDown={tabKey}>
              <button
                id="events-tab"
                role="tab"
                tabIndex={tab === "events" ? 0 : -1}
                aria-selected={tab === "events"}
                aria-controls="investigation-panel"
                onClick={() => switchTab("events")}
              >
                事件时间线
              </button>
              <button
                id="evidence-tab"
                role="tab"
                tabIndex={tab === "evidence" ? 0 : -1}
                aria-selected={tab === "evidence"}
                aria-controls="investigation-panel"
                onClick={() => switchTab("evidence")}
              >
                证据引用
              </button>
            </div>
            <div className="investigation-grid">
              <section
                className="panel"
                id="investigation-panel"
                role="tabpanel"
                aria-labelledby={`${tab}-tab`}
                aria-busy={Boolean(busy[tab])}
              >
                <div className="panel-heading">
                  <h2>{tab === "events" ? "事件时间线" : "证据引用"}</h2>
                  <span className="muted">
                    本页{" "}
                    {tab === "events"
                      ? (events?.events.length ?? 0)
                      : (evidence?.artifacts.length ?? 0)}{" "}
                    条
                  </span>
                </div>
                <Failure problem={problems[tab] ?? null} />
                {problems[tab] ? null : busy[tab] ? (
                  <p className="empty" role="status">
                    正在读取{tab === "events" ? "事件" : "证据目录"}…
                  </p>
                ) : tab === "events" ? (
                  <EventTable
                    events={events?.events ?? []}
                    selected={selected}
                    onSelect={(id) => {
                      clearArtifact();
                      invalidateCausality();
                      setSelected(id);
                    }}
                  />
                ) : (
                  <EvidenceTable artifacts={evidence?.artifacts ?? []} onOpen={openArtifact} />
                )}
                <div className="pagination">
                  <button
                    className="outline"
                    disabled={
                      Boolean(busy[tab]) ||
                      !(tab === "events" ? events?.next_cursor : evidence?.next_cursor)
                    }
                    onClick={() => {
                      if (tab === "events" && events?.next_cursor)
                        loadEvents(summary.source_request_id, events.next_cursor);
                      if (tab === "evidence" && evidence?.next_cursor)
                        loadEvidence(evidence.next_cursor);
                    }}
                  >
                    下一页
                  </button>
                  <span className="muted">
                    {tab === "events" ? "按事件序号分页" : "按目录记录分页"}
                  </span>
                  {problems[tab] && (
                    <button
                      className="text-button"
                      onClick={() =>
                        tab === "events" ? loadEvents(summary.source_request_id) : loadEvidence()
                      }
                    >
                      重新加载首页
                    </button>
                  )}
                </div>
              </section>
              {eventDetails}
            </div>
          </>
        ) : (
          queryKind !== "api-keys" &&
          !busy.query &&
          !problems.query && (
            <section className="panel empty-state">
              <h2>
                {queryKind === "request"
                  ? "从一个请求开始"
                  : queryKind === "model"
                    ? "查询模型调用"
                    : queryKind === "agent"
                      ? "查询 Agent 运行"
                      : "查询账本记录"}
              </h2>
              <p className="muted">
                {queryKind === "request"
                  ? "输入请求 ID，读取判定摘要、事件时间线与证据目录。"
                  : queryKind === "model"
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
