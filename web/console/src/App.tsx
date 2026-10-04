import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent, KeyboardEvent } from "react";
import {
  ApiError,
  ControlClient,
  bootstrapBrowserSession,
  validateModelCallListPlan,
} from "./api";
import { validateCausalityPlan, validateSearchPlan } from "./search";
import type {
  CausalityResponse,
  SearchPlan,
  SearchResponse,
} from "./search";
import { SearchPanel } from "./SearchPanel";
import type { SearchPreset } from "./SearchPanel";
import { LedgerPanel } from "./LedgerPanel";
import { CasePanel } from "./CasePanel";
import { EvidenceAccessPanel } from "./EvidenceAccessPanel";
import { EvidenceHoldPanel } from "./EvidenceHoldPanel";
import { ExportPanel } from "./ExportPanel";
import { SiteOperationsPanel } from "./SiteOperationsPanel";
import { SiteConfigPanel } from "./SiteConfigPanel";
import { AdminShell } from "./AdminShell";
import { OverviewWorkbench } from "./OverviewWorkbench";
import { ManagementApiKeyPanel } from "./ManagementApiKeyPanel";
import { routeQueryKind, routeTarget, siteRoute } from "./admin-routes";
import type { BindingResponse, GrantResponse } from "./ledger";
import type {
  ArtifactResponse,
  AuditHealthResponse,
  WorkbenchOverviewResponse,
  CalibrationReportResponse,
  AgentRunResponse,
  EventsResponse,
  EvidenceResponse,
  ModelCallListPlan,
  ModelCallListResponse,
  ModelCallResponse,
  SummaryResponse,
  SiteConfigResponse,
  SiteApplyResponse,
  SiteListItem,
  SiteRevision,
  BrowserSession,
  JobResponse,
} from "./api";
import {
  ArtifactDetail,
  AuditHealthPanel,
  AgentRunOverview,
  CalibrationReportPanel,
  EventDetail,
  EventTable,
  EvidenceTable,
  ModelCallListPanel,
  ModelCallOverview,
  RequestOverview,
  WatermarkNotice,
} from "./panels";

type Problem = { message: string; code: string; requestId?: string | null; status?: number };
type Channel = "query" | "events" | "evidence" | "artifact" | "case" | "access" | "hold" | "export" | "sites" | "health" | "workbench";
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
const idleMs = 15 * 60 * 1000;
const machineLoginEnabled =
  import.meta.env.DEV && import.meta.env.VITE_XSHIELD_E2E_MACHINE_LOGIN === "1";

function Failure({ problem }: { problem: Problem | null }) {
  return (
    problem && (
      <div className="notice danger" role="alert">
        <div>
          {problem.message}
          <small className="mono">
            {problem.code}{problem.status ? " · HTTP " + problem.status : ""}
            {problem.requestId ? ` · ${problem.requestId}` : ""}
          </small>
        </div>
      </div>
    )
  );
}

export function App() {
  const client = useRef<ControlClient | null>(null);
  const lifetime = useRef(new AbortController());
  const epoch = useRef(0);
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
    workbench: 0,
  });
  const scope = useRef<{ tenant_id: string; site_id: string } | null>(null);
  const [connected, setConnected] = useState(false);
  const [pathname, setPathname] = useState(() => window.location.pathname || "/");
  const [sessionInfo, setSessionInfo] = useState<BrowserSession | null>(null);
  // `null` is the explicitly enabled local machine-login mode. Browser
  // sessions always carry the server-provided role list.
  const [managementRoles, setManagementRoles] = useState<string[] | null>(null);
  const [token, setToken] = useState("");
  const [authReady, setAuthReady] = useState(machineLoginEnabled);
  const [requestId, setRequestId] = useState("");
  const queryKind = routeQueryKind(pathname);
  const currentSite = siteRoute(pathname);
  const [ledger, setLedger] = useState<GrantResponse | BindingResponse | null>(
    null,
  );
  const [searchPreset, setSearchPreset] = useState<SearchPreset | null>(null);
  const [searchPresetVersion, setSearchPresetVersion] = useState(0);
  const [searchPlan, setSearchPlan] = useState<SearchPlan | null>(null);
  const [search, setSearch] = useState<SearchResponse | null>(null);
  const [causality, setCausality] = useState<CausalityResponse | null>(null);
  const [model, setModel] = useState<ModelCallResponse | null>(null);
  const [agentRun, setAgentRun] = useState<AgentRunResponse | null>(null);
  const [modelListPlan, setModelListPlan] =
    useState<ModelCallListPlan | null>(null);
  const [modelList, setModelList] = useState<ModelCallListResponse | null>(
    null,
  );
  const [job, setJob] = useState<JobResponse | null>(null);
  const [health, setHealth] = useState<AuditHealthResponse | null>(null);
  const [workbench, setWorkbench] = useState<WorkbenchOverviewResponse | null>(null);
  const [calibrationReport, setCalibrationReport] =
    useState<CalibrationReportResponse | null>(null);
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
  const [problems, setProblems] = useState<Partial<Record<Channel, Problem>>>(
    {},
  );
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  const clearResults = useCallback(() => {
    lifetime.current.abort();
    lifetime.current = new AbortController();
    epoch.current += 1;
    setSummary(null);
    setModel(null);
    setAgentRun(null);
    setModelListPlan(null);
    setModelList(null);
    setHealth(null);
    setWorkbench(null);
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

  const disconnect = useCallback(
    (notice: string | null = null) => {
      clearResults();
      client.current = null;
      scope.current = null;
      setConnected(false);
      setSessionInfo(null);
      setManagementRoles(null);
      setToken("");
      setAuthReady(true);
      setRequestId("");
      setSiteList([]);
      setSiteListCursor(null);
      setSearchPreset(null);
      setSessionNotice(notice);
    },
    [clearResults],
  );

  useEffect(() => {
    if (machineLoginEnabled) return;
    const controller = new AbortController();
    void bootstrapBrowserSession(controller.signal)
      .then((session) => {
        client.current = new ControlClient(undefined, session.csrf_token);
        scope.current = {
          tenant_id: session.tenant_id,
          site_id: session.site_id,
        };
        setManagementRoles(session.roles);
        setSessionInfo(session);
        setSessionNotice(null);
        setConnected(true);
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (!(error instanceof ApiError && error.status === 401)) {
          setSessionNotice(
            error instanceof ApiError
              ? error.message
              : "无法恢复管理会话，请检查服务后重试。",
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setAuthReady(true);
      });
    return () => controller.abort();
  }, []);

  useEffect(() => { document.getElementById("main-content")?.focus(); }, [pathname]);
  const siteUnsaved = useRef(false);
  const historyIndex = useRef<number>(Number(window.history.state?.xshieldIndex ?? 0));
  useEffect(() => {
    window.history.replaceState({ ...window.history.state, xshieldIndex: historyIndex.current }, "");
  }, []);
  const setSiteUnsaved = useCallback((value: boolean) => { siteUnsaved.current = value; }, []);
  const allowNavigation = useCallback((nextPath: string, previousPath: string) => {
    const before = siteRoute(previousPath);
    const after = siteRoute(nextPath);
    if (!siteUnsaved.current || (before && after && before.siteId === after.siteId)) return true;
    return window.confirm("当前站点有未保存草稿或待确认操作。确定离开？");
  }, []);
  const syncRoute = useCallback((nextPath: string, previousPath: string) => {
    const previous = siteRoute(previousPath);
    const next = siteRoute(nextPath);
    // A category is part of the same editing session. Other route changes
    // invalidate every in-flight response before another view can render.
    if (!previous || !next || previous.siteId !== next.siteId) clearResults();
    if (!previous || !next || previous.siteId !== next.siteId) siteUnsaved.current = false;
    setPathname(nextPath);
    setRequestId("");
    setSearchPreset(null);
  }, [clearResults]);

  useEffect(() => {
    const onPopState = () => {
      const next = window.location.pathname || "/";
      const index = Number(window.history.state?.xshieldIndex ?? historyIndex.current - 1);
      if (!allowNavigation(next, pathname)) {
        const delta = historyIndex.current - index;
        if (delta) window.history.go(delta);
        else window.history.replaceState({ xshieldIndex: historyIndex.current }, "", pathname);
        return;
      }
      historyIndex.current = index;
      syncRoute(next, pathname);
    };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, [pathname, syncRoute, allowNavigation]);

  const navigate = useCallback((path: string, completed = false) => {
    if (path === window.location.pathname + window.location.search) return;
    const previous = window.location.pathname;
    if (!completed && !allowNavigation(path.split("?")[0] ?? path, previous)) return;
    historyIndex.current += 1;
    window.history.pushState({ xshieldIndex: historyIndex.current }, "", path);
    syncRoute(window.location.pathname || "/", previous);
  }, [syncRoute, allowNavigation]);

  useEffect(() => {
    const target = routeTarget(pathname, queryKind);
    if (target) setRequestId(target);
  }, [pathname, queryKind]);

  useEffect(() => {
    if (!connected) return;
    const target = routeTarget(pathname, queryKind);
    if (!target) return;
    if (queryKind === "request") loadRequest(target);
    else if (queryKind === "model") void run("query", (api, signal) => api.modelCall(target, signal), (response) => setModel(response));
    else if (queryKind === "agent") void run("query", (api, signal) => api.agentRun(target, signal), (response) => setAgentRun(response));
    else if (queryKind === "grant") void run("query", (api, signal) => api.grant(target, signal), (response) => setLedger(response));
    else if (queryKind === "binding") loadBinding(target);
    else if (queryKind === "calibration-report") loadCalibrationReport(target);
  }, [connected, pathname, queryKind]);

  useEffect(() => {
    if (!connected) return;
    let timer: ReturnType<typeof setTimeout>;
    const reset = () => {
      clearTimeout(timer);
      timer = setTimeout(
        () => disconnect("会话已因闲置断开，请重新连接。"),
        idleMs,
      );
    };
    const leave = () => disconnect();
    reset();
    window.addEventListener("pointerdown", reset);
    window.addEventListener("keydown", reset);
    window.addEventListener("pagehide", leave);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("pointerdown", reset);
      window.removeEventListener("keydown", reset);
      window.removeEventListener("pagehide", leave);
    };
  }, [connected, disconnect]);
  useEffect(() => {
    // StrictMode replays setup/cleanup; a new mount needs a live request signal.
    if (lifetime.current.signal.aborted) lifetime.current = new AbortController();
    return () => lifetime.current.abort();
  }, []);
  useEffect(() => {
    if (connected && queryKind === "site-config") loadSiteConfig();
  }, [connected, queryKind, selectedSiteId]);

  useEffect(() => {
    if (!connected || queryKind !== "overview") return;
    void run("workbench", (api, signal) => api.workbenchOverview(signal), (response) => setWorkbench(response));
  }, [connected, queryKind, managementRoles]);

  // Every response belongs to a query generation and one authenticated scope.
  // Abort alone cannot stop already-resolved promises from repainting old data.
  async function run<T extends { tenant_id: string; site_id: string }>(
    channel: Channel,
    fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
    apply: (response: T) => void,
    fail?: (error: unknown) => void,
    expectedSiteId?: string,
  ): Promise<boolean> {
    const api = client.current;
    if (!api) return false;
    const generation = epoch.current;
    const operation = ++operations.current[channel];
    const signal = lifetime.current.signal;
    const current = () =>
      epoch.current === generation &&
      operations.current[channel] === operation &&
      !signal.aborted;
    setBusy((value) => ({ ...value, [channel]: true }));
    setProblems((value) => ({ ...value, [channel]: undefined }));
    try {
      const response = await fetcher(api, signal);
      if (!current()) return false;
      if (expectedSiteId && response.site_id !== expectedSiteId) {
        throw new ApiError("INVALID_RESPONSE");
      }
      if (
        scope.current &&
        (scope.current.tenant_id !== response.tenant_id ||
          (!expectedSiteId && scope.current.site_id !== response.site_id))
      ) {
        disconnect("响应范围校验失败，连接已断开。");
        return false;
      }
      if (!expectedSiteId) {
        scope.current = {
          tenant_id: response.tenant_id,
          site_id: response.site_id,
        };
      }
      apply(response);
      return true;
    } catch (error) {
      if (!current()) return false;
      if (error instanceof ApiError && error.status === 401) {
        disconnect("管理会话已失效，请重新登录。");
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

  function connect(event: FormEvent) {
    event.preventDefault();
    try {
    client.current = new ControlClient(token);
    } catch {
      setSessionNotice("请输入有效的管理凭证。");
      return;
    }
    lifetime.current = new AbortController();
    setToken("");
    setManagementRoles(null);
    setSessionInfo(null);
    setSessionNotice(null);
    setConnected(true);
  }
  async function logout() {
    const activeClient = client.current;
    if (!activeClient) return;
    try {
      await activeClient.logoutBrowserSession();
      disconnect("已安全退出管理会话。");
    } catch (error) {
      const notice =
        error instanceof ApiError
          ? `${error.message} 页面状态已清理，请重新登录确认会话状态。`
          : "退出状态未确认；页面状态已清理，请重新登录确认会话状态。";
      // The server may have revoked the session before an audit or network
      // failure prevented a success response. Never keep sensitive UI state.
      disconnect(notice);
    }
  }
  async function reauthenticate() {
    const activeClient = client.current;
    if (!activeClient) return;
    try {
      const authorizationUrl = await activeClient.startReauthentication(
        lifetime.current.signal,
      );
      window.location.assign(authorizationUrl);
    } catch (error) {
      setSessionNotice(
        error instanceof ApiError
          ? `${error.message} 页面状态保持不变。`
          : "无法启动身份再认证，请稍后重试。",
      );
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
      queryKind === "access" || queryKind === "hold" || queryKind === "export" || queryKind === "model-list" ||
      queryKind === "audit-health" || queryKind === "site-config"
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
      void run("query", (api, signal) => api.job(target, signal), (response) => setJob(response));
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
    void run("sites", (api, signal) => api.siteList(signal, cursor), (response) => {
      setSiteList((current) => {
        if (!append) return response.sites;
        const seen = new Set(current.map((site) => site.site_id));
        return [...current, ...response.sites.filter((site) => !seen.has(site.site_id))];
      });
      setSiteListCursor(response.next_cursor);
    });
  }
  function refreshOverview() {
    clearResults();
    void run("workbench", (api, signal) => api.workbenchOverview(signal), (response) => setWorkbench(response));
  }
  function loadSiteDetails(siteId: string) {
    if (managementRoles !== null && !managementRoles.includes("system_admin")) {
      if (managementRoles.includes("observer")) {
        void run("query", (api, signal) => api.siteStatus(siteId, signal), (response) => setSiteStatus(response), undefined, siteId);
        void run("sites", (api, signal) => api.siteRevisions(siteId, signal), (response) => setSiteRevisions(response.revisions), undefined, siteId);
      }
      return;
    }
    void run("query", async (api, signal) => {
      const config = await api.siteConfig(siteId, signal);
      // Each response is checked before combining projections. A revision
      // response from another tenant/site must never be silently merged.
      if (config.site_id !== siteId) throw new ApiError("INVALID_RESPONSE");
      return config;
    }, (response) => setSiteConfig(response), undefined, siteId);
    if (managementRoles === null || managementRoles.includes("observer")) {
      void run("sites", async (api, signal) => {
        const response = await api.siteRevisions(siteId, signal);
        if (response.site_id !== siteId) throw new ApiError("INVALID_RESPONSE");
        return response;
      }, (response) => setSiteRevisions(response.revisions), undefined, siteId);
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
  function openTarget(
    kind: "request" | "binding" | "model" | "agent",
    id: string,
  ) {
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
    navigate("/investigation/search");
    setSearchPreset(preset);
    setSearchPresetVersion((version) => version + 1);
    setRequestId("");
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
  const event = (search?.events ?? events?.events)?.find(
    (value) => value.event_id === selected,
  );
  const relatedEvents =
    search?.events ?? events?.events ?? (event ? [event] : []);
  const title = {
    overview: "运行概览",
    session: "权限中心",
    request: "请求调查",
    model: "模型调用调查",
    agent: "Agent 运行调查",
    "model-list": "模型调用列表",
    "audit-health": "审计发布状态",
    "calibration-report": "校准报告调查",
    grant: "资格调查",
    binding: "身份绑定调查",
    search: "结构化事件检索",
    case: "案件工作台",
    access: "证据访问",
    hold: "证据保留",
    export: "调查导出",
    "site-config": "受保护站点",
    "api-keys": "管理 API Key",
    jobs: "后台任务",
    "not-found": "页面不存在",
  }[queryKind];
  const eventDetails = (
    <aside className="panel detail-panel" aria-live="polite">
      <div className="panel-heading">
        <h2>
          {artifact || busy.artifact || problems.artifact
            ? "证据详情"
            : "事件详情"}
        </h2>
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
            onPreviousEvent={(id) =>
              prepareSearchHistory({ kind: "event_id", value: id })
            }
            onFollowEvent={(id) =>
              prepareSearchHistory({ kind: "caused_by_event_id", value: id })
            }
            onCausalEvent={(id) => {
              clearArtifact();
              invalidateCausality();
              if (relatedEvents.some((item) => item.event_id === id)) {
                setSelected(id);
              } else {
                prepareSearchHistory({ kind: "event_id", value: id });
              }
            }}
            onTraceId={(traceId) =>
              prepareSearchHistory({ kind: "trace_id", value: traceId })
            }
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

  return (
    <AdminShell
      connected={connected}
      pathname={pathname}
      title={title}
      scope={scope.current ? `${scope.current.tenant_id} / ${scope.current.site_id}` : "等待查询验证范围"}
      roles={managementRoles}
      session={sessionInfo}
      machineLoginEnabled={machineLoginEnabled}
      onNavigate={navigate}
      onLogout={() => void logout()}
      onReauthenticate={() => void reauthenticate()}
      onRefresh={queryKind === "overview" ? refreshOverview : undefined}
      refreshing={queryKind === "overview" && Boolean(busy.sites || busy.health)}
      observedAt={queryKind === "overview" ? workbench?.as_of ?? null : null}
    >
        <h1>{title}</h1>
        <p className="lead">
          {queryKind === "overview"
            ? "查看当前管理范围内的站点、审计和调查服务状态。"
            : queryKind === "session"
              ? "查看当前主体、角色、站点范围和再认证状态。"
            : queryKind === "request"
            ? "沿着请求时间线，核对每一次判定与证据。"
            : queryKind === "model"
              ? "核对模型调用生命周期、版本与证据引用。"
              : queryKind === "agent"
                ? "核对 Agent 脱敏生命周期与固定事件引用。"
              : queryKind === "site-config"
                ? "配置受保护网站、上游、安全入口与反向代理监听端口。"
              : queryKind === "api-keys"
                ? "创建和撤销绑定 tenant、site 与能力集合的 Agent API Key。"
              : queryKind === "audit-health"
                ? "按需读取配置审计日志到索引的发布快照。"
                : queryKind === "calibration-report"
                  ? "读取受限校准报告的冻结元数据与正文保留观察。"
                : queryKind === "search"
                ? "按时间与事件字段检索，核对直接引用的历史事实。"
                : queryKind === "case"
                  ? "建立本人调查案件，核对证据引用与案件状态。"
                  : queryKind === "access"
                    ? "复核访问申请，通过独立审批后按需下载证据原文。"
                    : queryKind === "hold"
                      ? "管理案件证据保留期限，核对创建与释放历史。"
                    : queryKind === "export"
                      ? "申请经独立审批的案件与目录元数据包；下载需重新验证。"
                    : "核对当前账本的状态、代际与期限。"}
        </p>
        {sessionNotice && (
          <div className="notice" role="status">
            {sessionNotice}
          </div>
        )}
        {!connected ? (
          <section
            className="panel connect-panel"
            aria-labelledby="connect-title"
          >
            <h2 id="connect-title">
              {machineLoginEnabled ? "连接管理服务" : "企业身份登录"}
            </h2>
            {machineLoginEnabled ? (
              <>
                <p className="muted">
                  自动化测试专用的机器凭证入口。生产控制台仅使用企业 OIDC 身份。
                </p>
                <form onSubmit={connect}>
                  <label htmlFor="token">管理凭证</label>
                  <input
                    id="token"
                    type="password"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    maxLength={4096}
                    required
                  />
                  <button type="submit">连接</button>
                </form>
                <p className="footnote">
                  此入口仅在显式开启的本地 Playwright 测试环境可用。
                </p>
              </>
            ) : !authReady ? (
              <p className="empty" role="status">正在恢复管理会话…</p>
            ) : (
              <>
                <p className="muted">
                  使用企业身份提供方完成 MFA。访问角色与站点范围由服务端部署映射决定。
                </p>
                <button
                  type="button"
                  onClick={() => window.location.assign("/control/v1/auth/oidc/start")}
                >
                  使用企业身份登录
                </button>
                {sessionNotice && (
                  <button
                    className="outline"
                    type="button"
                    onClick={() => window.location.reload()}
                  >
                    重试会话检查
                  </button>
                )}
                <p className="footnote">
                  浏览器只持有 HttpOnly 服务端会话 Cookie；闲置 15 分钟或达到 8 小时绝对时限后须重新登录。
                </p>
              </>
            )}
          </section>
        ) : (
          <>
            {queryKind === "overview" && (
              <OverviewWorkbench
                overview={workbench}
                busy={Boolean(busy.workbench)}
                failed={Boolean(problems.workbench)}
                onRefresh={refreshOverview}
                onNavigate={navigate}
              />
            )}
            {queryKind === "jobs" && job && <section className="panel" aria-label="后台任务详情"><h2>任务状态</h2>{job.job ? <dl className="session-grid"><div><dt>任务</dt><dd>{job.job.job_id}</dd></div><div><dt>案件</dt><dd>{job.job.case_id}</dd></div><div><dt>状态</dt><dd>{job.job.status}</dd></div><div><dt>原因</dt><dd>{job.job.reason_code}</dd></div><div><dt>证据数量</dt><dd>{job.job.artifact_count}</dd></div></dl> : <p>当前主体范围内未找到该任务。</p>}</section>}
            {queryKind === "not-found" && <p className="empty">该地址没有对应页面，请从侧栏选择功能。</p>}
            {queryKind === "session" && sessionInfo && (
              <section className="panel session-panel" aria-labelledby="session-title">
                <h2 id="session-title">当前管理会话</h2>
                <dl className="session-grid">
                  <div><dt>主体</dt><dd className="mono">{sessionInfo.subject}</dd></div>
                  <div><dt>租户</dt><dd className="mono">{sessionInfo.tenant_id}</dd></div>
                  <div><dt>站点范围</dt><dd className="mono">{sessionInfo.site_id}</dd></div>
                  <div><dt>角色</dt><dd>{sessionInfo.roles.join("、") || "无"}</dd></div>
                  <div><dt>绝对到期</dt><dd>{sessionInfo.session_expires_at}</dd></div>
                  <div><dt>闲置到期</dt><dd>{sessionInfo.idle_expires_at}</dd></div>
                  <div><dt>最近再认证</dt><dd>{sessionInfo.last_reauthenticated_at ?? "尚未再认证"}</dd></div>
                  <div><dt>Step-up</dt><dd>{sessionInfo.step_up_valid ? "有效" : "未生效"}</dd></div>
                </dl>
              </section>
            )}
            {["request", "model", "agent", "calibration-report", "grant", "binding", "jobs"].includes(queryKind) && (
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
                  maxLength={(queryPrefixes[queryKind as keyof typeof queryPrefixes] ?? "req").length + 37}
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
            {queryKind === "api-keys" && client.current && scope.current && (managementRoles?.includes("system_admin") || managementRoles?.includes("key_administrator")) && (
              <ManagementApiKeyPanel client={client.current} tenantId={scope.current.tenant_id} onNotice={setSessionNotice} />
            )}
            <div hidden={queryKind !== "case"}>
              <CasePanel
                active={queryKind === "case"}
                busy={Boolean(busy.case)}
                onInvalidate={clearResults}
                onRun={(fetcher, apply, fail) =>
                  run("case", fetcher, apply, fail)
                }
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
            </div>
            <div hidden={queryKind !== "access"}>
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
                onRun={(fetcher, apply, fail) =>
                  run("access", fetcher, apply, fail)
                }
              />
            </div>
            <div hidden={queryKind !== "hold"}>
              <EvidenceHoldPanel active={queryKind === "hold"} busy={Boolean(busy.hold)}
                onInvalidate={clearResults} onHistory={(holdId) => {
                  prepareSearchHistory({ kind: "evidence_hold_id", value: holdId });
                }} onRun={(fetcher, apply, fail) => run("hold", fetcher, apply, fail)} />
            </div>
            <div hidden={queryKind !== "export"}>
              <ExportPanel
                active={queryKind === "export"}
                busy={Boolean(busy.export)}
                onInvalidate={clearResults}
                onRun={(fetcher, apply, fail) =>
                  run("export", fetcher, apply, fail)
                }
              />
            </div>
            {queryKind === "site-config" && currentSite && managementRoles !== null && !managementRoles.includes("system_admin") ? (
              <SiteOperationsPanel
                key={selectedSiteId} siteId={selectedSiteId} section={currentSite.section} roles={managementRoles}
                status={siteStatus} health={siteHealth} revisions={siteRevisions}
                busy={Boolean(busy.query || busy.sites || busy.health)} failed={Boolean(problems.query || problems.sites)}
                onRefresh={() => loadSiteDetails(selectedSiteId)} onNavigate={navigate} onUnsavedChange={setSiteUnsaved}
                onHealth={() => { setSiteHealth(null); void run("health", (api, signal) => api.siteHealth(selectedSiteId, signal), (response) => setSiteHealth(response), undefined, selectedSiteId); }}
                onValidate={() => run("query", (api, signal) => api.validateSite(selectedSiteId, signal), (response) => setSessionNotice(response.valid ? "配置验证通过。" : "配置验证未通过：" + response.reason_code), undefined, selectedSiteId)}
                onApply={(key) => run("query", (api, signal) => api.applySite(selectedSiteId, key, signal), () => loadSiteDetails(selectedSiteId), undefined, selectedSiteId)}
                onApprove={(key) => run("query", (api, signal) => api.approveSite(selectedSiteId, key, signal), () => loadSiteDetails(selectedSiteId), undefined, selectedSiteId)}
                onRollback={(key) => run("query", (api, signal) => api.rollbackSite(selectedSiteId, key, signal), () => loadSiteDetails(selectedSiteId), undefined, selectedSiteId)}
              />
            ) : queryKind === "site-config" ? (
              <SiteConfigPanel
                roles={managementRoles}
                onUnsavedChange={setSiteUnsaved}
                health={siteHealth}
                healthBusy={Boolean(busy.health)}
                onHealth={() => {
                  setSiteHealth(null);
                  void run("health", (api, signal) => api.siteHealth(selectedSiteId, signal), (response) => setSiteHealth(response), undefined, selectedSiteId);
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
                onLoadMore={() => { if (siteListCursor) void loadSiteConfig(siteListCursor, true); }}
                listView={pathname === "/sites"}
                section={currentSite?.section ?? "overview"}
                onSelectSite={(siteId) => {
                  navigate(`/sites/${siteId}/overview`);
                }}
                onSave={(siteId, draft, key) => {
                  const creating = currentSite?.creating === true;
                  return run("query", (api, signal) => creating
                    ? api.createSite(siteId, draft, key, signal)
                    : api.saveSiteConfig(siteId, draft, key, signal), (response) => {
                    setSiteConfig(response);
                    if (creating) navigate("/sites/" + siteId + "/overview", true);
                  }, undefined, siteId);
                }}
                onValidate={(siteId) => {
                  return run("query", (api, signal) => api.validateSite(siteId, signal), (result) => {
                    setSessionNotice(result.valid ? "配置验证通过。" : "配置验证未通过：" + result.reason_code);
                  }, undefined, siteId);
                }}
                onApply={(siteId, key) => run("query", (api, signal) => api.applySite(siteId, key, signal), () => loadSiteDetails(siteId), undefined, siteId)}
                onApprove={(siteId, key) => run("query", (api, signal) => api.approveSite(siteId, key, signal), () => loadSiteDetails(siteId), undefined, siteId)}
                revisions={siteRevisions}
                onRollback={(siteId, key) => run("query", (api, signal) => api.rollbackSite(siteId, key, signal), () => loadSiteDetails(siteId), undefined, siteId)}
                onOpenInvestigation={() => {
                  navigate("/investigation/requests");
                }}
              />
            ) : queryKind === "case" || queryKind === "hold" ||
            queryKind === "access" || queryKind === "export" ? null : queryKind === "search" ? (
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
                  if (searchPlan && search?.next_cursor)
                    searchEvents(searchPlan, search.next_cursor);
                }}
                onSelect={(id) => {
                  clearArtifact();
                  invalidateCausality();
                  setSelected(id);
                }}
              />
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
              <AuditHealthPanel
                response={health}
                busy={Boolean(busy.query)}
                onRefresh={loadHealth}
              />
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
              <LedgerPanel
                response={ledger}
                onBinding={(id) => openTarget("binding", id)}
                onRequest={(id) => openTarget("request", id)}
                onHistory={(preset) => {
                  prepareSearchHistory(preset);
                }}
              />
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
                  onPreviousEvent={(id) =>
                    prepareSearchHistory({ kind: "event_id", value: id })
                  }
                  onFollowEvent={(id) =>
                    prepareSearchHistory({ kind: "caused_by_event_id", value: id })
                  }
                />
                {(artifact || busy.artifact || problems.artifact) && (
                  <section
                    className="panel detail-panel"
                    aria-label="模型证据详情"
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
                <div
                  className="tabs"
                  role="tablist"
                  aria-label="调查内容"
                  onKeyDown={tabKey}
                >
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
                      <EvidenceTable
                        artifacts={evidence?.artifacts ?? []}
                        onOpen={openArtifact}
                      />
                    )}
                    <div className="pagination">
                      <button
                        className="outline"
                        disabled={
                          Boolean(busy[tab]) ||
                          !(tab === "events"
                            ? events?.next_cursor
                            : evidence?.next_cursor)
                        }
                        onClick={() => {
                          if (tab === "events" && events?.next_cursor)
                            loadEvents(
                              summary.source_request_id,
                              events.next_cursor,
                            );
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
                            tab === "events"
                              ? loadEvents(summary.source_request_id)
                              : loadEvidence()
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
              !busy.query &&
              !problems.query && (
                <section className="panel empty-state">
                  <h2>
                    {queryKind === "overview"
                      ? "后台运行概览"
                      : queryKind === "session"
                        ? "当前权限中心"
                        : queryKind === "request"
                          ? "从一个请求开始"
                      : queryKind === "model"
                        ? "查询模型调用"
                        : queryKind === "agent"
                          ? "查询 Agent 运行"
                        : "查询账本记录"}
                  </h2>
                  <p className="muted">
                    {queryKind === "overview"
                      ? "进入左侧模块开始管理。"
                      : queryKind === "session"
                        ? "此页面只读展示当前会话和服务端角色。"
                        : queryKind === "request"
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
        )}
        <footer>历史记录用于调查，当前访问资格由服务端独立校验。</footer>
    </AdminShell>
  );
}
