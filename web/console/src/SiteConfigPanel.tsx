import { useEffect, useState } from "react";
import { siteSections } from "./admin-routes";
import type { SiteSection } from "./admin-routes";
import type {
  SiteApplyResponse,
  SiteConfig,
  SiteConfigResponse,
  SiteListItem,
  SitePolicyConfig,
  SiteRevision,
  SiteRouteConfig,
  SiteSecretReference,
} from "./api";

export type SiteConfigDraft = {
  display_name: string;
  public_origin: string;
  upstream_address: string;
  upstream_server_name: string;
  upstream_tls: boolean;
  listen_port: number;
  entry_path: string;
  security_entry: SiteConfig["security_entry"];
  sensor_enabled: boolean;
  policy_revision: string;
  status: SiteConfig["status"];
  policy: SitePolicyConfig;
};

const empty: SiteConfigDraft = {
  display_name: "",
  public_origin: "",
  upstream_address: "",
  upstream_server_name: "",
  upstream_tls: false,
  listen_port: 0,
  entry_path: "/",
  security_entry: "ui_action_required",
  sensor_enabled: false,
  policy_revision: "policy-v1",
  status: "draft",
  policy: {
    routes: [],
    identity: {
      enabled: false,
      cookie_name: "__Host-xshield_sid",
      credential_header: "Authorization",
      profile: "default",
      session_ttl_seconds: 3600,
      generation: 1,
    },
    crypto: {
      adapter_revision: "observe-v1",
      failure_strategy: "fail_closed",
      protocol_version: null,
    },
    waf: {
      enabled: true,
      blocked_headers: [],
      blocked_query_fragments: [],
      max_cookie_bytes: 8192,
    },
    limits: {
      max_request_body_bytes: 1_048_576,
      max_response_body_bytes: 16_777_216,
      requests_per_second: 1000,
      burst: 2000,
    },
    health_check: { path: "/health", interval_seconds: 15, timeout_ms: 2000, expected_status: 200 },
    secret_refs: [],
  },
};

export function SiteConfigPanel({
  roles,
  revisions,
  response,
  sites,
  nextCursor,
  selectedSiteId,
  listView = false,
  section = "overview",
  creating = false,
  failed = false,
  onNavigate,
  onUnsavedChange,
  health,
  healthBusy,
  onHealth,
  busy,
  onRefresh,
  onLoadMore,
  onSelectSite,
  onSave,
  onValidate,
  onApply,
  onApprove,
  onRollback,
  onOpenInvestigation,
}: {
  roles: string[] | null;
  revisions: SiteRevision[];
  response: SiteConfigResponse | null;
  sites: SiteListItem[];
  nextCursor: string | null;
  selectedSiteId: string;
  listView?: boolean;
  section?: SiteSection;
  creating?: boolean;
  failed?: boolean;
  onNavigate: (path: string) => void;
  onUnsavedChange: (value: boolean) => void;
  health: SiteApplyResponse | null;
  healthBusy: boolean;
  onHealth: () => void;
  busy: boolean;
  onRefresh: () => void;
  onLoadMore: () => void;
  onSelectSite: (siteId: string) => void;
  onSave: (siteId: string, draft: SiteConfigDraft, key: string) => Promise<boolean>;
  onValidate: (siteId: string) => Promise<boolean>;
  onApply: (siteId: string, key: string) => Promise<boolean>;
  onApprove: (siteId: string, key: string) => Promise<boolean>;
  onRollback: (siteId: string, key: string) => Promise<boolean>;
  onOpenInvestigation: () => void;
}) {
  const [draft, setDraft] = useState<SiteConfigDraft>(empty);
  const [siteId, setSiteId] = useState(selectedSiteId);
  const [pending, setPending] = useState<{ label: string; run: () => Promise<boolean> } | null>(
    null,
  );
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState("");
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    onUnsavedChange(dirty || pending !== null);
    return () => onUnsavedChange(false);
  }, [dirty, pending, onUnsavedChange]);
  async function execute(operation: { label: string; run: () => Promise<boolean> }) {
    setPending(operation);
    setRunning(true);
    setNotice("");
    try {
      if (await operation.run()) {
        setPending(null);
        setDirty(false);
        setNotice(operation.label + "已完成，请查看服务端状态。");
      }
    } finally {
      setRunning(false);
    }
  }
  function save() {
    if (
      !/^[A-Za-z0-9_.-]{1,128}$/.test(siteId) ||
      siteId === "new" ||
      !draft.display_name.trim() ||
      !draft.public_origin ||
      !draft.upstream_address ||
      !draft.upstream_server_name
    ) {
      setNotice("请在网络页填写有效站点 ID、名称、公网入口和源站地址。");
      return;
    }
    const key = crypto.randomUUID();
    const frozen = structuredClone(draft);
    void execute({
      label: creating ? "创建站点" : "保存配置",
      run: () => onSave(siteId, frozen, key),
    });
  }
  function release(label: string, action: (id: string, key: string) => Promise<boolean>) {
    const key = crypto.randomUUID();
    void execute({ label, run: () => action(siteId, key) });
  }
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (dirty || pending) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty, pending]);
  useEffect(() => setSiteId(selectedSiteId), [selectedSiteId]);
  useEffect(() => {
    if (!response?.config) return;
    const {
      revision: _revision,
      config_digest: _digest,
      updated_by: _updatedBy,
      created_at: _createdAt,
      updated_at: _updatedAt,
      gateway_config: _gateway,
      ...rest
    } = response.config;
    setDraft(rest);
    setDirty(false);
  }, [response]);
  const set = <K extends keyof SiteConfigDraft>(name: K, value: SiteConfigDraft[K]) =>
    setDraft((current) => ({ ...current, [name]: value }));
  const setPolicy = <K extends keyof SitePolicyConfig>(name: K, value: SitePolicyConfig[K]) =>
    setDraft((current) => ({ ...current, policy: { ...current.policy, [name]: value } }));
  const newRoute = (
    entryPath: string,
    securityEntry: SiteConfigDraft["security_entry"],
    index: number,
  ): SiteRouteConfig => ({
    operation_id: index === 0 ? "protected.entry" : `protected.operation.${index + 1}`,
    method: "GET",
    path: entryPath,
    security_entry: securityEntry,
    source_action: null,
    resource_type: null,
    view_profile: null,
    resource_query_parameter: null,
    resource_path_parameter: null,
    request_crypto: null,
    response_crypto: null,
    response_mode: "",
    max_response_bytes: 1_048_576,
  });
  const routes =
    draft.policy.routes.length > 0
      ? draft.policy.routes
      : [newRoute(draft.entry_path, draft.security_entry, 0)];
  const firstRoute = routes[0] ?? newRoute(draft.entry_path, draft.security_entry, 0);
  const updateRoute = (index: number, route: SiteRouteConfig) =>
    setDraft((current) => {
      const currentRoutes =
        current.policy.routes.length > 0
          ? current.policy.routes
          : [newRoute(current.entry_path, current.security_entry, 0)];
      return {
        ...current,
        policy: {
          ...current.policy,
          routes: currentRoutes.map((item, routeIndex) => (routeIndex === index ? route : item)),
        },
      };
    });
  const removeRoute = (index: number) =>
    setPolicy(
      "routes",
      draft.policy.routes.filter((_, routeIndex) => routeIndex !== index),
    );
  const addRoute = () =>
    setPolicy("routes", [...routes, newRoute("/", "ui_action_required", routes.length)]);
  const addSecret = () =>
    setPolicy("secret_refs", [
      ...draft.policy.secret_refs,
      { kind: "tls", secret_ref: "", key_id: "", state: "pending_rotation" },
    ]);
  const updateSecret = (index: number, secret: SiteSecretReference) =>
    setPolicy(
      "secret_refs",
      draft.policy.secret_refs.map((item, secretIndex) => (secretIndex === index ? secret : item)),
    );
  const removeSecret = (index: number) =>
    setPolicy(
      "secret_refs",
      draft.policy.secret_refs.filter((_, secretIndex) => secretIndex !== index),
    );
  const revisionDiff = (index: number, revision: SiteRevision): string[] => {
    const previous = revisions[index + 1]?.config;
    if (!previous) return ["初始配置"];
    const keys = [...new Set([...Object.keys(previous), ...Object.keys(revision.config)])].sort();
    return keys.filter(
      (field) => JSON.stringify(previous[field]) !== JSON.stringify(revision.config[field]),
    );
  };
  const activeSites = sites.filter((site) => site.status === "active").length;
  const pendingSites = sites.filter((site) => site.apply_state === "pending").length;
  const failedSites = sites.filter((site) => site.apply_state === "failed").length;
  const fullAccess = roles === null;
  const canConfigure = fullAccess || roles?.includes("system_admin") === true;
  const canValidate = fullAccess || roles?.includes("policy_author") === true;
  const canApply = fullAccess || roles?.includes("release_operator") === true;
  const canApprove = fullAccess || roles?.includes("policy_approver") === true;
  const locked = busy || running || pending !== null;
  const editing = !["overview", "releases", "audit"].includes(section);
  const sitePath = "/sites/" + (creating ? "new" : selectedSiteId);
  function refresh() {
    if ((dirty || pending) && !window.confirm("放弃当前草稿或待确认操作，重新读取服务端状态？"))
      return;
    setPending(null);
    setDirty(false);
    if (creating) {
      setDraft(structuredClone(empty));
      setSiteId("");
    }
    onRefresh();
  }
  if (listView) {
    return (
      <section className="panel site-list-page" aria-label="受保护站点列表">
        <div className="panel-heading">
          <h2>站点列表</h2>
          <div className="form-actions">
            <button className="outline" type="button" onClick={onRefresh} disabled={busy}>
              刷新
            </button>
            {canConfigure && (
              <button type="button" onClick={() => onNavigate("/sites/new/network")}>
                新建站点
              </button>
            )}
          </div>
        </div>
        <div className="site-summary" aria-label="已加载站点统计">
          <div>
            <strong>{sites.length}</strong>
            <span>已加载站点</span>
          </div>
          <div>
            <strong>{activeSites}</strong>
            <span>启用</span>
          </div>
          <div>
            <strong>{pendingSites}</strong>
            <span>待应用</span>
          </div>
          <div>
            <strong>{failedSites}</strong>
            <span>应用失败</span>
          </div>
        </div>
        {busy && <p role="status">正在读取站点列表…</p>}
        {failed ? (
          <p className="notice danger">站点列表读取失败，请使用刷新重试。</p>
        ) : !busy && sites.length === 0 ? (
          <div className="empty-state">
            <strong>暂无受保护站点</strong>
            <p>点击新建站点，填写网络配置后保存。</p>
          </div>
        ) : (
          <div className="site-card-list">
            {sites.map((site) => (
              <article className="site-card" key={site.site_id}>
                <div>
                  <h3>{site.display_name}</h3>
                  <p className="mono">{site.site_id}</p>
                  <p>{site.public_origin}</p>
                </div>
                <dl>
                  <div>
                    <dt>状态</dt>
                    <dd>{site.status}</dd>
                  </div>
                  <div>
                    <dt>应用</dt>
                    <dd>{site.apply_state}</dd>
                  </div>
                  <div>
                    <dt>版本</dt>
                    <dd>
                      desired {site.desired_revision} · active {site.active_revision ?? "—"}
                    </dd>
                  </div>
                </dl>
                <button type="button" onClick={() => onSelectSite(site.site_id)}>
                  打开站点
                </button>
              </article>
            ))}
          </div>
        )}
        {nextCursor && (
          <button className="outline" type="button" onClick={onLoadMore} disabled={busy}>
            加载更多站点
          </button>
        )}
      </section>
    );
  }
  return (
    <section className="panel site-editor" aria-label="受保护站点配置">
      <div className="panel-heading">
        <div>
          <button className="text-button" type="button" onClick={() => onNavigate("/sites")}>
            返回站点列表
          </button>
          <h2>{creating ? "新建站点" : response?.config?.display_name || selectedSiteId}</h2>
        </div>
        <button className="outline" type="button" onClick={refresh} disabled={busy || running}>
          刷新站点
        </button>
      </div>
      <nav className="site-nav" aria-label="站点运营导航">
        {siteSections.map(([id, label]) => (
          <a
            key={id}
            href={sitePath + "/" + id}
            aria-current={section === id ? "page" : undefined}
            onClick={(event) => {
              if (
                event.button !== 0 ||
                event.metaKey ||
                event.ctrlKey ||
                event.shiftKey ||
                event.altKey
              )
                return;
              event.preventDefault();
              onNavigate(sitePath + "/" + id);
            }}
          >
            {label}
          </a>
        ))}
      </nav>
      {notice && (
        <p className="notice" role="status">
          {notice}
        </p>
      )}
      {pending && !running && (
        <div className="notice warning" role="alert">
          <p>{pending.label}的结果待确认。重试将使用原有参数和幂等键。</p>
          <button type="button" onClick={() => void execute(pending)}>
            确认后原样重试
          </button>
          <button className="outline" type="button" onClick={refresh}>
            重新读取状态
          </button>
        </div>
      )}
      {!creating && !response ? (
        <p className="empty" role="status">
          {failed ? "配置读取失败，请刷新重试。" : "正在读取站点配置…"}
        </p>
      ) : !creating && !response?.found ? (
        <p className="empty">站点不存在或当前范围内不可见。</p>
      ) : (
        <>
          {section === "overview" && (
            <section aria-label="站点概览">
              <h3>站点概览</h3>
              <dl className="session-grid">
                <div>
                  <dt>站点 ID</dt>
                  <dd>{siteId || "尚未填写"}</dd>
                </div>
                <div>
                  <dt>公网入口</dt>
                  <dd>{draft.public_origin || "尚未填写"}</dd>
                </div>
                <div>
                  <dt>应用状态</dt>
                  <dd>{response?.apply_state ?? "未保存"}</dd>
                </div>
                <div>
                  <dt>期望版本</dt>
                  <dd>{response?.desired_revision ?? "—"}</dd>
                </div>
                <div>
                  <dt>活动版本</dt>
                  <dd>{response?.active_revision ?? "—"}</dd>
                </div>
                <div>
                  <dt>审批</dt>
                  <dd>
                    {response?.requires_approval
                      ? "等待独立审批"
                      : response?.found
                        ? "无需审批"
                        : "未保存"}
                  </dd>
                </div>
              </dl>
            </section>
          )}
          <fieldset
            className="site-fields"
            disabled={locked || !canConfigure}
            onChange={() => setDirty(true)}
          >
            {section === "network" && (
              <>
                <label>
                  站点 ID
                  <input
                    value={siteId}
                    readOnly={!creating}
                    onChange={(event) => setSiteId(event.target.value)}
                    maxLength={128}
                    pattern="[A-Za-z0-9_.-]+"
                    required
                  />
                </label>
                <h3 id="site-network">网络配置</h3>
                <div className="form-grid">
                  <label>
                    站点名称
                    <input
                      value={draft.display_name}
                      onChange={(e) => set("display_name", e.target.value)}
                      required
                    />
                  </label>
                  <label>
                    公网入口
                    <input
                      value={draft.public_origin}
                      onChange={(e) => set("public_origin", e.target.value)}
                      required
                    />
                  </label>
                  <label>
                    源站地址
                    <input
                      value={draft.upstream_address}
                      onChange={(e) => set("upstream_address", e.target.value)}
                      required
                    />
                  </label>
                  <label>
                    源站 Server Name
                    <input
                      value={draft.upstream_server_name}
                      onChange={(e) => set("upstream_server_name", e.target.value)}
                      required
                    />
                  </label>
                  <label>
                    监听端口（0 自动分配）
                    <input
                      type="number"
                      min="0"
                      max="65535"
                      value={draft.listen_port}
                      onChange={(e) => set("listen_port", Number(e.target.value))}
                    />
                  </label>
                  <label>
                    入口路径
                    <input
                      value={draft.entry_path}
                      onChange={(e) => {
                        const value = e.target.value;
                        set("entry_path", value);
                        updateRoute(0, { ...firstRoute, path: value });
                      }}
                      required
                    />
                  </label>
                </div>
              </>
            )}
            {section === "security-entry" && (
              <>
                <h3 id="site-security">安全入口</h3>
                <div className="form-grid">
                  <label>
                    安全入口
                    <select
                      value={draft.security_entry}
                      onChange={(e) => {
                        const value = e.target.value as SiteConfigDraft["security_entry"];
                        set("security_entry", value);
                        updateRoute(0, { ...firstRoute, security_entry: value });
                      }}
                    >
                      <option value="public">公开</option>
                      <option value="authenticated_root">已认证根</option>
                      <option value="ui_action_required">必须有界面操作来源</option>
                    </select>
                  </label>
                  <label>
                    策略版本
                    <input
                      value={draft.policy_revision}
                      onChange={(e) => set("policy_revision", e.target.value)}
                      required
                    />
                  </label>
                  <label>
                    状态
                    <select
                      value={draft.status}
                      onChange={(e) => set("status", e.target.value as SiteConfigDraft["status"])}
                    >
                      <option value="draft">草稿</option>
                      <option value="active">启用</option>
                      <option value="paused">暂停</option>
                    </select>
                  </label>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={draft.upstream_tls}
                      onChange={(e) => set("upstream_tls", e.target.checked)}
                    />{" "}
                    上游 TLS
                  </label>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={draft.sensor_enabled}
                      onChange={(e) => set("sensor_enabled", e.target.checked)}
                    />{" "}
                    启用浏览器探针运行时
                  </label>
                </div>
              </>
            )}
            {section === "routes" && (
              <>
                <h3 id="site-operations">路由与操作</h3>
                {routes.map((route, index) => (
                  <fieldset className="route-editor" key={index}>
                    <legend>操作 {index + 1}</legend>
                    <div className="form-grid">
                      <label>
                        操作 ID
                        <input
                          value={route.operation_id}
                          onChange={(e) =>
                            updateRoute(index, { ...route, operation_id: e.target.value })
                          }
                        />
                      </label>
                      <label>
                        方法
                        <select
                          value={route.method}
                          onChange={(e) =>
                            updateRoute(index, {
                              ...route,
                              method: e.target.value as SiteRouteConfig["method"],
                            })
                          }
                        >
                          <option>GET</option>
                          <option>POST</option>
                          <option>PUT</option>
                          <option>PATCH</option>
                          <option>DELETE</option>
                        </select>
                      </label>
                      <label>
                        路径
                        <input
                          value={route.path}
                          onChange={(e) => updateRoute(index, { ...route, path: e.target.value })}
                        />
                      </label>
                      <label>
                        安全入口
                        <select
                          value={route.security_entry}
                          onChange={(e) =>
                            updateRoute(index, {
                              ...route,
                              security_entry: e.target.value as SiteRouteConfig["security_entry"],
                            })
                          }
                        >
                          <option value="public">公开</option>
                          <option value="authenticated_root">已认证根</option>
                          <option value="ui_action_required">必须有界面操作来源</option>
                        </select>
                      </label>
                      <label>
                        操作来源
                        <input
                          value={route.source_action ?? ""}
                          onChange={(e) =>
                            updateRoute(index, { ...route, source_action: e.target.value || null })
                          }
                        />
                      </label>
                      <label>
                        资源类型
                        <input
                          value={route.resource_type ?? ""}
                          onChange={(e) =>
                            updateRoute(index, { ...route, resource_type: e.target.value || null })
                          }
                        />
                      </label>
                      <label>
                        视图 profile
                        <input
                          value={route.view_profile ?? ""}
                          onChange={(e) =>
                            updateRoute(index, { ...route, view_profile: e.target.value || null })
                          }
                        />
                      </label>
                      <label>
                        资源查询字段
                        <input
                          value={route.resource_query_parameter ?? ""}
                          onChange={(e) =>
                            updateRoute(index, {
                              ...route,
                              resource_query_parameter: e.target.value || null,
                            })
                          }
                        />
                      </label>
                      <label>
                        资源路径字段
                        <input
                          value={route.resource_path_parameter ?? ""}
                          onChange={(e) =>
                            updateRoute(index, {
                              ...route,
                              resource_path_parameter: e.target.value || null,
                            })
                          }
                        />
                      </label>
                      <label>
                        响应模式
                        <select
                          value={route.response_mode}
                          onChange={(e) =>
                            updateRoute(index, {
                              ...route,
                              response_mode: e.target.value as SiteRouteConfig["response_mode"],
                            })
                          }
                        >
                          <option value="">透传</option>
                          <option value="BUFFERED_JSON">BUFFERED_JSON</option>
                          <option value="SENSOR_HTML">SENSOR_HTML</option>
                        </select>
                      </label>
                      <label>
                        响应上限
                        <input
                          type="number"
                          min="1"
                          max="16777216"
                          value={route.max_response_bytes}
                          onChange={(e) =>
                            updateRoute(index, {
                              ...route,
                              max_response_bytes: Number(e.target.value),
                            })
                          }
                        />
                      </label>
                    </div>
                    {routes.length > 1 && (
                      <button
                        className="outline"
                        type="button"
                        onClick={() => {
                          setDirty(true);
                          removeRoute(index);
                        }}
                        disabled={busy}
                      >
                        移除操作
                      </button>
                    )}
                  </fieldset>
                ))}
                <button
                  className="outline"
                  type="button"
                  onClick={() => {
                    setDirty(true);
                    addRoute();
                  }}
                  disabled={busy || routes.length >= 256}
                >
                  新增操作
                </button>
                <p className="footnote">
                  未声明的 HTTP 操作继续拒绝；路由、方法、准入和资源约束随 policy revision
                  原子发布。
                </p>
              </>
            )}
            {section === "identity" && (
              <>
                <h3 id="site-identity">身份绑定</h3>
                <div className="form-grid">
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={draft.policy.identity.enabled}
                      onChange={(e) =>
                        setPolicy("identity", {
                          ...draft.policy.identity,
                          enabled: e.target.checked,
                        })
                      }
                    />{" "}
                    启用身份绑定
                  </label>
                  <label>
                    身份 profile
                    <input
                      value={draft.policy.identity.profile}
                      onChange={(e) =>
                        setPolicy("identity", { ...draft.policy.identity, profile: e.target.value })
                      }
                    />
                  </label>
                  <label>
                    会话 Cookie
                    <input
                      value={draft.policy.identity.cookie_name}
                      readOnly
                      aria-describedby="identity-fixed-fields"
                    />
                  </label>
                  <label>
                    业务凭证头
                    <input
                      value={draft.policy.identity.credential_header}
                      readOnly
                      aria-describedby="identity-fixed-fields"
                    />
                  </label>
                  <label>
                    会话期限（秒）
                    <input
                      type="number"
                      min="1"
                      max="86400"
                      value={draft.policy.identity.session_ttl_seconds}
                      onChange={(e) =>
                        setPolicy("identity", {
                          ...draft.policy.identity,
                          session_ttl_seconds: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    身份代际
                    <input
                      type="number"
                      min="1"
                      value={draft.policy.identity.generation}
                      onChange={(e) =>
                        setPolicy("identity", {
                          ...draft.policy.identity,
                          generation: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                </div>
              </>
            )}
            {section === "crypto" && (
              <>
                <h3 id="site-crypto">加密适配</h3>
                <div className="form-grid">
                  <label>
                    协议适配器
                    <input
                      value={draft.policy.crypto.adapter_revision}
                      onChange={(e) =>
                        setPolicy("crypto", {
                          ...draft.policy.crypto,
                          adapter_revision: e.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    失败策略
                    <select
                      value={draft.policy.crypto.failure_strategy}
                      onChange={(e) =>
                        setPolicy("crypto", {
                          ...draft.policy.crypto,
                          failure_strategy: e.target.value,
                        })
                      }
                    >
                      <option value="fail_closed">严格拒绝</option>
                      <option value="observe">仅观察</option>
                    </select>
                  </label>
                  <label>
                    协议版本
                    <input
                      value={draft.policy.crypto.protocol_version ?? ""}
                      onChange={(e) =>
                        setPolicy("crypto", {
                          ...draft.policy.crypto,
                          protocol_version: e.target.value || null,
                        })
                      }
                    />
                  </label>
                </div>
                <fieldset className="route-editor">
                  <legend>Secret references</legend>
                  {draft.policy.secret_refs.map((secret, index) => (
                    <div className="form-grid" key={index}>
                      <label>
                        用途
                        <select
                          value={secret.kind}
                          onChange={(e) =>
                            updateSecret(index, {
                              ...secret,
                              kind: e.target.value as SiteSecretReference["kind"],
                            })
                          }
                        >
                          <option value="tls">TLS</option>
                          <option value="session_hmac">会话 HMAC</option>
                          <option value="request_crypto">请求加密</option>
                          <option value="response_crypto">响应加密</option>
                          <option value="model">模型</option>
                        </select>
                      </label>
                      <label>
                        Secret reference
                        <input
                          value={secret.secret_ref}
                          onChange={(e) =>
                            updateSecret(index, { ...secret, secret_ref: e.target.value })
                          }
                          maxLength={512}
                        />
                      </label>
                      <label>
                        Key ID
                        <input
                          value={secret.key_id}
                          onChange={(e) =>
                            updateSecret(index, { ...secret, key_id: e.target.value })
                          }
                          maxLength={128}
                        />
                      </label>
                      <label>
                        状态
                        <select
                          value={secret.state}
                          onChange={(e) =>
                            updateSecret(index, {
                              ...secret,
                              state: e.target.value as SiteSecretReference["state"],
                            })
                          }
                        >
                          <option value="active">active</option>
                          <option value="pending_rotation">pending_rotation</option>
                          <option value="retired">retired</option>
                          <option value="unavailable">unavailable</option>
                        </select>
                      </label>
                      <button
                        className="outline"
                        type="button"
                        onClick={() => {
                          setDirty(true);
                          removeSecret(index);
                        }}
                        disabled={busy}
                      >
                        移除引用
                      </button>
                    </div>
                  ))}
                  <button
                    className="outline"
                    type="button"
                    onClick={() => {
                      setDirty(true);
                      addSecret();
                    }}
                    disabled={busy || draft.policy.secret_refs.length >= 32}
                  >
                    新增 secret reference
                  </button>
                  <p className="footnote">
                    这里只保存引用、Key ID 和轮换状态；密钥正文由部署侧秘密管理系统提供。
                  </p>
                </fieldset>
              </>
            )}
            {section === "waf-limits" && (
              <>
                <h3 id="site-waf">WAF 与限流</h3>
                <div className="form-grid">
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={draft.policy.waf.enabled}
                      onChange={(e) =>
                        setPolicy("waf", { ...draft.policy.waf, enabled: e.target.checked })
                      }
                    />{" "}
                    启用基础 WAF
                  </label>
                  <label>
                    拦截请求头（逗号分隔）
                    <input
                      value={draft.policy.waf.blocked_headers.join(", ")}
                      onChange={(e) =>
                        setPolicy("waf", {
                          ...draft.policy.waf,
                          blocked_headers: e.target.value
                            .split(",")
                            .map((value) => value.trim())
                            .filter(Boolean),
                        })
                      }
                    />
                  </label>
                  <label>
                    查询阻断片段（每行一条，3–128 个 ASCII 字符）
                    <textarea
                      rows={3}
                      value={draft.policy.waf.blocked_query_fragments.join("\n")}
                      onChange={(e) =>
                        setPolicy("waf", {
                          ...draft.policy.waf,
                          blocked_query_fragments: e.target.value
                            .split("\n")
                            .map((value) => value.trim())
                            .filter(Boolean),
                        })
                      }
                    />
                    <small>按一次解码后的查询串匹配；保存前请先验证正常业务样本。</small>
                  </label>
                  <label>
                    Cookie 上限
                    <input
                      type="number"
                      min="1"
                      max="1048576"
                      value={draft.policy.waf.max_cookie_bytes}
                      onChange={(e) =>
                        setPolicy("waf", {
                          ...draft.policy.waf,
                          max_cookie_bytes: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    请求体上限
                    <input
                      type="number"
                      min="1"
                      max="16777216"
                      value={draft.policy.limits.max_request_body_bytes}
                      onChange={(e) =>
                        setPolicy("limits", {
                          ...draft.policy.limits,
                          max_request_body_bytes: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    响应体上限
                    <input
                      type="number"
                      min="1"
                      max="16777216"
                      value={draft.policy.limits.max_response_body_bytes}
                      onChange={(e) =>
                        setPolicy("limits", {
                          ...draft.policy.limits,
                          max_response_body_bytes: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    每秒请求数
                    <input
                      type="number"
                      min="1"
                      max="1000000"
                      value={draft.policy.limits.requests_per_second}
                      onChange={(e) =>
                        setPolicy("limits", {
                          ...draft.policy.limits,
                          requests_per_second: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    突发容量
                    <input
                      type="number"
                      min="1"
                      max="2000000"
                      value={draft.policy.limits.burst}
                      onChange={(e) =>
                        setPolicy("limits", {
                          ...draft.policy.limits,
                          burst: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                </div>
              </>
            )}
            {section === "policies" && (
              <>
                <h3 id="site-policies">策略与健康检查</h3>
                <div className="form-grid">
                  <label>
                    健康检查路径
                    <input
                      value={draft.policy.health_check.path}
                      onChange={(e) =>
                        setPolicy("health_check", {
                          ...draft.policy.health_check,
                          path: e.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    检查间隔（秒）
                    <input
                      type="number"
                      min="1"
                      max="3600"
                      value={draft.policy.health_check.interval_seconds}
                      onChange={(e) =>
                        setPolicy("health_check", {
                          ...draft.policy.health_check,
                          interval_seconds: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    超时（毫秒）
                    <input
                      type="number"
                      min="100"
                      max="30000"
                      value={draft.policy.health_check.timeout_ms}
                      onChange={(e) =>
                        setPolicy("health_check", {
                          ...draft.policy.health_check,
                          timeout_ms: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                  <label>
                    期望状态
                    <input
                      type="number"
                      min="100"
                      max="599"
                      value={draft.policy.health_check.expected_status}
                      onChange={(e) =>
                        setPolicy("health_check", {
                          ...draft.policy.health_check,
                          expected_status: Number(e.target.value),
                        })
                      }
                    />
                  </label>
                </div>
                <p id="identity-fixed-fields" className="footnote">
                  身份 Cookie 与业务凭证头由安全策略固定，避免跨站身份绑定被改写。
                </p>
              </>
            )}
          </fieldset>
          {section === "policies" &&
            !creating &&
            (roles === null || roles.includes("observer")) && (
              <section aria-label="站点运行健康">
                <h3>运行健康</h3>
                <button type="button" className="outline" disabled={healthBusy} onClick={onHealth}>
                  {healthBusy ? "正在读取健康状态…" : "读取健康状态"}
                </button>
                {health && (
                  <dl className="session-grid">
                    {(["edge_state", "upstream_state", "audit_state"] as const).map((key) => (
                      <div key={key}>
                        <dt>
                          {{ edge_state: "Edge", upstream_state: "源站", audit_state: "审计" }[key]}
                        </dt>
                        <dd>
                          {["healthy", "degraded", "unavailable", "unconfigured"].includes(
                            String(health.edge_health?.[key]),
                          )
                            ? String(health.edge_health?.[key])
                            : "unknown"}
                        </dd>
                      </div>
                    ))}
                    <div>
                      <dt>配置状态</dt>
                      <dd>{health.apply_state}</dd>
                    </div>
                    <div>
                      <dt>请求 ID</dt>
                      <dd>{health.request_id}</dd>
                    </div>
                  </dl>
                )}
              </section>
            )}
          {editing && canConfigure && (
            <div className="form-actions site-save">
              <span className="muted">{dirty ? "草稿尚未保存" : "配置草稿"}</span>
              <button type="button" onClick={save} disabled={locked}>
                {running ? "正在提交…" : creating ? "创建站点" : "保存配置"}
              </button>
            </div>
          )}
          {section === "releases" && (
            <section aria-label="站点发布">
              <h3>发布与回滚</h3>
              <p>
                当前状态：{response?.apply_state ?? "未保存"} · {response?.reason_code ?? "—"}
              </p>
              <p>
                期望版本 {response?.desired_revision ?? "—"} · 活动版本{" "}
                {response?.active_revision ?? "—"} ·{" "}
                {response?.requires_approval ? "等待独立审批" : "无需审批"}
              </p>
              <div className="form-actions">
                {canValidate && (
                  <button
                    className="outline"
                    type="button"
                    onClick={() => void onValidate(siteId)}
                    disabled={locked || creating}
                  >
                    验证配置
                  </button>
                )}
                {canApply && (
                  <button
                    type="button"
                    onClick={() => release("应用配置", onApply)}
                    disabled={
                      locked ||
                      creating ||
                      !response?.desired_revision ||
                      response?.requires_approval === true
                    }
                  >
                    应用期望版本
                  </button>
                )}
                {canApprove && response?.requires_approval && (
                  <button
                    type="button"
                    onClick={() => release("批准配置", onApprove)}
                    disabled={locked || creating}
                  >
                    批准并应用
                  </button>
                )}
                {canApply && (
                  <button
                    className="outline"
                    type="button"
                    onClick={() => release("回滚配置", onRollback)}
                    disabled={locked || creating || !response?.active_revision}
                  >
                    回滚上一版本
                  </button>
                )}
              </div>
              <h4>修订历史</h4>
              {revisions.length === 0 ? (
                <p className="empty">暂无可读取的修订历史。</p>
              ) : (
                <ul className="revision-list">
                  {revisions.map((revision, index) => (
                    <li key={revision.revision}>
                      r{revision.revision} · {revision.policy_revision} · {revision.created_by} ·{" "}
                      {revision.created_at}
                      <details>
                        <summary>查看变更字段</summary>
                        {revisionDiff(index, revision).join("、")}
                      </details>
                    </li>
                  ))}
                </ul>
              )}
              {response?.config && (
                <details>
                  <summary>配置预览</summary>
                  <pre className="config-preview">
                    {JSON.stringify(response.config.gateway_config, null, 2)}
                  </pre>
                </details>
              )}
            </section>
          )}
          {section === "audit" && (
            <section aria-label="站点审计">
              <h3>审计与调查</h3>
              <p>
                管理请求 ID：<span className="mono">{response?.request_id ?? "—"}</span>
              </p>
              <p>调查读取按当前管理会话的站点范围授权。</p>
              <button className="outline" type="button" onClick={onOpenInvestigation}>
                打开调查控制台
              </button>
            </section>
          )}
        </>
      )}
    </section>
  );
}
