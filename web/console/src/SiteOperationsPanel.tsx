import { useEffect, useState } from "react";
import type { SiteApplyResponse, SiteRevision } from "./api";
import type { SiteSection } from "./admin-routes";

type Props = {
  siteId: string;
  section: SiteSection;
  roles: string[];
  status: SiteApplyResponse | null;
  health: SiteApplyResponse | null;
  revisions: SiteRevision[];
  busy: boolean;
  failed: boolean;
  onRefresh: () => void;
  onHealth: () => void;
  onNavigate: (path: string) => void;
  onUnsavedChange: (value: boolean) => void;
  onValidate: () => Promise<boolean>;
  onApply: (key: string) => Promise<boolean>;
  onApprove: (key: string) => Promise<boolean>;
  onRollback: (key: string) => Promise<boolean>;
};
/** Read and release permissions stay independent from SystemAdmin configuration access. */
export function SiteOperationsPanel(props: Props) {
  const { siteId, section, roles, status, health, revisions, busy, failed } = props;
  const [pending, setPending] = useState<{ label: string; run: () => Promise<boolean> } | null>(
    null,
  );
  const [notice, setNotice] = useState("");
  const [running, setRunning] = useState(false);
  const observe = roles.includes("observer");
  const release = roles.some((role) =>
    ["policy_author", "policy_approver", "release_operator"].includes(role),
  );
  useEffect(() => {
    props.onUnsavedChange(pending !== null);
    return () => props.onUnsavedChange(false);
  }, [pending, props.onUnsavedChange]);
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      if (pending) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [pending]);
  async function execute(operation: { label: string; run: () => Promise<boolean> }) {
    setPending(operation);
    setRunning(true);
    setNotice("");
    try {
      if (await operation.run()) {
        setPending(null);
        setNotice(operation.label + "已完成。");
      }
    } finally {
      setRunning(false);
    }
  }
  function mutate(label: string, action: (key: string) => Promise<boolean>) {
    const key = crypto.randomUUID();
    void execute({ label, run: () => action(key) });
  }
  const locked = busy || running || pending !== null;
  return (
    <section className="panel" aria-label="站点运行与发布">
      <h2>{siteId}</h2>
      <nav className="site-nav" aria-label="站点操作导航">
        {(observe
          ? [
              ["overview", "状态"],
              ["policies", "健康"],
            ]
          : []
        )
          .concat(release ? [["releases", "发布"]] : [])
          .map(([part, title]) => (
            <a
              href={"/sites/" + siteId + "/" + part}
              key={part}
              aria-current={section === part ? "page" : undefined}
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
                props.onNavigate("/sites/" + siteId + "/" + part);
              }}
            >
              {title}
            </a>
          ))}
      </nav>
      <p>当前站点：{siteId}。每次操作由服务端独立校验角色、范围及再认证状态。</p>
      {notice && <p role="status">{notice}</p>}
      {pending && !running && (
        <div role="alert" className="notice warning">
          <p>{pending.label}的结果待确认。重试使用原参数和幂等键。</p>
          <button type="button" onClick={() => void execute(pending)}>
            确认后原样重试
          </button>
        </div>
      )}
      {observe && (
        <>
          <button className="outline" onClick={props.onRefresh} disabled={busy}>
            刷新站点状态
          </button>
          {status ? (
            <dl className="session-grid">
              <div>
                <dt>应用状态</dt>
                <dd>{status.apply_state}</dd>
              </div>
              <div>
                <dt>期望版本</dt>
                <dd>{status.desired_revision}</dd>
              </div>
              <div>
                <dt>活动版本</dt>
                <dd>{status.active_revision ?? "—"}</dd>
              </div>
              <div>
                <dt>审批</dt>
                <dd>{status.requires_approval ? "等待独立审批" : "无需审批"}</dd>
              </div>
            </dl>
          ) : (
            <p>
              {failed
                ? "站点状态读取失败，请刷新重试。"
                : busy
                  ? "正在读取站点状态…"
                  : "暂无站点状态。"}
            </p>
          )}
        </>
      )}
      {section === "policies" && observe && (
        <>
          <button onClick={props.onHealth} disabled={busy}>
            读取健康状态
          </button>
          {health && (
            <dl className="session-grid">
              {["edge_state", "upstream_state", "audit_state"].map((key) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd>
                    {["healthy", "degraded", "unavailable", "unconfigured"].includes(
                      String(health.edge_health?.[key]),
                    )
                      ? String(health.edge_health?.[key])
                      : "unknown"}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </>
      )}
      {section === "releases" && release && (
        <section aria-label="站点发布">
          <h3>发布与回滚</h3>
          {!observe && <p>状态及修订读取需要 observer 角色。操作授权仍按当前角色校验。</p>}
          <div className="form-actions">
            {roles.includes("policy_author") && (
              <button onClick={() => void props.onValidate()} disabled={locked}>
                验证配置
              </button>
            )}
            {roles.includes("policy_approver") && (
              <button
                onClick={() => mutate("批准配置", props.onApprove)}
                disabled={locked || status?.requires_approval === false}
              >
                批准并应用
              </button>
            )}
            {roles.includes("release_operator") && (
              <>
                <button
                  onClick={() => mutate("应用配置", props.onApply)}
                  disabled={locked || status?.requires_approval === true}
                >
                  应用期望版本
                </button>
                <button
                  onClick={() => mutate("回滚配置", props.onRollback)}
                  disabled={locked || status?.active_revision === null}
                >
                  回滚上一版本
                </button>
              </>
            )}
          </div>
          {observe && (
            <ul>
              {revisions.map((revision) => (
                <li key={revision.revision}>
                  r{revision.revision} · {revision.policy_revision} · {revision.created_by}
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
      {!["overview", "policies", "releases"].includes(section) && (
        <p>配置编辑需要 system_admin 角色。</p>
      )}
    </section>
  );
}
