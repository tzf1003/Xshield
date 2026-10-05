import {
  ArrowLeftOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  ExclamationCircleFilled,
  ReloadOutlined,
} from "@ant-design/icons";
import { useRouter } from "@tanstack/react-router";
import { Alert, Button, Card, Collapse, Descriptions, Form, Popconfirm, Steps } from "antd";
import { type WizardStep, wizardSteps } from "../../admin-routes.ts";
import { PageActions } from "../../shell/page-actions";
import { securityEntryLabel, statusLabel } from "../../sites/model/config.ts";
import { applyRouteTemplate, spaTemplate } from "../../sites/model/route-templates.ts";
import type { Issue } from "../../sites/model/validation.ts";
import { DiffTable } from "./DiffView";
import { busy } from "./fields";
import {
  EntryPathField,
  EntryChoice,
  ListenPortField,
  OriginField,
  ProbeFields,
  SiteIdFields,
  StatusChoice,
  UpstreamFields,
} from "./tabs/site-fields";
import { RoutesTab } from "./tabs/RoutesTab";
import { NoticeBanner, PendingBanner } from "./workspace/Banners";
import { useSiteWorkspace, type WorkspaceApi } from "./workspace/use-workspace.ts";
import "../../ui/ui.css";
import "./sites.css";
import "./workspace.css";

/** Which validation findings belong to which step; the review step shows them all. */
const owns: Record<WizardStep, (issue: Issue) => boolean> = {
  basics: (issue) => ["site_id", "display_name", "public_origin"].includes(issue.path),
  upstream: (issue) =>
    ["upstream_address", "upstream_server_name", "listen_port"].includes(issue.path),
  entry: (issue) => ["entry_path", "policy_revision"].includes(issue.path),
  routes: (issue) => issue.path.startsWith("routes"),
  review: () => true,
};

const stepNote: Record<WizardStep, string> = {
  basics: "站点 ID、名称与公网入口",
  upstream: "源站地址、服务名、TLS 与监听端口",
  entry: "入口路径、准入、探针与状态",
  routes: "edge 允许的操作",
  review: "核对后保存",
};

const checklist: { step: WizardStep; label: string }[] = [
  { step: "basics", label: "基本信息" },
  { step: "upstream", label: "上游与监听" },
  { step: "entry", label: "入口与模式" },
  { step: "routes", label: "路由" },
];

function Checklist({ ws }: { ws: WorkspaceApi }) {
  return (
    <ul className="xs-checklist" aria-label="校验结果">
      {checklist.map(({ step, label }) => {
        const found = ws.issues.filter(owns[step]);
        const errors = found.filter((issue) => issue.severity === "error");
        const warnings = found.filter((issue) => issue.severity === "warning");
        const icon =
          errors.length > 0 ? (
            <CloseCircleFilled className="xs-check-icon xs-check-icon--error" aria-hidden="true" />
          ) : warnings.length > 0 ? (
            <ExclamationCircleFilled
              className="xs-check-icon xs-check-icon--warning"
              aria-hidden="true"
            />
          ) : (
            <CheckCircleFilled className="xs-check-icon xs-check-icon--ok" aria-hidden="true" />
          );
        return (
          <li key={step}>
            {icon}
            <span>
              <strong>{label}</strong>
              <span className="xs-visually-hidden">
                {errors.length > 0 ? "：有错误" : warnings.length > 0 ? "：有提示" : "：通过"}
              </span>
              {errors.length === 0 && warnings.length === 0 && <span className="muted"> 通过</span>}
              {[...errors, ...warnings].map((issue) => (
                <span key={`${issue.path}-${issue.message}`} className="xs-check-message">
                  {issue.message}
                </span>
              ))}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function ReviewStep({ ws }: { ws: WorkspaceApi }) {
  const draft = ws.draft;
  if (!draft) return null;
  const consequence =
    draft.status === "draft"
      ? "保存为草稿后，站点不会发布，也不需要审批。准备好后到“安全入口”把状态改为启用并保存；它属于上线变更，需要另一位审批人批准后才会对外服务。"
      : draft.status === "active"
        ? "这个站点将创建为“启用”：首次上线需要独立审批，批准前 edge 不会服务它。"
        : "这个站点将创建为“暂停”：edge 不会对外服务。";
  return (
    <div className="xs-cards">
      <Card title="站点概要" className="xs-card">
        <Descriptions
          size="small"
          column={1}
          items={[
            { key: "id", label: "站点 ID", children: <span className="mono">{ws.newSiteId}</span> },
            { key: "name", label: "站点名称", children: draft.display_name },
            {
              key: "origin",
              label: "公网入口",
              children: <span className="mono xs-wrap">{draft.public_origin}</span>,
            },
            {
              key: "up",
              label: "上游",
              children: (
                <span className="mono xs-wrap">
                  {draft.upstream_address}（{draft.upstream_tls ? "TLS" : "明文"}，
                  {draft.upstream_server_name}）
                </span>
              ),
            },
            {
              key: "port",
              label: "监听端口",
              children:
                draft.listen_port === 0 ? (
                  "自动分配"
                ) : (
                  <span className="mono">{draft.listen_port}</span>
                ),
            },
            {
              key: "entry",
              label: "入口",
              children: `${draft.entry_path} · ${securityEntryLabel[draft.security_entry]}`,
            },
            { key: "status", label: "状态", children: statusLabel[draft.status] },
            {
              key: "routes",
              label: "路由",
              children:
                draft.policy.routes.length === 0
                  ? "默认入口路由 protected.entry"
                  : `${draft.policy.routes.length} 条`,
            },
          ]}
        />
      </Card>
      <Card title="校验结果" className="xs-card">
        <Checklist ws={ws} />
        <p className="muted xs-wizard-note">
          这是控制台按服务端规则做的预检；服务端在保存时会再次完整校验，保存后可在“发布”页对已保存的修订再次验证。
        </p>
      </Card>
      <Card title="保存的后果" className="xs-card xs-card-wide">
        <Alert type="info" showIcon role="note" title={consequence} />
        <Collapse
          className="xs-wizard-diff"
          ghost
          items={[
            {
              key: "diff",
              label: `查看全部配置差异（相对新站点默认值，共 ${ws.changes.length} 项）`,
              children: <DiffTable changes={ws.changes} empty="与默认值没有差异。" />,
            },
          ]}
        />
      </Card>
    </div>
  );
}

/**
 * 新建站点: five steps from identity to a saved draft. The draft lives in the workspace, so it
 * survives step changes and the browser's back and forward buttons; leaving the wizard with
 * anything entered asks first, and a reload starts over (nothing is stored).
 */
export function NewSiteWizard({ step }: { step: WizardStep }) {
  const ws = useSiteWorkspace(null);
  const router = useRouter();
  const index = wizardSteps.findIndex(([key]) => key === step);
  const errorsOf = (key: WizardStep) => ws.errors.filter(owns[key]);
  const blocking = errorsOf(step);
  const reachable = (target: number) =>
    wizardSteps.slice(0, target).every(([key]) => errorsOf(key).length === 0);
  const go = (key: string) => void router.navigate({ to: `/sites/new/${key}` } as never);
  const next = wizardSteps[index + 1]?.[0];
  const previous = wizardSteps[index - 1]?.[0];
  const draft = ws.draft;

  let body: React.ReactNode = null;
  if (draft) {
    if (step === "basics") {
      body = (
        <Form layout="vertical" className="xs-form" disabled={ws.locked}>
          <div className="xs-cards">
            <Card title="站点标识" className="xs-card">
              <SiteIdFields ws={ws} />
            </Card>
            <Card title="公网入口" className="xs-card">
              <OriginField ws={ws} />
            </Card>
          </div>
        </Form>
      );
    } else if (step === "upstream") {
      body = (
        <Form layout="vertical" className="xs-form" disabled={ws.locked}>
          <div className="xs-cards">
            <Card title="源站（上游）" className="xs-card">
              <UpstreamFields ws={ws} />
            </Card>
            <Card title="监听" className="xs-card">
              <ListenPortField ws={ws} />
            </Card>
          </div>
        </Form>
      );
    } else if (step === "entry") {
      body = (
        <Form layout="vertical" className="xs-form" disabled={ws.locked}>
          <div className="xs-cards">
            <Card title="入口" className="xs-card">
              <EntryPathField ws={ws} />
              <EntryChoice ws={ws} />
            </Card>
            <Card title="运行状态" className="xs-card">
              <StatusChoice ws={ws} />
            </Card>
            <Card title="探针与策略标签" className="xs-card">
              <ProbeFields ws={ws} />
            </Card>
          </div>
        </Form>
      );
    } else if (step === "routes") {
      const customized = draft.policy.routes.length > 0;
      const apply = () => ws.update((current) => applyRouteTemplate(current, spaTemplate));
      body = (
        <div className="xs-wizard-routes">
          <Card title="快速开始（可选）" className="xs-card">
            <p>{spaTemplate.description}</p>
            {customized ? (
              <Popconfirm
                title="套用示例会替换当前的路由列表。"
                okText="替换"
                cancelText="取消"
                onConfirm={apply}
              >
                <Button disabled={ws.locked}>套用示例：{spaTemplate.title}</Button>
              </Popconfirm>
            ) : (
              <Button disabled={ws.locked} onClick={apply}>
                套用示例：{spaTemplate.title}
              </Button>
            )}
            <p className="muted xs-wizard-note">
              不套用也可以：没有任何路由时，edge 使用入口路径与安全入口生成的默认路由
              protected.entry，之后随时可以在站点的“路由与操作”中补充。
            </p>
          </Card>
          <RoutesTab ws={ws} />
        </div>
      );
    } else {
      body = <ReviewStep ws={ws} />;
    }
  }

  return (
    <section className="xs-site-page xs-wizard" aria-label="新建站点向导">
      <PageActions>
        <Button
          icon={<ArrowLeftOutlined aria-hidden="true" />}
          onClick={() => void router.navigate({ to: "/sites" } as never)}
        >
          返回站点列表
        </Button>
        <Button
          icon={<ReloadOutlined aria-hidden="true" />}
          disabled={ws.running}
          onClick={ws.refresh}
        >
          清空并重新填写
        </Button>
      </PageActions>
      <Steps
        className="xs-wizard-steps"
        size="small"
        current={index}
        onChange={(target) => {
          const key = wizardSteps[target]?.[0];
          if (key && reachable(target)) go(key);
        }}
        items={wizardSteps.map(([key, title], at) => ({
          title,
          content: stepNote[key],
          disabled: !reachable(at),
          status:
            at === index
              ? "process"
              : at < index && errorsOf(key).length === 0
                ? "finish"
                : errorsOf(key).length > 0 && at < index
                  ? "error"
                  : "wait",
        }))}
      />
      <PendingBanner ws={ws} />
      <NoticeBanner ws={ws} />
      <div className="xs-section-body">{body}</div>
      <div className="xs-wizard-footer">
        <Button disabled={!previous || ws.locked} onClick={() => previous && go(previous)}>
          上一步
        </Button>
        <span className="xs-wizard-hint">
          {blocking.length > 0 && !ws.locked
            ? `本步还有 ${blocking.filter((issue) => issue.severity === "error").length} 项需要修正`
            : ""}
        </span>
        {next ? (
          <Button
            type="primary"
            disabled={blocking.some((issue) => issue.severity === "error") || ws.locked}
            onClick={() => go(next)}
          >
            下一步
          </Button>
        ) : (
          <Button
            type="primary"
            loading={busy(ws.running)}
            disabled={ws.errors.length > 0 || ws.locked}
            onClick={() => void ws.save()}
          >
            {draft?.status === "draft" ? "保存为草稿" : "创建站点"}
          </Button>
        )}
      </div>
    </section>
  );
}
