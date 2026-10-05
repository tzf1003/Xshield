import { ArrowLeftOutlined, CloseCircleOutlined, ReloadOutlined } from "@ant-design/icons";
import { useParams } from "@tanstack/react-router";
import { Alert, Button, Space, Tabs } from "antd";
import { lazy, Suspense, useState } from "react";
import { ApiError } from "../../api-contract.ts";
import { type CaseTab, caseTabs } from "../../admin-routes.ts";
import { useSession } from "../../security/SessionProvider";
import { useGuardedQuery } from "../../security/hooks";
import { PageActions } from "../../shell/page-actions";
import { RouteLink, useGo } from "../../work/nav";
import { owners } from "../../work/operations.ts";
import { ErrorNotice, IdChip, Observed, StatePill, Time } from "../../work/Parts";
import { specs } from "../../work/queries.ts";
import { role, useRoles } from "../../work/roles.ts";
import { casePill } from "../../work/status.ts";
import { useUnresolved } from "../../work/use-write.ts";
import { PendingNotice } from "../../work/WriteDialog";
import { WorkRoot } from "../../work/WorkRoot";
import { CloseCaseDialog } from "./dialogs";
import { EvidenceTab } from "./EvidenceTab";

// The less used tabs load when they are first opened.
const AccessTab = lazy(() => import("./AccessTab").then((m) => ({ default: m.AccessTab })));
const ExportsTab = lazy(() => import("./ExportsTab").then((m) => ({ default: m.ExportsTab })));
const HoldsTab = lazy(() => import("./HoldsTab").then((m) => ({ default: m.HoldsTab })));
const AnalysisTab = lazy(() => import("./AnalysisTab").then((m) => ({ default: m.AnalysisTab })));

const tabNames: Record<CaseTab, string> = {
  evidence: "证据集合",
  access: "访问申请",
  holds: "保留锁",
  exports: "导出",
  analysis: "分析任务",
};

export function CaseDetailPage() {
  return (
    <WorkRoot>
      <CaseDetailBody />
    </WorkRoot>
  );
}

function CaseDetailBody() {
  const params = useParams({ strict: false }) as { caseId?: string; tab?: string };
  const caseId = params.caseId ?? "";
  const { has, subject } = useRoles();
  const { state } = useSession();
  const go = useGo();
  const investigator = has(role.investigator);
  const audit = has(role.audit);
  const header = useGuardedQuery({ ...specs.caseItems(caseId), enabled: investigator });
  const [closing, setClosing] = useState(false);
  const unresolvedClose = useUnresolved(owners.closeCase(caseId));
  const collection = header.data;
  const facts = collection?.case;
  const open = facts ? facts.status === "open" : null;

  // Which tabs this operator's roles can use; the server still decides every call.
  const visible = caseTabs.filter((name) => (name === "holds" ? audit : investigator));
  const requested = (caseTabs as readonly string[]).includes(params.tab ?? "")
    ? (params.tab as CaseTab)
    : "evidence";
  const active = visible.includes(requested) ? requested : (visible[0] ?? "evidence");
  const unavailable =
    header.error instanceof ApiError && header.error.code === "CONTROL_CASE_NOT_AVAILABLE";

  const body = (name: CaseTab) => {
    switch (name) {
      case "evidence":
        return <EvidenceTab caseId={caseId} canWrite={investigator} canRequest={investigator} />;
      case "access":
        return (
          <AccessTab
            caseId={caseId}
            caseOpen={open}
            members={collection?.items ?? []}
            canRequest={investigator}
          />
        );
      case "holds":
        return <HoldsTab caseId={caseId} members={collection?.items ?? []} />;
      case "exports":
        return <ExportsTab caseId={caseId} canRequest={investigator} />;
      case "analysis":
        return <AnalysisTab caseId={caseId} canWrite={investigator} />;
    }
  };

  return (
    <div className="xs-w-stack">
      <PageActions>
        <RouteLink to="/cases">
          <ArrowLeftOutlined aria-hidden="true" /> 返回案件列表
        </RouteLink>
        {investigator && (
          <>
            <Button
              icon={<ReloadOutlined aria-hidden="true" />}
              loading={header.isFetching}
              onClick={() => void header.refetch()}
            >
              刷新案件
            </Button>
            <Button
              danger
              icon={<CloseCircleOutlined aria-hidden="true" />}
              disabled={open !== true}
              title={open === false ? "案件已关闭" : undefined}
              onClick={() => setClosing(true)}
            >
              关闭案件
            </Button>
          </>
        )}
      </PageActions>
      <PendingNotice operation={unresolvedClose} label="关闭案件" onOpen={() => setClosing(true)} />
      <section className="xs-w-card xs-w-case-head" aria-label="案件概要">
        {facts && collection ? (
          <>
            <div className="xs-w-between">
              <h2 className="xs-w-title">{facts.purpose}</h2>
              <StatePill pill={casePill[facts.status]} />
            </div>
            <Space wrap size="middle" className="xs-w-muted">
              <IdChip id={facts.case_id} label="案件 ID" />
              <span>
                创建 <Time value={facts.created_at} />
              </span>
              {subject && <span>负责人 {subject}</span>}
            </Space>
            <Observed asOf={collection.as_of} requestId={collection.request_id} />
            {facts.status === "closed" && (
              <Alert
                type="warning"
                showIcon
                title="案件已关闭"
                description="历史证据引用、保留历史与导出仍可浏览；不能新增关联或申请原文访问。已通过校验的在途读取可能完成。"
              />
            )}
          </>
        ) : (
          <>
            <div className="xs-w-between">
              <h2 className="xs-w-title">案件</h2>
            </div>
            <IdChip id={caseId} label="案件 ID" />
            {header.isPending && investigator && <p className="xs-w-muted">正在读取案件…</p>}
            {unavailable && (
              <Alert
                type="warning"
                showIcon
                title="当前身份和范围内案件不可用"
                description="案件不存在、不属于你或超出当前作用域时统一显示为不可用，不泄露它是否存在。"
              />
            )}
            {header.error && !unavailable && (
              <ErrorNotice
                error={header.error}
                action={
                  <Button size="small" onClick={() => void header.refetch()}>
                    重试
                  </Button>
                }
              />
            )}
            {!investigator && audit && (
              <Alert
                type="info"
                showIcon
                title="仅显示保留锁"
                description="案件概要、证据集合、访问申请和导出需要 Investigator 角色；你的角色可以管理本案件的保留锁。"
              />
            )}
            {!investigator && !audit && state.status === "connected" && (
              <Alert type="info" showIcon title="当前角色不能读取案件" />
            )}
          </>
        )}
      </section>
      {!unavailable && (
        <Tabs
          activeKey={active}
          onChange={(key) =>
            go(key === "evidence" ? `/cases/${caseId}` : `/cases/${caseId}/${key}`)
          }
          items={visible.map((name) => ({
            key: name,
            label: tabNames[name],
            children:
              name === active ? (
                <Suspense fallback={<p className="xs-w-muted">正在加载…</p>}>{body(name)}</Suspense>
              ) : null,
          }))}
        />
      )}
      {closing && <CloseCaseDialog caseId={caseId} onClose={() => setClosing(false)} />}
    </div>
  );
}
