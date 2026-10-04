import { ArrowLeftOutlined, ReloadOutlined } from "@ant-design/icons";
import { useParams, useRouter } from "@tanstack/react-router";
import { Button, Skeleton } from "antd";
import { useMemo } from "react";
import { type SiteSection, siteSections } from "../../admin-routes.ts";
import { safeError } from "../../security/errors.ts";
import { PageActions } from "../../shell/page-actions";
import { groupChanges } from "../../sites/model/diff.ts";
import { configSections, sectionLabel, visibleSections } from "../../sites/sections.ts";
import { ProblemAlert } from "../../ui/ProblemAlert";
import { busy } from "./fields";
import { NoticeBanner, PendingBanner } from "./workspace/Banners";
import { ChangeBar } from "./workspace/ChangeBar";
import { SectionNav } from "./workspace/SectionNav";
import { SiteHeader } from "./workspace/SiteHeader";
import { useSiteWorkspace, type WorkspaceApi } from "./workspace/use-workspace.ts";
import { NetworkTab, SecurityEntryTab } from "./tabs/NetworkTabs";
import { AuditTab, OverviewTab } from "./tabs/OverviewTabs";
import { CryptoTab, IdentityTab, PoliciesTab, WafLimitsTab } from "./tabs/PolicyTabs";
import { ReleasesTab } from "./tabs/ReleasesTab";
import { RoutesTab } from "./tabs/RoutesTab";
import "../../ui/ui.css";
import "./sites.css";
import "./workspace.css";

const sectionNames = siteSections.map(([key]) => key) as readonly string[];

/** `/sites/{siteId}/{section}`. (New sites are created in the wizard at `/sites/new/{step}`.) */
export function SiteDetailPage() {
  const params = useParams({ strict: false }) as { siteId?: string; section?: string };
  const siteId = params.siteId ?? "";
  const section = (
    sectionNames.includes(params.section ?? "") ? params.section : "overview"
  ) as SiteSection;
  // A different site is a different workspace: drafts and unsaved edits never cross sites.
  return <SiteWorkspace key={siteId} siteId={siteId} section={section} />;
}

function renderSection(section: SiteSection, ws: WorkspaceApi) {
  switch (section) {
    case "overview":
      return <OverviewTab ws={ws} />;
    case "network":
      return <NetworkTab ws={ws} />;
    case "security-entry":
      return <SecurityEntryTab ws={ws} />;
    case "routes":
      return <RoutesTab ws={ws} />;
    case "identity":
      return <IdentityTab ws={ws} />;
    case "crypto":
      return <CryptoTab ws={ws} />;
    case "waf-limits":
      return <WafLimitsTab ws={ws} />;
    case "policies":
      return <PoliciesTab ws={ws} />;
    case "releases":
      return <ReleasesTab ws={ws} />;
    case "audit":
      return <AuditTab ws={ws} />;
  }
}

function SiteWorkspace({ siteId, section }: { siteId: string; section: SiteSection }) {
  const ws = useSiteWorkspace(siteId);
  const router = useRouter();
  const basePath = `/sites/${siteId}`;
  const sections = visibleSections(ws.access, ws.creating);
  const offered = sections.includes(section);
  const go = (key: string) => void router.navigate({ to: `${basePath}/${key}` } as never);

  const unsaved = useMemo(() => {
    const counts = new Map(
      [...groupChanges(ws.changes)].map(([group, items]) => [group, items.length] as const),
    );
    return counts;
  }, [ws.changes]);

  // Only an editor needs the draft; an observer opening 策略与健康 reads health, nothing else.
  const needsDraft = ws.access.canConfigure && configSections.includes(section as never);
  const configReady = ws.draft !== null;
  const readError = ws.access.canConfigure
    ? ws.configQuery.error
    : ws.access.canObserve
      ? ws.statusQuery.error
      : null;
  const waiting = ws.access.canConfigure && ws.configQuery.isPending;
  const missing = ws.found === false;

  let body: React.ReactNode;
  if (!offered) {
    body = (
      <p className="empty">
        当前角色没有权限查看“{sectionLabel[section]}”。
        {sections[0] && (
          <>
            {" "}
            <button type="button" className="text-button" onClick={() => go(sections[0] as string)}>
              转到“{sectionLabel[sections[0]]}”
            </button>
          </>
        )}
      </p>
    );
  } else if (readError) {
    body = <ProblemAlert problem={safeError(readError)} />;
  } else if (waiting) {
    body = <Skeleton active paragraph={{ rows: 6 }} />;
  } else if (missing) {
    body = <p className="empty">站点不存在或当前范围内不可见。</p>;
  } else if (needsDraft && !configReady) {
    body = <Skeleton active paragraph={{ rows: 6 }} />;
  } else {
    body = renderSection(section, ws);
  }

  const refreshable = ws.access.canConfigure || ws.access.canObserve;
  return (
    <section
      className="xs-site-page"
      aria-label={ws.access.canConfigure ? "受保护站点配置" : "站点运行与发布"}
    >
      <PageActions>
        <Button
          icon={<ArrowLeftOutlined aria-hidden="true" />}
          onClick={() => void router.navigate({ to: "/sites" } as never)}
        >
          返回站点列表
        </Button>
        {refreshable && (
          <Button
            icon={<ReloadOutlined aria-hidden="true" />}
            disabled={ws.running}
            loading={busy(ws.configQuery.isFetching || ws.statusQuery.isFetching)}
            onClick={ws.refresh}
          >
            {ws.access.canConfigure ? "刷新站点" : "刷新站点状态"}
          </Button>
        )}
      </PageActions>
      <SiteHeader ws={ws} />
      <PendingBanner ws={ws} />
      <NoticeBanner ws={ws} />
      {sections.length > 0 && (
        <SectionNav basePath={basePath} sections={sections} current={section} unsaved={unsaved} />
      )}
      <div className="xs-section-body">{body}</div>
      <ChangeBar ws={ws} onGo={go} />
    </section>
  );
}
