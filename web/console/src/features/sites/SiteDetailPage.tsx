// The site page at /sites/$name (docs/06 6.4.9). Overview, configuration, tuning suggestions and change history
// share one draft. The draft lives in sessionStorage until it is saved, so a refresh keeps it, and leaving the
// page with unsaved changes asks first. After a save or a rollback the page follows the gateways until they have
// loaded the new version (docs/07 7.9.13): one poll a second, for at most two minutes.

import { Link, useBlocker, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { Modal, Tabs } from "antd";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useDeleteSite, useSite } from "../../api/queries.ts";
import type { SiteDetail, SiteSpec, SiteVersion } from "../../api/types.ts";
import { useKeys } from "../../app/keys.ts";
import { useNowBucket, useSetSearch } from "../../app/scope.ts";
import { canonical, semanticChanges } from "../../lib/diff.ts";
import { fmtInt } from "../../lib/format.ts";
import { validateSpec } from "../../lib/site-validate.ts";
import { ErrorBar, Loading, Notice, PageHead } from "../../ui/Page.tsx";
import { ConfigTab, isConfigGroup } from "./ConfigTab.tsx";
import { HistoryTab } from "./HistoryTab.tsx";
import { InsightsTab } from "./InsightsTab.tsx";
import { ModeSwitchDialog } from "./ModeSwitchDialog.tsx";
import { OverviewTab } from "./OverviewTab.tsx";
import { RollbackDialog } from "./RollbackDialog.tsx";
import { type RolloutTone, rolloutView } from "./rollout.ts";
import { SaveDialog } from "./SaveDialog.tsx";
import { SiteHeader } from "./SiteHeader.tsx";
import { emptySpec } from "./spec-model.ts";
import {
  clearCreated,
  clearDraft,
  readCreated,
  readDraft,
  writeCopy,
  writeDraft,
} from "./site-storage.ts";
import "./sites.css";

type Pending = { version: number; savedAt: number };
type Settled = { version: number; seconds: number; loaded: number; online: number };

/** After this long the page stops polling; the banner keeps the last state until it is closed. */
const FOLLOW_MS = 120_000;

const BANNER_TONE: Record<RolloutTone, string> = {
  ok: "ok",
  wait: "",
  warn: "warn",
  bad: "bad",
  none: "",
};

export function SiteDetailPage() {
  const { name } = useParams({ from: "/sites/$name" });
  return <SiteDetailBody key={name} name={name} />;
}

function RolloutBanner({
  version,
  site,
  now,
  onClose,
}: {
  version: number;
  site: SiteDetail;
  now: number;
  onClose: () => void;
}) {
  const view = rolloutView(site.rollout, site.updated_at, now);
  const needsSystem = view.tone === "warn" || view.tone === "bad";
  return (
    <div className={`banner ${BANNER_TONE[view.tone]}`} role="status" aria-live="polite">
      <div className="grow">
        <div>
          已保存 v{version} · {view.headline}
        </div>
        {view.lines.map((line) => (
          <div key={line.text} className={line.tone === "bad" ? "field-error small" : "small"}>
            {line.text}
          </div>
        ))}
      </div>
      {needsSystem ? (
        <Link to="/system" search={{ tab: "edges" }} className="linkbtn">
          查看网关
        </Link>
      ) : null}
      <button type="button" className="linkbtn" onClick={onClose}>
        收起
      </button>
    </div>
  );
}

function SiteDetailBody({ name }: { name: string }) {
  const search = useSearch({ from: "/sites/$name" });
  const setSearch = useSetSearch();
  const navigate = useNavigate();
  const now = useNowBucket(5_000);
  const [draft, setDraft] = useState(() => readDraft(name));
  const [pending, setPending] = useState<Pending | null>(null);
  const [settled, setSettled] = useState<Settled | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [modeOpen, setModeOpen] = useState(false);
  const [rollbackTo, setRollbackTo] = useState<SiteVersion | null>(null);
  const [flash, setFlash] = useState<string | null>(null);
  const [created, setCreated] = useState(() => readCreated(name));
  const leaving = useRef(false);
  const dirtyRef = useRef(false);
  const following = pending !== null && now - pending.savedAt < FOLLOW_MS;
  const site = useSite(name, { refetchInterval: following ? 1_000 : false });
  const remove = useDeleteSite();
  const data = site.data;

  // The draft is kept only while it differs from the saved configuration; `working` is what the page shows.
  const working: SiteSpec = draft?.spec ?? data?.spec ?? emptySpec();
  const dirty =
    data !== undefined && draft !== null && canonical(draft.spec) !== canonical(data.spec);
  const issues = validateSpec(working);
  const changeCount = data === undefined ? 0 : semanticChanges(data.spec, working).length;

  // The creation banner is shown once: the page that opens after a new site reads it, then forgets it.
  useEffect(() => {
    clearCreated();
  }, []);

  useEffect(() => {
    dirtyRef.current = dirty;
  });

  // Once the gateways have loaded the saved version, the banner turns into a short confirmation.
  useEffect(() => {
    if (pending === null || data === undefined) return;
    const view = rolloutView(data.rollout, data.updated_at, Date.now());
    if (view.tone !== "ok" || data.rollout.version < pending.version) return;
    setSettled({
      version: pending.version,
      seconds: (Date.now() - pending.savedAt) / 1000,
      loaded: view.loaded,
      online: view.online,
    });
    setPending(null);
  }, [pending, data]);

  // Leaving with unsaved changes asks first; moving between tabs or groups (the same path) does not.
  const blocker = useBlocker({
    shouldBlockFn: ({ current, next }) =>
      dirtyRef.current && !leaving.current && next.pathname !== current.pathname,
    enableBeforeUnload: () => dirtyRef.current && !leaving.current,
    withResolver: true,
  });

  const changeDraft = (next: SiteSpec) => {
    if (data === undefined) return;
    setFlash(null);
    if (canonical(next) === canonical(data.spec)) {
      clearDraft(name);
      setDraft(null);
      return;
    }
    const record = { base: draft?.base ?? data.version, spec: next };
    writeDraft(name, record);
    setDraft(record);
  };

  const discard = () => {
    clearDraft(name);
    setDraft(null);
    setFlash(null);
  };

  /** Save (⌘S or the draft bar): a configuration with errors goes to the first wrong group, otherwise the dialog. */
  const requestSave = () => {
    if (!dirty) return;
    const first = issues.errors[0];
    if (first) {
      setFlash(`有 ${fmtInt(issues.errors.length)} 项需要修正：${first.message}`);
      setSearch({ tab: "config", group: first.group });
      return;
    }
    setSaveOpen(true);
  };

  useKeys(
    {
      "Mod+s": (event) => {
        event.preventDefault();
        requestSave();
      },
    },
    !saveOpen && !modeOpen && rollbackTo === null,
  );

  const startFollowing = (version: number) => {
    setSettled(null);
    setPending({ version, savedAt: Date.now() });
  };

  const savedDraft = (version: number) => {
    clearDraft(name);
    setDraft(null);
    setSaveOpen(false);
    startFollowing(version);
  };

  const copySite = () => {
    if (data === undefined) return;
    // A copy takes every setting but the name: the new site needs a name of its own.
    writeCopy({ ...data.spec, name: "" });
    void navigate({ to: "/sites/new" });
  };

  const deleteSite = () => {
    remove.mutate(name, {
      onSuccess: () => {
        clearDraft(name);
        leaving.current = true;
        void navigate({ to: "/sites" });
      },
    });
  };

  if (data === undefined) {
    if (!site.isError) return <Loading height={200} />;
    return (
      <>
        <PageHead title={name} crumbs={<Link to="/sites">站点</Link>} />
        <ErrorBar error={site.error} onRetry={() => void site.refetch()} />
      </>
    );
  }

  const tab = search.tab ?? "overview";
  const edit = search.edit ?? "form";
  const group = isConfigGroup(search.group) ? search.group : "basics";
  const tabItems = [
    { key: "overview", label: "概览" },
    { key: "config", label: "配置" },
    {
      key: "insights",
      label: data.suggestions > 0 ? `调优建议 ${fmtInt(data.suggestions)}` : "调优建议",
    },
    { key: "history", label: "变更历史" },
  ];

  let body: ReactNode;
  if (tab === "overview") {
    body = <OverviewTab site={data} now={now} onInsights={() => setSearch({ tab: "insights" })} />;
  } else if (tab === "config") {
    body = (
      <ConfigTab
        site={data}
        draft={working}
        dirty={dirty}
        changeCount={changeCount}
        issues={issues}
        edit={edit}
        group={group}
        onEdit={(value) => setSearch({ edit: value }, true)}
        onGroup={(value) => setSearch({ group: value }, true)}
        onDraft={changeDraft}
        onDiscard={discard}
        onReview={requestSave}
        onSwitchMode={() => setModeOpen(true)}
      />
    );
  } else if (tab === "insights") {
    body = (
      <InsightsTab
        site={data}
        working={working}
        now={now}
        onAdd={changeDraft}
        onApply={(spec) => {
          changeDraft(spec);
          setSaveOpen(true);
        }}
      />
    );
  } else {
    body = <HistoryTab site={data} diff={search.diff} onRollback={setRollbackTo} />;
  }

  return (
    <>
      <SiteHeader
        site={data}
        now={now}
        onSwitchMode={() => setModeOpen(true)}
        onCopy={copySite}
        onDelete={deleteSite}
        deleting={remove.isPending}
      />

      {created ? (
        <Notice tone="info">
          <div className="row between">
            <span>
              已创建 v{created.version}。下一步：把 Host
              解析到网关；用浏览器走一遍正常流程，再回来看请求追溯。
            </span>
            <button type="button" className="linkbtn" onClick={() => setCreated(null)}>
              知道了
            </button>
          </div>
        </Notice>
      ) : null}

      {pending !== null ? (
        <RolloutBanner
          version={pending.version}
          site={data}
          now={now}
          onClose={() => setPending(null)}
        />
      ) : null}

      {settled !== null ? (
        <div className="banner ok" role="status">
          <div className="grow">
            ● v{settled.version} 已生效（{fmtInt(settled.loaded)}/{fmtInt(settled.online)} 个网关，
            {settled.seconds.toFixed(1)} 秒）
          </div>
          <button type="button" className="linkbtn" onClick={() => setSettled(null)}>
            收起
          </button>
        </div>
      ) : null}

      {flash ? <Notice tone="bad">{flash}</Notice> : null}

      <div className="tabs-wrap">
        <Tabs activeKey={tab} onChange={(key) => setSearch({ tab: key })} items={tabItems} />
      </div>

      {dirty && tab !== "config" ? (
        <Notice>
          未保存的改动 {fmtInt(changeCount)} 处 ·{" "}
          <button type="button" className="linkbtn" onClick={() => setSearch({ tab: "config" })}>
            去配置查看
          </button>
        </Notice>
      ) : null}

      {body}

      {saveOpen && dirty ? (
        <SaveDialog
          site={data}
          draft={working}
          baseVersion={draft?.base ?? data.version}
          onClose={() => setSaveOpen(false)}
          onSaved={(_spec, version) => savedDraft(version)}
          onDiscard={() => {
            discard();
            setSaveOpen(false);
          }}
        />
      ) : null}

      {modeOpen ? (
        <ModeSwitchDialog
          site={data}
          dirty={dirty}
          onClose={() => setModeOpen(false)}
          onSaved={(version) => {
            setModeOpen(false);
            startFollowing(version);
          }}
        />
      ) : null}

      {rollbackTo !== null ? (
        <RollbackDialog
          site={data}
          target={rollbackTo}
          dirty={dirty}
          onClose={() => setRollbackTo(null)}
          onDone={(version) => {
            setRollbackTo(null);
            startFollowing(version);
          }}
        />
      ) : null}

      {blocker.status === "blocked" ? (
        <Modal open onCancel={blocker.reset} title="离开前保存改动？" width={460} footer={null}>
          <div className="stack">
            <div>
              还有 {fmtInt(changeCount)} 处未保存的改动。草稿保存在这个浏览器里，回到本页时会恢复。
            </div>
            <div className="row" style={{ justifyContent: "flex-end" }}>
              <button type="button" className="btn" onClick={blocker.reset}>
                留在此页
              </button>
              <button type="button" className="btn-primary" onClick={blocker.proceed}>
                离开
              </button>
            </div>
          </div>
        </Modal>
      ) : null}
    </>
  );
}
