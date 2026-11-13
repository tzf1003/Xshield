// The site page at /sites/$name (docs/06 6.4.9). Overview, configuration, tuning suggestions and change history
// share one draft. The draft lives in sessionStorage until it is saved, so a refresh keeps it, and leaving the
// page with unsaved changes asks first. After a save or a rollback the page follows the gateways until they have
// loaded the new version (docs/07 7.9.13): one poll a second, for at most two minutes.

import { Link, useBlocker, useNavigate, useParams, useSearch } from "@tanstack/react-router";
import { Modal, Tabs } from "antd";
import { type ReactNode, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { useDeleteSite, useSite, useSiteObjects } from "../../api/queries.ts";
import type { SiteDetail, SiteSpec, SiteVersion } from "../../api/types.ts";
import { useKeys } from "../../app/keys.ts";
import { useNowBucket, useSetSearch } from "../../app/scope.ts";
import { canonical, semanticChanges } from "../../lib/diff.ts";
import { fmtInt } from "../../lib/format.ts";
import { validateSpec } from "../../lib/site-validate.ts";
import { OBJECT_TEXT } from "../../lib/vocab.ts";
import { ErrorBar, Loading, Notice, PageHead } from "../../ui/Page.tsx";
import { type ConfigGroupId, ConfigTab, isConfigGroup } from "./ConfigTab.tsx";
import { HistoryTab } from "./HistoryTab.tsx";
import { InsightsTab } from "./InsightsTab.tsx";
import { ModeSwitchDialog } from "./ModeSwitchDialog.tsx";
import { OverviewTab } from "./OverviewTab.tsx";
import type { ApplyOptions } from "./objects/objects-model.ts";
import { LazyObjectsTab } from "./objects/objects-lazy.ts";
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

/** The group a configuration link opens: the one it names, else the rules when it names a path, else the basics. */
function groupOf(search: { group?: string; route?: string }): ConfigGroupId {
  if (isConfigGroup(search.group)) return search.group;
  return search.route ? "routes" : "basics";
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
  const [notice, setNotice] = useState<string | null>(null);
  const [saveHint, setSaveHint] = useState<ApplyOptions>({});
  const [created, setCreated] = useState(() => readCreated(name));
  // The wizard's hand-off (console design 1.4): the draft it wrote opens the save dialog once, and the count of the
  // positions it confirmed is said after the save.
  const handoff = useRef({
    save: search.save === "1",
    count: search.bootstrap as number | undefined,
  });
  const handedOff = useRef(false);
  const leaving = useRef(false);
  const dirtyRef = useRef(false);
  const following = pending !== null && now - pending.savedAt < FOLLOW_MS;
  const site = useSite(name, { refetchInterval: following ? 1_000 : false });
  // The map's counts give the tab its label; the tab itself reads the map with its filters.
  const objectMap = useSiteObjects(name);
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

  // The wizard's hand-off opens the save dialog of its draft once the site has loaded, and drops its parameters.
  useEffect(() => {
    if (handedOff.current || !handoff.current.save || !dirty) return;
    handedOff.current = true;
    setSaveHint({ note: OBJECT_TEXT.events.noteWizard });
    setSaveOpen(true);
    setSearch({ save: undefined, bootstrap: undefined }, true);
  }, [dirty, setSearch]);

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

  const changeDraft = useCallback(
    (next: SiteSpec) => {
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
    },
    [data, draft, name],
  );

  const discard = () => {
    clearDraft(name);
    setDraft(null);
    setFlash(null);
  };

  // A link to the configuration with `route=<path>` adds a rule for that path, its segment reading a request header
  // and its name left for the user to fill in. Each link adds it once: a rule for the path already there is kept.
  const routeLink = useRef<string | null>(null);
  useEffect(() => {
    const route = search.route;
    if (!route || search.tab !== "config" || data === undefined) return;
    const key = `${name}\n${route}`;
    if (routeLink.current === key) return;
    routeLink.current = key;
    const rules = working.routes ?? [];
    if (rules.some((rule) => rule.path === route)) return;
    changeDraft({ ...working, routes: [...rules, { path: route, name_from: [["header."]] }] });
  }, [search.route, search.tab, data, name, working, changeDraft]);

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
    setSaveHint({});
    const count = handoff.current.count;
    handoff.current.count = undefined;
    if (count !== undefined) setNotice(OBJECT_TEXT.wizard.saved(count, version));
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
  const group = groupOf(search);
  const proposed = objectMap.data?.counts.proposed ?? 0;
  const tabItems = [
    { key: "overview", label: "概览" },
    { key: "config", label: "配置" },
    {
      key: "objects",
      label: proposed > 0 ? `${OBJECT_TEXT.tab} ${fmtInt(proposed)}` : OBJECT_TEXT.tab,
    },
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
  } else if (tab === "objects") {
    body = (
      <Suspense fallback={<Loading height={240} />}>
        <LazyObjectsTab
          site={data}
          working={working}
          now={now}
          dialogOpen={saveOpen || modeOpen || rollbackTo !== null}
          onAdd={changeDraft}
          onApply={(spec, options) => {
            changeDraft(spec);
            setSaveHint(options ?? {});
            setSaveOpen(true);
          }}
        />
      </Suspense>
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
      {remove.isError ? <ErrorBar error={remove.error} /> : null}

      {created ? (
        <div className="created-site">
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
        </div>
      ) : null}

      {/* Written as enforce, the site has no observation period: a hint, not a block (docs/06 6.4.8). */}
      {created?.mode === "enforce" ? (
        <Notice>▲ 新站点没有观察期，入口和绕过设错会直接拦截正常请求</Notice>
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
      {notice ? <Notice tone="info">{notice}</Notice> : null}

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
          initialNote={saveHint.note}
          objectEvent={saveHint.objectEvent}
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
