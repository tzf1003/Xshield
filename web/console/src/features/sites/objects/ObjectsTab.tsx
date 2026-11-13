// The object map of a site (console design 3.1 to 3.6): what the proxy has learned about the values that name objects,
// by class or by position. The counters, the search, the view, the source filter and the open position live in the URL.
// The learning task's line and its run record sit under the counters (3.2, 3.3). The drawer, the declaration dialog, the
// synonym migration and the learning settings change the draft, which the save dialog saves as a version; ignoring,
// marking ambiguous, dismissing, keeping a pause and asking the agent again are learning state and are written at once.

import { useSearch } from "@tanstack/react-router";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useSiteFunctions, useSiteObjects } from "../../../api/queries.ts";
import type { ObjectSlotRow, SiteDetail, SiteSpec } from "../../../api/types.ts";
import { useKeys } from "../../../app/keys.ts";
import { useSetSearch } from "../../../app/scope.ts";
import { effectiveLearning } from "../../../lib/objects-validate.ts";
import { FUNCTION_VIEW, OBJECT_AGENT_TEXT, OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Empty, ErrorBar, Loading, Notice } from "../../../ui/Page.tsx";
import { ColdStartPanel } from "./ColdStartPanel.tsx";
import { DeclareKindDialog } from "./DeclareKindDialog.tsx";
import { LearningRunsDrawer } from "./LearningRunsDrawer.tsx";
import { LearningSettings } from "./LearningSettings.tsx";
import { LearningStatusBar } from "./LearningStatusBar.tsx";
import { ObjectClassCard } from "./ObjectClassCard.tsx";
import { ObjectClassList } from "./ObjectClassList.tsx";
import { ObjectCounters } from "./ObjectCounters.tsx";
import { ObjectEventsDrawer } from "./ObjectEventsDrawer.tsx";
import { JudgementPanel } from "./JudgementPanel.tsx";
import { ObjectsBanner } from "./ObjectsBanner.tsx";
import { FunctionsView } from "./FunctionsView.tsx";
import { choiceOf, filtersOf, type SourceChoice } from "./objects-agent.ts";
import { type ApplyOptions, classMatches, slotsOfClass } from "./objects-model.ts";
import { sameJson } from "../spec-model.ts";
import { SlotDrawer } from "./SlotDrawer.tsx";
import { SlotTable } from "./SlotTable.tsx";
import { SynonymMigrateDialog } from "./SynonymMigrateDialog.tsx";
import "./objects.css";

type Props = {
  site: SiteDetail;
  /** The draft, or the saved configuration when there is none: every change applies on top of it. */
  working: SiteSpec;
  now: number;
  /** A dialog of the page is open (save, mode, rollback): the keys of this tab wait. */
  dialogOpen: boolean;
  onAdd: (spec: SiteSpec) => void;
  /** Opens the save dialog with the draft; the options carry the note and the automatic change it undoes or confirms. */
  onApply: (spec: SiteSpec, options?: ApplyOptions) => void;
};

export function ObjectsTab({ site, working, now, dialogOpen, onAdd, onApply }: Props) {
  const search = useSearch({ from: "/sites/$name" });
  const setSearch = useSetSearch();
  const objects = useSiteObjects(site.name, {
    state: search.state,
    q: search.q,
    source: search.source,
    agent: search.agent,
  });
  // The function table is read with the page's first view, so the radio can say how many proposals wait (7.9.20).
  const functions = useSiteFunctions(site.name);
  const [text, setText] = useState(search.q ?? "");
  const [declareOpen, setDeclareOpen] = useState(false);
  // A kind the learning agent proposed for the position the declaration dialog opens for (console design 3.4).
  const [declareKind, setDeclareKind] = useState<string | undefined>(undefined);
  const [synonymsOpen, setSynonymsOpen] = useState(false);
  const [learningOpen, setLearningOpen] = useState(false);
  const [skipped, setSkipped] = useState(false);
  const searchBox = useRef<HTMLInputElement>(null);

  const data = objects.data;
  const q = search.q ?? "";
  const view: "class" | "slot" | "functions" =
    search.view === "slot" ? "slot" : search.view === "functions" ? "functions" : "class";
  const classes = (data?.classes ?? []).filter((item) => classMatches(item, q));
  const current = classes.find((item) => item.id === search.class) ?? classes[0];
  // The rows the page shows, in the order the keys step through them.
  let rows: readonly ObjectSlotRow[] = [];
  if (data !== undefined) {
    if (view === "slot") rows = data.slots;
    else if (current !== undefined) rows = slotsOfClass(data.slots, current.id);
  }
  const slot = search.slot;
  const slotIndex = rows.findIndex((row) => row.id === slot);
  const declaring = declareOpen || search.declare !== undefined;
  const eventsOpen = search.objevents !== undefined;
  const runsOpen = search.runs === "1";
  const dialogsOpen =
    dialogOpen || declaring || synonymsOpen || learningOpen || eventsOpen || runsOpen;
  // The source menu's choice, and the saved configuration's switches: the server answers a run or a question by the
  // saved configuration, so the status line and the agent's buttons follow it rather than the draft.
  const choice: SourceChoice = choiceOf(search.source, search.agent);
  const savedLearning = effectiveLearning(site.spec.objects?.learning);
  const autoLearn = savedLearning.auto_learn;
  const agentOn = savedLearning.agent.enabled;

  const open = (id: string) => setSearch({ slot: id }, true);
  const close = () => setSearch({ slot: undefined }, true);
  const move = (step: number) => {
    if (rows.length === 0) return;
    // Without an open position, the first step lands on the first row going down and the last one going up.
    let target = slotIndex + step;
    if (slotIndex < 0) target = step > 0 ? 0 : rows.length - 1;
    const next = rows[Math.min(Math.max(target, 0), rows.length - 1)];
    if (next !== undefined) open(next.id);
  };

  // The search box writes the URL once the typing pauses, so each keystroke does not reload the map.
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const next = text.trim();
      if (next !== (search.q ?? "")) setSearch({ q: next.length > 0 ? next : undefined }, true);
    }, 250);
    return () => window.clearTimeout(timer);
  }, [text, search.q, setSearch]);

  useKeys(
    {
      j: () => move(1),
      k: () => move(-1),
      Escape: () => {
        if (slot !== undefined) close();
      },
      "/": (event) => {
        event.preventDefault();
        searchBox.current?.focus();
      },
    },
    !dialogsOpen,
  );

  if (objects.isError)
    return <ErrorBar error={objects.error} onRetry={() => void objects.refetch()} />;
  if (data === undefined) return <Loading height={180} />;

  const counts = data.counts;
  // The draft holds changes of its own: a judgement confirmed now would be written over the version the draft started from.
  const drafted = !sameJson(working, site.spec);
  const mapped =
    counts.pending + counts.proposed + counts.confirmed + counts.ambiguous + counts.suspended;
  const empty = counts.classes === 0 && mapped === 0;
  const closeDeclare = () => {
    setDeclareOpen(false);
    setDeclareKind(undefined);
    if (search.declare !== undefined || search.in !== undefined) {
      setSearch({ declare: undefined, in: undefined }, true);
    }
  };

  let body: ReactNode;
  if (view === "functions") {
    body = (
      <FunctionsView
        site={site.name}
        working={working}
        data={functions.data}
        failure={functions.isError ? functions.error : null}
        onRetry={() => void functions.refetch()}
        dirty={drafted}
        onApply={onApply}
      />
    );
  } else if (empty && !skipped) {
    body = (
      <ColdStartPanel
        site={site.name}
        working={working}
        classes={data.classes}
        pathConfirm={data.features.path_confirm}
        onApply={onApply}
        onLater={() => setSkipped(true)}
      />
    );
  } else if (view === "slot") {
    body =
      rows.length === 0 ? (
        <Empty title={OBJECT_TEXT.none} />
      ) : (
        <SlotTable
          rows={rows}
          classes={data.classes}
          selected={slot ?? null}
          now={now}
          onOpen={open}
        />
      );
  } else if (current === undefined) {
    body = (
      <Empty title={OBJECT_TEXT.none}>
        {data.classes.length === 0 ? OBJECT_TEXT.noClasses : null}
      </Empty>
    );
  } else {
    body = (
      <div className="obj-split">
        <ObjectClassList
          classes={classes}
          selected={current.id}
          onSelect={(id) => setSearch({ class: id }, true)}
        />
        <ObjectClassCard
          cls={current}
          rows={rows}
          classes={data.classes}
          selected={slot ?? null}
          now={now}
          onOpen={open}
        />
      </div>
    );
  }

  return (
    <div className="obj-stack">
      <ObjectsBanner site={site.name} events={data.events} />

      {view === "functions" ? null : (
        <div className="obj-tools">
          <ObjectCounters
            counts={counts}
            state={search.state}
            onState={(next) => setSearch({ state: next }, true)}
          />
          <input
            ref={searchBox}
            type="search"
            className="native-input obj-search"
            aria-label={OBJECT_TEXT.search}
            placeholder={OBJECT_TEXT.search}
            value={text}
            onChange={(event) => setText(event.target.value)}
          />
        </div>
      )}

      {view === "functions" ? null : (
        <LearningStatusBar
          site={site.name}
          learning={data.learning_run}
          autoLearn={autoLearn}
          agentOn={agentOn}
          agentHealth={data.agent_health}
          now={now}
          onRuns={() => setSearch({ runs: "1" }, true)}
          onFilter={(next) => {
            if ("agent" in next) setSearch(filtersOf(next.agent), true);
            else setSearch({ state: next.state }, true);
          }}
        />
      )}

      <div className="obj-tools">
        <div className="obj-tools-line">
          <div className="obj-tools-line" role="radiogroup" aria-label={OBJECT_TEXT.viewLabel}>
            <label className="adv-radio">
              <input
                type="radio"
                name="object-view"
                checked={view === "class"}
                onChange={() => setSearch({ view: undefined }, true)}
              />
              {OBJECT_TEXT.view.byClass}
            </label>
            <label className="adv-radio">
              <input
                type="radio"
                name="object-view"
                checked={view === "slot"}
                onChange={() => setSearch({ view: "slot" }, true)}
              />
              {OBJECT_TEXT.view.byPosition}
            </label>
            <label className="adv-radio">
              <input
                type="radio"
                name="object-view"
                checked={view === "functions"}
                onChange={() => setSearch({ view: "functions" }, true)}
              />
              {FUNCTION_VIEW.radio(functions.data?.proposals.length ?? 0)}
            </label>
          </div>
          {view === "functions" ? null : (
            <label className="small">
              {OBJECT_AGENT_TEXT.filter.label}{" "}
              <select
                className="native-input"
                value={choice}
                onChange={(event) => setSearch(filtersOf(event.target.value as SourceChoice), true)}
              >
                <option value="all">{OBJECT_AGENT_TEXT.filter.all}</option>
                <option value="admin">{OBJECT_AGENT_TEXT.filter.admin}</option>
                <option value="rule">{OBJECT_AGENT_TEXT.filter.rule}</option>
                <option value="agent">{OBJECT_AGENT_TEXT.filter.agent}</option>
                {agentOn || choice === "waiting" ? (
                  <option value="waiting">{OBJECT_AGENT_TEXT.filter.waiting}</option>
                ) : null}
                {agentOn || choice === "failed" ? (
                  <option value="failed">{OBJECT_AGENT_TEXT.filter.failed}</option>
                ) : null}
              </select>
            </label>
          )}
        </div>
        {view === "functions" ? null : (
          <div className="obj-tools-line">
            <button type="button" className="btn" onClick={() => setDeclareOpen(true)}>
              {OBJECT_TEXT.declareButton}
            </button>
            <button type="button" className="btn" onClick={() => setSynonymsOpen(true)}>
              {OBJECT_TEXT.fromSynonyms}
            </button>
            <button type="button" className="btn" onClick={() => setLearningOpen(true)}>
              {OBJECT_TEXT.learningButton}
            </button>
          </div>
        )}
      </div>

      {empty && skipped && view !== "functions" ? (
        <Notice>{OBJECT_TEXT.coldStart.skipped}</Notice>
      ) : null}
      {view === "functions" ? null : (
        <JudgementPanel
          site={site.name}
          judgements={data.judgements ?? []}
          rows={data.slots}
          classes={data.classes}
          dirty={drafted}
        />
      )}
      {body}

      {/* Keyed by the position: the notice and the open picker of one position do not carry to the next. */}
      {slot === undefined || view === "functions" ? null : (
        <SlotDrawer
          key={slot}
          site={site.name}
          slotId={slot}
          classes={data.classes}
          working={working}
          features={data.features}
          now={now}
          agentOn={agentOn}
          today={data.learning_run.agent_today}
          nextAt={data.learning_run.next_at}
          onClose={close}
          onApply={onApply}
          onReclass={(field, scope, kind) => {
            setDeclareKind(kind);
            setSearch({ declare: field, in: scope }, true);
          }}
        />
      )}

      {search.objevents === undefined ? null : (
        <ObjectEventsDrawer
          site={site.name}
          openEvents={data.events}
          classes={data.classes}
          saved={site.spec}
          working={working}
          now={now}
          status={search.objevents}
          kind={search.objkind}
          onClose={() => setSearch({ objevents: undefined, objkind: undefined }, true)}
          onApply={onApply}
          onChangeFilter={(next) =>
            setSearch(
              next.status === undefined ? { objkind: next.kind } : { objevents: next.status },
              true,
            )
          }
        />
      )}

      {declaring ? (
        <DeclareKindDialog
          key={`${search.declare ?? ""}|${search.in ?? ""}`}
          site={site.name}
          working={working}
          classes={data.classes}
          initialField={search.declare ?? ""}
          initialScope={search.in}
          initialNewKind={declareKind}
          onClose={closeDeclare}
          onDraft={(spec) => {
            onAdd(spec);
            closeDeclare();
          }}
          onSave={(spec) => {
            onApply(spec);
            closeDeclare();
          }}
        />
      ) : null}

      {synonymsOpen ? (
        <SynonymMigrateDialog
          site={site.name}
          working={working}
          onClose={() => setSynonymsOpen(false)}
          onApply={(spec) => {
            onAdd(spec);
            setSynonymsOpen(false);
          }}
        />
      ) : null}

      {learningOpen ? (
        <LearningSettings
          site={site.name}
          working={working}
          agentConfigured={data.agent_configured}
          agentHealth={data.agent_health}
          features={data.features}
          learning={data.learning_run}
          status={data.learning_status}
          onOpenEvents={(kind) => {
            setLearningOpen(false);
            setSearch({ objevents: "open", objkind: kind }, true);
          }}
          onClose={() => setLearningOpen(false)}
          onApply={(spec) => {
            onApply(spec);
            setLearningOpen(false);
          }}
        />
      ) : null}

      {runsOpen ? (
        <LearningRunsDrawer site={site.name} onClose={() => setSearch({ runs: undefined }, true)} />
      ) : null}
    </div>
  );
}
