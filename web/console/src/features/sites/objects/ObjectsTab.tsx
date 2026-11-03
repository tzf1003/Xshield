// The object map of a site (console design 3.1 to 3.6): what the proxy has learned about the values that name objects,
// by class or by position. The counters, the search, the view and the open position live in the URL. The drawer, the
// declaration dialog, the synonym migration and the learning settings change the draft, which the save dialog saves as
// a version; ignoring, marking ambiguous, dismissing and keeping a pause are learning state and are written at once.

import { useSearch } from "@tanstack/react-router";
import { type ReactNode, useEffect, useRef, useState } from "react";
import { useSiteObjects } from "../../../api/queries.ts";
import type { ObjectSlotRow, SiteDetail, SiteSpec } from "../../../api/types.ts";
import { useKeys } from "../../../app/keys.ts";
import { useSetSearch } from "../../../app/scope.ts";
import { OBJECT_TEXT } from "../../../lib/vocab.ts";
import { Empty, ErrorBar, Loading, Notice } from "../../../ui/Page.tsx";
import { ColdStartPanel } from "./ColdStartPanel.tsx";
import { DeclareKindDialog } from "./DeclareKindDialog.tsx";
import { LearningSettings } from "./LearningSettings.tsx";
import { ObjectClassCard } from "./ObjectClassCard.tsx";
import { ObjectClassList } from "./ObjectClassList.tsx";
import { ObjectCounters } from "./ObjectCounters.tsx";
import { ObjectEventsDrawer } from "./ObjectEventsDrawer.tsx";
import { ObjectsBanner } from "./ObjectsBanner.tsx";
import { type ApplyOptions, classMatches, slotsOfClass } from "./objects-model.ts";
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
  const objects = useSiteObjects(site.name, { state: search.state, q: search.q });
  const [text, setText] = useState(search.q ?? "");
  const [declareOpen, setDeclareOpen] = useState(false);
  const [synonymsOpen, setSynonymsOpen] = useState(false);
  const [learningOpen, setLearningOpen] = useState(false);
  const [skipped, setSkipped] = useState(false);
  const searchBox = useRef<HTMLInputElement>(null);

  const data = objects.data;
  const q = search.q ?? "";
  const view: "class" | "slot" = search.view === "slot" ? "slot" : "class";
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
  const dialogsOpen = dialogOpen || declaring || synonymsOpen || learningOpen || eventsOpen;

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
  const mapped =
    counts.pending + counts.proposed + counts.confirmed + counts.ambiguous + counts.suspended;
  const empty = counts.classes === 0 && mapped === 0;
  const closeDeclare = () => {
    setDeclareOpen(false);
    if (search.declare !== undefined || search.in !== undefined) {
      setSearch({ declare: undefined, in: undefined }, true);
    }
  };

  let body: ReactNode;
  if (empty && !skipped) {
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

      <div className="obj-tools">
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
        </div>
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
      </div>

      {empty && skipped ? <Notice>{OBJECT_TEXT.coldStart.skipped}</Notice> : null}
      {body}

      {slot === undefined ? null : (
        <SlotDrawer
          site={site.name}
          slotId={slot}
          classes={data.classes}
          working={working}
          features={data.features}
          now={now}
          onClose={close}
          onApply={onApply}
          onReclass={(field, scope) => setSearch({ declare: field, in: scope }, true)}
        />
      )}

      {search.objevents === undefined ? null : (
        <ObjectEventsDrawer
          site={site.name}
          events={data.events}
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
          working={working}
          agentConfigured={data.agent_configured}
          features={data.features}
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
    </div>
  );
}
