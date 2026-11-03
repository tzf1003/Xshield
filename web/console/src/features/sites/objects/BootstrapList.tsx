// The cold start list (console design 1): the named positions the recent requests read, grouped by the class the rules
// propose, each with the class it will be written as. The empty map's cold start panel and the wizard's object step
// both show it. The selection lives in a hook, so the footer of each page can confirm what is picked (1.6): a field
// position becomes a field declaration, a path position an object slot, and a class the map lacks is added with its
// name. Nothing is written until the save dialog saves the draft.

import { useState } from "react";
import type { BootstrapCandidate, ObjectClass, ObjectSide, SiteSpec } from "../../../api/types.ts";
import { fmtInt } from "../../../lib/format.ts";
import {
  checkDeclarations,
  checkKind,
  checkObjects,
  declarationProblem,
  pathSlotOf,
} from "../../../lib/objects-validate.ts";
import { nameReasonText, OBJECT_SIDE_INFO, OBJECT_TEXT, DECLARE_TEXT } from "../../../lib/vocab.ts";
import { SafeText } from "../../../ui/SafeText.tsx";
import { ClassPicker, NEW_CLASS } from "./ClassPicker.tsx";
import { PathSlotLabel } from "./PathSlotLabel.tsx";
import {
  type BootstrapChoice,
  type BootstrapPlan,
  candidateName,
  entriesOf,
  fieldOfKey,
  planBootstrap,
  scopeOfKey,
} from "./objects-model.ts";

/** What the user has changed on one row; the rest follows the candidate. */
type RowEdit = { picked?: boolean; select?: string; newId?: string; newName?: string };

/** One row as the list shows it: the candidate, its state, and the class it would be written as. */
export type RowView = {
  candidate: BootstrapCandidate;
  picked: boolean;
  select: string;
  newId: string;
  newName: string;
  kind: string;
  name: string;
  changed: boolean;
  /** Why the row cannot be picked: a conflict in the map or the draft; null when it can. */
  blocked: string | null;
  /** What is wrong with the row's class, e.g. a bad id; null when it is fine. */
  problem: string | null;
};

export type Selection = {
  rows: RowView[];
  /** The rows that will be written: picked, and neither blocked nor wrong. */
  chosen: RowView[];
  plan: BootstrapPlan;
  /** The messages the plan breaks (the counts, the shapes, the duplicates); the confirm button waits for none. */
  messages: string[];
  setPicked: (ids: readonly string[], value: boolean) => void;
  setRow: (id: string, edit: RowEdit) => void;
};

/** Whether a candidate starts checked: it is clear (no note) and free of conflicts. */
function startsPicked(candidate: BootstrapCandidate): boolean {
  return candidate.note === null && candidate.conflict === null;
}

/**
 * The selection of a cold start list: which rows are checked, the class each one is written as, and what the save
 * would write. `working` is the draft (or the saved configuration): a position the draft already holds cannot be picked.
 */
export function useBootstrapSelection(
  candidates: readonly BootstrapCandidate[],
  classes: readonly ObjectClass[],
  working: SiteSpec,
  pathConfirm: boolean,
): Selection {
  const [edits, setEdits] = useState<Record<string, RowEdit>>({});
  const names = new Map<string, string>();
  for (const item of classes) names.set(item.id, item.name);
  for (const item of working.objects?.classes ?? []) names.set(item.id, item.name);
  for (const candidate of candidates) {
    if (!names.has(candidate.kind)) names.set(candidate.kind, candidateName(candidate));
  }

  const rows: RowView[] = candidates.map((candidate) => {
    const edit = edits[candidate.id] ?? {};
    const select = edit.select ?? candidate.kind;
    const newId = edit.newId ?? "";
    const newName = edit.newName ?? "";
    const kind = select === NEW_CLASS ? newId.trim().toLowerCase() : select;
    const name =
      select === NEW_CLASS
        ? newName.trim() || (names.get(kind) ?? "")
        : (names.get(kind) ?? candidateName(candidate));
    const problem =
      select === NEW_CLASS && checkKind(kind) !== null
        ? DECLARE_TEXT.kindFormat
        : select === NEW_CLASS && name.length === 0
          ? DECLARE_TEXT.classNameEmpty
          : null;
    return {
      candidate,
      picked: edit.picked ?? startsPicked(candidate),
      select,
      newId,
      newName,
      kind,
      name,
      changed: kind !== candidate.kind,
      // A path position needs the gateway's path confirmation (`features.path_confirm`); until it runs, it cannot be picked.
      blocked:
        pathSlotOf(candidate.key) !== null && !pathConfirm
          ? OBJECT_TEXT.pathParam.unsupported
          : blockedBy(candidate, kind, working),
      problem,
    };
  });

  const chosen = rows.filter((row) => row.picked && row.blocked === null && row.problem === null);
  const choices: BootstrapChoice[] = chosen.map((row) => ({
    candidate: row.candidate,
    kind: row.kind,
    name: row.name,
    changed: row.changed,
  }));
  const plan = planBootstrap(choices, classes, working.objects);

  const messages = [
    ...checkDeclarations([...(working.advanced?.field_kinds ?? []), ...plan.declarations]),
    ...checkObjects({
      classes: [...(working.objects?.classes ?? []), ...plan.classes],
      slots: [...(working.objects?.slots ?? []), ...plan.slots],
    }),
  ];

  return {
    rows,
    chosen,
    plan,
    messages,
    setPicked: (ids, value) =>
      setEdits((previous) => {
        const next = { ...previous };
        for (const id of ids) next[id] = { ...next[id], picked: value };
        return next;
      }),
    setRow: (id, edit) =>
      setEdits((previous) => ({ ...previous, [id]: { ...previous[id], ...edit } })),
  };
}

/** Why a position cannot take this class: the backend's conflict, or what the draft already says about it. */
function blockedBy(candidate: BootstrapCandidate, kind: string, working: SiteSpec): string | null {
  if (candidate.conflict !== null) return OBJECT_TEXT.coldStart.conflict(candidate.conflict);
  const field = fieldOfKey(candidate.key);
  if (field !== null) {
    const declaration = { field, kind, in: [scopeOfKey(candidate.key)] };
    const clash = declarationProblem(working.advanced?.field_kinds ?? [], declaration);
    if (clash === null) return null;
    return clash.kind === "duplicate"
      ? OBJECT_TEXT.coldStart.inDraft
      : OBJECT_TEXT.coldStart.conflict(clash.with.kind);
  }
  const held = entriesOf(working, candidate.key);
  if (held.length === 0) return null;
  const same = (working.objects?.slots ?? []).find((item) => item.key === candidate.key);
  return same !== undefined && same.class === kind
    ? OBJECT_TEXT.coldStart.inDraft
    : OBJECT_TEXT.coldStart.conflict(same?.class ?? kind);
}

/** The source of a candidate in words: the rule that named its class (console design 1.5). */
function sourceText(candidate: BootstrapCandidate): string {
  return nameReasonText(candidate.reason.code, candidate.reason.word, candidate.reason.field);
}

type Props = {
  selection: Selection;
  records: number;
  windowHours: number;
  /** The classes the group headers and the summary name: the map's, and the proposals'. */
  classes: readonly ObjectClass[];
};

/** The grouped list with the select-all, the filter and the summary. The footer belongs to the page. */
export function BootstrapList({ selection, classes, windowHours, records }: Props) {
  const [filter, setFilter] = useState("");
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const needle = filter.trim().toLowerCase();
  const visible = selection.rows.filter(
    (row) =>
      needle.length === 0 ||
      row.candidate.key.toLowerCase().includes(needle) ||
      row.candidate.kind.toLowerCase().includes(needle) ||
      candidateName(row.candidate).toLowerCase().includes(needle),
  );
  const selectable = (row: RowView) => row.blocked === null && row.problem === null;
  const pickable = visible.filter(selectable);
  const pickedCount = selection.rows.filter((row) => row.picked && selectable(row)).length;
  const allVisibleOn = pickable.length > 0 && pickable.every((row) => row.picked);

  const groups = new Map<string, RowView[]>();
  for (const row of visible)
    groups.set(row.candidate.kind, [...(groups.get(row.candidate.kind) ?? []), row]);
  // The classes on offer: the proposals of this list, then the classes the site already has.
  const offered = new Map<string, string>();
  for (const row of selection.rows) offered.set(row.candidate.kind, candidateName(row.candidate));
  for (const item of classes) offered.set(item.id, item.name);
  const classOptions = [...offered.entries()].map(([id, name]) => ({ id, name }));
  const plan = selection.plan;
  const names = plan.classes.map((item) => item.name).join("、");

  return (
    <div className="stack">
      <div className="small muted">
        {OBJECT_TEXT.coldStart.windowLine(windowHours, records)}
        <br />
        {OBJECT_TEXT.coldStart.explain}
        <br />
        {OBJECT_TEXT.coldStart.explainSave}
      </div>

      <div className="obj-list-tools">
        <label className="adv-radio">
          <input
            type="checkbox"
            aria-label={OBJECT_TEXT.coldStart.selectAll(pickedCount, selection.rows.length)}
            checked={allVisibleOn}
            disabled={pickable.length === 0}
            onChange={(event) =>
              selection.setPicked(
                pickable.map((row) => row.candidate.id),
                event.target.checked,
              )
            }
          />
          {OBJECT_TEXT.coldStart.selectAll(pickedCount, selection.rows.length)}
        </label>
        <input
          type="search"
          className="native-input obj-search"
          aria-label={OBJECT_TEXT.coldStart.filter}
          placeholder={OBJECT_TEXT.coldStart.filter}
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
      </div>

      {selection.rows.length === 0 ? (
        <div className="small muted">{OBJECT_TEXT.coldStart.none}</div>
      ) : (
        <ul className="obj-groups">
          {[...groups.entries()].map(([kind, rows]) => {
            const groupPickable = rows.filter(selectable);
            const groupPicked = groupPickable.filter((row) => row.picked).length;
            const open = collapsed[kind] !== true;
            const groupName = rows[0] === undefined ? kind : candidateName(rows[0].candidate);
            return (
              <li key={kind} className="obj-group">
                <div className="obj-group-head">
                  <button
                    type="button"
                    className="linkbtn"
                    aria-expanded={open}
                    onClick={() => setCollapsed((previous) => ({ ...previous, [kind]: open }))}
                  >
                    {open ? "▾" : "▸"}
                  </button>
                  <label className="adv-radio">
                    <input
                      type="checkbox"
                      aria-label={`${groupName} ${kind}`}
                      checked={groupPicked > 0 && groupPicked === groupPickable.length}
                      ref={(element) => {
                        if (element)
                          element.indeterminate =
                            groupPicked > 0 && groupPicked < groupPickable.length;
                      }}
                      disabled={groupPickable.length === 0}
                      onChange={(event) =>
                        selection.setPicked(
                          groupPickable.map((row) => row.candidate.id),
                          event.target.checked,
                        )
                      }
                    />
                    <span className="obj-class-name">
                      <SafeText text={groupName} />
                    </span>{" "}
                    <span className="mono small dim">
                      <SafeText text={kind} />
                    </span>
                  </label>
                </div>
                {open ? (
                  <ul className="obj-rule-list">
                    {rows.map((row) => (
                      <RowLine
                        key={row.candidate.id}
                        row={row}
                        options={classOptions}
                        disabled={!selectable(row)}
                        onPick={(value) => selection.setRow(row.candidate.id, { picked: value })}
                        onChange={(edit) => selection.setRow(row.candidate.id, edit)}
                      />
                    ))}
                  </ul>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}

      {selection.messages.map((message) => (
        <div key={message} className="field-error" role="alert">
          {message}
        </div>
      ))}

      {pickedCount === 0 ? (
        <div className="small muted">{OBJECT_TEXT.coldStart.noneChosen}</div>
      ) : (
        <div className="small muted">
          {OBJECT_TEXT.coldStart.summary(
            plan.declarations.length,
            plan.slots.length,
            plan.classes.length,
            names,
          )}
        </div>
      )}
    </div>
  );
}

function RowLine({
  row,
  options,
  disabled,
  onPick,
  onChange,
}: {
  row: RowView;
  options: ReadonlyArray<{ id: string; name: string }>;
  disabled: boolean;
  onPick: (value: boolean) => void;
  onChange: (edit: RowEdit) => void;
}) {
  const { candidate } = row;
  const side: ObjectSide = candidate.side;
  const isPath = fieldOfKey(candidate.key) === null;
  const hint = row.blocked ?? row.problem;
  return (
    <li className="obj-rule obj-rule-wide">
      <label className="row small">
        <input
          type="checkbox"
          aria-label={`${OBJECT_SIDE_INFO[side].name} ${candidate.key}`}
          checked={row.picked}
          disabled={disabled}
          onChange={(event) => onPick(event.target.checked)}
        />
        <span className="obj-side" aria-hidden="true" title={OBJECT_SIDE_INFO[side].desc}>
          {OBJECT_SIDE_INFO[side].icon}
        </span>
        <span className="obj-code">
          <SafeText text={candidate.key} />
        </span>
      </label>
      <span className="obj-row-class">
        <ClassPicker
          label={`${candidate.key} ${OBJECT_TEXT.columns.state}`}
          value={row.select}
          options={options}
          disabled={disabled}
          onChange={(value) => onChange({ select: value })}
        />
        {row.select === NEW_CLASS ? (
          <span className="obj-new-class">
            <input
              className="native-input mono"
              aria-label={OBJECT_TEXT.coldStart.newClassId}
              placeholder="doctor"
              value={row.newId}
              disabled={disabled}
              onChange={(event) => onChange({ newId: event.target.value })}
            />
            <input
              className="native-input"
              aria-label={OBJECT_TEXT.coldStart.newClassName}
              placeholder={OBJECT_TEXT.coldStart.newClassName}
              value={row.newName}
              disabled={disabled}
              onChange={(event) => onChange({ newName: event.target.value })}
            />
          </span>
        ) : null}
        {row.changed && row.select !== NEW_CLASS ? (
          <span
            className="small muted"
            title={OBJECT_TEXT.coldStart.changedFrom(candidateName(candidate))}
          >
            {OBJECT_TEXT.coldStart.changed}
          </span>
        ) : null}
      </span>
      <span className="obj-rule-meta small muted" title={OBJECT_TEXT.coldStart.note}>
        <SafeText text={sourceText(candidate)} />
        <span className="obj-uses">
          {fmtInt(candidate.uses)} 次 · {fmtInt(candidate.sessions)} 个会话
        </span>
      </span>
      {candidate.note === null ? null : (
        <span className="field-warn obj-row-hint">
          ▲ <SafeText text={candidate.note} />
        </span>
      )}
      {isPath ? (
        <span className="obj-row-hint">
          <PathSlotLabel slotKey={candidate.key} />
        </span>
      ) : null}
      {hint === null ? null : (
        <span className="small muted obj-row-hint">
          <SafeText text={hint} />
        </span>
      )}
    </li>
  );
}
