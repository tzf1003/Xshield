// The dialog that declares the class of a field (console design 3.3): a field name, a class (one of the map's, or a
// new id), and where it applies: the given interfaces, or the whole site. Before the change goes into the draft,
// the dialog lists the positions the same field name has in the latest records, inside and outside the scope.
// Opened from the table, from a position, or from a request, with the field and the scope filled in.

import { Modal } from "antd";
import { useState } from "react";
import { useSiteObjects } from "../../../api/queries.ts";
import type { FieldKindDeclaration, ObjectClass, SiteSpec } from "../../../api/types.ts";
import {
  checkField,
  checkKind,
  checkScope,
  DECLARATIONS_MAX,
  declarationProblem,
  fieldKey,
  inScope,
  SCOPE_MAX,
} from "../../../lib/objects-validate.ts";
import { OBJECT_SIDE_INFO, OBJECT_TEXT, DECLARE_TEXT } from "../../../lib/vocab.ts";
import { ErrorBar, Loading } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { useDebounced } from "../hooks.ts";
import { TagInput } from "../TagInput.tsx";
import { classNameOf, fieldOfKey, keyParts, withDeclarations } from "./objects-model.ts";

/** The select's value for a class that does not exist yet; never a valid class id, which is lower-case letters. */
const NEW_KIND = "__new__";
const LISTED_MAX = 8;

type Props = {
  site: string;
  working: SiteSpec;
  classes: readonly ObjectClass[];
  /** The field the dialog opens with, from the URL or the position it was opened from. */
  initialField: string;
  /** The interface the field is limited to at first, when one is known. */
  initialScope: string | undefined;
  onClose: () => void;
  onDraft: (spec: SiteSpec) => void;
  onSave: (spec: SiteSpec) => void;
};

export function DeclareKindDialog({
  site,
  working,
  classes,
  initialField,
  initialScope,
  onClose,
  onDraft,
  onSave,
}: Props) {
  const [field, setField] = useState(initialField);
  const [kindChoice, setKindChoice] = useState<string>(classes[0]?.id ?? NEW_KIND);
  const [newKind, setNewKind] = useState("");
  const [mode, setMode] = useState<"only" | "all">("only");
  const [patterns, setPatterns] = useState<string[]>(
    initialScope === undefined ? [] : [initialScope],
  );
  const [touched, setTouched] = useState(false);

  const name = field.trim();
  const kind = kindChoice === NEW_KIND ? newKind.trim().toLowerCase() : kindChoice;
  const declaration: FieldKindDeclaration =
    mode === "only" ? { field: name, kind, in: patterns } : { field: name, kind };
  const list = working.objects?.field_kinds ?? [];

  // The problems, the first of which is shown once the dialog has been touched and blocks both buttons.
  const problems: string[] = [];
  const fieldProblem = checkField(name);
  if (fieldProblem !== null) problems.push(fieldProblem);
  if (kindChoice === NEW_KIND) {
    const kindProblem = checkKind(kind);
    if (kindProblem !== null) problems.push(kindProblem);
  }
  if (mode === "only") {
    if (patterns.length === 0) problems.push(OBJECT_TEXT.declare.scopeEmpty);
    const scopeProblem = checkScope(patterns);
    if (scopeProblem !== null) problems.push(scopeProblem);
  }
  if (list.length >= DECLARATIONS_MAX) problems.push(DECLARE_TEXT.countMax);
  if (problems.length === 0) {
    const clash = declarationProblem(list, declaration);
    if (clash !== null) {
      problems.push(
        clash.kind === "duplicate"
          ? DECLARE_TEXT.duplicate(name)
          : DECLARE_TEXT.conflict(name, clash.with.kind),
      );
    }
  }
  const shown = touched ? problems[0] : undefined;

  // The positions the same field name has in the latest records, read once the name settles.
  const settled = useDebounced(name, 300);
  const settledOk = settled.length > 0 && checkField(settled) === null;
  const found = useSiteObjects(site, { q: settled }, { enabled: settledOk });
  const same = (found.data?.slots ?? []).filter((row) => {
    const other = fieldOfKey(row.key);
    return other !== null && fieldKey(other) === fieldKey(settled);
  });
  const inside = same.filter((row) => {
    if (mode === "all") return true;
    return patterns.length > 0 && inScope(patterns, keyParts(row.key).path);
  });
  const outside = same.length - inside.length;
  const targets = [...new Set(same.map((row) => row.class).filter((item) => item !== null))];
  const warnAll = mode === "all" && targets.length > 1;

  const submit = (save: boolean) => {
    if (problems.length > 0) {
      setTouched(true);
      return;
    }
    const next = withDeclarations(working, [declaration]);
    if (save) onSave(next);
    else onDraft(next);
  };

  return (
    <Modal open title={OBJECT_TEXT.declare.title} onCancel={onClose} footer={null} width={600}>
      <div className="stack">
        <div className="stack-tight">
          <label className="field-label" htmlFor="declare-field">
            {OBJECT_TEXT.declare.field}
          </label>
          <input
            id="declare-field"
            className="native-input mono"
            value={field}
            placeholder="doc_id"
            aria-invalid={shown !== undefined ? true : undefined}
            onChange={(event) => {
              setField(event.target.value);
              setTouched(true);
            }}
          />
          <div className="small muted">{OBJECT_TEXT.declare.fieldHint}</div>
        </div>

        <div className="stack-tight">
          <label className="field-label" htmlFor="declare-kind">
            {OBJECT_TEXT.declare.kind}
          </label>
          <select
            id="declare-kind"
            className="native-input"
            value={kindChoice}
            onChange={(event) => {
              setKindChoice(event.target.value);
              setTouched(true);
            }}
          >
            {classes.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} {item.id}
              </option>
            ))}
            <option value={NEW_KIND}>{OBJECT_TEXT.declare.kindNew}</option>
          </select>
          {kindChoice === NEW_KIND ? (
            <>
              <label className="field-label" htmlFor="declare-new-kind">
                {OBJECT_TEXT.declare.kindNewLabel}
              </label>
              <input
                id="declare-new-kind"
                className="native-input mono"
                value={newKind}
                placeholder="doctor"
                onChange={(event) => {
                  setNewKind(event.target.value);
                  setTouched(true);
                }}
              />
              <div className="small muted">{OBJECT_TEXT.declare.kindHint}</div>
            </>
          ) : null}
        </div>

        <div className="stack-tight">
          <div className="field-label">{OBJECT_TEXT.declare.scope}</div>
          <div role="radiogroup" aria-label={OBJECT_TEXT.declare.scope} className="adv-choice">
            <label className="adv-radio">
              <input
                type="radio"
                name="declare-scope"
                checked={mode === "only"}
                onChange={() => setMode("only")}
              />
              {OBJECT_TEXT.declare.scopeOnly}
            </label>
            <label className="adv-radio">
              <input
                type="radio"
                name="declare-scope"
                checked={mode === "all"}
                onChange={() => {
                  setMode("all");
                  setTouched(true);
                }}
              />
              {OBJECT_TEXT.declare.scopeAll}
            </label>
          </div>
          {mode === "only" ? (
            <>
              <TagInput
                id="declare-paths"
                label={OBJECT_TEXT.declare.paths}
                values={patterns}
                onChange={(next) => {
                  setPatterns(next);
                  setTouched(true);
                }}
                check={(value) => checkScope([value])}
                max={SCOPE_MAX}
                placeholder="/api/appointments*"
              />
              <div className="small muted">{OBJECT_TEXT.declare.scopeHint}</div>
            </>
          ) : null}
          {mode === "all" ? (
            <div className="small muted">{OBJECT_TEXT.declare.scopeAllNote}</div>
          ) : null}
          {warnAll ? (
            <div className="field-warn">
              ▲{" "}
              {OBJECT_TEXT.declare.scopeAllWarn(
                targets.map((id) => classNameOf(classes, id)).join("、"),
              )}
            </div>
          ) : null}
        </div>

        <section className="stack-tight" aria-label={OBJECT_TEXT.declare.matches}>
          <div className="field-label">{OBJECT_TEXT.declare.matches}</div>
          {!settledOk ? null : found.isError ? (
            <ErrorBar error={found.error} onRetry={() => void found.refetch()} />
          ) : found.data === undefined ? (
            <Loading height={48} />
          ) : (
            <>
              {inside.length === 0 ? (
                <div className="small muted">{OBJECT_TEXT.declare.noMatches}</div>
              ) : (
                <ul className="obj-rule-list">
                  {inside.slice(0, LISTED_MAX).map((row) => (
                    <li key={row.id} className="obj-rule small">
                      <span className="obj-side" aria-hidden="true">
                        {OBJECT_SIDE_INFO[row.side].icon}
                      </span>
                      <span className="obj-code">
                        <SafeText text={row.key} />
                      </span>
                      <span className="muted">
                        <SafeText text={classNameOf(classes, row.class)} />
                      </span>
                    </li>
                  ))}
                </ul>
              )}
              {outside > 0 ? (
                <div className="small muted">{OBJECT_TEXT.declare.outside(outside)}</div>
              ) : null}
            </>
          )}
        </section>

        {shown === undefined ? null : (
          <div className="field-error" role="alert">
            {shown}
          </div>
        )}

        <div className="obj-foot">
          <button type="button" className="btn" onClick={onClose}>
            {OBJECT_TEXT.declare.cancel}
          </button>
          <button
            type="button"
            className="btn"
            disabled={problems.length > 0}
            onClick={() => submit(false)}
          >
            {OBJECT_TEXT.declare.draft}
          </button>
          <button
            type="button"
            className="btn-primary"
            disabled={problems.length > 0}
            onClick={() => submit(true)}
          >
            {OBJECT_TEXT.declare.save}
          </button>
        </div>
      </div>
    </Modal>
  );
}
