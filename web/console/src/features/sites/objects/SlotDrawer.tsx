// The drawer of one position (console design 3.2 and 4): the proposal and its flows, with links to the request list,
// the example requests, the response structure as paths and types (never values), the format and the condition when
// the position has them, the agent's verdict when it was asked, the impact, the scope, the history and the actions.
// A field position is confirmed as a field declaration; a path position as an object slot, with its class picked here
// (console design 4.1 to 4.3). A paused position shows why it was paused and how to restore it. Ignoring, marking
// ambiguous, dismissing and keeping a pause are learning state, written on the server at once; every change to the
// configuration goes through the save dialog.

import { Link } from "@tanstack/react-router";
import { Drawer } from "antd";
import { useState } from "react";
import { useAckEvent, useObjectSlot, useSlotLearning } from "../../../api/queries.ts";
import type {
  FieldKindDeclaration,
  ObjectAgentVerdict,
  ObjectClass,
  ObjectConfigEntry,
  ObjectFeatures,
  ObjectFlow,
  ObjectSource,
  SiteSpec,
} from "../../../api/types.ts";
import { fmtInt, pct } from "../../../lib/format.ts";
import {
  checkDeclarations,
  checkObjects,
  classProblem,
  declarationProblem,
  fieldKey,
  type PathSlot,
  pathSlotOf,
} from "../../../lib/objects-validate.ts";
import {
  DECLARE_TEXT,
  IMPACT_INFO,
  OBJECT_SIDE_INFO,
  OBJECT_SOURCE_LABEL,
  OBJECT_STATE_INFO,
  OBJECT_TEXT,
} from "../../../lib/vocab.ts";
import { ErrorBar, Kv, Loading, Notice } from "../../../ui/Page.tsx";
import { RequestLink } from "../../../ui/RequestRef.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { ClassPicker, NEW_CLASS } from "./ClassPicker.tsx";
import {
  type ApplyOptions,
  classNameOf,
  fieldOfKey,
  flowSearch,
  isDeclaration,
  scopeOfKey,
  seenText,
  withClasses,
  withEntry,
  withoutDeclaration,
  withoutSlot,
} from "./objects-model.ts";
import { PathSlotLabel } from "./PathSlotLabel.tsx";
import { StateTag } from "./SlotTable.tsx";
import { SuspensionSection } from "./SuspensionSection.tsx";

type Props = {
  site: string;
  slotId: string;
  classes: readonly ObjectClass[];
  /** The draft, or the saved configuration: a confirmed proposal is added to it. */
  working: SiteSpec;
  features: ObjectFeatures;
  now: number;
  onClose: () => void;
  onApply: (spec: SiteSpec, options?: ApplyOptions) => void;
  /** Opens the declaration dialog with this field and scope, to choose another class (field positions). */
  onReclass: (field: string, scope: string) => void;
};

/** The agent's choice in words: a class, a new class, or an ambiguous position. */
function agentChoiceText(verdict: ObjectAgentVerdict, classes: readonly ObjectClass[]): string {
  if (verdict.choice === "new") return OBJECT_TEXT.declare.kindNew;
  if (verdict.choice === "ambiguous") return OBJECT_STATE_INFO.ambiguous.name;
  return classNameOf(classes, verdict.choice);
}

/** The label of a path position: its parameter number, or its segment when that segment is not a parameter. */
function pathLabelOf(path: PathSlot): string {
  return path.ordinal === null
    ? OBJECT_TEXT.pathParam.literal(path.method, path.route, path.segment)
    : OBJECT_TEXT.pathParam.label(path.method, path.route, path.ordinal, path.segment);
}

/** The declaration of this field in this scope, when the configuration holds one. */
function declarationIn(
  list: readonly FieldKindDeclaration[],
  field: string,
  scope: string,
): FieldKindDeclaration | undefined {
  return list.find(
    (item) => fieldKey(item.field) === fieldKey(field) && (item.in ?? []).join("|") === scope,
  );
}

/** One flow of the values: its share, its use, and where it goes; the row opens the request list. */
function FlowRow({
  flow,
  index,
  site,
  cls,
  highlight,
}: {
  flow: ObjectFlow;
  index: number;
  site: string;
  cls: string | null;
  highlight: string | null;
}) {
  const id = `f${index + 1}`;
  return (
    <li>
      <Link
        id={id}
        to="/requests"
        search={{ site, q: flowSearch(flow, cls) }}
        className="obj-flow"
        data-hl={highlight === id ? "true" : "false"}
      >
        <span className="obj-flow-line">
          <span className="tnum">{pct(flow.share)}</span>
          <span className="obj-code">
            <SafeText text={flow.key} />
          </span>
        </span>
        <span className="obj-flow-line small muted">
          <span>
            {fmtInt(flow.uses)} 次 · {fmtInt(flow.sessions)} 个会话
          </span>
          <span>
            Jev 通过 {fmtInt(flow.jev_allow)} · 拒绝 {fmtInt(flow.jev_deny)}
          </span>
        </span>
      </Link>
    </li>
  );
}

export function SlotDrawer({
  site,
  slotId,
  classes,
  working,
  features,
  now,
  onClose,
  onApply,
  onReclass,
}: Props) {
  const detail = useObjectSlot(site, slotId);
  const learning = useSlotLearning();
  const ack = useAckEvent();
  const [highlight, setHighlight] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [picking, setPicking] = useState(false);
  const [pickClass, setPickClass] = useState("");
  const [pickNewId, setPickNewId] = useState("");
  const [pickNewName, setPickNewName] = useState("");
  const data = detail.data;

  const title =
    data === undefined ? (
      <span className="obj-code">{slotId}</span>
    ) : (
      <span className="obj-card-title">
        <span>{OBJECT_SIDE_INFO[data.side].name}</span>
        <span className="obj-code">
          <SafeText text={data.key} />
        </span>
      </span>
    );

  let body = <Loading height={200} />;
  if (detail.isError)
    body = <ErrorBar error={detail.error} onRetry={() => void detail.refetch()} />;
  if (data !== undefined) {
    const field = fieldOfKey(data.key);
    const path = pathSlotOf(data.key);
    const scope = scopeOfKey(data.key);
    const suspension = data.suspension;
    const previous = suspension?.previous ?? null;
    // A paused position is `suspended` with its suspension; stopped when the gateway does not use its class now.
    const paused = data.state === "suspended" && suspension !== null;
    const stopped = paused && !data.in_effect;
    const inEffect = paused && data.in_effect;
    const editable = data.state !== "ambiguous" && data.state !== "retired";
    const slots = working.objects?.slots ?? [];
    const fields = working.advanced?.field_kinds ?? [];
    const flowsLabel =
      data.side === "response" ? OBJECT_TEXT.drawer.flowsOut : OBJECT_TEXT.drawer.flowsIn;
    const className = (id: string | null) => classNameOf(classes, id);
    const pathLabel = path === null ? "" : pathLabelOf(path);

    // The entry a class writes for this position: a declaration for a field, an object slot for a path position.
    const entryOf = (cls: string, source: ObjectSource): ObjectConfigEntry =>
      field === null ? { key: data.key, class: cls, source } : { field, kind: cls, in: [scope] };

    // The configuration with the entry put in, and its class added to the map (under `name`) when the map lacks it.
    const withEntryAndClass = (entry: ObjectConfigEntry, name?: string): SiteSpec => {
      const next = withEntry(working, entry);
      const cls = isDeclaration(entry) ? entry.kind : entry.class;
      if ((working.objects?.classes ?? []).some((item) => item.id === cls)) return next;
      return withClasses(next, [{ id: cls, name: name ?? className(cls) }]);
    };

    // Why an entry cannot be confirmed now, or null when it can.
    const blockOf = (entry: ObjectConfigEntry): string | null => {
      if (isDeclaration(entry)) {
        const clash = declarationProblem(fields, entry);
        if (clash !== null) {
          return clash.kind === "duplicate"
            ? OBJECT_TEXT.coldStart.inDraft
            : DECLARE_TEXT.conflict(entry.field, clash.with.kind);
        }
        return checkDeclarations([...fields, entry])[0] ?? null;
      }
      if (features.path_confirm === false) return OBJECT_TEXT.pathParam.unsupported;
      // A paused entry of this key is the one a restore replaces, so it does not block the restore.
      const held = slots.find((item) => item.key === entry.key && !item.paused);
      if (held !== undefined) {
        return held.class === entry.class
          ? OBJECT_TEXT.coldStart.inDraft
          : OBJECT_TEXT.coldStart.conflict(className(held.class));
      }
      return checkObjects(withEntryAndClass(entry).objects)[0] ?? null;
    };

    // A proposal is written as the agent's when the agent chose this class, otherwise as the rule's (console design 4.3).
    const proposalSource: ObjectSource = data.agent?.choice === data.class ? "agent" : "rule";
    const proposalEntry = data.class === null ? null : entryOf(data.class, proposalSource);
    const proposalBlock =
      proposalEntry === null ? OBJECT_TEXT.drawer.noClass : blockOf(proposalEntry);

    // A paused position takes back the entry from before its pause, without the pause (console design 3.3).
    const restoreEntry: ObjectConfigEntry | null =
      previous === null || previous.class === null
        ? null
        : field === null
          ? { key: data.key, class: previous.class, source: previous.source }
          : { field, kind: previous.class, in: [scope] };
    const restoreBlock = restoreEntry === null ? null : blockOf(restoreEntry);

    // Stopping an in-effect position takes its entry out of the configuration and writes nothing else.
    let stopSpec: SiteSpec | null = null;
    if (field === null) {
      if (slots.some((item) => item.key === data.key)) stopSpec = withoutSlot(working, data.key);
    } else {
      const held = declarationIn(fields, field, scope);
      if (held !== undefined) stopSpec = withoutDeclaration(working, held);
    }

    // The class a path position takes from the picker: an id from the list, or a new id with its name.
    const pickedClass = pickClass === NEW_CLASS ? pickNewId.trim().toLowerCase() : pickClass;
    const pickedName = pickClass === NEW_CLASS ? pickNewName.trim() : className(pickedClass);
    const pickEntry: ObjectConfigEntry | null =
      picking && path !== null && pickedClass.length > 0 ? entryOf(pickedClass, "admin") : null;
    const pickProblem = (): string | null => {
      if (pickEntry === null) return OBJECT_TEXT.pathParam.pickNote;
      if (pickClass === NEW_CLASS) {
        const problem = classProblem({ id: pickedClass, name: pickedName });
        if (problem !== null) return problem;
        if (classes.some((item) => item.id === pickedClass))
          return DECLARE_TEXT.classDuplicate(pickedClass);
      }
      return blockOf(pickEntry);
    };
    const pickBlock = pickProblem();

    // The reason the primary button cannot act, shown above the footer.
    let footReason: string | null = null;
    if (stopped) footReason = restoreEntry === null ? OBJECT_TEXT.drawer.noClass : restoreBlock;
    else if (inEffect) footReason = OBJECT_TEXT.suspension.stopNote;
    else if (data.state === "proposed") footReason = proposalBlock;

    const act = (action: "dismiss" | "ambiguous") => {
      setNotice(null);
      learning.mutate(
        { name: site, id: data.id, action },
        {
          onSuccess: () =>
            setNotice(
              action === "dismiss"
                ? OBJECT_TEXT.drawer.dismissed
                : OBJECT_TEXT.drawer.markedAmbiguous,
            ),
        },
      );
    };
    const keep = () => {
      if (suspension === null || suspension.event_id === null) return;
      setNotice(null);
      ack.mutate(
        { name: site, id: suspension.event_id },
        {
          onSuccess: () =>
            setNotice(
              inEffect ? OBJECT_TEXT.suspension.keptEffect : OBJECT_TEXT.suspension.keptPaused,
            ),
        },
      );
    };
    const commit = (spec: SiteSpec, options?: ApplyOptions) => {
      onApply(spec, options);
      onClose();
    };
    const confirmProposal = () => {
      if (proposalEntry === null || proposalBlock !== null) return;
      commit(withEntryAndClass(proposalEntry));
    };
    const restore = () => {
      if (restoreEntry === null || restoreBlock !== null) return;
      commit(withEntryAndClass(restoreEntry), {
        note: OBJECT_TEXT.events.noteReconfirm(data.key, suspension?.version ?? null),
        objectEvent: suspension?.event_id ?? undefined,
      });
    };
    const stop = () => {
      // Not an undo of the automatic pause, so the save carries no event id.
      if (stopSpec === null) return;
      commit(stopSpec);
    };
    const confirmPick = () => {
      if (pickEntry === null || pickBlock !== null) return;
      commit(withEntryAndClass(pickEntry, pickClass === NEW_CLASS ? pickedName : undefined));
    };
    const reclass = () => {
      if (field !== null) onReclass(field, scope);
      else setPicking((value) => !value);
    };

    body = (
      <div className="stack">
        <div className="row small">
          <StateTag state={data.state} />
          <span className="muted">{OBJECT_SOURCE_LABEL[data.source]}</span>
          <span className="muted">{seenText(data.last_seen, now)}</span>
        </div>

        {path === null ? null : (
          <div className="obj-section">
            <PathSlotLabel slotKey={data.key} />
          </div>
        )}

        {paused && suspension !== null ? (
          <SuspensionSection
            slot={data}
            suspension={suspension}
            examples={data.examples}
            classes={classes}
            autoPause={working.objects?.learning?.auto_pause ?? true}
            pauseApplied={features.auto_pause}
            now={now}
          />
        ) : null}

        {data.dismissed && !paused ? (
          <div className="small muted">{OBJECT_TEXT.drawer.dismissed}</div>
        ) : null}

        {data.class === null || paused ? null : (
          <div>
            {data.state === "proposed"
              ? OBJECT_TEXT.drawer.proposal(`${className(data.class)} ${data.class}`)
              : `${className(data.class)} ${data.class}`}
          </div>
        )}
        <div className="small">
          <SafeText text={data.basis} />
        </div>

        <section className="obj-section">
          <div className="field-label">{flowsLabel}</div>
          {data.flows_in.length === 0 ? (
            <div className="small muted">—</div>
          ) : (
            <ul className="obj-flows">
              {data.flows_in.map((flow, index) => (
                <FlowRow
                  key={`${flow.side}|${flow.key}|${flow.method}|${flow.route}`}
                  flow={flow}
                  index={index}
                  site={site}
                  cls={data.class}
                  highlight={highlight}
                />
              ))}
            </ul>
          )}
        </section>

        {data.examples.length === 0 || paused ? null : (
          <section className="obj-section">
            <div className="field-label">{OBJECT_TEXT.drawer.examples}</div>
            <div className="obj-ref-list">
              {data.examples.map((id) => (
                <RequestLink key={id} id={id} />
              ))}
            </div>
          </section>
        )}

        <section className="obj-section">
          <div className="field-label">{OBJECT_TEXT.drawer.shape}</div>
          {data.shape.length === 0 ? (
            <div className="small muted">—</div>
          ) : (
            <ul className="obj-ref-list">
              {data.shape.map((item) => (
                <li key={item.path} className="obj-code">
                  <SafeText text={`${item.path}:${item.type}`} />
                </li>
              ))}
            </ul>
          )}
        </section>

        {data.format === undefined ? null : (
          <section className="obj-section">
            <div className="field-label">{OBJECT_TEXT.drawer.format}</div>
            <div>
              <SafeText text={data.format.summary} />
            </div>
            <ul className="obj-rule-list">
              {data.format.parts.map((part) => (
                <li key={part}>
                  <SafeText text={part} />
                </li>
              ))}
            </ul>
            {data.format.rest === null ? null : (
              <div className="field-warn">
                ▲ <SafeText text={data.format.rest} />
              </div>
            )}
          </section>
        )}

        {data.condition === undefined ? null : (
          <section className="obj-section">
            <div className="field-label">{OBJECT_TEXT.drawer.condition}</div>
            <div>
              <SafeText text={data.condition} />
            </div>
          </section>
        )}

        {data.agent === undefined ? null : (
          <section className="obj-section">
            <div className="field-label">{OBJECT_TEXT.drawer.agent}</div>
            <Kv
              items={[
                [
                  OBJECT_TEXT.drawer.agentChoice,
                  <SafeText key="choice" text={agentChoiceText(data.agent, classes)} />,
                ],
                [OBJECT_TEXT.drawer.agentConfidence, pct(data.agent.confidence)],
                [
                  OBJECT_TEXT.drawer.agentCites,
                  <span key="cites" className="obj-ref-list">
                    {data.agent.cites.map((cite) =>
                      /^f[0-9]+$/.test(cite) ? (
                        <button
                          key={cite}
                          type="button"
                          className="linkbtn"
                          onClick={() => setHighlight(cite)}
                        >
                          {cite}
                        </button>
                      ) : (
                        <span key={cite} className="obj-code">
                          <SafeText text={cite} />
                        </span>
                      ),
                    )}
                  </span>,
                ],
              ]}
            />
            <div className="small muted">{OBJECT_TEXT.drawer.agentReason}</div>
            <div>
              <SafeText text={data.agent.reason} />
            </div>
          </section>
        )}

        <section className="obj-section">
          <div className="field-label">{OBJECT_TEXT.drawer.impact}</div>
          {data.impact.length === 0 ? (
            <div className="small muted">—</div>
          ) : (
            <ul className="changes">
              {data.impact.map((change) => (
                <li key={change.kind}>
                  · {IMPACT_INFO[change.kind]} {fmtInt(change.count)} 次
                  {change.sample === undefined ? null : (
                    <>
                      {" · "}
                      <RequestLink id={change.sample} />
                    </>
                  )}
                </li>
              ))}
            </ul>
          )}
          {data.state === "proposed" && proposalEntry !== null && proposalBlock === null ? (
            <div className="small muted">
              {field === null
                ? OBJECT_TEXT.pathParam.after(pathLabel, className(data.class))
                : OBJECT_TEXT.drawer.confirmPreview +
                  OBJECT_TEXT.drawer.confirmLine(
                    OBJECT_SIDE_INFO[data.side].name,
                    data.key,
                    className(data.class),
                    scope,
                  )}
            </div>
          ) : null}
        </section>

        <div className="small">
          {OBJECT_TEXT.drawer.scope}：
          {path === null ? OBJECT_TEXT.drawer.scopeOf(scope) : OBJECT_TEXT.pathParam.routeOnly}
        </div>

        <section className="obj-section">
          <div className="field-label">{OBJECT_TEXT.drawer.history}</div>
          <ul className="obj-rule-list">
            {data.history.map((entry) => (
              <li key={`${entry.at}|${entry.text}`} className="small">
                <span className="mono">{seenText(entry.at, now)}</span>{" "}
                <SafeText text={entry.text} />
              </li>
            ))}
          </ul>
        </section>

        {picking && path !== null ? (
          <section className="obj-section" aria-label={OBJECT_TEXT.pathParam.pickClass}>
            <div className="field-label">{OBJECT_TEXT.pathParam.pickClass}</div>
            <div className="obj-new-class">
              <ClassPicker
                label={OBJECT_TEXT.pathParam.pickClass}
                value={pickClass}
                options={classes}
                onChange={setPickClass}
              />
              {pickClass === NEW_CLASS ? (
                <>
                  <input
                    className="native-input mono"
                    aria-label={OBJECT_TEXT.coldStart.newClassId}
                    placeholder="doctor"
                    value={pickNewId}
                    onChange={(event) => setPickNewId(event.target.value)}
                  />
                  <input
                    className="native-input"
                    aria-label={OBJECT_TEXT.coldStart.newClassName}
                    placeholder={OBJECT_TEXT.coldStart.newClassName}
                    value={pickNewName}
                    onChange={(event) => setPickNewName(event.target.value)}
                  />
                </>
              ) : null}
            </div>
            {pickEntry === null || path === null ? null : (
              <div className="small muted">
                {OBJECT_TEXT.pathParam.after(pathLabel, pickedName || pickedClass)}
              </div>
            )}
            {pickBlock === null ? null : <div className="small muted">{pickBlock}</div>}
            <div className="obj-foot">
              <button type="button" className="btn" onClick={() => setPicking(false)}>
                {OBJECT_TEXT.declare.cancel}
              </button>
              <button
                type="button"
                className="btn-primary"
                disabled={pickBlock !== null}
                title={pickBlock ?? undefined}
                onClick={confirmPick}
              >
                {OBJECT_TEXT.pathParam.confirmLabel}
              </button>
            </div>
          </section>
        ) : null}

        {notice === null ? null : <Notice tone="info">{notice}</Notice>}
        {learning.isError ? <ErrorBar error={learning.error} /> : null}
        {ack.isError ? <ErrorBar error={ack.error} /> : null}
        {footReason === null ? null : <div className="small muted">{footReason}</div>}
        {inEffect ? (
          <div className="small muted">{OBJECT_TEXT.suspension.ambiguousAfterStop}</div>
        ) : null}

        <div className="obj-foot">
          {editable && !inEffect ? (
            <button
              type="button"
              className="btn"
              disabled={learning.isPending}
              onClick={() => act("ambiguous")}
            >
              {OBJECT_TEXT.drawer.ambiguous}
            </button>
          ) : null}
          {stopped ? (
            <button
              type="button"
              className="btn"
              disabled={learning.isPending}
              onClick={() => act("dismiss")}
            >
              {OBJECT_TEXT.suspension.reject}
            </button>
          ) : null}
          {data.state === "proposed" ? (
            <button
              type="button"
              className="btn"
              disabled={learning.isPending}
              onClick={() => act("dismiss")}
            >
              {OBJECT_TEXT.drawer.ignore}
            </button>
          ) : null}
          {paused &&
          suspension !== null &&
          suspension.event_id !== null &&
          !suspension.acknowledged ? (
            <button type="button" className="btn" disabled={ack.isPending} onClick={keep}>
              {inEffect ? OBJECT_TEXT.suspension.keepEffect : OBJECT_TEXT.suspension.keepPaused}
            </button>
          ) : null}
          {editable ? (
            <button
              type="button"
              className="btn"
              disabled={path === null && field === null}
              onClick={reclass}
            >
              {OBJECT_TEXT.drawer.reclass}
            </button>
          ) : null}
          {stopped && restoreEntry !== null ? (
            <button
              type="button"
              className="btn-primary"
              disabled={restoreBlock !== null}
              title={restoreBlock ?? undefined}
              onClick={restore}
            >
              {OBJECT_TEXT.suspension.reconfirm(className(previous?.class ?? null))}
            </button>
          ) : null}
          {inEffect ? (
            <button
              type="button"
              className="btn-primary"
              disabled={stopSpec === null}
              title={stopSpec === null ? OBJECT_TEXT.suspension.stopMissing : undefined}
              onClick={stop}
            >
              {OBJECT_TEXT.suspension.stopUse}
            </button>
          ) : null}
          {data.state === "proposed" ? (
            <button
              type="button"
              className="btn-primary"
              disabled={proposalEntry === null || proposalBlock !== null}
              title={proposalBlock ?? undefined}
              onClick={confirmProposal}
            >
              {OBJECT_TEXT.drawer.confirm}
            </button>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <Drawer open placement="right" size={480} mask={false} onClose={onClose} title={title}>
      {body}
    </Drawer>
  );
}
