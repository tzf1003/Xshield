// The drawer of one position (console design 3.2): the proposal and its flows, with links to the request list, the
// example requests, the response structure as paths and types (never values), the format and the condition when
// the position has them, the agent's verdict when it was asked, the impact, the scope, the history and the
// actions. Confirming writes a field declaration into the draft through the save dialog; ignoring and marking
// ambiguous are learning state, written on the server at once.

import { Link } from "@tanstack/react-router";
import { Drawer } from "antd";
import { useState } from "react";
import { useObjectSlot, useSlotLearning } from "../../../api/queries.ts";
import type { ObjectAgentVerdict, ObjectClass, ObjectFlow, SiteSpec } from "../../../api/types.ts";
import { fmtInt, pct } from "../../../lib/format.ts";
import {
  IMPACT_INFO,
  OBJECT_SIDE_INFO,
  OBJECT_SOURCE_LABEL,
  OBJECT_STATE_INFO,
  OBJECT_TEXT,
} from "../../../lib/vocab.ts";
import { ErrorBar, Kv, Loading, Notice } from "../../../ui/Page.tsx";
import { RequestLink } from "../../../ui/RequestRef.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import {
  classNameOf,
  declarationFor,
  fieldOfKey,
  flowSearch,
  scopeOfKey,
  seenText,
  withDeclarations,
} from "./objects-model.ts";
import { StateTag } from "./SlotTable.tsx";

type Props = {
  site: string;
  slotId: string;
  classes: readonly ObjectClass[];
  /** The draft, or the saved configuration: a confirmed proposal is added to it. */
  working: SiteSpec;
  now: number;
  onClose: () => void;
  onApply: (spec: SiteSpec) => void;
  /** Opens the declaration dialog with this field and scope, to choose another class. */
  onReclass: (field: string, scope: string) => void;
};

/** The agent's choice in words: a class, a new class, or an ambiguous position. */
function agentChoiceText(verdict: ObjectAgentVerdict, classes: readonly ObjectClass[]): string {
  if (verdict.choice === "new") return OBJECT_TEXT.declare.kindNew;
  if (verdict.choice === "ambiguous") return OBJECT_STATE_INFO.ambiguous.name;
  return classNameOf(classes, verdict.choice);
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
  now,
  onClose,
  onApply,
  onReclass,
}: Props) {
  const detail = useObjectSlot(site, slotId);
  const learning = useSlotLearning();
  const [highlight, setHighlight] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
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
    const scope = scopeOfKey(data.key);
    const declaration = declarationFor(data);
    const canConfirm = declaration !== null && data.state === "proposed";
    const canIgnore = data.state === "proposed";
    const canMarkAmbiguous = data.state !== "ambiguous" && data.state !== "retired";
    const flowsLabel =
      data.side === "response" ? OBJECT_TEXT.drawer.flowsOut : OBJECT_TEXT.drawer.flowsIn;
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
    const confirm = () => {
      if (declaration === null) return;
      onApply(withDeclarations(working, [declaration]));
      onClose();
    };

    body = (
      <div className="stack">
        <div className="row small">
          <StateTag state={data.state} />
          <span className="muted">{OBJECT_SOURCE_LABEL[data.source]}</span>
          <span className="muted">{seenText(data.last_seen, now)}</span>
        </div>
        {data.class === null ? null : (
          <div>
            {OBJECT_TEXT.drawer.proposal(`${classNameOf(classes, data.class)} ${data.class}`)}
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

        {data.examples.length === 0 ? null : (
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
          {declaration === null ? null : (
            <div className="small muted">
              {OBJECT_TEXT.drawer.confirmPreview}
              {OBJECT_TEXT.drawer.confirmLine(
                OBJECT_SIDE_INFO[data.side].name,
                data.key,
                classNameOf(classes, declaration.kind),
                scope,
              )}
            </div>
          )}
        </section>

        <div className="small">
          {OBJECT_TEXT.drawer.scope}：{OBJECT_TEXT.drawer.scopeOf(scope)}
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

        {field === null ? <div className="small muted">{OBJECT_TEXT.drawer.noField}</div> : null}
        {field !== null && data.class === null ? (
          <div className="small muted">{OBJECT_TEXT.drawer.noClass}</div>
        ) : null}
        {notice === null ? null : <Notice tone="info">{notice}</Notice>}
        {learning.isError ? <ErrorBar error={learning.error} /> : null}

        <div className="obj-foot">
          <button
            type="button"
            className="btn"
            disabled={!canMarkAmbiguous || learning.isPending}
            onClick={() => act("ambiguous")}
          >
            {OBJECT_TEXT.drawer.ambiguous}
          </button>
          <button
            type="button"
            className="btn"
            disabled={field === null}
            onClick={() => {
              if (field !== null) onReclass(field, scope);
            }}
          >
            {OBJECT_TEXT.drawer.reclass}
          </button>
          <button
            type="button"
            className="btn"
            disabled={!canIgnore || learning.isPending}
            onClick={() => act("dismiss")}
          >
            {OBJECT_TEXT.drawer.ignore}
          </button>
          <button type="button" className="btn-primary" disabled={!canConfirm} onClick={confirm}>
            {OBJECT_TEXT.drawer.confirm}
          </button>
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
