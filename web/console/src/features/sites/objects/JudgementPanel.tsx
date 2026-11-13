// The proposals the rules make for declared positions (docs/07 7.9.16): whose objects a response position shows, or
// whether a request position takes public sources. An administrator confirms one, which writes the judgement into the
// site as one new version, or dismisses it, which keeps the rules from proposing it again. Confirming writes a version,
// so it waits while the draft holds changes of its own: the draft would otherwise be saved over a version it never saw.

import { Modal } from "antd";
import { useState } from "react";
import { useConfirmJudgement, useDismissJudgement } from "../../../api/queries.ts";
import type {
  ObjectClass,
  ObjectJudgement,
  ObjectJudgementConfirmation,
  ObjectSlotRow,
} from "../../../api/types.ts";
import {
  isAcceptance,
  proposalFigures,
  proposalWords,
  unidentifiedNoteOfProposal,
} from "../../../lib/judgement.ts";
import { errorText, OBJECT_JUDGEMENT, OBJECT_SIDE_INFO } from "../../../lib/vocab.ts";
import { ApiError } from "../../../api/client.ts";
import { Card, Notice } from "../../../ui/Page.tsx";
import { SafeText } from "../../../ui/SafeText.tsx";
import { classNameOf } from "./objects-model.ts";

type Props = {
  site: string;
  judgements: readonly ObjectJudgement[];
  /** The position rows, to name each position's side and class. */
  rows: readonly ObjectSlotRow[];
  classes: readonly ObjectClass[];
  /** Whether the site declares a user identity: an acceptance proposal says so when it does not (LQ-7). */
  identified: boolean;
  /** Whether the draft holds changes of its own: a confirmation then waits for them to be saved or dropped. */
  dirty: boolean;
};

/** The body a confirmation sends: the judgement and the reliability the proposal states, as the proposal has them. */
function confirmationOf(proposal: ObjectJudgement): ObjectJudgementConfirmation {
  if (isAcceptance(proposal)) {
    return { accepts_public: proposal.accepts_public, reliability: proposal.reliability };
  }
  return { tier: proposal.tier, reliability: proposal.reliability };
}

function errorOf(error: unknown): string {
  return error instanceof ApiError ? errorText(error.code) : errorText(undefined);
}

export function JudgementPanel({ site, judgements, rows, classes, identified, dirty }: Props) {
  const confirm = useConfirmJudgement();
  const dismiss = useDismissJudgement();
  const [pending, setPending] = useState<ObjectJudgement | null>(null);
  const [notice, setNotice] = useState<{ tone: "info" | "bad"; text: string } | null>(null);

  if (judgements.length === 0) return null;

  const rowOf = (proposal: ObjectJudgement) => rows.find((row) => row.id === proposal.id);
  const act = (proposal: ObjectJudgement, action: "confirm" | "dismiss") => {
    setNotice(null);
    if (action === "dismiss") {
      dismiss.mutate(
        { name: site, id: proposal.id },
        {
          onSuccess: () => setNotice({ tone: "info", text: OBJECT_JUDGEMENT.panel.dismissed }),
          onError: (error) => setNotice({ tone: "bad", text: errorOf(error) }),
        },
      );
      return;
    }
    confirm.mutate(
      { name: site, id: proposal.id, body: confirmationOf(proposal) },
      {
        onSuccess: () => {
          setPending(null);
          setNotice({ tone: "info", text: OBJECT_JUDGEMENT.panel.confirmed });
        },
        onError: (error) => {
          setPending(null);
          setNotice({ tone: "bad", text: errorOf(error) });
        },
      },
    );
  };

  return (
    <Card
      className="obj-judgements"
      title={OBJECT_JUDGEMENT.panel.title(judgements.length)}
      aside={<span className="small muted">{OBJECT_JUDGEMENT.panel.lead}</span>}
    >
      {notice === null ? null : (
        <Notice tone={notice.tone === "bad" ? "bad" : "info"}>{notice.text}</Notice>
      )}
      <ul className="obj-judge-list">
        {judgements.map((proposal) => {
          const row = rowOf(proposal);
          const side = row === undefined ? null : OBJECT_SIDE_INFO[row.side];
          const cls = row === undefined ? null : classNameOf(classes, row.class);
          const note = unidentifiedNoteOfProposal(proposal, identified);
          return (
            <li key={proposal.id} className="obj-judge-row">
              <div className="obj-judge-where">
                {side === null ? null : (
                  <span className="obj-side" aria-hidden="true" title={side.desc}>
                    {side.icon}
                  </span>
                )}
                <span className="obj-code">
                  <SafeText text={proposal.key} />
                </span>
                {cls === null ? null : (
                  <span className="small muted">
                    <SafeText text={cls} />
                  </span>
                )}
              </div>
              <div className="obj-judge-what">
                <SafeText text={proposalWords(proposal)} />
                <span className="small muted"> {proposalFigures(proposal).join(" · ")}</span>
                {note === null ? null : (
                  <div className="small muted">
                    <SafeText text={note} />
                  </div>
                )}
              </div>
              <div className="obj-judge-actions">
                <button
                  type="button"
                  className="btn"
                  disabled={dirty || confirm.isPending}
                  title={dirty ? OBJECT_JUDGEMENT.panel.dirtyDraft : undefined}
                  onClick={() => setPending(proposal)}
                >
                  {OBJECT_JUDGEMENT.panel.confirm}
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={dismiss.isPending}
                  onClick={() => act(proposal, "dismiss")}
                >
                  {OBJECT_JUDGEMENT.panel.dismiss}
                </button>
              </div>
            </li>
          );
        })}
      </ul>
      <Modal
        open={pending !== null}
        title={OBJECT_JUDGEMENT.panel.confirmTitle}
        okText={OBJECT_JUDGEMENT.panel.confirmOk}
        cancelText={OBJECT_JUDGEMENT.panel.cancel}
        okButtonProps={{ loading: confirm.isPending }}
        onOk={() => pending !== null && act(pending, "confirm")}
        onCancel={() => setPending(null)}
      >
        {pending === null ? null : (
          <p>
            <SafeText
              text={OBJECT_JUDGEMENT.panel.confirmBody(pending.key, proposalWords(pending))}
            />
          </p>
        )}
      </Modal>
    </Card>
  );
}
