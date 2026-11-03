// The judgement of one declared position, in its drawer (docs/07 7.9.15, 7.9.16): the identity a response states about
// the session, the tier a response shows or the acceptance a request takes, and how sure the learning is of it. The
// choices change the draft, and the save dialog saves them as a version. A position with no entry in the draft has no
// judgement to edit until its class is confirmed.

import { useState } from "react";
import type {
  ObjectIdentity,
  ObjectReliability,
  ObjectSide,
  ObjectSlotEntry,
  ObjectTier,
} from "../../../api/types.ts";
import {
  type JudgementChoice,
  judgementKey,
  judgementWords,
  withJudgement,
} from "../../../lib/judgement.ts";
import { OBJECT_JUDGEMENT } from "../../../lib/vocab.ts";

const UNSET = "";
const IDENTITIES: readonly ObjectIdentity[] = ["user", "org", "role"];
const TIERS: readonly ObjectTier[] = ["self", "org", "admin", "public"];
const RELIABILITIES: readonly ObjectReliability[] = ["high", "medium", "low"];

type Props = {
  side: ObjectSide;
  /** The position's entry in the draft, or undefined when the draft has none. */
  entry: ObjectSlotEntry | undefined;
  /** Whether the entry is paused: it keeps its judgement, which the judge does not use until it is restored. */
  paused: boolean;
  /** Applies the choice to the draft and opens the save dialog with it. */
  onApply: (choice: JudgementChoice, note: string) => void;
};

/** What the choice is for these selections: a response takes an identity or a tier, a request an acceptance. */
function choiceOf(
  side: ObjectSide,
  identity: string,
  tier: string,
  accepts: string,
  reliability: string,
): JudgementChoice {
  const rel = reliability === UNSET ? null : (reliability as ObjectReliability);
  if (side === "request") {
    return {
      identity: null,
      tier: null,
      accepts_public: accepts === UNSET ? null : accepts === "yes",
      reliability: accepts === UNSET ? null : rel,
    };
  }
  if (identity !== UNSET) {
    return {
      identity: identity as ObjectIdentity,
      tier: null,
      accepts_public: null,
      reliability: null,
    };
  }
  return {
    identity: null,
    tier: tier === UNSET ? null : (tier as ObjectTier),
    accepts_public: null,
    reliability: tier === UNSET ? null : rel,
  };
}

export function JudgementEditor({ side, entry, paused, onApply }: Props) {
  const [identity, setIdentity] = useState<string>(entry?.identity ?? UNSET);
  const [tier, setTier] = useState<string>(entry?.tier ?? UNSET);
  const [accepts, setAccepts] = useState<string>(
    entry?.accepts_public === undefined ? UNSET : entry.accepts_public ? "yes" : "no",
  );
  const [reliability, setReliability] = useState<string>(entry?.reliability ?? UNSET);

  const heading = <div className="field-label">{OBJECT_JUDGEMENT.editor.title}</div>;
  if (entry === undefined) {
    return (
      <section className="obj-section">
        {heading}
        <div className="small muted">{OBJECT_JUDGEMENT.editor.needClass}</div>
      </section>
    );
  }

  const response = side === "response";
  const identityOn = response && identity !== UNSET;
  const choice = choiceOf(side, identity, tier, accepts, reliability);
  const next = withJudgement(entry, choice);
  const changed = judgementKey(next) !== judgementKey(entry);
  const current = judgementWords(entry) ?? OBJECT_JUDGEMENT.editor.none;
  const tierOn = response && !identityOn;
  const relOn = tierOn ? tier !== UNSET : accepts !== UNSET;

  return (
    <section className="obj-section" aria-label={OBJECT_JUDGEMENT.editor.title}>
      {heading}
      <div className="small">{current}</div>
      {paused ? <div className="small muted">{OBJECT_JUDGEMENT.editor.paused}</div> : null}
      <div className="stack-tight">
        {response ? (
          <>
            <label className="field-label" htmlFor="judge-identity">
              {OBJECT_JUDGEMENT.editor.identity}
            </label>
            <select
              id="judge-identity"
              className="native-input"
              value={identity}
              onChange={(event) => setIdentity(event.target.value)}
            >
              <option value={UNSET}>{OBJECT_JUDGEMENT.editor.none}</option>
              {IDENTITIES.map((item) => (
                <option key={item} value={item}>
                  {OBJECT_JUDGEMENT.identity[item].name}
                </option>
              ))}
            </select>
            <label className="field-label" htmlFor="judge-tier">
              {OBJECT_JUDGEMENT.editor.tier}
            </label>
            <select
              id="judge-tier"
              className="native-input"
              value={tier}
              disabled={identityOn}
              title={identityOn ? OBJECT_JUDGEMENT.editor.identityOff : undefined}
              onChange={(event) => setTier(event.target.value)}
            >
              <option value={UNSET}>{OBJECT_JUDGEMENT.editor.none}</option>
              {TIERS.map((item) => (
                <option key={item} value={item} title={OBJECT_JUDGEMENT.tier[item].desc}>
                  {OBJECT_JUDGEMENT.tier[item].name}
                </option>
              ))}
            </select>
          </>
        ) : (
          <>
            <label className="field-label" htmlFor="judge-accepts">
              {OBJECT_JUDGEMENT.editor.accepts}
            </label>
            <select
              id="judge-accepts"
              className="native-input"
              value={accepts}
              onChange={(event) => setAccepts(event.target.value)}
            >
              <option value={UNSET}>{OBJECT_JUDGEMENT.editor.none}</option>
              <option value="yes">{OBJECT_JUDGEMENT.accepts.yes.name}</option>
              <option value="no">{OBJECT_JUDGEMENT.accepts.no.name}</option>
            </select>
          </>
        )}
        {identityOn ? null : (
          <>
            <label className="field-label" htmlFor="judge-reliability">
              {OBJECT_JUDGEMENT.editor.reliability}
            </label>
            <select
              id="judge-reliability"
              className="native-input"
              value={reliability}
              disabled={!relOn}
              onChange={(event) => setReliability(event.target.value)}
            >
              <option value={UNSET}>{OBJECT_JUDGEMENT.editor.reliabilityUnset}</option>
              {RELIABILITIES.map((item) => (
                <option key={item} value={item} title={OBJECT_JUDGEMENT.reliability[item].desc}>
                  {OBJECT_JUDGEMENT.reliability[item].name}
                </option>
              ))}
            </select>
          </>
        )}
      </div>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={!changed}
          title={changed ? undefined : OBJECT_JUDGEMENT.editor.unchanged}
          onClick={() => onApply(choice, OBJECT_JUDGEMENT.editor.note(entry.key))}
        >
          {OBJECT_JUDGEMENT.editor.apply}
        </button>
      </div>
    </section>
  );
}
