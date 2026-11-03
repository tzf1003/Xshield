// The judgements a declared position carries (docs/07 7.9.15, 7.9.16) as the console reads and writes them: the words a
// row shows, the figures of a proposal, and the entry the drawer's choices make. Pure functions; the object map, the
// save path and the request detail all use them, so a judgement is never rebuilt field by field somewhere else.

import type {
  ObjectAcceptanceJudgement,
  ObjectIdentity,
  ObjectJudgement,
  ObjectReliability,
  ObjectSlotEntry,
  ObjectTier,
} from "../api/types.ts";
import { OBJECT_JUDGEMENT } from "./vocab.ts";

/** The judgement fields an entry may carry. */
export type Judgement = Pick<
  ObjectSlotEntry,
  "identity" | "tier" | "accepts_public" | "reliability"
>;

/** What the drawer's choices set. `null` takes the field away; an absent field is left as it is. */
export type JudgementChoice = {
  identity?: ObjectIdentity | null;
  tier?: ObjectTier | null;
  accepts_public?: boolean | null;
  reliability?: ObjectReliability | null;
};

const FIELDS = ["identity", "tier", "accepts_public", "reliability"] as const;

/** The judgement an entry carries, in words: `身份 用户`, `归属 自身 · 可靠性 高`, `不接受公共来源 · 可靠性 中`.
 *  Null when the entry carries none. */
export function judgementWords(judgement: Judgement): string | null {
  const parts: string[] = [];
  if (judgement.identity !== undefined) {
    parts.push(
      `${OBJECT_JUDGEMENT.field.identity} ${OBJECT_JUDGEMENT.identity[judgement.identity].name}`,
    );
  }
  if (judgement.tier !== undefined) {
    parts.push(`${OBJECT_JUDGEMENT.field.tier} ${OBJECT_JUDGEMENT.tier[judgement.tier].name}`);
  }
  if (judgement.accepts_public !== undefined) {
    parts.push(
      judgement.accepts_public
        ? OBJECT_JUDGEMENT.accepts.yes.name
        : OBJECT_JUDGEMENT.accepts.no.name,
    );
  }
  if (judgement.reliability !== undefined) {
    parts.push(
      `${OBJECT_JUDGEMENT.field.reliability} ${OBJECT_JUDGEMENT.reliability[judgement.reliability].name}`,
    );
  }
  return parts.length === 0 ? null : parts.join(" · ");
}

/** A stable text of an entry's judgement, to tell whether a draft changed it. */
export function judgementKey(judgement: Judgement): string {
  return JSON.stringify(FIELDS.map((field) => judgement[field] ?? null));
}

/** The choice that keeps an entry's judgement as it is: each field the entry carries, and null for each it does not.
 *  Passing it to `withJudgement` copies the judgement from one entry to another. */
export function judgementChoiceOf(judgement: Judgement | undefined): JudgementChoice {
  return {
    identity: judgement?.identity ?? null,
    tier: judgement?.tier ?? null,
    accepts_public: judgement?.accepts_public ?? null,
    reliability: judgement?.reliability ?? null,
  };
}

/** The configuration entry with its judgement replaced by the choice. A reliability without a tier or an acceptance
 *  to qualify is dropped, as the gateway would refuse it. Everything else on the entry is kept: its key, class,
 *  source and pause, so a judgement change never loses the rest. */
export function withJudgement(entry: ObjectSlotEntry, choice: JudgementChoice): ObjectSlotEntry {
  const next: ObjectSlotEntry = { ...entry };
  for (const field of FIELDS) {
    if (choice[field] === undefined) continue;
    if (choice[field] === null) delete next[field];
    else Object.assign(next, { [field]: choice[field] });
  }
  if (next.tier === undefined && next.accepts_public === undefined) delete next.reliability;
  return next;
}

/** A proposal in words: the judgement it makes and how sure the rules are, e.g. `不接受公共来源 · 可靠性 高`. */
export function proposalWords(proposal: ObjectJudgement): string {
  const reliability = `${OBJECT_JUDGEMENT.field.reliability} ${OBJECT_JUDGEMENT.reliability[proposal.reliability].name}`;
  if (isAcceptance(proposal)) {
    const accepts = proposal.accepts_public
      ? OBJECT_JUDGEMENT.accepts.yes.name
      : OBJECT_JUDGEMENT.accepts.no.name;
    return `${accepts} · ${reliability}`;
  }
  return `${OBJECT_JUDGEMENT.field.tier} ${OBJECT_JUDGEMENT.tier[proposal.tier].name} · ${reliability}`;
}

/** The figures a proposal rests on, in short phrases: `票 1234`, `会话 56`, `公共票 0.4%`; for a tier, `单位 12`. */
export function proposalFigures(proposal: ObjectJudgement): string[] {
  if (isAcceptance(proposal)) {
    return [
      `票 ${proposal.votes}`,
      `会话 ${proposal.sessions}`,
      `公共票 ${shareOfMille(proposal.public_per_mille)}`,
    ];
  }
  return [
    `单位 ${proposal.units}`,
    `不同值 ${proposal.seen_values}`,
    `一致 ${shareOfMille(proposal.agreement_per_mille)}`,
  ];
}

/** Whether a proposal is an acceptance judgement of a request position (it has `accepts_public`). */
export function isAcceptance(proposal: ObjectJudgement): proposal is ObjectAcceptanceJudgement {
  return "accepts_public" in proposal;
}

/** A share in thousandths, as a percentage: `0.4%` below one percent, whole numbers from there. */
export function shareOfMille(perMille: number): string {
  if (perMille < 10) return `${(perMille / 10).toFixed(1)}%`;
  return `${Math.round(perMille / 10)}%`;
}

/** Whether a configuration entry carries any judgement at all. */
export function hasJudgement(entry: Judgement): boolean {
  return FIELDS.some((field) => entry[field] !== undefined);
}
