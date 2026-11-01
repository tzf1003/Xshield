// Labels for decision paths, outcomes, Jev answers and health (docs/06 6.5.3, 6.6). Colour is only
// ever a background behind an icon and a word, and allowed traffic carries no colour at all.

import type { ContextKind, DecisionPath, JevHealth, JevSummary, Outcome } from "../api/types.ts";
import { pct } from "../lib/format.ts";
import { ACCESS_LABEL, ATTACK_LABEL, CONTEXT_LABEL, DECISION_INFO, FAILURE_INFO, HEALTH_LABEL, OUTCOME_INFO, type Tone } from "../lib/vocab.ts";

function toneClass(tone: Tone): string {
  switch (tone) {
    case "blocked":
      return "tag-blocked";
    case "would":
      return "tag-would";
    case "unjudged":
      return "tag-unjudged";
    case "ok":
      return "tag-ok";
    case "neutral":
      return "tag-allowed";
  }
}

/** The decision path: a neutral outline, an icon and the short name. The code name is in the title. */
export function DecisionTag({ path }: { path: DecisionPath }) {
  const info = DECISION_INFO[path];
  return (
    <span className="tag tag-path" title={`${info.desc}（${path}）`}>
      <span className="ico" aria-hidden="true">
        {info.icon}
      </span>
      {info.name}
    </span>
  );
}

export function OutcomeTag({ outcome }: { outcome: Outcome }) {
  const info = OUTCOME_INFO[outcome];
  return (
    <span className={`tag ${toneClass(info.tone)}`} title={`${info.desc}（${outcome}）`}>
      <span className="ico" aria-hidden="true">
        {info.icon}
      </span>
      {info.name}
    </span>
  );
}

export function ContextTag({ context }: { context: ContextKind | null }) {
  if (context === null) return <span className="dim">—</span>;
  return <span className="small muted">{CONTEXT_LABEL[context]}</span>;
}

/**
 * The Jev answer of a row: the answer that decided and its confidence, or the failure short name.
 * The confidence is the smaller of the two top probabilities (docs/07 7.9.3).
 */
export function JevCell({ jev }: { jev: JevSummary | null }) {
  if (jev === null) return <span className="dim">—</span>;
  if (jev.failure !== null) {
    const failure = FAILURE_INFO[jev.failure];
    return (
      <span className="jev-cell fail" title={failure.desc}>
        {failure.short}
      </span>
    );
  }
  const answer =
    jev.attack === "ATTACK"
      ? ATTACK_LABEL.ATTACK
      : jev.access === "DENY"
        ? ACCESS_LABEL.DENY
        : jev.access === "ALLOW"
          ? ACCESS_LABEL.ALLOW
          : ACCESS_LABEL.UNKNOWN;
  return (
    <span className="jev-cell" title={`访问：${jev.access ?? "—"}，内容：${jev.attack ?? "—"}`}>
      {answer} {pct(jev.confidence)}
    </span>
  );
}

const HEALTH_TONE: Record<JevHealth, string> = {
  ok: "tag-ok",
  idle: "tag-neutral",
  degraded: "tag-would",
  down: "tag-blocked",
};

export function HealthTag({ health }: { health: JevHealth }) {
  const info = HEALTH_LABEL[health];
  return (
    <span className={`tag ${HEALTH_TONE[health]}`}>
      <span className="ico" aria-hidden="true">
        {info.icon}
      </span>
      {info.name}
    </span>
  );
}
