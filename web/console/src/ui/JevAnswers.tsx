// The two Jev questions drawn as segmented bars (docs/06 6.4.5, 6.5.4): the pass, fail and unknown
// shares of each question, the answer it reached beside its bar, and then the conclusion the call
// reached with its confidence. Hovering a row shows the raw probabilities; a confidence under 70% is
// marked.

import type { AccessProbabilities, AttackProbabilities, JevRecord } from "../api/types.ts";
import { topOf } from "../lib/explain.ts";
import { pct } from "../lib/format.ts";
import { ACCESS_LABEL, ATTACK_LABEL, CONCLUSION_LABEL } from "../lib/vocab.ts";
import { AnswerBar, type AnswerSegment } from "./Charts.tsx";

/** Below this confidence the conclusion is marked as weak (docs/06 6.4.5). */
const LOW_CONFIDENCE = 0.7;

type Option = { key: string; label: string; cls: AnswerSegment["cls"] };

const ACCESS_OPTIONS: Option[] = [
  { key: "ALLOW", label: ACCESS_LABEL.ALLOW, cls: "seg-pass" },
  { key: "DENY", label: ACCESS_LABEL.DENY, cls: "seg-fail" },
  { key: "UNKNOWN", label: ACCESS_LABEL.UNKNOWN, cls: "seg-unknown" },
];

const ATTACK_OPTIONS: Option[] = [
  { key: "BENIGN", label: ATTACK_LABEL.BENIGN, cls: "seg-pass" },
  { key: "ATTACK", label: ATTACK_LABEL.ATTACK, cls: "seg-fail" },
  { key: "UNKNOWN", label: ATTACK_LABEL.UNKNOWN, cls: "seg-unknown" },
];

export function JevAnswers({ jev }: { jev: JevRecord }) {
  const access = jev.access;
  const attack = jev.attack;
  const accessTop = topOf(access);
  const attackTop = topOf(attack);
  const accessAnswer = accessTop === null ? null : ACCESS_LABEL[accessTop];
  const attackAnswer = attackTop === null ? null : ATTACK_LABEL[attackTop];
  const confidence = confidenceOf(access, attack);
  const conclusion = jev.conclusion === null ? "—" : CONCLUSION_LABEL[jev.conclusion];
  const reasons = `access = ${accessTop ?? "—"}，attack = ${attackTop ?? "—"}`;

  return (
    <div className="stack" style={{ gap: 4 }}>
      <QuestionRow
        label="访问有依据吗"
        options={ACCESS_OPTIONS}
        probabilities={access}
        answer={accessAnswer}
      />
      <QuestionRow
        label="内容是攻击吗"
        options={ATTACK_OPTIONS}
        probabilities={attack}
        answer={attackAnswer}
      />
      <div className="jevmeta">
        结论：{conclusion}（{reasons}）· 置信度 {pct(confidence)}
        {confidence !== null && confidence < LOW_CONFIDENCE ? (
          <span className="hint-warn"> · 置信度低</span>
        ) : null}
      </div>
    </div>
  );
}

function QuestionRow({
  label,
  options,
  probabilities,
  answer,
}: {
  label: string;
  options: Option[];
  probabilities: Partial<Record<string, number>> | null;
  answer: string | null;
}) {
  const raw =
    probabilities === null
      ? ""
      : options
          .map((option) => `${option.label} ${(probabilities[option.key] ?? 0).toFixed(4)}`)
          .join(" · ");
  return (
    <div className="qrow" title={raw === "" ? undefined : `原始概率：${raw}`}>
      <span className="qlabel">{label}</span>
      {probabilities === null ? (
        <span className="small dim">没有回答</span>
      ) : (
        <AnswerBar
          segments={options.map((option) => ({
            key: option.key,
            label: option.label,
            value: probabilities[option.key] ?? 0,
            cls: option.cls,
          }))}
        />
      )}
      <span className="qconc">→ {answer ?? "无结果"}</span>
    </div>
  );
}

/** The smaller of the two top probabilities: a call is only as sure as its weaker question (docs/07 7.9.3). */
function confidenceOf(
  access: AccessProbabilities | null,
  attack: AttackProbabilities | null,
): number | null {
  const first = topProbability(access);
  const second = topProbability(attack);
  if (first === null || second === null) return null;
  return Math.min(first, second);
}

function topProbability(probabilities: Partial<Record<string, number>> | null): number | null {
  if (probabilities === null) return null;
  const values = Object.values(probabilities).filter(
    (value): value is number => typeof value === "number",
  );
  return values.length === 0 ? null : Math.max(...values);
}
