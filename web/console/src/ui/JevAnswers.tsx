// The two Jev questions drawn as segmented bars (docs/06 6.4.5, 6.5.4): pass, fail, and unknown,
// with the conclusion each question reached written beside its bar.

import type { JevRecord } from "../api/types.ts";
import { topOf } from "../lib/explain.ts";
import { pct } from "../lib/format.ts";
import { ACCESS_LABEL, ATTACK_LABEL } from "../lib/vocab.ts";
import { AnswerBar, type AnswerSegment } from "./Charts.tsx";

export function JevAnswers({ jev }: { jev: JevRecord }) {
  const access = jev.access ?? {};
  const attack = jev.attack ?? {};
  const accessTop = topOf(jev.access);
  const attackTop = topOf(jev.attack);

  const accessSegments: AnswerSegment[] = [
    { key: "ALLOW", label: ACCESS_LABEL.ALLOW, value: access.ALLOW ?? 0, cls: "seg-pass" },
    { key: "DENY", label: ACCESS_LABEL.DENY, value: access.DENY ?? 0, cls: "seg-fail" },
    { key: "UNKNOWN", label: ACCESS_LABEL.UNKNOWN, value: access.UNKNOWN ?? 0, cls: "seg-unknown" },
  ];
  const attackSegments: AnswerSegment[] = [
    { key: "BENIGN", label: ATTACK_LABEL.BENIGN, value: attack.BENIGN ?? 0, cls: "seg-pass" },
    { key: "ATTACK", label: ATTACK_LABEL.ATTACK, value: attack.ATTACK ?? 0, cls: "seg-fail" },
    { key: "UNKNOWN", label: ATTACK_LABEL.UNKNOWN, value: attack.UNKNOWN ?? 0, cls: "seg-unknown" },
  ];

  return (
    <div className="stack" style={{ gap: 4 }}>
      <div className="qrow">
        <span className="qlabel">访问有依据吗</span>
        <AnswerBar segments={accessSegments} />
        <span className="qconc">→ {accessTop ? ACCESS_LABEL[accessTop] : "无结果"}</span>
      </div>
      <div className="qrow">
        <span className="qlabel">内容是攻击吗</span>
        <AnswerBar segments={attackSegments} />
        <span className="qconc">→ {attackTop ? ATTACK_LABEL[attackTop] : "无结果"}</span>
      </div>
      <div className="jevmeta">
        置信度{" "}
        {pct(
          jev.access || jev.attack ? Math.min(topValue(jev.access), topValue(jev.attack)) : null,
        )}
        {jev.access && jev.attack && Math.min(topValue(jev.access), topValue(jev.attack)) < 0.7 ? (
          <span className="hint-warn"> · 置信度低</span>
        ) : null}
      </div>
    </div>
  );
}

function topValue(probabilities: Partial<Record<string, number>> | null): number {
  if (!probabilities) return 0;
  return Math.max(0, ...Object.values(probabilities).map((value) => value ?? 0));
}
