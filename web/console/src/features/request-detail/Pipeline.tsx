// The judgement tab (docs/06 6.4.4): a timing bar that says where the time went, then the steps. The
// marks are neutral (✓ ran, – did not run or did not hold); the step that settled the conclusion is
// bold with the outcome beside it.

import { Link } from "@tanstack/react-router";
import type { Outcome, RequestDetail } from "../../api/types.ts";
import { keepScope, useSetSearch } from "../../app/scope.ts";
import { fmtMs } from "../../lib/format.ts";
import { isSessionLabel } from "../../lib/ids.ts";
import { OutcomeTag } from "../../ui/Badges.tsx";
import { Card, Notice } from "../../ui/Page.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import {
  type PipelineStep,
  pipelineSteps,
  type StepLink,
  type Waterfall,
  waterfallOf,
} from "./detail-model.ts";
import { LinkedRequest } from "./parts.tsx";

export function Pipeline({ detail }: { detail: RequestDetail }) {
  const { summary, trace, jev } = detail;
  const steps = pipelineSteps(summary, trace, jev);
  const water = waterfallOf(trace.timing, jev?.millis ?? null);
  return (
    <Card title="判定过程">
      {trace.v === 0 ? (
        <Notice tone="info">旧格式记录没有判定依据，这里只有站点和执行。</Notice>
      ) : null}
      {water ? <Timing water={water} /> : null}
      <ol className="steps rd-steps" aria-label="判定步骤">
        {steps.map((step) => (
          <StepRow key={step.id} step={step} outcome={summary.outcome} />
        ))}
      </ol>
    </Card>
  );
}

function Timing({ water }: { water: Waterfall }) {
  const width = (value: number) => `${water.scale > 0 ? (value / water.scale) * 100 : 0}%`;
  const share = (value: number) =>
    `${water.scale > 0 ? Math.round((value / water.scale) * 100) : 0}%`;
  const jevWidth =
    water.jev !== null && water.judge > 0 ? `${(water.jev / water.judge) * 100}%` : "0%";
  return (
    <div className="rd-timing">
      <div className="rd-wf" aria-hidden="true">
        <span
          className="rd-wf-judge"
          style={{ width: width(water.judge) }}
          title={`判定 ${fmtMs(water.judge)}，占 ${share(water.judge)}`}
        >
          {water.jev !== null && water.jev > 0 ? (
            <span
              className="rd-wf-jev"
              style={{ width: jevWidth }}
              title={`Jev ${fmtMs(water.jev)}`}
            />
          ) : null}
        </span>
        <span
          className="rd-wf-origin"
          style={{ width: width(water.origin) }}
          title={`源站 ${fmtMs(water.origin)}，占 ${share(water.origin)}`}
        />
        <span
          className="rd-wf-other"
          style={{ width: width(water.other) }}
          title={`其他 ${fmtMs(water.other)}，占 ${share(water.other)}`}
        />
      </div>
      <div className="small rd-wf-legend">
        <span>总计 {fmtMs(water.total)}</span>
        <span>
          判定 {fmtMs(water.judge)}
          {water.jev !== null ? `（Jev ${fmtMs(water.jev)} 在判定内）` : ""}
        </span>
        <span>源站 {fmtMs(water.origin)}</span>
        <span>其他 {fmtMs(water.other)}</span>
      </div>
    </div>
  );
}

function StepRow({ step, outcome }: { step: PipelineStep; outcome: Outcome }) {
  const setSearch = useSetSearch();
  const classes = ["step", "rd-step"];
  if (step.decisive) classes.push("dec", `rd-${outcome}`);
  if (!step.done) classes.push("skipped");
  if (step.warn) classes.push("rd-step-warn");
  const mark = step.warn ? "!" : step.done ? "✓" : "–";
  const label = step.warn ? "需要注意" : step.done ? "已执行" : "未执行或不满足";
  return (
    <li className={classes.join(" ")}>
      <span className="step-mark" role="img" aria-label={label}>
        {mark}
      </span>
      <span className="rd-stepname">{step.name}</span>
      <div className="step-body">
        <SafeText text={step.reason} />
        {step.attention !== null ? (
          <div className="rd-attention hint-warn">
            ▲ <SafeText text={step.attention} />
          </div>
        ) : null}
        {step.notes.map((note) => (
          <div key={note} className="step-detail">
            <SafeText text={note} />
          </div>
        ))}
        {step.links.length > 0 ? (
          <div className="step-detail rd-steplinks">
            {step.links.map((link) => (
              <StepLinkView
                key={linkKey(link)}
                link={link}
                onJev={() => setSearch({ tab: "jev" })}
              />
            ))}
          </div>
        ) : null}
      </div>
      <span className="rd-side">
        {step.ms !== null ? <span className="tnum">{fmtMs(step.ms)}</span> : null}
        {step.decisive ? <OutcomeTag outcome={outcome} /> : null}
      </span>
    </li>
  );
}

function linkKey(link: StepLink): string {
  if (link.kind === "jev") return "jev";
  if (link.kind === "request") return `request-${link.id}`;
  return `session-${link.label}`;
}

function StepLinkView({ link, onJev }: { link: StepLink; onJev: () => void }) {
  if (link.kind === "jev") {
    return (
      <button type="button" className="linkbtn" onClick={onJev}>
        {link.text}
      </button>
    );
  }
  if (link.kind === "request") {
    return <LinkedRequest id={link.id}>{link.text}</LinkedRequest>;
  }
  if (!isSessionLabel(link.label)) return <span>{link.text}</span>;
  return (
    <Link to="/sessions/$label" params={{ label: link.label }} search={keepScope}>
      {link.text}
    </Link>
  );
}
