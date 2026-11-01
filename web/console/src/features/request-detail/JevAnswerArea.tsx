// The answer area of the Jev tab (docs/06 6.4.5): Jev's two answers with its conclusion, what the
// gateway did with that conclusion, the model and route, the latency against the timeout, and the size
// of the state against its 8 KiB limit. A failed call shows a failure card instead of the answers.

import type { JevRecord, Outcome, DecisionPath } from "../../api/types.ts";
import { STATE_LIMIT_BYTES, gatewayText, timeoutSource } from "./detail-model.ts";
import { fmtBytes, fmtInt, fmtMs, pct } from "../../lib/format.ts";
import { trimNote } from "../../lib/align.ts";
import { FAILURE_INFO, ROUTE_LABEL } from "../../lib/vocab.ts";
import { JevAnswers } from "../../ui/JevAnswers.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { Card } from "../../ui/Page.tsx";
import { Gauge } from "./parts.tsx";

type Props = {
  jev: JevRecord;
  outcome: Outcome;
  status: number | null;
  path: DecisionPath;
  /** The deployment's default timeout, to say where the timeout came from; null while unknown. */
  defaultTimeout: number | null;
  /** The UTF-8 size of the state text, or null when no state was sent. */
  stateBytes: number | null;
  onPrompt: () => void;
};

export function JevAnswerArea({ jev, outcome, status, path, defaultTimeout, stateBytes, onPrompt }: Props) {
  const gateway = gatewayText(outcome, status, path);
  const usage: Record<string, unknown> = jev.usage ?? {};
  const input = typeof usage.input_tokens === "number" ? usage.input_tokens : null;
  const output = typeof usage.output_tokens === "number" ? usage.output_tokens : null;
  const source = timeoutSource(jev.timeout_ms, defaultTimeout);
  const ratio = jev.millis !== null && jev.timeout_ms > 0 ? jev.millis / jev.timeout_ms : null;
  const trim = trimNote(jev.trim);

  return (
    <Card title="Jev 回答">
      {jev.failure !== null ? (
        <FailureCard jev={jev} gateway={gateway} />
      ) : (
        <>
          <JevAnswers jev={jev} />
          <div className="rd-gateway">
            <span className="dim">Jev 的结论在网关那里变成了什么：</span> <span>{gateway}</span>
          </div>
        </>
      )}

      <div className="jevmeta" title={jev.request_bytes !== null ? `完整请求体 ${fmtBytes(jev.request_bytes)}` : undefined}>
        模型 <span className="mono">{jev.model}</span> · {ROUTE_LABEL[jev.route]} · 指令{" "}
        <button type="button" className="linkbtn mono" onClick={onPrompt}>
          {jev.prompt}
        </button>
        {input !== null || output !== null
          ? ` · 用量 输入 ${fmtInt(input)} / 输出 ${fmtInt(output)} token`
          : ""}
      </div>

      {jev.millis !== null ? (
        <div className="rd-gauge-row">
          <span className="small tnum">
            耗时 {fmtMs(jev.millis)} / 超时 {fmtMs(jev.timeout_ms)}
            {source !== null ? `（${source}）` : ""}
          </span>
          <Gauge
            ratio={ratio ?? 0}
            warn={ratio !== null && ratio >= 0.8}
            label={`耗时占超时的 ${pct(ratio)}`}
          />
        </div>
      ) : null}

      {stateBytes !== null ? (
        <div className="rd-gauge-row">
          <span className="small tnum">
            state {fmtBytes(stateBytes)} / 8 KiB
          </span>
          <Gauge ratio={stateBytes / STATE_LIMIT_BYTES} label={`state 占 8 KiB 上限的 ${pct(stateBytes / STATE_LIMIT_BYTES)}`} />
          {trim !== null ? <div className="small dim">{trim}</div> : null}
        </div>
      ) : null}
    </Card>
  );
}

function FailureCard({ jev, gateway }: { jev: JevRecord; gateway: string }) {
  const failure = jev.failure;
  if (failure === null) return null;
  const info = FAILURE_INFO[failure];
  return (
    <div className="notice bad rd-failure" role="status">
      <div>
        <strong>{info.short}</strong>：{info.desc}
        {jev.http_status !== null ? `（HTTP ${jev.http_status}）` : ""}
      </div>
      <div className="small">网关的处理：{gateway}</div>
      {jev.response !== null ? (
        <>
          <div className="small dim">原始响应（前 8 KiB）</div>
          <pre className="codeblock">
            <SafeText text={jev.response.slice(0, 8192)} />
          </pre>
        </>
      ) : null}
    </div>
  );
}
