// The preview beside the list (docs/06 6.4.3): the verdict and its one-sentence reason, the values
// that still need checking, the session, the timing, and the Jev answers when Jev was called.

import { Link } from "@tanstack/react-router";
import { Button } from "antd";
import { useRequestDetail } from "../../api/queries.ts";
import { keepScope } from "../../app/scope.ts";
import { apiValueLocations, isNameValue } from "../../lib/api-name.ts";
import { explainRecord } from "../../lib/explain.ts";
import { fmtElapsed, fmtLocalDateTime, fmtMs } from "../../lib/format.ts";
import { isRequestId, shortSession } from "../../lib/ids.ts";
import { DecisionTag, JevCell, OutcomeTag } from "../../ui/Badges.tsx";
import { JevAnswers } from "../../ui/JevAnswers.tsx";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { CopyButton } from "../../ui/RequestRef.tsx";
import { SafeText } from "../../ui/SafeText.tsx";
import { SourceChip } from "../../ui/SourceChip.tsx";

const PREVIEW_VALUES = 5;

type Props = {
  requestId: string;
  onClose: () => void;
  onOpen: () => void;
};

export function PeekPanel({ requestId, onClose, onOpen }: Props) {
  const detail = useRequestDetail(requestId);

  if (detail.isPending) {
    return (
      <aside className="peek" aria-label="预览">
        <Loading height={120} />
      </aside>
    );
  }
  if (detail.isError) {
    return (
      <aside className="peek" aria-label="预览">
        <ErrorBar error={detail.error} onRetry={() => void detail.refetch()} />
      </aside>
    );
  }

  const { summary, trace, jev, sources } = detail.data;
  // A value that is the interface name is not checked (design 4.2), so it is not listed to verify.
  const names = apiValueLocations(summary.api);
  const toVerify = (trace.values ?? []).filter(
    (value) => !value.inert && !value.verified && !isNameValue(value, names),
  );
  const explanation = explainRecord({
    decision_path: summary.decision_path,
    outcome: summary.outcome,
    status: summary.status,
    host: summary.host,
    context: summary.context,
    trace,
    jev,
    api: summary.api,
  });

  return (
    <aside className="peek" aria-label="预览">
      <div className="peek-head">
        <span className="mono small">{summary.method}</span>
        <strong className="mono" style={{ fontSize: 13, wordBreak: "break-all" }}>
          <SafeText text={summary.path} />
        </strong>
      </div>
      <div className="row" style={{ marginTop: 6 }}>
        <OutcomeTag outcome={summary.outcome} />
        <DecisionTag path={summary.decision_path} />
        <JevCell jev={summary.jev} />
      </div>
      <div className="explain">{explanation}</div>
      <dl className="kv">
        <dt>时间</dt>
        <dd className="tnum">{fmtLocalDateTime(summary.at_millis)}</dd>
        <dt>站点</dt>
        <dd>
          {summary.site ?? "—"}
          {summary.site_version !== null ? ` · 配置 v${summary.site_version}` : ""}
        </dd>
        <dt>会话</dt>
        <dd>
          {summary.session && isRequestId(requestId) ? (
            <>
              <Link
                to="/sessions/$label"
                params={{ label: summary.session }}
                search={keepScope}
                className="mono"
              >
                {shortSession(summary.session)}
              </Link>
              {trace.session ? ` · 已 ${fmtElapsed(trace.session.age_seconds)}` : ""}
            </>
          ) : (
            "无会话"
          )}
        </dd>
        <dt>耗时</dt>
        <dd className="tnum">
          {fmtMs(trace.timing?.total_ms ?? summary.total_ms)}
          {trace.timing?.judge_ms != null ? ` · 判定 ${fmtMs(trace.timing.judge_ms)}` : ""}
        </dd>
      </dl>

      {toVerify.length > 0 ? (
        <div style={{ marginTop: 10 }}>
          <div className="field-label">
            需要核验的值（{toVerify.length}
            {toVerify.length > PREVIEW_VALUES ? `，显示前 ${PREVIEW_VALUES} 个` : ""}）
          </div>
          {toVerify.slice(0, PREVIEW_VALUES).map((value) => (
            <div key={value.at} className="small" style={{ margin: "4px 0" }}>
              <span className="mono">{value.at}</span> <SafeText text={value.value} />
              {value.sources.length > 0 ? (
                <div>
                  {value.sources.slice(0, 2).map((source) => (
                    <SourceChip
                      key={`${source.field}-${source.request_id ?? source.request}`}
                      source={source}
                      sources={sources}
                    />
                  ))}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      ) : null}

      {jev ? (
        <div style={{ marginTop: 12 }}>
          <div className="field-label">Jev 回答</div>
          <JevAnswers jev={jev} />
        </div>
      ) : null}

      <div className="peek-actions">
        <Button type="primary" onClick={onOpen}>
          打开详情 ⏎
        </Button>
        <CopyButton text={summary.request_id} label="复制 ID" />
        <Button type="text" onClick={onClose}>
          关闭
        </Button>
      </div>
    </aside>
  );
}
