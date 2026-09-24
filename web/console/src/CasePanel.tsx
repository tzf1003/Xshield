/** Investigator case workflow. Frozen mutation requests stay in this session's
 * memory until explicitly replaced after a known outcome or the session ends. */
import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { ApiError } from "./api";
import type { ControlClient, Envelope, JobResponse } from "./api";
import { artifactPattern } from "./api-contract";
import { casePattern, validCaseText, validIdempotencyKey } from "./cases";
import type {
  CaseCollection,
  CaseCreated,
  CaseItemAdded,
  CaseClosed,
} from "./cases";
import { Rows } from "./panels";
import { CaseList } from "./CaseList";

type Action = "create" | "add" | "close";
type FrozenRequest = {
  action: Action;
  key: string;
  value: string;
  caseId: string;
};
type MutationResult = CaseCreated | CaseItemAdded | CaseClosed;
type Attempt = {
  request: FrozenRequest;
  phase: "pending" | "unknown" | "rejected" | "confirmed";
  result?: MutationResult;
  error?: unknown;
};
type AnalysisRequest = { caseId: string; key: string };
type AnalysisAttempt = {
  request: AnalysisRequest;
  phase: "pending" | "unknown" | "rejected" | "confirmed";
  result?: JobResponse;
  error?: unknown;
};
type Run = <T extends Envelope>(
  fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
  apply: (response: T) => void,
  fail: (error: unknown) => void,
) => Promise<boolean>;
const actions = { create: "创建案件", add: "加入证据", close: "关闭案件" };
const fields = { create: "调查目的", add: "证据 ID", close: "关闭理由" };
const catalogLabels = {
  active: "目录有效",
  expired: "已到期",
  deleted: "已删除",
  unavailable: "目录不可用",
};
const newKey = () => globalThis.crypto?.randomUUID?.() ?? "";

function CaseFailure({ error }: { error: unknown }) {
  return error ? (
    <div className="notice danger" role="alert">
      <div>
        {error instanceof ApiError
          ? error.message
          : "请求未完成，请核对结果后重试。"}
        <small className="mono">
          {error instanceof ApiError ? error.code : "CONSOLE_REQUEST_FAILED"}
          {error instanceof ApiError && error.requestId
            ? ` · ${error.requestId}`
            : ""}
        </small>
      </div>
    </div>
  ) : null;
}

export function CasePanel({
  active,
  busy,
  onInvalidate,
  onRun,
  onArtifact,
  onHistory,
  artifactDetails,
}: {
  active: boolean;
  busy: boolean;
  onInvalidate: () => void;
  onRun: Run;
  onArtifact: (id: string) => void;
  onHistory: (jobId: string) => void;
  artifactDetails: ReactNode;
}) {
  const [caseId, setCaseId] = useState("");
  const [collection, setCollection] = useState<CaseCollection | null>(null);
  const [readError, setReadError] = useState<unknown>(null);
  const [action, setAction] = useState<Action>("create");
  const [value, setValue] = useState("");
  const [key, setKey] = useState<string>(newKey);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [analysisKey, setAnalysisKey] = useState<string>(newKey);
  const [analysis, setAnalysis] = useState<AnalysisAttempt | null>(null);
  const mounted = useRef(true);
  // A ref freezes synchronously, including rapid double clicks before React paints.
  const inFlight = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    if (!active) {
      setCollection(null);
      setReadError(null);
      setAnalysis(null);
    }
  }, [active]);
  const mutationUnresolved =
    attempt?.phase === "pending" ||
    attempt?.phase === "unknown";
  const analysisUnresolved =
    analysis?.phase === "pending" ||
    analysis?.phase === "unknown";
  const unresolved = mutationUnresolved || analysisUnresolved;
  useEffect(() => {
    if (!unresolved) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [unresolved]);

  function browse(cursor?: string, target = caseId) {
    if (!casePattern.test(target) || inFlight.current) return;
    onInvalidate();
    setCollection(null);
    setReadError(null);
    setAnalysis(null);
    setAnalysisKey(newKey());
    void onRun<CaseCollection>(
      (api, signal) => api.caseItems(target, cursor, signal),
      setCollection,
      setReadError,
    );
  }

  async function mutate(request: FrozenRequest) {
    if (inFlight.current) return;
    inFlight.current = true;
    const wasUnknown = attempt?.phase === "unknown";
    setAttempt({ request, phase: "pending" });
    onInvalidate();
    setCollection(null);
    setReadError(null);
    let handled = false;
    await onRun<MutationResult>(
      (api, signal) =>
        request.action === "create"
          ? api.createCase(request.value, request.key, signal)
          : request.action === "add"
            ? api.addCaseItem(
                request.caseId,
                request.value,
                request.key,
                signal,
              )
            : api.closeCase(request.caseId, request.value, request.key, signal),
      (result) => {
        handled = true;
        setAttempt({ request, phase: "confirmed", result });
        setCaseId(result.case_id);
      },
      (error) => {
        handled = true;
        // A later denial cannot establish whether an earlier uncertain attempt
        // committed. Only a validated success resolves that uncertainty.
        const knownRejection =
          !wasUnknown &&
          error instanceof ApiError &&
          error.code.startsWith("CONTROL_") &&
          [400, 403, 404, 409, 422, 429].includes(error.status);
        setAttempt({
          request,
          phase: knownRejection ? "rejected" : "unknown",
          error,
        });
      },
    );
    inFlight.current = false;
    if (mounted.current && !handled) setAttempt({ request, phase: "unknown" });
  }

  async function analyze(request: AnalysisRequest) {
    if (inFlight.current) return;
    inFlight.current = true;
    const wasUnknown = analysis?.phase === "unknown";
    setAnalysis({ request, phase: "pending" });
    onInvalidate();
    let handled = false;
    await onRun<JobResponse>(
      (api, signal) => api.analyzeCase(request.caseId, request.key, signal),
      (result) => {
        handled = true;
        setAnalysis({ request, phase: "confirmed", result });
      },
      (error) => {
        handled = true;
        const knownRejection =
          !wasUnknown &&
          error instanceof ApiError &&
          error.code.startsWith("CONTROL_") &&
          [400, 403, 404, 409, 422, 429].includes(error.status);
        setAnalysis({
          request,
          phase: knownRejection ? "rejected" : "unknown",
          error,
        });
      },
    );
    inFlight.current = false;
    if (mounted.current && !handled)
      setAnalysis({ request, phase: "unknown" });
  }

  async function readAnalysis(jobId: string) {
    if (inFlight.current || !analysis) return;
    inFlight.current = true;
    const request = analysis.request;
    const previous = analysis.result;
    setAnalysis({ request, phase: "pending", result: previous });
    onInvalidate();
    let handled = false;
    await onRun<JobResponse>(
      (api, signal) => api.job(jobId, signal),
      (result) => {
        handled = true;
        setAnalysis({ request, phase: "confirmed", result });
      },
      (error) => {
        handled = true;
        setAnalysis({ request, phase: "unknown", result: previous, error });
      },
    );
    inFlight.current = false;
    if (mounted.current && !handled)
      setAnalysis({ request, phase: "unknown", result: previous });
  }

  function submitAnalysis(event: FormEvent) {
    event.preventDefault();
    const target = collection?.case.case_id ?? caseId;
    if (
      analysis ||
      !casePattern.test(target) ||
      !validIdempotencyKey(analysisKey)
    )
      return;
    void analyze({ caseId: target, key: analysisKey });
  }

  function resetAnalysis() {
    setAnalysis(null);
    setAnalysisKey(newKey());
  }

  const openCase = collection?.case.status === "open";
  const canTarget =
    action === "create" || (action === "add" ? openCase : Boolean(collection));
  const validValue =
    action === "add" ? artifactPattern.test(value) : validCaseText(value);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (attempt || !validValue || !validIdempotencyKey(key) || !canTarget)
      return;
    void mutate({
      action,
      key,
      value,
      caseId: action === "create" ? "" : caseId,
    });
  }
  const result = attempt?.result;
  const frozen = attempt?.request;
  const payload =
    frozen &&
    JSON.stringify(
      frozen.action === "create"
        ? { purpose: frozen.value }
        : frozen.action === "add"
          ? { artifact_id: frozen.value }
          : { reason: frozen.value },
      null,
      2,
    );

  return (
    <div className="case-workbench">
      <div className="notice">
        <div>
          Investigator
          可创建、查询和关闭本人案件。案件及关联只建立调查上下文，原文读取与导出仍需独立授权；关联不延长保留期限，也不建立保留锁。
          <p>
            所有变更由按钮显式提交。刷新、断连、401、页面离开或闲置 15
            分钟会清除内存中的键和参数，请先保存需要恢复的请求。
          </p>
        </div>
      </div>
      <CaseList
        active={active}
        busy={busy || attempt?.phase === "pending"}
        onLoad={(cursor, apply, fail) => {
          if (inFlight.current) return;
          onInvalidate();
          void onRun((api, signal) => api.cases(cursor, signal), apply, fail);
        }}
        onOpen={(target) => {
          if (inFlight.current) return;
          setCaseId(target);
          browse(undefined, target);
        }}
      />
      <div className="case-grid">
        <section className="panel" aria-label="案件操作">
          <div className="panel-heading">
            <h2>案件操作</h2>
            <span className="muted">精确幂等重试</span>
          </div>
          <form className="case-form" onSubmit={submit}>
            <label htmlFor="case-action">操作</label>
            <select
              id="case-action"
              value={action}
              disabled={Boolean(attempt)}
              onChange={(event) => {
                setAction(event.target.value as Action);
                setValue("");
              }}
            >
              <option value="create">创建案件</option>
              <option value="add" disabled={!openCase}>
                加入证据
              </option>
              <option value="close" disabled={!collection}>
                关闭案件
              </option>
            </select>
            {action !== "create" && (
              <p className="muted">
                目标案件：
                <span className="mono">
                  {frozen?.caseId ??
                    collection?.case.case_id ??
                    "请先读取本人开放案件"}
                </span>
              </p>
            )}
            <label htmlFor="case-value">{fields[action]}</label>
            <input
              id="case-value"
              value={value}
              disabled={Boolean(attempt)}
              onChange={(event) => setValue(event.target.value)}
              maxLength={512}
              autoComplete="off"
              spellCheck={false}
              required
            />
            <p className="muted">
              {action === "add"
                ? "规范 artifact_ UUIDv7；新关联要求证据目录有效且未到期。"
                : "1–512 UTF-8 字节，无首尾空白及控制字符。"}
            </p>
            <label htmlFor="case-key">幂等键</label>
            <input
              id="case-key"
              className="mono"
              value={key}
              readOnly={Boolean(attempt)}
              onChange={(event) => setKey(event.target.value)}
              autoComplete="off"
              spellCheck={false}
              minLength={16}
              maxLength={128}
              required
            />
            <p className="muted">
              16–128 个 ASCII 字母、数字或
              -_.:；恢复原请求时填写保存的原键及原参数。
            </p>
            {action === "close" && (
              <div className="notice warning">
                关闭后保留历史引用与原期限；新增关联、原文申请和后续读取校验要求开放案件。已通过校验的在途读取可能完成。
              </div>
            )}
            {action === "close" && collection?.case.status === "closed" && (
              <p className="muted">
                恢复关闭请求：填写原关闭理由与原幂等键，服务端将验证精确重试。
              </p>
            )}
            {!attempt && (
              <button
                type="submit"
                disabled={
                  busy || !validValue || !validIdempotencyKey(key) || !canTarget
                }
              >
                {actions[action]}
              </button>
            )}
          </form>
          {attempt && (
            <div className="case-result" aria-live="polite">
              <h3>
                {attempt.phase === "pending"
                  ? "提交中，等待结果"
                  : attempt.phase === "unknown"
                    ? "操作结果未知"
                    : attempt.phase === "rejected"
                      ? "本次请求被拒绝"
                      : `${actions[attempt.request.action]}已确认`}
              </h3>
              <CaseFailure error={attempt.error} />
              {mutationUnresolved && (
                <div className="notice warning">
                  服务端可能已经提交。保留原幂等键与参数，使用下方“原样重试”确认结果。离开或会话清空前，请手动保存这份请求。
                </div>
              )}
              <Rows
                entries={[
                  [
                    "方法与路径",
                    <span className="mono">
                      POST /control/v1/cases
                      {frozen?.action === "create"
                        ? ""
                        : `/${frozen?.caseId}/${frozen?.action === "add" ? "items" : "close"}`}
                    </span>,
                  ],
                  ["原幂等键", <span className="mono">{frozen?.key}</span>],
                ]}
              />
              <pre className="mono case-payload" aria-label="冻结请求参数">
                {payload}
              </pre>
              {result && (
                <Rows
                  entries={[
                    ["案件 ID", <span className="mono">{result.case_id}</span>],
                    [
                      "管理请求 ID",
                      <span className="mono">{result.request_id}</span>,
                    ],
                    [
                      "replayed",
                      result.replayed
                        ? "true（返回原操作结果）"
                        : "false（首次提交）",
                    ],
                    ...("status" in result
                      ? [["响应案件状态", result.status] as [string, ReactNode]]
                      : []),
                    [
                      "操作时间",
                      <span className="mono">
                        {"created_at" in result
                          ? result.created_at
                          : "added_at" in result
                            ? result.added_at
                            : result.closed_at}
                      </span>,
                    ],
                    ...("artifact_id" in result
                      ? ([
                          [
                            "证据 ID",
                            <span className="mono">{result.artifact_id}</span>,
                          ],
                          ["加入者", result.added_by],
                        ] as [string, ReactNode][])
                      : []),
                  ]}
                />
              )}
              <div className="case-actions">
                <button
                  className="outline"
                  disabled={busy || attempt.phase === "pending"}
                  onClick={() => void mutate(attempt.request)}
                >
                  原样重试
                </button>
                <button
                  className="text-button"
                  disabled={busy || mutationUnresolved}
                  onClick={() => {
                    setAttempt(null);
                    setValue("");
                    setKey(newKey());
                    setAction("create");
                  }}
                >
                  准备新操作
                </button>
              </div>
            </div>
          )}
        </section>
        <section className="panel" aria-label="案件证据集合" aria-busy={busy}>
          <div className="panel-heading">
            <h2>案件证据集合</h2>
            <span className="muted">本人 · 固定作用域</span>
          </div>
          <form
            className="case-form"
            onSubmit={(event) => {
              event.preventDefault();
              browse();
            }}
          >
            <label htmlFor="case-id">案件 ID</label>
            <input
              id="case-id"
              className="mono"
              value={caseId}
              disabled={attempt?.phase === "pending"}
              onChange={(event) => {
                onInvalidate();
                setCaseId(event.target.value);
                setCollection(null);
                setReadError(null);
                setAnalysis(null);
                setAnalysisKey(newKey());
              }}
              placeholder="case_…"
              autoComplete="off"
              spellCheck={false}
              maxLength={41}
              required
            />
            <button
              type="submit"
              disabled={
                busy ||
                attempt?.phase === "pending" ||
                !casePattern.test(caseId)
              }
            >
              读取案件 / 刷新首页
            </button>
          </form>
          <CaseFailure error={readError} />
          {collection ? (
            <>
              <div className="detail-body case-snapshot">
                <Rows
                  entries={[
                    [
                      "案件状态",
                      <span className="badge">{collection.case.status}</span>,
                    ],
                    ["调查目的", collection.case.purpose],
                    [
                      "创建时间",
                      <span className="mono">
                        {collection.case.created_at}
                      </span>,
                    ],
                    [
                      "数据库 as_of",
                      <span className="mono">{collection.as_of}</span>,
                    ],
                    [
                      "管理请求 ID",
                      <span className="mono">{collection.request_id}</span>,
                    ],
                  ]}
                />
                <p className="footnote">
                  状态以本页数据库快照为准；翻页会重新观察。catalog
                  状态仅描述目录，不证明原文读取权或对象完整性。
                </p>
                {collection.case.status === "closed" && (
                  <p className="notice warning">
                    案件已关闭，历史证据引用仍可浏览。
                  </p>
                )}
                <form className="case-analysis" onSubmit={submitAnalysis}>
                  <h3>案件清单分析</h3>
                  <p className="muted">
                    只统计当前集合的引用与目录状态，结果写入耐久任务；不会读取正文。
                  </p>
                  <label htmlFor="case-analysis-key">分析幂等键</label>
                  <input
                    id="case-analysis-key"
                    className="mono"
                    value={analysis?.request.key ?? analysisKey}
                    readOnly={Boolean(analysis)}
                    onChange={(event) => setAnalysisKey(event.target.value)}
                    autoComplete="off"
                    spellCheck={false}
                    minLength={16}
                    maxLength={128}
                    required
                  />
                  {!analysis && (
                    <button
                      type="submit"
                      disabled={
                        busy ||
                        !validIdempotencyKey(analysisKey) ||
                        !casePattern.test(collection.case.case_id)
                      }
                    >
                      提交清单分析
                    </button>
                  )}
                  {analysis && (
                    <div className="case-result" aria-live="polite">
                      <strong>
                        {analysis.phase === "pending"
                          ? "分析提交中"
                          : analysis.phase === "unknown"
                            ? "分析结果未知"
                            : analysis.phase === "rejected"
                              ? "分析请求被拒绝"
                              : "分析任务已确认"}
                      </strong>
                      <CaseFailure error={analysis.error} />
                      {analysis.result?.job && (
                        <Rows
                          entries={[
                            [
                              "任务 ID",
                              <span className="mono">
                                {analysis.result.job.job_id}
                              </span>,
                            ],
                            ["任务状态", analysis.result.job.status],
                            ["引用总数", analysis.result.job.artifact_count],
                            [
                              "当前有效引用",
                              analysis.result.job.active_artifact_count,
                            ],
                            [
                              "管理请求 ID",
                              <span className="mono">
                                {analysis.result.request_id}
                              </span>,
                            ],
                          ]}
                        />
                      )}
                      <div className="case-actions">
                        <button
                          type="button"
                          className="text-button"
                          disabled={busy || analysis.phase === "pending"}
                          onClick={() => {
                            const jobId = analysis.result?.job?.job_id;
                            if (jobId) void readAnalysis(jobId);
                          }}
                        >
                          重新读取任务状态
                        </button>
                        {analysis.result?.job && (
                          <button
                            type="button"
                            className="text-button"
                            disabled={busy}
                            onClick={() =>
                              onHistory(analysis.result!.job!.job_id)
                            }
                          >
                            准备任务历史检索
                          </button>
                        )}
                        <button
                          type="button"
                          className="text-button"
                          disabled={busy || analysisUnresolved}
                          onClick={resetAnalysis}
                        >
                          准备新分析
                        </button>
                      </div>
                    </div>
                  )}
                </form>
              </div>
              <div className="case-items">
                {collection.items.length === 0 ? (
                  <p className="empty">当前案件尚无证据引用。</p>
                ) : (
                  collection.items.map((item) => (
                    <article className="case-item" key={item.artifact_id}>
                      <strong className="mono">{item.artifact_id}</strong>
                      <span className="badge">
                        {item.catalog_status} ·{" "}
                        {catalogLabels[item.catalog_status]}
                      </span>
                      <Rows
                        entries={[
                          ["加入者", item.added_by],
                          [
                            "加入时间",
                            <span className="mono">{item.added_at}</span>,
                          ],
                        ]}
                      />
                      <button
                        className="text-button"
                        onClick={() => onArtifact(item.artifact_id)}
                      >
                        查看元数据（需 Observer）
                      </button>
                    </article>
                  ))
                )}
              </div>
              <div className="pagination">
                <button
                  className="outline"
                  disabled={busy || !collection.next_cursor}
                  onClick={() => {
                    if (collection.next_cursor) browse(collection.next_cursor);
                  }}
                >
                  下一页证据
                </button>
                <span className="muted">
                  本页 {collection.items.length} 条 ·{" "}
                  {collection.truncated ? "还有后续引用" : "已到当前集合末页"}
                </span>
              </div>
            </>
          ) : (
            <p className="empty">
              {busy
                ? "正在处理案件请求…"
                : "输入案件 ID 读取当前集合。新关联需开放案件；已关闭案件可用原键确认关闭结果。"}
            </p>
          )}
        </section>
      </div>
      {artifactDetails}
    </div>
  );
}
