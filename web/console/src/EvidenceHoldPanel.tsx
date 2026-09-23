/** Hold operations retain exact recovery inputs only for the connected session. */
import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { ApiError } from "./api";
import type { ControlClient, Envelope } from "./api";
import { artifactPattern } from "./api-contract";
import { casePattern, validIdempotencyKey } from "./cases";
import { holdPattern, validHoldReason, validHoldUntil } from "./evidence-holds";
import type { HoldCollection, HoldMutation } from "./evidence-holds";
import { HoldHistory } from "./HoldHistory";
import { Rows } from "./panels";

type Action = "create" | "release";
type Frozen = { action: Action; caseId: string; artifactId: string; holdId: string;
  reason: string; holdUntil: string; key: string; recovery: boolean };
type Attempt = { request: Frozen; phase: "pending" | "unknown" | "rejected" | "confirmed";
  error?: unknown; result?: HoldMutation };
type Run = <T extends Envelope>(fetcher: (api: ControlClient, signal: AbortSignal) => Promise<T>,
  apply: (response: T) => void, fail: (error: unknown) => void) => Promise<boolean>;
const newKey = () => globalThis.crypto?.randomUUID?.() ?? "";
const labels = { create: "创建保留锁", release: "释放保留锁" };

function HoldFailure({ error }: { error: unknown }) {
  return error ? <div className="notice danger" role="alert"><div>
    {error instanceof ApiError ? error.message : "请求未完成，请核对结果后重试。"}
    <small className="mono">{error instanceof ApiError ? error.code : "CONSOLE_REQUEST_FAILED"}
      {error instanceof ApiError && error.requestId ? ` · ${error.requestId}` : ""}</small>
  </div></div> : null;
}

export function EvidenceHoldPanel({ active, busy, onInvalidate, onHistory, onRun }: {
  active: boolean; busy: boolean; onInvalidate: () => void;
  onHistory: (holdId: string) => void; onRun: Run;
}) {
  const [action, setAction] = useState<Action>("create");
  const [caseId, setCaseId] = useState("");
  const [artifactId, setArtifactId] = useState("");
  const [holdId, setHoldId] = useState("");
  const [reason, setReason] = useState("");
  const [holdUntil, setHoldUntil] = useState("");
  const [key, setKey] = useState<string>(newKey);
  const [recover, setRecover] = useState(false);
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [queryCase, setQueryCase] = useState("");
  const [page, setPage] = useState<HoldCollection | null>(null);
  const [readError, setReadError] = useState<unknown>(null);
  const inFlight = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    if (!active) {
      setPage(null); setReadError(null);
      setAttempt((value) => value?.phase === "pending" ? { ...value, phase: "unknown" } : value);
    }
  }, [active]);
  const unresolved = attempt?.phase === "pending" || attempt?.phase === "unknown";
  useEffect(() => {
    if (!unresolved) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [unresolved]);
  function invalidateHistory() { onInvalidate(); setPage(null); setReadError(null); }
  function load(cursor?: string) {
    if (busy || inFlight.current || !casePattern.test(queryCase)) return;
    invalidateHistory();
    void onRun<HoldCollection>((api, signal) => api.evidenceHolds(queryCase, cursor, signal), setPage, setReadError);
  }
  async function mutate(request: Frozen) {
    if (inFlight.current) return;
    inFlight.current = true;
    const wasUnknown = request.recovery || attempt?.phase === "unknown";
    setAttempt({ request, phase: "pending" });
    invalidateHistory();
    let handled = false;
    await onRun<HoldMutation>(
      (api, signal) => request.action === "create"
        ? api.createEvidenceHold(request.caseId, request.artifactId, request.reason, request.holdUntil, request.key, signal)
        : api.releaseEvidenceHold(request.holdId, request.reason, request.key, signal),
      (result) => {
        handled = true;
        setAttempt({ request, phase: "confirmed", result });
        setQueryCase(result.case_id);
      },
      (error) => {
        handled = true;
        // A later rejection cannot establish the outcome of an earlier write.
        const rejected = !wasUnknown && error instanceof ApiError && error.code.startsWith("CONTROL_") &&
          [400, 403, 404, 409, 422, 429].includes(error.status);
        setAttempt({ request, phase: rejected ? "rejected" : "unknown", error });
      },
    );
    inFlight.current = false;
    if (mounted.current && !handled) setAttempt({ request, phase: "unknown" });
  }
  const valid = (action === "create"
    ? casePattern.test(caseId) && artifactPattern.test(artifactId) && validHoldUntil(holdUntil)
    : holdPattern.test(holdId)) && validHoldReason(reason) && validIdempotencyKey(key);
  function submit(event: FormEvent) {
    event.preventDefault();
    if (attempt || busy || !valid) return;
    void mutate({ action, caseId, artifactId, holdId, reason, holdUntil, key, recovery: recover });
  }
  const frozen = attempt?.request;
  return <div className="case-workbench hold-workbench">
    <div className="notice"><div>
      AuditAdministrator 可管理同作用域案件的证据保留。活动保留锁推迟物理删除；原始内容期限及访问审批继续生效。
      <p>新建保留锁要求开放案件中的现有证据成员，期限由数据库时钟校验为未来 720 小时内。释放支持已关闭案件和已过期保留锁。</p>
      <p>写入结果未知时保留原键与参数。刷新、断连、401、页面离开或闲置 15 分钟会清空内存；请先手动保存需要恢复的请求。</p>
    </div></div>
    <div className="case-grid">
      <section className="panel" aria-label="保留操作">
        <div className="panel-heading"><h2>保留操作</h2><span className="muted">创建 · 释放</span></div>
        <form className="case-form" onSubmit={submit}>
          <label htmlFor="hold-action">保留操作类型</label>
          <select id="hold-action" value={action} disabled={Boolean(attempt)} onChange={(event) => {
            setAction(event.target.value as Action); setReason(""); setRecover(false);
          }}><option value="create">创建保留锁</option><option value="release">释放保留锁</option></select>
          {action === "create" ? <>
            <label htmlFor="hold-case">保留案件 ID</label>
            <input id="hold-case" className="mono" value={caseId} disabled={Boolean(attempt)} onChange={(e) => setCaseId(e.target.value)} maxLength={41} autoComplete="off" spellCheck={false} required />
            <label htmlFor="hold-artifact">保留证据 ID</label>
            <input id="hold-artifact" className="mono" value={artifactId} disabled={Boolean(attempt)} onChange={(e) => setArtifactId(e.target.value)} maxLength={45} autoComplete="off" spellCheck={false} required />
            <label htmlFor="hold-until">保留至（UTC）</label>
            <input id="hold-until" className="mono" value={holdUntil} disabled={Boolean(attempt)} onChange={(e) => setHoldUntil(e.target.value)} placeholder="2026-10-01T00:00:00.000Z" maxLength={24} autoComplete="off" spellCheck={false} required />
            <p className="muted">完整 UTC 时间，精确到毫秒：YYYY-MM-DDTHH:MM:SS.sssZ。恢复请求使用原期限。</p>
          </> : <>
            <label htmlFor="hold-id">释放保留锁 ID</label>
            <input id="hold-id" className="mono" value={holdId} disabled={Boolean(attempt)} onChange={(e) => setHoldId(e.target.value)} maxLength={39} autoComplete="off" spellCheck={false} required />
            <p className="muted">填写 ev_ 前缀的保留锁 ID，或从案件保留历史中选择。</p>
          </>}
          <label htmlFor="hold-reason">{action === "create" ? "保留理由" : "释放理由"}</label>
          <textarea id="hold-reason" value={reason} disabled={Boolean(attempt)} onChange={(e) => setReason(e.target.value)} maxLength={512} autoComplete="off" spellCheck={false} required />
          <p className="muted">1–512 UTF-8 字节，无首尾空白及控制字符。</p>
          <label className="access-recovery" htmlFor="hold-recover"><input id="hold-recover" type="checkbox" checked={recover} disabled={Boolean(attempt)} onChange={(e) => setRecover(e.target.checked)} />恢复原保留操作</label>
          {recover && <p className="notice warning">填写保存的原目标、原理由、原期限及原幂等键。服务端校验精确重试，在确认成功前保留未知结果。</p>}
          <label htmlFor="hold-key">保留幂等键</label>
          <input id="hold-key" className="mono" value={key} readOnly={Boolean(attempt)} onChange={(e) => setKey(e.target.value)} minLength={16} maxLength={128} autoComplete="off" spellCheck={false} required />
          <p className="muted">16–128 个 ASCII 字母、数字或 -_.:；恢复时填写原键。</p>
          {!attempt && <button type="submit" disabled={busy || !valid}>{labels[action]}</button>}
        </form>
        {attempt && <div className="case-result" aria-live="polite">
          <h3>{attempt.phase === "pending" ? "提交中，等待结果" : attempt.phase === "unknown" ? "保留操作结果未知" : attempt.phase === "rejected" ? "本次保留操作被拒绝" : `${labels[attempt.request.action]}已确认`}</h3>
          <HoldFailure error={attempt.error} />
          {unresolved && <div className="notice warning">服务端可能已经提交。请保存原键与参数，使用“原样重试保留操作”确认结果。</div>}
          <Rows entries={[
            ["方法与路径", <span className="mono">POST {frozen?.action === "create" ? `/control/v1/cases/${frozen.caseId}/holds` : `/control/v1/evidence-holds/${frozen?.holdId}/release`}</span>],
            ["原幂等键", <span className="mono">{frozen?.key}</span>],
          ]} />
          <pre className="mono case-payload" aria-label="冻结保留请求参数">{JSON.stringify(frozen?.action === "create"
            ? { artifact_id: frozen.artifactId, reason: frozen.reason, hold_until: frozen.holdUntil }
            : { reason: frozen?.reason }, null, 2)}</pre>
          {attempt.result && <><Rows entries={[
            ["返回保留锁 ID", attempt.result.hold_id], ["返回案件", attempt.result.case_id],
            ["返回证据", attempt.result.artifact_id], ["原始保留期限", attempt.result.hold_until],
            ["释放时间", attempt.result.released_at ?? "—"], ["管理请求 ID", attempt.result.request_id],
            ["replayed", attempt.result.replayed ? "true（返回原操作结果）" : "false（首次提交）"],
          ]} /><p className="footnote">操作已确认。请显式读取案件保留历史，核对数据库当前观察。</p></>}
          <div className="case-actions">
            <button className="outline" disabled={busy || attempt.phase === "pending"} onClick={() => void mutate(attempt.request)}>原样重试保留操作</button>
            <button className="text-button" disabled={busy || unresolved} onClick={() => {
              setAttempt(null); setReason(""); setHoldUntil(""); setRecover(false); setKey(newKey());
            }}>准备新的保留操作</button>
          </div>
        </div>}
      </section>
      <section className="panel" aria-label="案件保留历史" aria-busy={busy}>
        <div className="panel-heading"><h2>案件保留历史</h2><span className="muted">固定作用域 · 历史观察</span></div>
        <form className="case-form" onSubmit={(event) => { event.preventDefault(); load(); }}>
          <label htmlFor="hold-query-case">保留历史案件 ID</label>
          <input id="hold-query-case" className="mono" value={queryCase} disabled={attempt?.phase === "pending"} onChange={(e) => { invalidateHistory(); setQueryCase(e.target.value); }} maxLength={41} autoComplete="off" spellCheck={false} required />
          <button type="submit" disabled={busy || attempt?.phase === "pending" || !casePattern.test(queryCase)}>读取保留历史 / 刷新</button>
          <p className="muted">按保留锁 ID 升序分页，每页使用独立数据库时间。到期与持久释放分别展示；操作后请刷新。</p>
        </form>
        <HoldFailure error={readError} />
        {page ? <HoldHistory page={page} busy={busy} canSelect={!attempt} onHistory={onHistory}
          onNext={load} onSelect={(hold) => {
          setAction("release"); setHoldId(hold.hold_id); setReason(""); setRecover(false);
        }} /> : !readError && <p className="empty">填写案件 ID，查看保留锁与释放事实。</p>}
      </section>
    </div>
  </div>;
}
