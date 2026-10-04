/**
 * Which unresolved writes in the pending-operation registry belong to which control, and how a
 * frozen request is shown to the operator. The registry is the source of truth: a control that
 * is unmounted and mounted again finds its unknown write here, with its original key and body.
 */
import type { OperationSnapshot } from "../security/pending-operations.ts";
import { describeCode, type ErrorView, isStepUpCode } from "./errors.ts";

export type Owner = (operation: OperationSnapshot) => boolean;

const base = "/control/v1";
const artifactAccessPath = /^\/control\/v1\/artifacts\/artifact_[0-9a-f-]{36}\/access$/;

function bodyOf(operation: OperationSnapshot): Record<string, unknown> | null {
  if (operation.body === null) return null;
  try {
    const value: unknown = JSON.parse(operation.body);
    return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** One factory per write kind. A kind that targets one object claims every write on that object. */
export const owners = {
  createCase: (): Owner => (operation) => operation.path === `${base}/cases`,
  closeCase:
    (caseId: string): Owner =>
    (operation) =>
      operation.path === `${base}/cases/${caseId}/close`,
  addEvidence:
    (caseId: string): Owner =>
    (operation) =>
      operation.path === `${base}/cases/${caseId}/items`,
  analyzeCase:
    (caseId: string): Owner =>
    (operation) =>
      operation.path === `${base}/cases/${caseId}/analyze`,
  requestAccess:
    (caseId: string): Owner =>
    (operation) =>
      artifactAccessPath.test(operation.path) && bodyOf(operation)?.case_id === caseId,
  /** Approve and deny are one decision slot: whichever was frozen first blocks the other. */
  decideAccess:
    (accessId: string): Owner =>
    (operation) =>
      operation.path.startsWith(`${base}/evidence-access-requests/${accessId}/`),
  requestExport:
    (caseId: string): Owner =>
    (operation) =>
      operation.path === `${base}/exports` && bodyOf(operation)?.case_id === caseId,
  decideExport:
    (exportId: string): Owner =>
    (operation) =>
      operation.path.startsWith(`${base}/exports/${exportId}/`),
  createHold:
    (caseId: string): Owner =>
    (operation) =>
      operation.path === `${base}/cases/${caseId}/holds`,
  releaseHold:
    (holdId: string): Owner =>
    (operation) =>
      operation.path === `${base}/evidence-holds/${holdId}/release`,
};

export type OperationView = Readonly<{
  /** `POST /control/v1/cases/…/close` */
  request: string;
  key: string;
  /** The exact frozen body, pretty-printed; empty for bodiless requests. */
  body: string;
  phase: "inflight" | "unknown" | "step-up";
  phaseLabel: string;
  attempts: number;
  error: ErrorView | null;
}>;

function prettyBody(body: string | null): string {
  if (body === null || body === "") return "";
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

export function viewOperation(operation: OperationSnapshot): OperationView {
  const last = operation.lastError;
  const error = last ? describeCode(last.code, last.status, last.requestId) : null;
  const stepUp = last !== null && isStepUpCode(last.code);
  const phase = operation.phase === "inflight" ? "inflight" : stepUp ? "step-up" : "unknown";
  return {
    request: `${operation.method} ${operation.path}`,
    key: operation.idempotencyKey,
    body: prettyBody(operation.body),
    phase,
    phaseLabel:
      phase === "inflight" ? "请求中" : phase === "step-up" ? "等待 MFA 再认证" : "结果未知",
    attempts: operation.attempts,
    error,
  };
}
