/** A richer synthetic request: several gateway stages, a model call, evidence and a skipped stage. */
import {
  ARTIFACT_ID,
  AS_OF,
  EVENT_CURSOR,
  MODEL_CALL_ID,
  REQUEST_ID,
  summaryFixture,
} from "./fixtures";

const SCOPE = {
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
};

export const richEventId = (n: number) =>
  `ev_018f2a3b-4c5d-7000-8000-${String(3000 + n).padStart(12, "0")}`;

type StageSpec = {
  stage: string;
  outcome: "PASS" | "DENY" | "UNKNOWN" | "ERROR" | "SKIPPED" | "CANCELLED";
  reason: string;
  proof: "deterministic" | "model" | "observation" | "none";
  confidence: number | null;
  status: "provided" | "not_applicable" | "not_provided" | "unavailable";
  seq: number;
  duration: number;
};

const stageSpecs: StageSpec[] = [
  {
    stage: "operation_admission",
    outcome: "PASS",
    reason: "UI_ACTION_ALLOWED",
    proof: "deterministic",
    confidence: null,
    status: "not_applicable",
    seq: 2,
    duration: 24,
  },
  {
    stage: "crypto_decode",
    outcome: "PASS",
    reason: "REQUEST_CRYPTO_DECODED",
    proof: "deterministic",
    confidence: null,
    status: "not_applicable",
    seq: 3,
    duration: 310,
  },
  {
    stage: "model_eval",
    outcome: "PASS",
    reason: "MODEL_EVALUATED",
    proof: "model",
    confidence: 0.8,
    status: "provided",
    seq: 4,
    duration: 1_200,
  },
  {
    stage: "evidence_capture",
    outcome: "PASS",
    reason: "EVIDENCE_CAPTURED",
    proof: "deterministic",
    confidence: null,
    status: "not_applicable",
    seq: 5,
    duration: 90,
  },
  {
    stage: "crypto_encode",
    outcome: "SKIPPED",
    reason: "SKIPPED_BY_SITE_UNAVAILABLE",
    proof: "none",
    confidence: null,
    status: "not_applicable",
    seq: 6,
    duration: 0,
  },
];

/** An ALLOW request whose origin answered; not every stage ran. */
export function richSummaryFixture(requestId = REQUEST_ID) {
  const base = summaryFixture(requestId);
  return {
    ...base,
    has_gaps: false,
    pending_segments: 0,
    summary: {
      ...base.summary,
      event_count: 8,
      decision: "ALLOW",
      reason_code: "UI_ACTION_ALLOWED",
      status: 200,
      origin_state: "response_received",
      duration_us: 4_800,
      forwarded: true,
      terminal: true,
      business_result_confirmed: true,
      stages: stageSpecs.map((spec) => ({
        stage: spec.stage,
        outcome: spec.outcome,
        reason_code: spec.reason,
        proof_kind: spec.proof,
        confidence: spec.confidence,
        confidence_status: spec.status,
        first_request_seq: spec.seq,
        last_request_seq: spec.seq,
        duration_us: spec.duration,
        event_count: 1,
      })),
    },
  };
}

const micros = Date.parse(AS_OF) * 1000;

function auditEvent(n: number, overrides: Record<string, unknown>) {
  return {
    event_id: richEventId(n),
    event_type: "stage.completed",
    stage: "",
    outcome: "",
    reason_code: "",
    proof_kind: "",
    confidence: null,
    confidence_status: "",
    occurred_at: micros + n * 1_000,
    request_seq: n,
    duration_us: 0,
    policy_revision: "policy-demo-r3",
    model_revision: "",
    model_call_id: null,
    evidence_refs: [],
    cause_event_ids: n > 1 ? [richEventId(n - 1)] : [],
    sensitivity: "INTERNAL",
    ...overrides,
  };
}

const stageEvent = (n: number, spec: StageSpec, extra: Record<string, unknown> = {}) =>
  auditEvent(n, {
    event_type: spec.outcome === "SKIPPED" ? "stage.skipped" : "stage.completed",
    stage: spec.stage,
    outcome: spec.outcome,
    reason_code: spec.reason,
    proof_kind: spec.proof,
    confidence: spec.confidence,
    confidence_status: spec.status,
    duration_us: spec.duration,
    ...extra,
  });

/** Eight events over two pages, the model event linking MODEL_CALL_ID. */
export function richEventsFixture(requestId = REQUEST_ID, nextPage = false) {
  const spec = (name: string) => stageSpecs.find((item) => item.stage === name) as StageSpec;
  const first = [
    auditEvent(1, { event_type: "request.accepted" }),
    stageEvent(2, spec("operation_admission")),
    stageEvent(3, spec("crypto_decode")),
    stageEvent(4, spec("model_eval"), {
      model_revision: "jev-1.13.0",
      model_call_id: MODEL_CALL_ID,
    }),
    stageEvent(5, spec("evidence_capture"), { evidence_refs: [ARTIFACT_ID] }),
  ];
  const second = [
    stageEvent(6, spec("crypto_encode")),
    auditEvent(7, {
      event_type: "origin.response",
      outcome: "response_received",
      reason_code: "ORIGIN_RESPONSE_RECEIVED",
    }),
    auditEvent(8, {
      event_type: "request.completed",
      outcome: "ALLOW",
      reason_code: "UI_ACTION_ALLOWED",
      duration_us: 4_800,
    }),
  ];
  return {
    ...SCOPE,
    source_request_id: requestId,
    as_of: AS_OF,
    index_watermark: summaryFixture().index_watermark,
    has_gaps: false,
    truncated: !nextPage,
    next_cursor: nextPage ? null : EVENT_CURSOR,
    events: nextPage ? second : first,
  };
}
