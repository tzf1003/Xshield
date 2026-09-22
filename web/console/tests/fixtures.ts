/** Synthetic HTTP fixtures mirroring control and worker response DTOs.
 * They model wire contracts for browser tests, not captured production records.
 */
export const TOKEN =
  "synthetic-observer-token-for-browser-tests-000000000000000000000000";
export const REQUEST_ID = "req_018f2a3b-4c5d-7000-8000-000000000001";
export const OTHER_REQUEST_ID = "req_018f2a3b-4c5d-7000-8000-000000000002";
export const MODEL_CALL_ID = "mdl_018f2a3b-4c5d-7000-8000-000000000001";
export const OTHER_MODEL_CALL_ID = "mdl_018f2a3b-4c5d-7000-8000-000000000002";
export const ARTIFACT_ID = "artifact_018f2a3b-4c5d-7000-8000-000000000011";
export const OTHER_ARTIFACT_ID =
  "artifact_018f2a3b-4c5d-7000-8000-000000000012";
export const EVENT_CURSOR = "synthetic.events.cursor-2";
export const EVIDENCE_CURSOR = "synthetic.evidence.cursor-2";
export const AS_OF = "2026-09-20T08:10:30.000Z";

function envelope() {
  return {
    request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
    tenant_id: "tenant_demo",
    site_id: "site_demo",
  };
}

export function summaryFixture(requestId = REQUEST_ID) {
  return {
    ...envelope(),
    source_request_id: requestId,
    as_of: AS_OF,
    index_watermark: {
      producer_boot_id: "018f2a3b-4c5d-7000-8000-000000000088",
      producer_sequence: 42,
    },
    has_gaps: true,
    pending_segments: 2,
    found: true,
    completeness: "complete",
    summary: {
      event_count: 4,
      first_occurred_at: AS_OF,
      last_occurred_at: AS_OF,
      method: "GET",
      operation_id: "user.profile.read",
      decision: "DENY",
      reason_code: "UI_ACTION_NOT_AVAILABLE",
      status: 403,
      origin_state: "not_sent",
      duration_us: 84,
      forwarded: false,
      terminal: true,
      business_result_confirmed: false,
      stages: [
        {
          stage: "ui_action",
          outcome: "DENY",
          reason_code: "UI_ACTION_NOT_AVAILABLE",
          proof_kind: "deterministic",
          confidence: null,
          confidence_status: "not_applicable",
          first_request_seq: 3,
          last_request_seq: 3,
          duration_us: 24,
          event_count: 1,
        },
      ],
    },
  };
}

export function eventsFixture(requestId = REQUEST_ID, nextPage = false) {
  const event = (
    sequence: number,
    stage: string,
    outcome: string,
    reason: string,
  ) => ({
    event_id: `ev_018f2a3b-4c5d-7000-8000-${String(sequence).padStart(12, "0")}`,
    event_type: "stage.completed",
    stage,
    outcome,
    reason_code: reason,
    proof_kind: "deterministic",
    confidence: null,
    confidence_status: "not_applicable",
    occurred_at: Date.parse(AS_OF) * 1000,
    request_seq: sequence,
    duration_us: 24,
    policy_revision: "policy-demo-r3",
    model_revision: "",
    model_call_id: null,
    evidence_refs: sequence === 3 ? [ARTIFACT_ID] : [],
    cause_event_ids: [],
    sensitivity: "INTERNAL",
  });
  return {
    ...envelope(),
    source_request_id: requestId,
    as_of: AS_OF,
    index_watermark: {
      producer_boot_id: "018f2a3b-4c5d-7000-8000-000000000088",
      producer_sequence: 42,
    },
    has_gaps: true,
    truncated: !nextPage,
    next_cursor: nextPage ? null : EVENT_CURSOR,
    events: nextPage
      ? [event(4, "terminal", "DENY", "REQUEST_DENIED")]
      : [
          event(1, "admission", "PASS", "REQUEST_ACCEPTED"),
          event(2, "auth_binding", "PASS", "AUTH_BINDING_VALID"),
          event(3, "ui_action", "DENY", "UI_ACTION_NOT_AVAILABLE"),
        ],
  };
}

export function manifestFixture(
  artifactId = ARTIFACT_ID,
  requestId = REQUEST_ID,
) {
  return {
    recorded_at: AS_OF,
    schema_version: 3,
    artifact_id: artifactId,
    request_id: requestId,
    tenant_id: "tenant_demo",
    site_id: "site_demo",
    kind: "request_decoded",
    content_type: "application/json",
    capture_status: "complete",
    fidelity: "redacted",
    bytes_observed: 256,
    bytes_saved: 256,
    classification: "RESTRICTED",
    // This is the production wire value required by the catalog contract;
    // the enclosing test fixture remains explicitly synthetic.
    example_only: false,
    storage: {
      profile: "aead_envelope_v1",
      locator: "synthetic-vault-object.bin",
      key_ref: "synthetic-key-ref",
    },
    integrity: { algorithm: "sha256_ciphertext", digest: "a".repeat(64) },
    parent_refs: [],
    expires_at: "2026-09-21T08:10:30.000Z",
  };
}

export function evidenceFixture(requestId = REQUEST_ID, nextPage = false) {
  return {
    ...envelope(),
    source_request_id: requestId,
    truncated: !nextPage,
    next_cursor: nextPage ? null : EVIDENCE_CURSOR,
    artifacts: [
      manifestFixture(nextPage ? OTHER_ARTIFACT_ID : ARTIFACT_ID, requestId),
    ],
  };
}

export function artifactFixture(
  artifactId = ARTIFACT_ID,
  requestId = REQUEST_ID,
) {
  return {
    ...envelope(),
    source_artifact_id: artifactId,
    found: true,
    artifact: manifestFixture(artifactId, requestId),
  };
}

export function errorFixture(code: string) {
  return {
    error_code: code,
    message_safe: "Synthetic server detail must not be rendered",
    request_id: envelope().request_id,
    retryable: code === "CONTROL_RATE_LIMITED",
    next_action: "contact_operator",
  };
}

export function modelCallFixture(modelCallId = MODEL_CALL_ID) {
  const facts = {
    provider: "vercel_ai_gateway",
    provider_model_id: "typesafe-ai/jev",
    model_revision: "jev-1.13.0",
    prompt_revision: "evaluation-r1",
    question_type: "choice",
    status: "success",
    reason_code: "MODEL_EVALUATED",
    confidence: 0.8 as number | null,
    confidence_status: "provided",
    duration_us: 1200,
    input_artifact_id: ARTIFACT_ID as string | null,
    output_artifact_id: OTHER_ARTIFACT_ID as string | null,
    call_artifact_id: "artifact_018f2a3b-4c5d-7000-8000-000000000013" as
      string | null,
  };
  const events = ["started", "requested", "success"].map((status, index) => ({
    ...facts,
    status,
    reason_code: [
      "MODEL_EVALUATION_STARTED",
      "MODEL_REQUESTED",
      "MODEL_EVALUATED",
    ][index]!,
    confidence: index === 2 ? 0.8 : null,
    confidence_status: index === 2 ? "provided" : "unavailable",
    input_artifact_id: index === 0 ? null : facts.input_artifact_id,
    output_artifact_id: index === 2 ? facts.output_artifact_id : null,
    call_artifact_id: index === 2 ? facts.call_artifact_id : null,
    event_id: `ev_018f2a3b-4c5d-7000-8000-00000000000${index + 1}`,
    event_type: ["model.started", "model.requested", "model.responded"][index]!,
    request_id: REQUEST_ID,
    occurred_at: AS_OF,
    request_seq: index + 1,
    evidence_refs:
      index === 0
        ? []
        : index === 1
          ? [ARTIFACT_ID]
          : [ARTIFACT_ID, OTHER_ARTIFACT_ID, facts.call_artifact_id!],
    cause_event_ids:
      index === 0 ? [] : [`ev_018f2a3b-4c5d-7000-8000-00000000000${index}`],
    sensitivity: "RESTRICTED",
  }));
  return {
    ...envelope(),
    source_model_call_id: modelCallId,
    watermark_scope: "configured_journal",
    as_of: AS_OF,
    index_watermark: summaryFixture().index_watermark,
    has_gaps: true,
    pending_segments: 2,
    found: true,
    completeness: "complete",
    model_call: {
      ...facts,
      model_call_id: modelCallId,
      request_id: REQUEST_ID,
      events,
      lifecycle_complete: true,
    },
  };
}

import { searchPlanDigest } from "../src/search.ts";
import type { SearchEvent, SearchPlan, SearchResponse } from "../src/search.ts";

export const SEARCH_PLAN: SearchPlan = {
  schema_version: 3,
  start: "2026-09-20T00:00:00Z",
  end: "2026-09-21T00:00:00Z",
  filters: [],
  sort: "occurred_at_desc",
  limit: 2,
};

/** Synthetic HMAC bytes only model cursor shape; server signing is tested in Rust. */
export async function searchFixture(
  plan = SEARCH_PLAN,
  nextPage = false,
): Promise<SearchResponse> {
  const events: SearchEvent[] = (nextPage ? [3] : [1, 2]).map((sequence) => ({
    event_id: `ev_018f2a3b-4c5d-7000-8000-${String(sequence).padStart(12, "0")}`,
    event_type: sequence === 1 ? "evidence.deleted" : "stage.completed",
    request_id: sequence === 1 ? null : REQUEST_ID,
    stage: sequence === 1 ? null : "admission",
    outcome: sequence === 1 ? null : "DENY",
    reason_code: sequence === 1 ? null : "SEARCH_SYNTHETIC_DENIAL",
    proof_kind: sequence === 1 ? null : "deterministic",
    confidence: null,
    confidence_status: sequence === 1 ? null : "not_applicable",
    occurred_at: `2026-09-20T08:10:30.${plan.sort === "occurred_at_asc" ? 123453 + sequence : 123458 - sequence}Z`,
    request_seq: sequence,
    duration_us: 24,
    policy_revision: "policy-demo-r3",
    model_revision: null,
    model_call_id: null,
    evidence_refs: [ARTIFACT_ID],
    cause_event_ids: [],
    sensitivity: "INTERNAL",
  }));
  const last = events.at(-1)!;
  const position =
    BigInt(Date.parse(last.occurred_at.slice(0, 19) + "Z")) * 1000n +
    BigInt(last.occurred_at.slice(20, 26));
  return {
    ...envelope(),
    schema_version: 3,
    query_digest: await searchPlanDigest(plan),
    as_of: AS_OF,
    index_watermark: summaryFixture().index_watermark,
    has_gaps: true,
    pending_segments: 2,
    scanned_rows: null,
    scanned_bytes: 0,
    truncated: !nextPage,
    next_cursor: nextPage
      ? null
      : `v1.${position}.${last.event_id}.${"0".repeat(64)}`,
    events,
  };
}
