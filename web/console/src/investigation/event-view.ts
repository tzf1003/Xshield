import type { AuditEvent } from "../api.ts";
import type { CausalRecord } from "../event-causality.ts";
import type { SearchEvent } from "../search.ts";
import { isoToMs, microsToIso } from "../ui/time-range.ts";

/**
 * One event as the investigation UI shows it, whichever endpoint it came from. The request
 * timeline and the structured search describe the same redacted facts with slightly different
 * wire shapes (microsecond number versus RFC 3339 text, empty string versus null); this is the
 * common projection. It carries no payload, storage or key material because neither source does.
 */
export type EventView = Readonly<{
  eventId: string;
  eventType: string;
  requestId: string | null;
  /** Only the search projection carries the W3C trace. */
  traceId: string | null;
  stage: string | null;
  outcome: string | null;
  reasonCode: string | null;
  proofKind: string | null;
  confidence: number | null;
  confidenceStatus: string | null;
  /** UTC RFC 3339 with microseconds. */
  occurredAt: string;
  requestSeq: number;
  durationUs: number;
  policyRevision: string | null;
  modelRevision: string | null;
  modelCallId: string | null;
  evidenceRefs: readonly string[];
  causeEventIds: readonly string[];
  sensitivity: string;
}>;

const blank = (value: string | null | undefined): string | null =>
  value === null || value === undefined || value === "" ? null : value;

export function fromAuditEvent(event: AuditEvent, requestId: string): EventView {
  return {
    eventId: event.event_id,
    eventType: event.event_type,
    requestId,
    traceId: null,
    stage: blank(event.stage),
    outcome: blank(event.outcome),
    reasonCode: blank(event.reason_code),
    proofKind: blank(event.proof_kind),
    confidence: event.confidence,
    confidenceStatus: blank(event.confidence_status),
    occurredAt: microsToIso(event.occurred_at),
    requestSeq: event.request_seq,
    durationUs: event.duration_us,
    policyRevision: blank(event.policy_revision),
    modelRevision: blank(event.model_revision),
    modelCallId: event.model_call_id,
    evidenceRefs: event.evidence_refs,
    causeEventIds: event.cause_event_ids,
    sensitivity: event.sensitivity,
  };
}

export function fromSearchEvent(event: SearchEvent): EventView {
  return {
    eventId: event.event_id,
    eventType: event.event_type,
    requestId: event.request_id,
    traceId: event.trace_id,
    stage: event.stage,
    outcome: event.outcome,
    reasonCode: event.reason_code,
    proofKind: event.proof_kind,
    confidence: event.confidence,
    confidenceStatus: event.confidence_status,
    occurredAt: event.occurred_at,
    requestSeq: event.request_seq,
    durationUs: event.duration_us,
    policyRevision: blank(event.policy_revision),
    modelRevision: event.model_revision,
    modelCallId: event.model_call_id,
    evidenceRefs: event.evidence_refs,
    causeEventIds: event.cause_event_ids,
    sensitivity: event.sensitivity,
  };
}

export function toCausalRecord(event: EventView): CausalRecord {
  return {
    event_id: event.eventId,
    event_type: event.eventType,
    stage: event.stage,
    cause_event_ids: [...event.causeEventIds],
  };
}

export function eventTimeMs(event: Pick<EventView, "occurredAt">): number | null {
  return isoToMs(event.occurredAt);
}

/** Evidence references that name catalog artifacts (the only ones that open metadata). */
export function artifactRefs(refs: readonly string[]): string[] {
  return refs.filter((ref) => ref.startsWith("artifact_"));
}
