//! Strict facts for committed evidence-hold creation and release.
//!
//! Holds describe maintenance of one artifact in a case. Indexing these facts
//! neither establishes the complete hold history nor grants content access.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_subject};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde::Deserialize;
use xshield_core::domain::{ArtifactId, CaseId, EventId};

#[cfg(test)]
pub(crate) mod tests;

pub(super) const EVENT_TYPES: &[&str] = &["evidence.hold.created", "evidence.hold.released"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldPayload {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    hold_id: String,
    case_id: String,
    artifact_id: String,
    subject_ref: String,
    request_digest: String,
    hold_until: String,
}

/// Validates the producer, closed payload, frozen clock and referenced hold.
///
/// `IndexRow::parse_outbox` validates the common envelope, source and duplicate
/// keys first. Invalid facts return `InvalidEvent` or a decoding error; this
/// bounded parser has no storage, authorization or audit-writing effects.
pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let expected_reason = match event.event_type.as_str() {
        "evidence.hold.created" => "EVIDENCE_HOLD_CREATED",
        "evidence.hold.released" => "EVIDENCE_HOLD_RELEASED",
        _ => return Err(PublishError::UnsupportedEventType),
    };
    let event_uuid = event
        .event_id
        .strip_prefix("ev_")
        .ok_or(PublishError::InvalidEvent)?;
    if event.producer_id != "evidence-hold"
        || event.policy_revision != "evidence-hold-v1"
        || event.producer_boot_id != event.event_id
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id != event_uuid.replace('-', "")
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
    {
        return Err(PublishError::InvalidEvent);
    }
    let occurred_at = utc_millis(&event.occurred_at)?;
    let value: HoldPayload = serde_json::from_str(event.payload.get())?;
    let hold_until = utc_millis(&value.hold_until)?;
    if value.stage != "evidence_hold"
        || value.outcome != "PASS"
        || value.reason_code != expected_reason
        || value.proof_kind != "deterministic"
        || value.confidence.is_some()
        || value.confidence_status != "not_applicable"
        || EventId::parse(&value.hold_id).is_err()
        || CaseId::parse(&value.case_id).is_err()
        || ArtifactId::parse(&value.artifact_id).is_err()
        || !valid_subject(&value.subject_ref)
        || value.subject_ref.trim() != value.subject_ref
        || !valid_lower_hex(&value.request_digest, 64)
        || event.evidence_refs.as_slice() != [value.artifact_id]
    {
        return Err(PublishError::InvalidEvent);
    }
    if event.event_type == "evidence.hold.created" {
        let duration = hold_until.signed_duration_since(occurred_at);
        if value.hold_id != event.event_id
            || !event.cause_event_ids.is_empty()
            || duration <= TimeDelta::zero()
            || duration > TimeDelta::days(30)
        {
            return Err(PublishError::InvalidEvent);
        }
    } else if value.hold_id == event.event_id || event.cause_event_ids.as_slice() != [value.hold_id]
    {
        // A release retains the original deadline, including an expired hold.
        return Err(PublishError::InvalidEvent);
    }
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: value.proof_kind,
        confidence_status: value.confidence_status,
        ..PayloadSummary::default()
    })
}

fn utc_millis(value: &str) -> Result<DateTime<Utc>, PublishError> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| PublishError::InvalidEvent)?;
    if value.len() != 24
        || parsed.to_rfc3339_opts(SecondsFormat::Millis, true) != value
        || parsed.timestamp() < 0
        // Chrono represents leap seconds with overflowing subseconds; persisted
        // hold clocks use ordinary UTC seconds consistently across boundaries.
        || parsed.timestamp_subsec_nanos() >= 1_000_000_000
        || parsed.timestamp_nanos_opt().is_none()
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(parsed.with_timezone(&Utc))
}
