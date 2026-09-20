//! Strict ciphertext-retention facts from committed deletion intents and attempts.
//!
//! These summaries describe maintenance, never business-request completion or
//! content access. Catalog and orphan observations have separate closed payloads.

use super::{PayloadSummary, PublishError, WireEvent, valid_uuid_v7};
use chrono::{DateTime, SecondsFormat};
use serde::Deserialize;
use xshield_core::domain::{ArtifactId, EventId, RequestId};

#[cfg(test)]
pub(crate) mod tests;

pub(super) const EVENT_TYPES: &[&str] = &[
    "evidence.purge_requested",
    "evidence.deleted",
    "evidence.purge_failed",
    "evidence.orphan.purge_requested",
    "evidence.orphan.deleted",
    "evidence.orphan.purge_failed",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogPayload {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    artifact_id: String,
    source_request_id: String,
    expires_at: String,
    retained_metadata: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrphanPayload {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    artifact_id: String,
    #[serde(rename = "authenticated_manifest")]
    _authenticated_manifest: bool,
}

/// Validates the maintenance producer and its exact closed payload contract.
///
/// Common envelope identity, scope, duplicate-key and integrity checks belong to
/// `IndexRow::parse_outbox`; this adapter adds producer, cause and target bindings.
/// Invalid facts return `InvalidEvent`; parsing has no storage or audit effects.
pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    if !EVENT_TYPES.contains(&event.event_type.as_str()) {
        return Err(PublishError::UnsupportedEventType);
    }
    if event.producer_id != "evidence-retention"
        || event.policy_revision != "evidence-retention-v1"
        || valid_uuid_v7(&event.producer_boot_id).is_err()
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
    {
        return Err(PublishError::InvalidEvent);
    }
    utc_millis(&event.occurred_at)?;
    let orphan = event.event_type.starts_with("evidence.orphan.");
    let (summary, artifact) = if orphan {
        let value: OrphanPayload = serde_json::from_str(event.payload.get())?;
        (
            PayloadSummary {
                stage: value.stage,
                outcome: value.outcome,
                reason_code: value.reason_code,
                proof_kind: value.proof_kind,
                confidence: value.confidence,
                confidence_status: value.confidence_status,
                ..PayloadSummary::default()
            },
            value.artifact_id,
        )
    } else {
        let value: CatalogPayload = serde_json::from_str(event.payload.get())?;
        if RequestId::parse(value.source_request_id).is_err() || !value.retained_metadata {
            return Err(PublishError::InvalidEvent);
        }
        // The signed local manifest fixes millisecond UTC precision. A clock
        // rollback can precede a failed attempt, so expiry is not ordered here.
        utc_millis(&value.expires_at)?;
        (
            PayloadSummary {
                stage: value.stage,
                outcome: value.outcome,
                reason_code: value.reason_code,
                proof_kind: value.proof_kind,
                confidence: value.confidence,
                confidence_status: value.confidence_status,
                ..PayloadSummary::default()
            },
            value.artifact_id,
        )
    };
    if summary.stage
        != if orphan {
            "evidence_orphan_retention"
        } else {
            "evidence_retention"
        }
        || summary.proof_kind != "deterministic"
        || summary.confidence.is_some()
        || summary.confidence_status != "not_applicable"
        || ArtifactId::parse(artifact.as_str()).is_err()
        || event.evidence_refs.as_slice() != [artifact]
        || !valid_result(event, &summary)
    {
        return Err(PublishError::InvalidEvent);
    }
    let intent = event.event_type.ends_with("purge_requested");
    match event.cause_event_ids.as_slice() {
        [] if intent => {}
        [cause] if !intent && cause != &event.event_id && EventId::parse(cause).is_ok() => {}
        _ => return Err(PublishError::InvalidEvent),
    }
    Ok(summary)
}

fn valid_result(event: &WireEvent, summary: &PayloadSummary) -> bool {
    matches!(
        (
            event.event_type.as_str(),
            summary.outcome.as_str(),
            summary.reason_code.as_str()
        ),
        (
            "evidence.purge_requested",
            "PASS",
            "EVIDENCE_PURGE_REQUESTED"
        ) | (
            "evidence.deleted",
            "PASS",
            "EVIDENCE_DELETED" | "EVIDENCE_DELETE_ALREADY_ABSENT"
        ) | (
            "evidence.purge_failed",
            "ERROR",
            "EVIDENCE_PURGE_REJECTED" | "EVIDENCE_PURGE_UNAVAILABLE"
        ) | (
            "evidence.orphan.purge_requested",
            "PASS",
            "EVIDENCE_ORPHAN_PURGE_REQUESTED"
        ) | (
            "evidence.orphan.deleted",
            "PASS",
            "EVIDENCE_ORPHAN_DELETED" | "EVIDENCE_ORPHAN_DELETE_ALREADY_ABSENT"
        ) | (
            "evidence.orphan.purge_failed",
            "ERROR",
            "EVIDENCE_ORPHAN_PURGE_REJECTED" | "EVIDENCE_ORPHAN_PURGE_UNAVAILABLE"
        )
    )
}

fn utc_millis(value: &str) -> Result<(), PublishError> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| PublishError::InvalidEvent)?;
    if value.len() != 24 || parsed.to_rfc3339_opts(SecondsFormat::Millis, true) != value {
        return Err(PublishError::InvalidEvent);
    }
    Ok(())
}
