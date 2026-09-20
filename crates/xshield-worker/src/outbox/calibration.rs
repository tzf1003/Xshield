//! Strict offline calibration-report metadata; indexing never changes policy.
//!
//! The detailed report and its source evidence stay in the separately protected
//! report artifact. This adapter only accepts the bounded metadata needed to
//! identify its frozen provenance in the analytical index.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_name};
use chrono::{DateTime, SecondsFormat};
use serde::Deserialize;
use xshield_core::domain::{ArtifactId, CalibrationReadCapabilityId, CalibrationReportId};

#[cfg(test)]
pub(crate) mod tests;

pub(super) const EVENT_TYPES: &[&str] =
    &["calibration.reported", "calibration.read_capability.issued"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationReport {
    stage: String,
    outcome: String,
    reason_code: String,
    report_id: String,
    report_artifact_id: String,
    approval_ref: String,
    dataset_revision: String,
    label_revision: String,
    task_revision: String,
    threshold_policy_revision: String,
    mapping_revision: String,
    evaluation_manifest_artifact_id: String,
    training_manifest_artifact_id: String,
    calibration_manifest_artifact_id: String,
    label_manifest_artifact_id: String,
    provider: String,
    provider_model_id: String,
    model_revision: String,
    prompt_revision: String,
    resolved_model_revision: ResolvedModelRevision,
}

/// Preserves the explicit unknown revision rather than treating an omitted field
/// as a known or current provider revision.
#[derive(Deserialize)]
#[serde(untagged)]
enum ResolvedModelRevision {
    Known(String),
    Unknown(()),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationReadCapabilityIssued {
    stage: String,
    outcome: String,
    reason_code: String,
    capability_id: String,
    scope_digest: String,
    member_count: u32,
    frozen_total_bytes: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
}

/// Validates one complete offline calibration-report event without side effects.
///
/// Common v3 envelope, leased event identity, duplicate JSON key, and scope
/// validation happen before this parser. This parser binds the producer, frozen
/// report identity, report artifact and non-sensitive provenance; it never reads
/// evidence, evaluates a model, changes a threshold, or grants authorization.
pub(super) fn parse(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    if !EVENT_TYPES.contains(&event.event_type.as_str()) {
        return Err(PublishError::UnsupportedEventType);
    }
    if event.event_type == "calibration.read_capability.issued" {
        return parse_capability_issued(event);
    }
    let value: CalibrationReport = serde_json::from_str(event.payload.get())?;
    let report_id = CalibrationReportId::parse(value.report_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let report_uuid = report_id
        .as_str()
        .strip_prefix("calr_")
        .ok_or(PublishError::InvalidEvent)?;
    if event.producer_id != "calibration-evaluator"
        || event.policy_revision != "calibration-v1"
        || event.producer_boot_id != event.event_id
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id != report_uuid.replace('-', "")
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
        || !event.cause_event_ids.is_empty()
        || value.stage != "calibration_report"
        || value.outcome != "PASS"
        || value.reason_code != "CALIBRATION_REPORTED"
        || ArtifactId::parse(&value.report_artifact_id).is_err()
        || !valid_scalars(&value)
        || !valid_provider_model_id(&value.provider_model_id)
        || !valid_resolved_revision(&value.resolved_model_revision)
        || !all_artifacts(&value)
        || event.evidence_refs.as_slice() != [value.report_artifact_id]
    {
        return Err(PublishError::InvalidEvent);
    }
    utc_millis(&event.occurred_at)?;
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}

/// Validates the restricted issuance fact. The complete member set remains in
/// `PostgreSQL` and is purpose-limited reader state, so it cannot exceed the
/// outbox envelope bound or become a searchable source-artifact list.
fn parse_capability_issued(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: CalibrationReadCapabilityIssued = serde_json::from_str(event.payload.get())?;
    let capability_id = CalibrationReadCapabilityId::parse(value.capability_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let capability_uuid = capability_id
        .as_str()
        .strip_prefix("calcap_")
        .ok_or(PublishError::InvalidEvent)?;
    let valid_bounds = value.member_count >= 6
        && value.member_count <= 20_004
        && (value.member_count - 4).is_multiple_of(2)
        && (1..=512 * 1024 * 1024).contains(&value.frozen_total_bytes)
        && value.not_before_unix < value.expires_at_unix
        && i64::try_from(value.not_before_unix).is_ok()
        && i64::try_from(value.expires_at_unix).is_ok();
    if event.producer_id != "calibration-capability-issuer"
        || event.policy_revision != "calibration-v1"
        || event.producer_boot_id != event.event_id
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id != capability_uuid.replace('-', "")
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
        || !event.evidence_refs.is_empty()
        || !event.cause_event_ids.is_empty()
        || value.stage != "calibration_read_capability"
        || value.outcome != "PASS"
        || value.reason_code != "CALIBRATION_READ_CAPABILITY_ISSUED"
        || !valid_lower_hex(&value.scope_digest, 64)
        || !valid_bounds
    {
        return Err(PublishError::InvalidEvent);
    }
    utc_millis(&event.occurred_at)?;
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: "deterministic".to_owned(),
        confidence_status: "not_applicable".to_owned(),
        ..PayloadSummary::default()
    })
}

fn valid_scalars(value: &CalibrationReport) -> bool {
    [
        &value.approval_ref,
        &value.dataset_revision,
        &value.label_revision,
        &value.task_revision,
        &value.threshold_policy_revision,
        &value.mapping_revision,
        &value.provider,
        &value.model_revision,
        &value.prompt_revision,
    ]
    .into_iter()
    .all(|field| valid_name(field))
}

fn valid_resolved_revision(value: &ResolvedModelRevision) -> bool {
    match value {
        ResolvedModelRevision::Known(revision) => valid_name(revision),
        ResolvedModelRevision::Unknown(()) => true,
    }
}

fn all_artifacts(value: &CalibrationReport) -> bool {
    let artifacts = [
        &value.report_artifact_id,
        &value.evaluation_manifest_artifact_id,
        &value.training_manifest_artifact_id,
        &value.calibration_manifest_artifact_id,
        &value.label_manifest_artifact_id,
    ];
    artifacts
        .iter()
        .all(|artifact| ArtifactId::parse(*artifact).is_ok())
        && artifacts
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == artifacts.len()
}

fn valid_provider_model_id(value: &str) -> bool {
    if value.len() > 128 {
        return false;
    }
    let Some((provider, model)) = value.split_once('/') else {
        return valid_name(value);
    };
    !model.contains('/') && valid_name(provider) && valid_name(model)
}

fn utc_millis(value: &str) -> Result<(), PublishError> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|_| PublishError::InvalidEvent)?;
    if value.len() != 24
        || parsed.to_rfc3339_opts(SecondsFormat::Millis, true) != value
        || parsed.timestamp() < 0
        || parsed.timestamp_nanos_opt().is_none()
        // Chrono accepts RFC 3339 leap seconds; persisted report clocks use
        // ordinary UTC seconds so this byte is constrained after canonical form.
        || value.as_bytes()[17] > b'5'
    {
        return Err(PublishError::InvalidEvent);
    }
    Ok(())
}
