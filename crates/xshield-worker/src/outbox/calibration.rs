//! Strict offline calibration-report metadata; indexing never changes policy.
//!
//! The detailed report and its source evidence stay in the separately protected
//! report artifact. This adapter only accepts the bounded metadata needed to
//! identify its frozen provenance in the analytical index.

use super::{PayloadSummary, PublishError, WireEvent, valid_lower_hex, valid_name, valid_uuid_v7};
use chrono::{DateTime, SecondsFormat};
use serde::Deserialize;
use xshield_core::domain::{
    ArtifactId, CalibrationLineageReviewId, CalibrationReadCapabilityId, CalibrationReportId,
    EventId,
};

#[cfg(test)]
pub(crate) mod tests;

pub(super) const EVENT_TYPES: &[&str] = &[
    "calibration.reported",
    "calibration.partition_lineage.reviewed",
    "calibration.read_capability.issued",
    "calibration.read_batch.completed",
    "calibration.report_retention.purge_requested",
    "calibration.report_retention.deleted",
    "calibration.report_retention.purge_failed",
    "calibration.report_retention.orphan_purge_requested",
    "calibration.report_retention.orphan_deleted",
    "calibration.report_retention.orphan_purge_failed",
    "calibration.lineage_review_retention.purge_requested",
    "calibration.lineage_review_retention.deleted",
    "calibration.lineage_review_retention.purge_failed",
    "calibration.lineage_review_retention.orphan_purge_requested",
    "calibration.lineage_review_retention.orphan_deleted",
    "calibration.lineage_review_retention.orphan_purge_failed",
];

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

/// Bounded projection of a declaration-review fact. The source graph remains
/// only in the encrypted review artifact and is never indexed through outbox.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationLineageReview {
    stage: String,
    outcome: String,
    reason_code: String,
    review_id: String,
    review_artifact_id: String,
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
    lineage_review_id: String,
    scope_digest: String,
    member_count: u32,
    frozen_total_bytes: u64,
    not_before_unix: u64,
    expires_at_unix: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationReadBatchCompleted {
    stage: String,
    outcome: String,
    reason_code: String,
    capability_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationReportRetention {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    report_id: String,
    report_artifact_id: String,
    expires_at: String,
    retained_metadata: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibrationLineageReviewRetention {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    #[serde(deserialize_with = "Option::deserialize")]
    confidence: Option<f64>,
    confidence_status: String,
    review_id: String,
    review_artifact_id: String,
    expires_at: String,
    retained_metadata: bool,
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
    if event.event_type == "calibration.read_batch.completed" {
        return parse_batch_completed(event);
    }
    if event.event_type == "calibration.partition_lineage.reviewed" {
        return parse_lineage_review(event);
    }
    if event
        .event_type
        .starts_with("calibration.report_retention.")
    {
        return parse_report_retention(event);
    }
    if event
        .event_type
        .starts_with("calibration.lineage_review_retention.")
    {
        return parse_lineage_review_retention(event);
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
        || event.evidence_refs.as_slice() != [value.report_artifact_id.as_str()]
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

/// Validates an expiry-maintenance fact for one lineage-review body.
///
/// It only records a restricted lifecycle phase. The durable review projection
/// and authenticated vault sidecar decide availability; an indexed event never
/// restores the body or makes it a source-evidence authorization.
fn parse_lineage_review_retention(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: CalibrationLineageReviewRetention = serde_json::from_str(event.payload.get())?;
    let review_id = CalibrationLineageReviewId::parse(value.review_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let review_uuid = review_id
        .as_str()
        .strip_prefix("calrev_")
        .ok_or(PublishError::InvalidEvent)?;
    if event.producer_id != "calibration-lineage-review-retention"
        || event.policy_revision != "calibration-retention-v1"
        || valid_uuid_v7(&event.producer_boot_id).is_err()
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id != review_uuid.replace('-', "")
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
        || value.stage != "calibration_lineage_review_retention"
        || value.proof_kind != "deterministic"
        || value.confidence.is_some()
        || value.confidence_status != "not_applicable"
        || ArtifactId::parse(&value.review_artifact_id).is_err()
        || event.evidence_refs.as_slice() != [value.review_artifact_id.as_str()]
        || !value.retained_metadata
        || utc_millis(&value.expires_at).is_err()
        || !valid_lineage_review_retention_result(event, &value)
    {
        return Err(PublishError::InvalidEvent);
    }
    let intent = event.event_type.ends_with("purge_requested");
    match event.cause_event_ids.as_slice() {
        [] if intent => {}
        [cause] if !intent && cause != &event.event_id && EventId::parse(cause).is_ok() => {}
        _ => return Err(PublishError::InvalidEvent),
    }
    utc_millis(&event.occurred_at)?;
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: value.proof_kind,
        confidence_status: value.confidence_status,
        ..PayloadSummary::default()
    })
}

fn valid_lineage_review_retention_result(
    event: &WireEvent,
    value: &CalibrationLineageReviewRetention,
) -> bool {
    matches!(
        (
            event.event_type.as_str(),
            value.outcome.as_str(),
            value.reason_code.as_str()
        ),
        (
            "calibration.lineage_review_retention.purge_requested",
            "PASS",
            "CALIBRATION_LINEAGE_REVIEW_PURGE_REQUESTED"
        ) | (
            "calibration.lineage_review_retention.deleted",
            "PASS",
            "CALIBRATION_LINEAGE_REVIEW_DELETED"
                | "CALIBRATION_LINEAGE_REVIEW_DELETE_ALREADY_ABSENT"
        ) | (
            "calibration.lineage_review_retention.purge_failed",
            "ERROR",
            "CALIBRATION_LINEAGE_REVIEW_PURGE_REJECTED"
                | "CALIBRATION_LINEAGE_REVIEW_PURGE_UNAVAILABLE"
        ) | (
            "calibration.lineage_review_retention.orphan_purge_requested",
            "PASS",
            "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_REQUESTED"
        ) | (
            "calibration.lineage_review_retention.orphan_deleted",
            "PASS",
            "CALIBRATION_LINEAGE_REVIEW_ORPHAN_DELETED"
                | "CALIBRATION_LINEAGE_REVIEW_ORPHAN_DELETE_ALREADY_ABSENT"
        ) | (
            "calibration.lineage_review_retention.orphan_purge_failed",
            "ERROR",
            "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_REJECTED"
                | "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_UNAVAILABLE"
        )
    )
}

/// Validates the restricted durable declaration-review history fact.
///
/// A successful parse only makes the independent review identifiable in the
/// analytical index. It never treats submitted graph metadata as proof of
/// corpus independence and never grants source evidence access.
fn parse_lineage_review(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: CalibrationLineageReview = serde_json::from_str(event.payload.get())?;
    let review_id = CalibrationLineageReviewId::parse(value.review_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let review_uuid = review_id
        .as_str()
        .strip_prefix("calrev_")
        .ok_or(PublishError::InvalidEvent)?;
    if event.producer_id != "calibration-lineage-reviewer"
        || event.policy_revision != "calibration-lineage-v1"
        || event.producer_boot_id != event.event_id
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id != review_uuid.replace('-', "")
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
        || !event.cause_event_ids.is_empty()
        || value.stage != "calibration_partition_lineage"
        || value.outcome != "PASS"
        || value.reason_code != "CALIBRATION_PARTITION_LINEAGE_REVIEWED"
        || ArtifactId::parse(&value.review_artifact_id).is_err()
        || !valid_lineage_scalars(&value)
        || !valid_provider_model_id(&value.provider_model_id)
        || !valid_resolved_revision(&value.resolved_model_revision)
        || !lineage_artifacts_are_distinct(&value)
        || event.evidence_refs.as_slice() != [value.review_artifact_id.as_str()]
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

/// Validates an expiry-maintenance fact for one report body.
///
/// The report artifact sidecar and `PostgreSQL` tombstone remain authoritative;
/// this restricted outbox record only makes a deterministic maintenance phase
/// searchable and never restores content or changes the report's provenance.
fn parse_report_retention(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: CalibrationReportRetention = serde_json::from_str(event.payload.get())?;
    let report_id = CalibrationReportId::parse(value.report_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let report_uuid = report_id
        .as_str()
        .strip_prefix("calr_")
        .ok_or(PublishError::InvalidEvent)?;
    if event.producer_id != "calibration-report-retention"
        || event.policy_revision != "calibration-retention-v1"
        || valid_uuid_v7(&event.producer_boot_id).is_err()
        || event.producer_seq != 1
        || event.request_seq != 1
        || event.request_id.is_some()
        || event.sensitivity != "RESTRICTED"
        || event.observed_at != event.occurred_at
        || event.trace_id != report_uuid.replace('-', "")
        || event.trace_id.get(..16) != Some(event.span_id.as_str())
        || value.stage != "calibration_report_retention"
        || value.proof_kind != "deterministic"
        || value.confidence.is_some()
        || value.confidence_status != "not_applicable"
        || ArtifactId::parse(&value.report_artifact_id).is_err()
        || event.evidence_refs.as_slice() != [value.report_artifact_id.as_str()]
        || !value.retained_metadata
        || utc_millis(&value.expires_at).is_err()
        || !valid_report_retention_result(event, &value)
    {
        return Err(PublishError::InvalidEvent);
    }
    let intent = event.event_type.ends_with("purge_requested");
    match event.cause_event_ids.as_slice() {
        [] if intent => {}
        [cause] if !intent && cause != &event.event_id && EventId::parse(cause).is_ok() => {}
        _ => return Err(PublishError::InvalidEvent),
    }
    utc_millis(&event.occurred_at)?;
    Ok(PayloadSummary {
        stage: value.stage,
        outcome: value.outcome,
        reason_code: value.reason_code,
        proof_kind: value.proof_kind,
        confidence_status: value.confidence_status,
        ..PayloadSummary::default()
    })
}

fn valid_report_retention_result(event: &WireEvent, value: &CalibrationReportRetention) -> bool {
    matches!(
        (
            event.event_type.as_str(),
            value.outcome.as_str(),
            value.reason_code.as_str()
        ),
        (
            "calibration.report_retention.purge_requested",
            "PASS",
            "CALIBRATION_REPORT_PURGE_REQUESTED"
        ) | (
            "calibration.report_retention.deleted",
            "PASS",
            "CALIBRATION_REPORT_DELETED" | "CALIBRATION_REPORT_DELETE_ALREADY_ABSENT"
        ) | (
            "calibration.report_retention.purge_failed",
            "ERROR",
            "CALIBRATION_REPORT_PURGE_REJECTED" | "CALIBRATION_REPORT_PURGE_UNAVAILABLE"
        ) | (
            "calibration.report_retention.orphan_purge_requested",
            "PASS",
            "CALIBRATION_REPORT_ORPHAN_PURGE_REQUESTED"
        ) | (
            "calibration.report_retention.orphan_deleted",
            "PASS",
            "CALIBRATION_REPORT_ORPHAN_DELETED" | "CALIBRATION_REPORT_ORPHAN_DELETE_ALREADY_ABSENT"
        ) | (
            "calibration.report_retention.orphan_purge_failed",
            "ERROR",
            "CALIBRATION_REPORT_ORPHAN_PURGE_REJECTED"
                | "CALIBRATION_REPORT_ORPHAN_PURGE_UNAVAILABLE"
        )
    )
}

/// Validates the content-free atomic terminal for one complete batch lease.
/// The durable header/lease rows remain the authority; this fact only makes
/// the terminal transition searchable and never authorizes a later read.
fn parse_batch_completed(event: &WireEvent) -> Result<PayloadSummary, PublishError> {
    let value: CalibrationReadBatchCompleted = serde_json::from_str(event.payload.get())?;
    let capability_id = CalibrationReadCapabilityId::parse(value.capability_id.clone())
        .map_err(|_| PublishError::InvalidEvent)?;
    let capability_uuid = capability_id
        .as_str()
        .strip_prefix("calcap_")
        .ok_or(PublishError::InvalidEvent)?;
    if event.producer_id != "calibration-evidence-batch-completer"
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
        || value.stage != "calibration_read_batch"
        || value.outcome != "PASS"
        || value.reason_code != "CALIBRATION_READ_BATCH_COMPLETED"
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
    CalibrationLineageReviewId::parse(value.lineage_review_id.clone())
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

fn valid_lineage_scalars(value: &CalibrationLineageReview) -> bool {
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

fn lineage_artifacts_are_distinct(value: &CalibrationLineageReview) -> bool {
    let artifacts = [
        &value.review_artifact_id,
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
