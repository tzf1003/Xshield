//! Scoped, read-only calibration-report metadata inspection.
//!
//! Calibration reports have a dedicated projection and encrypted-body store.
//! This adapter reads only the frozen projection plus the report body's
//! retained/deleted marker; it never opens the body or consults the generic
//! evidence catalog.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use uuid::{Uuid, Version};
use xshield_core::domain::{
    ApprovalRef, ArtifactId, CalibrationLineageReviewId, CalibrationReportId, DatasetRevision,
    EventId, LabelRevision, MappingRevision, ModelRevision, PromptRevision, ProviderId, SiteId,
    TaskRevision, TenantId, ThresholdPolicyRevision,
};

/// Physical state of the encrypted calibration-report body.
///
/// This status is a retention observation only. It grants neither report-body
/// access nor a policy-publication or business-admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationReportBodyStatus {
    /// The dedicated report vault has not recorded a terminal deletion.
    Active,
    /// Retention recorded a terminal report-body tombstone.
    Deleted,
}

impl CalibrationReportBodyStatus {
    /// Returns the stable API spelling of the retained body state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deleted => "deleted",
        }
    }
}

/// One frozen calibration-report metadata observation.
///
/// The projection intentionally omits storage metadata, encrypted-body data,
/// samples, labels, probabilities, metrics, source tuples, and every
/// evidence-read capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationReportInspection {
    /// Database statement time for this single read-only snapshot.
    pub as_of: DateTime<Utc>,
    /// Exact report identity in the authenticated tenant/site scope.
    pub report_id: CalibrationReportId,
    /// Frozen dedicated report-artifact identity; it is not a generic evidence
    /// catalog entry or a report-body read capability.
    pub report_artifact_id: ArtifactId,
    /// Frozen report terminal time.
    pub reported_at: DateTime<Utc>,
    /// Immutable terminal event identity for the report projection.
    pub reported_event_id: EventId,
    /// Expiry retained for the dedicated report body, independent of body state.
    pub body_expires_at: DateTime<Utc>,
    /// Frozen external-disclosure approval reference.
    pub approval_ref: ApprovalRef,
    /// Frozen completed-batch time, retained independently for investigation.
    pub completed_at: DateTime<Utc>,
    /// Frozen held-out dataset revision.
    pub dataset_revision: DatasetRevision,
    /// Frozen label-set revision.
    pub label_revision: LabelRevision,
    /// Frozen task-semantics revision.
    pub task_revision: TaskRevision,
    /// Frozen threshold-policy revision.
    pub threshold_policy_revision: ThresholdPolicyRevision,
    /// Frozen risk-mapping revision.
    pub mapping_revision: MappingRevision,
    /// Frozen held-out evaluation partition manifest identity.
    pub evaluation_manifest_artifact_id: ArtifactId,
    /// Frozen training partition manifest identity.
    pub training_manifest_artifact_id: ArtifactId,
    /// Frozen calibration partition manifest identity.
    pub calibration_manifest_artifact_id: ArtifactId,
    /// Frozen label-set manifest identity.
    pub label_manifest_artifact_id: ArtifactId,
    /// Frozen configured provider identity.
    pub provider: ProviderId,
    /// Frozen provider wire-model identity.
    pub provider_model_id: String,
    /// Frozen internal model revision.
    pub model_revision: ModelRevision,
    /// Frozen prompt revision.
    pub prompt_revision: PromptRevision,
    /// Provider-reported exact revision, if it was available at evaluation time.
    pub resolved_model_revision: Option<ModelRevision>,
    /// Immutable lineage-review identity when one was recorded for the report.
    ///
    /// Older retained reports can predate the lineage-review requirement, so a
    /// missing value is preserved as metadata rather than inferred.
    pub lineage_review_id: Option<CalibrationLineageReviewId>,
    /// Retention state of the dedicated encrypted report body.
    pub body_status: CalibrationReportBodyStatus,
}

impl PostgresIdentityStore {
    /// Reads frozen metadata for one calibration report in a fixed scope.
    ///
    /// Missing and foreign-scope report IDs return `None`. Historical reports
    /// remain observable after their dedicated encrypted body is deleted. This
    /// method takes no business locks, writes no outbox event, reads no report
    /// body, and never invokes a generic artifact or evidence-read path. SQL
    /// and lock waits are capped at five seconds; the caller bounds total
    /// execution time and durably audits before releasing the snapshot.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or malformed/corrupt visible
    /// metadata. A damaged linked projection is never represented as a miss.
    pub async fn read_calibration_report(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        report: &CalibrationReportId,
    ) -> Result<Option<CalibrationReportInspection>, StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await?;
        // LEFT JOIN keeps an otherwise visible report available to corruption
        // detection instead of accidentally turning damaged linkage into 404.
        let row = sqlx::query(
            "SELECT statement_timestamp() AS as_of,
                    report.tenant_id AS report_tenant_id, report.site_id AS report_site_id,
                    report.report_id, report.report_artifact_id, report.capability_id,
                    report.lineage_review_id, report.approval_ref,
                    report.dataset_revision, report.label_revision, report.task_revision,
                    report.threshold_policy_revision, report.mapping_revision,
                    report.evaluation_manifest_artifact_id,
                    report.training_manifest_artifact_id,
                    report.calibration_manifest_artifact_id,
                    report.label_manifest_artifact_id,
                    report.provider, report.provider_model_id, report.model_revision,
                    report.prompt_revision, report.resolved_model_revision,
                    report.completed_at, report.reported_at,
                    body.report_id AS body_report_id,
                    body.artifact_id AS body_artifact_id,
                    body.retention_status, body.recorded_at, body.published_at, body.expires_at,
                    body.deleted_at, body.purge_requested_event_id,
                    body.purge_completed_event_id,
                    purge_requested.event_id AS purge_requested_outbox_event_id,
                    purge_requested.tenant_id AS purge_requested_tenant_id,
                    purge_requested.site_id AS purge_requested_site_id,
                    purge_requested.aggregate_ref AS purge_requested_aggregate_ref,
                    purge_requested.event_type AS purge_requested_event_type,
                    purge_requested.envelope AS purge_requested_envelope,
                    purge_completed.event_id AS purge_completed_outbox_event_id,
                    purge_completed.tenant_id AS purge_completed_tenant_id,
                    purge_completed.site_id AS purge_completed_site_id,
                    purge_completed.aggregate_ref AS purge_completed_aggregate_ref,
                    purge_completed.event_type AS purge_completed_event_type,
                    purge_completed.envelope AS purge_completed_envelope,
                    completed.event_id AS completed_event_id,
                    completed.tenant_id AS completed_tenant_id,
                    completed.site_id AS completed_site_id,
                    completed.aggregate_ref AS completed_aggregate_ref,
                    completed.event_type AS completed_event_type,
                    reported.event_id AS reported_event_id,
                    reported.tenant_id AS reported_tenant_id,
                    reported.site_id AS reported_site_id,
                    reported.aggregate_ref AS reported_aggregate_ref,
                    reported.event_type AS reported_event_type,
                    reported.envelope AS reported_envelope,
                    capability.capability_id AS capability_linked_id,
                    capability.lineage_review_id AS capability_lineage_review_id,
                    (isfinite(report.completed_at) AND isfinite(report.reported_at)
                     AND COALESCE(isfinite(body.recorded_at), false)
                     AND COALESCE(isfinite(body.published_at), false)
                     AND COALESCE(isfinite(body.deleted_at), true)) AS finite_timestamps
             FROM xshield.calibration_reports report
             LEFT JOIN xshield.calibration_report_artifacts body
               ON body.tenant_id = report.tenant_id AND body.site_id = report.site_id
              AND body.report_id = report.report_id
              AND body.artifact_id = report.report_artifact_id
             LEFT JOIN xshield.audit_outbox completed
               ON completed.event_id = report.completion_event_id
             LEFT JOIN xshield.audit_outbox reported
               ON reported.event_id = report.reported_event_id
             LEFT JOIN xshield.calibration_read_capabilities capability
               ON capability.tenant_id = report.tenant_id
              AND capability.site_id = report.site_id
              AND capability.capability_id = report.capability_id
             LEFT JOIN xshield.audit_outbox purge_requested
               ON purge_requested.event_id = body.purge_requested_event_id
             LEFT JOIN xshield.audit_outbox purge_completed
               ON purge_completed.event_id = body.purge_completed_event_id
             WHERE report.tenant_id = $1 AND report.site_id = $2 AND report.report_id = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(report.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let inspection = row
            .as_ref()
            .map(decode)
            .transpose()
            .map_err(|error| match error {
                StoreError::Database(_) => {
                    StoreError::CorruptData("calibration_report_inspection_row")
                }
                other => other,
            });
        tx.rollback().await?;
        inspection
    }
}

fn decode(row: &PgRow) -> Result<CalibrationReportInspection, StoreError> {
    if row.try_get::<Option<bool>, _>("finite_timestamps")? != Some(true) {
        return Err(StoreError::CorruptData(
            "calibration_report_inspection_time",
        ));
    }
    let inspection = CalibrationReportInspection {
        as_of: time(row, "as_of")?,
        report_id: report_id(row, "report_id")?,
        report_artifact_id: artifact_id(row, "report_artifact_id")?,
        reported_at: time(row, "reported_at")?,
        completed_at: time(row, "completed_at")?,
        reported_event_id: event_id(row, "reported_event_id")?,
        body_expires_at: time(row, "expires_at")?,
        approval_ref: ApprovalRef::parse(row.try_get::<&str, _>("approval_ref")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_approval_ref"))?,
        dataset_revision: DatasetRevision::parse(row.try_get::<&str, _>("dataset_revision")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_dataset_revision"))?,
        label_revision: LabelRevision::parse(row.try_get::<&str, _>("label_revision")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_label_revision"))?,
        task_revision: TaskRevision::parse(row.try_get::<&str, _>("task_revision")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_task_revision"))?,
        threshold_policy_revision: ThresholdPolicyRevision::parse(
            row.try_get::<&str, _>("threshold_policy_revision")?,
        )
        .map_err(|_| StoreError::CorruptData("calibration_report_threshold_revision"))?,
        mapping_revision: MappingRevision::parse(row.try_get::<&str, _>("mapping_revision")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_mapping_revision"))?,
        evaluation_manifest_artifact_id: artifact_id(row, "evaluation_manifest_artifact_id")?,
        training_manifest_artifact_id: artifact_id(row, "training_manifest_artifact_id")?,
        calibration_manifest_artifact_id: artifact_id(row, "calibration_manifest_artifact_id")?,
        label_manifest_artifact_id: artifact_id(row, "label_manifest_artifact_id")?,
        provider: ProviderId::parse(row.try_get::<&str, _>("provider")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_provider"))?,
        provider_model_id: provider_model_id(row.try_get("provider_model_id")?)?,
        model_revision: ModelRevision::parse(row.try_get::<&str, _>("model_revision")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_model_revision"))?,
        prompt_revision: PromptRevision::parse(row.try_get::<&str, _>("prompt_revision")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_prompt_revision"))?,
        resolved_model_revision: row
            .try_get::<Option<&str>, _>("resolved_model_revision")?
            .map(ModelRevision::parse)
            .transpose()
            .map_err(|_| StoreError::CorruptData("calibration_report_resolved_model_revision"))?,
        lineage_review_id: row
            .try_get::<Option<&str>, _>("lineage_review_id")?
            .map(CalibrationLineageReviewId::parse)
            .transpose()
            .map_err(|_| StoreError::CorruptData("calibration_report_lineage_review_id"))?,
        body_status: body_status(row)?,
    };
    validate_linkage(row, &inspection)?;
    validate_reported_envelope(row, &inspection)?;
    Ok(inspection)
}

fn validate_linkage(
    row: &PgRow,
    inspection: &CalibrationReportInspection,
) -> Result<(), StoreError> {
    let report_id = inspection.report_id.as_str();
    let report_tenant_id = row.try_get::<&str, _>("report_tenant_id")?;
    let report_site_id = row.try_get::<&str, _>("report_site_id")?;
    let capability_id = row.try_get::<&str, _>("capability_id")?;
    let body_report_id = row.try_get::<Option<&str>, _>("body_report_id")?;
    let body_artifact_id = row.try_get::<Option<&str>, _>("body_artifact_id")?;
    let capability_linked_id = row.try_get::<Option<&str>, _>("capability_linked_id")?;
    let capability_review = row.try_get::<Option<&str>, _>("capability_lineage_review_id")?;
    validate_artifact_separation(inspection)?;
    let timestamps_match = time(row, "recorded_at")? == inspection.reported_at
        && time(row, "published_at")? == inspection.reported_at
        && inspection.completed_at == inspection.reported_at;
    let completed_valid = row
        .try_get::<Option<&str>, _>("completed_event_id")?
        .is_some()
        && row
            .try_get::<Option<&str>, _>("completed_tenant_id")?
            .is_some()
        && row
            .try_get::<Option<&str>, _>("completed_site_id")?
            .is_some()
        && row
            .try_get::<Option<&str>, _>("completed_aggregate_ref")?
            .is_some()
        && row
            .try_get::<Option<&str>, _>("completed_event_type")?
            .is_some();
    let reported_valid = row
        .try_get::<Option<&str>, _>("reported_event_id")?
        .is_some()
        && row
            .try_get::<Option<&str>, _>("reported_tenant_id")?
            .is_some()
        && row
            .try_get::<Option<&str>, _>("reported_site_id")?
            .is_some()
        && row
            .try_get::<Option<&str>, _>("reported_aggregate_ref")?
            .is_some()
        && row
            .try_get::<Option<&str>, _>("reported_event_type")?
            .is_some();
    if body_report_id != Some(report_id)
        || body_artifact_id != Some(inspection.report_artifact_id.as_str())
        || !timestamps_match
        || !completed_valid
        || !reported_valid
        || row.try_get::<&str, _>("completed_event_type")? != "calibration.read_batch.completed"
        || row.try_get::<&str, _>("reported_event_type")? != "calibration.reported"
        || row.try_get::<&str, _>("completed_aggregate_ref")? != capability_id
        || row.try_get::<&str, _>("reported_aggregate_ref")? != report_id
        || row.try_get::<&str, _>("completed_tenant_id")?
            != row.try_get::<&str, _>("reported_tenant_id")?
        || row.try_get::<&str, _>("completed_site_id")?
            != row.try_get::<&str, _>("reported_site_id")?
        || row.try_get::<&str, _>("completed_tenant_id")? != report_tenant_id
        || row.try_get::<&str, _>("completed_site_id")? != report_site_id
        || capability_linked_id != Some(capability_id)
        || capability_review
            != inspection
                .lineage_review_id
                .as_ref()
                .map(CalibrationLineageReviewId::as_str)
    {
        return Err(StoreError::CorruptData(
            "calibration_report_inspection_linkage",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportedEnvelope {
    schema_version: u8,
    event_id: String,
    event_type: String,
    tenant_id: String,
    site_id: String,
    request_id: Option<String>,
    trace_id: String,
    span_id: String,
    producer_id: String,
    producer_boot_id: String,
    producer_seq: u64,
    request_seq: u64,
    occurred_at: String,
    observed_at: String,
    policy_revision: String,
    example_only: bool,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    payload: ReportedPayload,
    sensitivity: String,
    integrity: PendingIntegrity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingIntegrity {
    state: String,
    previous_hash: Option<String>,
    event_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportedPayload {
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
    resolved_model_revision: Option<String>,
}

/// Closed representation of a report-body retention event.
///
/// A tombstone is meaningful only when its restricted maintenance fact is
/// complete. Parsing the whole envelope prevents an otherwise valid relation
/// row from accepting an unreviewed event shape into this read path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionEnvelope {
    schema_version: u8,
    event_id: String,
    event_type: String,
    tenant_id: String,
    site_id: String,
    request_id: Option<String>,
    trace_id: String,
    span_id: String,
    producer_id: String,
    producer_boot_id: String,
    producer_seq: u64,
    request_seq: u64,
    occurred_at: String,
    observed_at: String,
    policy_revision: String,
    example_only: bool,
    evidence_refs: Vec<String>,
    cause_event_ids: Vec<String>,
    payload: RetentionPayload,
    sensitivity: String,
    integrity: PendingIntegrity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPayload {
    stage: String,
    outcome: String,
    reason_code: String,
    proof_kind: String,
    confidence: Option<f64>,
    confidence_status: String,
    report_id: String,
    report_artifact_id: String,
    expires_at: String,
    retained_metadata: bool,
}

/// Checks that the read projection is exactly the immutable report event
/// snapshot. A live row may satisfy column constraints while still no longer
/// describing the fact that was atomically published, so type validation alone
/// is not enough for this restricted investigation surface.
fn validate_reported_envelope(
    row: &PgRow,
    inspection: &CalibrationReportInspection,
) -> Result<(), StoreError> {
    let envelope: ReportedEnvelope =
        serde_json::from_value(row.try_get::<Value, _>("reported_envelope")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_reported_envelope"))?;
    let trace_id = inspection
        .report_id
        .as_str()
        .strip_prefix("calr_")
        .ok_or(StoreError::CorruptData(
            "calibration_report_inspection_trace",
        ))?
        .replace('-', "");
    let report_time = inspection
        .reported_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let payload = &envelope.payload;
    let valid = envelope.schema_version == 3
        && envelope.event_id == inspection.reported_event_id.as_str()
        && envelope.event_type == "calibration.reported"
        && envelope.tenant_id == row.try_get::<&str, _>("report_tenant_id")?
        && envelope.site_id == row.try_get::<&str, _>("report_site_id")?
        && envelope.request_id.is_none()
        && envelope.trace_id == trace_id
        && envelope.span_id == trace_id[..16]
        && envelope.producer_id == "calibration-evaluator"
        && envelope.producer_boot_id == inspection.reported_event_id.as_str()
        && envelope.producer_seq == 1
        && envelope.request_seq == 1
        && envelope.occurred_at == report_time
        && envelope.observed_at == report_time
        && envelope.policy_revision == "calibration-v1"
        && !envelope.example_only
        && envelope.evidence_refs.len() == 1
        && envelope
            .evidence_refs
            .first()
            .is_some_and(|reference| reference == inspection.report_artifact_id.as_str())
        && envelope.cause_event_ids.is_empty()
        && envelope.sensitivity == "RESTRICTED"
        && envelope.integrity.state == "pending"
        && envelope.integrity.previous_hash.is_none()
        && envelope.integrity.event_hash.is_none()
        && payload.stage == "calibration_report"
        && payload.outcome == "PASS"
        && payload.reason_code == "CALIBRATION_REPORTED"
        && payload.report_id == inspection.report_id.as_str()
        && payload.report_artifact_id == inspection.report_artifact_id.as_str()
        && payload.approval_ref == inspection.approval_ref.as_str()
        && payload.dataset_revision == inspection.dataset_revision.as_str()
        && payload.label_revision == inspection.label_revision.as_str()
        && payload.task_revision == inspection.task_revision.as_str()
        && payload.threshold_policy_revision == inspection.threshold_policy_revision.as_str()
        && payload.mapping_revision == inspection.mapping_revision.as_str()
        && payload.evaluation_manifest_artifact_id
            == inspection.evaluation_manifest_artifact_id.as_str()
        && payload.training_manifest_artifact_id
            == inspection.training_manifest_artifact_id.as_str()
        && payload.calibration_manifest_artifact_id
            == inspection.calibration_manifest_artifact_id.as_str()
        && payload.label_manifest_artifact_id == inspection.label_manifest_artifact_id.as_str()
        && payload.provider == inspection.provider.as_str()
        && payload.provider_model_id == inspection.provider_model_id
        && payload.model_revision == inspection.model_revision.as_str()
        && payload.prompt_revision == inspection.prompt_revision.as_str()
        && payload.resolved_model_revision.as_deref()
            == inspection
                .resolved_model_revision
                .as_ref()
                .map(ModelRevision::as_str);
    if valid {
        Ok(())
    } else {
        Err(StoreError::CorruptData(
            "calibration_report_inspection_reported_envelope",
        ))
    }
}

/// Rejects a damaged projection that aliases the dedicated report artifact to
/// a frozen partition manifest. The database constraint protects new writes,
/// but inspection must not turn a restored or manually damaged row into a
/// trusted metadata response.
fn validate_artifact_separation(
    inspection: &CalibrationReportInspection,
) -> Result<(), StoreError> {
    let artifacts = [
        &inspection.report_artifact_id,
        &inspection.evaluation_manifest_artifact_id,
        &inspection.training_manifest_artifact_id,
        &inspection.calibration_manifest_artifact_id,
        &inspection.label_manifest_artifact_id,
    ];
    for (index, artifact) in artifacts.iter().enumerate() {
        if artifacts[index + 1..].contains(artifact) {
            return Err(StoreError::CorruptData(
                "calibration_report_inspection_artifact_alias",
            ));
        }
    }
    Ok(())
}

fn body_status(row: &PgRow) -> Result<CalibrationReportBodyStatus, StoreError> {
    let status = match row.try_get::<Option<&str>, _>("retention_status")? {
        Some("active") => CalibrationReportBodyStatus::Active,
        Some("deleted") => CalibrationReportBodyStatus::Deleted,
        _ => return Err(StoreError::CorruptData("calibration_report_body_status")),
    };
    let requested = row.try_get::<Option<&str>, _>("purge_requested_event_id")?;
    let completed = row.try_get::<Option<&str>, _>("purge_completed_event_id")?;
    let deleted_at = row.try_get::<Option<DateTime<Utc>>, _>("deleted_at")?;
    let report_id = report_id(row, "report_id")?;
    let tenant_id = row.try_get::<&str, _>("report_tenant_id")?;
    let site_id = row.try_get::<&str, _>("report_site_id")?;
    validate_retention_event(
        row,
        requested,
        "purge_requested",
        "calibration.report_retention.purge_requested",
        tenant_id,
        site_id,
        &report_id,
        None,
    )?;
    validate_retention_event(
        row,
        completed,
        "purge_completed",
        "calibration.report_retention.deleted",
        tenant_id,
        site_id,
        &report_id,
        requested,
    )?;
    let valid = match status {
        CalibrationReportBodyStatus::Active => completed.is_none() && deleted_at.is_none(),
        CalibrationReportBodyStatus::Deleted => {
            requested.is_some() && completed.is_some() && deleted_at.is_some()
        }
    };
    if valid {
        Ok(status)
    } else {
        Err(StoreError::CorruptData("calibration_report_body_retention"))
    }
}

/// Verifies that retention state points to the exact restricted outbox fact.
///
/// The report-body table intentionally has no foreign key to maintenance
/// events: retention retries create the event and tombstone in separate
/// recoverable phases. Inspection therefore authenticates the link before it
/// exposes a body-state observation.
#[allow(clippy::too_many_arguments)]
fn validate_retention_event(
    row: &PgRow,
    stored_event_id: Option<&str>,
    prefix: &str,
    expected_type: &str,
    tenant_id: &str,
    site_id: &str,
    report_id: &CalibrationReportId,
    expected_cause: Option<&str>,
) -> Result<(), StoreError> {
    let outbox_event_id =
        row.try_get::<Option<&str>, _>(format!("{prefix}_outbox_event_id").as_str())?;
    let outbox_tenant_id =
        row.try_get::<Option<&str>, _>(format!("{prefix}_tenant_id").as_str())?;
    let outbox_site_id = row.try_get::<Option<&str>, _>(format!("{prefix}_site_id").as_str())?;
    let outbox_aggregate_ref =
        row.try_get::<Option<&str>, _>(format!("{prefix}_aggregate_ref").as_str())?;
    let outbox_event_type =
        row.try_get::<Option<&str>, _>(format!("{prefix}_event_type").as_str())?;
    let outbox_envelope = row.try_get::<Option<Value>, _>(format!("{prefix}_envelope").as_str())?;
    let linked = matches!(
        (
            outbox_event_id,
            outbox_tenant_id,
            outbox_site_id,
            outbox_aggregate_ref,
            outbox_event_type,
        ),
        (Some(event_id), Some(event_tenant), Some(event_site), Some(aggregate), Some(event_type))
            if event_tenant == tenant_id
                && event_site == site_id
                && aggregate == report_id.as_str()
                && event_type == expected_type
                && EventId::parse(event_id).is_ok()
    );
    if !matches!(prefix, "purge_requested" | "purge_completed") {
        return Err(StoreError::CorruptData(
            "calibration_report_body_retention_event",
        ));
    }
    let envelope_valid = retention_envelope_valid(
        row,
        outbox_envelope.as_ref(),
        outbox_event_id,
        prefix,
        expected_type,
        tenant_id,
        site_id,
        report_id,
        expected_cause,
    );
    match stored_event_id {
        Some(stored)
            if EventId::parse(stored).is_ok()
                && outbox_event_id == Some(stored)
                && linked
                && envelope_valid =>
        {
            Ok(())
        }
        None if outbox_event_id.is_none()
            && outbox_tenant_id.is_none()
            && outbox_site_id.is_none()
            && outbox_aggregate_ref.is_none()
            && outbox_event_type.is_none()
            && outbox_envelope.is_none() =>
        {
            Ok(())
        }
        _ => Err(StoreError::CorruptData(
            "calibration_report_body_retention_event",
        )),
    }
}

/// Validates the closed maintenance event before a retention state becomes
/// visible. The body table records only event IDs, so this also binds the
/// event payload's artifact and expiry to the retained row.
#[allow(clippy::too_many_arguments)]
fn retention_envelope_valid(
    row: &PgRow,
    envelope: Option<&Value>,
    event_id: Option<&str>,
    prefix: &str,
    expected_type: &str,
    tenant_id: &str,
    site_id: &str,
    report_id: &CalibrationReportId,
    expected_cause: Option<&str>,
) -> bool {
    let Some(envelope) = envelope else {
        return false;
    };
    let Ok(envelope) = serde_json::from_value::<RetentionEnvelope>(envelope.clone()) else {
        return false;
    };
    let artifact_id = row.try_get::<&str, _>("body_artifact_id").ok();
    let trace_id = report_id
        .as_str()
        .strip_prefix("calr_")
        .map(|value| value.replace('-', ""));
    let expires_at = time(row, "expires_at")
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true))
        .ok();
    let canonical_boot_id = Uuid::parse_str(&envelope.producer_boot_id)
        .ok()
        .filter(|boot| boot.get_version() == Some(Version::SortRand))
        .map(|boot| boot.hyphenated().to_string());
    let occurred_at = DateTime::parse_from_rfc3339(&envelope.occurred_at)
        .ok()
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Millis, true));
    let payload = &envelope.payload;
    envelope.schema_version == 3
        && envelope.event_id == event_id.unwrap_or_default()
        && envelope.event_type == expected_type
        && envelope.tenant_id == tenant_id
        && envelope.site_id == site_id
        && envelope.request_id.is_none()
        && trace_id.as_deref() == Some(envelope.trace_id.as_str())
        && envelope.trace_id.get(..16) == Some(envelope.span_id.as_str())
        && envelope.producer_id == "calibration-report-retention"
        && canonical_boot_id.as_deref() == Some(envelope.producer_boot_id.as_str())
        && envelope.producer_seq == 1
        && envelope.request_seq == 1
        && occurred_at.as_deref() == Some(envelope.occurred_at.as_str())
        && envelope.observed_at == envelope.occurred_at
        && envelope.policy_revision == "calibration-retention-v1"
        && !envelope.example_only
        && envelope.evidence_refs.as_slice() == [artifact_id.unwrap_or_default()]
        && envelope.cause_event_ids.as_slice() == expected_cause.into_iter().collect::<Vec<_>>()
        && envelope.sensitivity == "RESTRICTED"
        && envelope.integrity.state == "pending"
        && envelope.integrity.previous_hash.is_none()
        && envelope.integrity.event_hash.is_none()
        && payload.stage == "calibration_report_retention"
        && payload.outcome == "PASS"
        && retention_reason_valid(prefix, &payload.reason_code)
        && payload.proof_kind == "deterministic"
        && payload.confidence.is_none()
        && payload.confidence_status == "not_applicable"
        && payload.report_id == report_id.as_str()
        && payload.report_artifact_id == artifact_id.unwrap_or_default()
        && expires_at.as_deref() == Some(payload.expires_at.as_str())
        && payload.retained_metadata
}

fn retention_reason_valid(prefix: &str, reason: &str) -> bool {
    matches!(
        (prefix, reason),
        ("purge_requested", "CALIBRATION_REPORT_PURGE_REQUESTED")
            | (
                "purge_completed",
                "CALIBRATION_REPORT_DELETED" | "CALIBRATION_REPORT_DELETE_ALREADY_ABSENT"
            )
    )
}

fn report_id(row: &PgRow, field: &'static str) -> Result<CalibrationReportId, StoreError> {
    CalibrationReportId::parse(row.try_get::<&str, _>(field)?)
        .map_err(|_| StoreError::CorruptData(field))
}

fn artifact_id(row: &PgRow, field: &'static str) -> Result<ArtifactId, StoreError> {
    ArtifactId::parse(row.try_get::<&str, _>(field)?).map_err(|_| StoreError::CorruptData(field))
}

fn event_id(row: &PgRow, field: &'static str) -> Result<EventId, StoreError> {
    EventId::parse(row.try_get::<&str, _>(field)?).map_err(|_| StoreError::CorruptData(field))
}

fn time(row: &PgRow, field: &'static str) -> Result<DateTime<Utc>, StoreError> {
    let value = row.try_get::<DateTime<Utc>, _>(field)?;
    if value.timestamp() < 0 {
        return Err(StoreError::CorruptData(field));
    }
    Ok(value)
}

fn provider_model_id(value: &str) -> Result<String, StoreError> {
    let valid = (1..=128).contains(&value.len())
        && value == value.trim()
        && !value.chars().any(char::is_control);
    if valid {
        Ok(value.to_owned())
    } else {
        Err(StoreError::CorruptData(
            "calibration_report_provider_model_id",
        ))
    }
}
