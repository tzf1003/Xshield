//! Atomic persistence for one completed offline calibration report.
//!
//! The report body is produced and authenticated outside this adapter. This
//! module persists only its typed identity and the authenticated manifest
//! metadata. A single `PostgreSQL` transaction binds the report artifact,
//! report projection, capability/lease terminal states, and both restricted
//! outbox facts.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use openssl::sha::sha256;
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};
use std::collections::BTreeMap;
use xshield_core::{
    calibration::{
        publication::{
            CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE, CALIBRATION_REPORT_ARTIFACT_KIND,
            CalibrationReportArtifact, CalibrationReportPublication,
        },
        read_capability::CalibrationEvidenceBatchCompletion,
    },
    domain::{
        ArtifactId, CalibrationReadCapabilityId, CalibrationReportId, EventId, ModelRevision,
    },
};
use xshield_evidence::{
    CALIBRATION_REPORT_CANONICAL_BODY_ENCODING, EvidenceClassification, EvidenceFidelity,
};

const COMPLETION_EVENT_TYPE: &str = "calibration.read_batch.completed";
const COMPLETION_EVENT_REASON: &str = "CALIBRATION_READ_BATCH_COMPLETED";
const REPORT_EVENT_TYPE: &str = "calibration.reported";
const REPORT_EVENT_REASON: &str = "CALIBRATION_REPORTED";

/// A fully cross-checked report commit command.
pub struct CalibrationReportCommit<'command, 'capability> {
    completion: &'command CalibrationEvidenceBatchCompletion<'capability>,
    publication: &'command CalibrationReportPublication,
    manifest: &'command xshield_evidence::AttestedCalibrationReportManifest,
    runner_id: &'command str,
    completion_event_id: &'command EventId,
    report_event_id: &'command EventId,
}

impl<'command, 'capability> CalibrationReportCommit<'command, 'capability> {
    /// Validates all report, completion, publication, and manifest bindings.
    ///
    /// This constructor performs no I/O. It reconstructs the immutable
    /// publication and protected report from the completion proof, then checks
    /// a fresh vault attestation's fixed report-artifact shape. The database
    /// clock and durable capability/lease state are checked by the commit
    /// method.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when any binding, scope, event,
    /// runner, or fixed manifest property is inconsistent.
    pub fn new(
        completion: &'command CalibrationEvidenceBatchCompletion<'capability>,
        report: &'command CalibrationReportArtifact,
        publication: &'command CalibrationReportPublication,
        manifest: &'command xshield_evidence::AttestedCalibrationReportManifest,
        runner_id: &'command str,
        completion_event_id: &'command EventId,
        report_event_id: &'command EventId,
    ) -> Result<Self, StoreError> {
        if !valid_text(runner_id, 128)
            || completion_event_id == report_event_id
            || !valid_event_id(completion_event_id)
            || !valid_event_id(report_event_id)
        {
            return Err(StoreError::InvalidCommand);
        }

        let capability = completion.session().capability();
        let manifest_value = manifest.manifest();
        let report_artifact_id = ArtifactId::parse(manifest_value.artifact_id.clone())
            .map_err(|_| StoreError::InvalidCommand)?;
        let rebuilt_publication = CalibrationReportPublication::new(
            publication.report_id().clone(),
            report_artifact_id.clone(),
            completion.report(),
        )
        .map_err(|_| StoreError::InvalidCommand)?;
        if rebuilt_publication != *publication
            || report.report_id() != publication.report_id()
            || report.report_artifact_id() != publication.report_artifact_id()
        {
            return Err(StoreError::InvalidCommand);
        }
        let rebuilt_report =
            CalibrationReportArtifact::from_evaluation(publication, completion.report())
                .map_err(|_| StoreError::InvalidCommand)?;
        if rebuilt_report != *report {
            return Err(StoreError::InvalidCommand);
        }
        if manifest_value.tenant_id != capability.tenant_id().as_str()
            || manifest_value.site_id != capability.site_id().as_str()
            || report_artifact_id != *publication.report_artifact_id()
            || manifest_value.report_id != publication.report_id().as_str()
            || manifest_value.schema_version
                != xshield_evidence::CALIBRATION_REPORT_EVIDENCE_MANIFEST_SCHEMA_VERSION
            || manifest_value.kind != CALIBRATION_REPORT_ARTIFACT_KIND
            || manifest_value.content_type != CALIBRATION_REPORT_ARTIFACT_CONTENT_TYPE
            || manifest_value.canonical_body_encoding != CALIBRATION_REPORT_CANONICAL_BODY_ENCODING
            || manifest_value.capture_status != "complete"
            || manifest_value.fidelity != EvidenceFidelity::EntityExact
            || manifest_value.classification != EvidenceClassification::Restricted
            || manifest_value.storage.profile != "aead_envelope_v1"
            || manifest_value.storage.locator != format!("{report_artifact_id}.xev")
            || manifest_value.storage.key_ref.is_none()
            || manifest_value.integrity.algorithm != "sha256_ciphertext"
            || manifest_value.bytes_observed != manifest_value.bytes_saved
        {
            return Err(StoreError::InvalidCommand);
        }
        manifest_value
            .validate_catalog_structure()
            .map_err(|_| StoreError::InvalidCommand)?;
        Ok(Self {
            completion,
            publication,
            manifest,
            runner_id,
            completion_event_id,
            report_event_id,
        })
    }
}

/// Durable identity returned after a report commit or exact retry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationReportCommitRecord {
    report_id: CalibrationReportId,
    report_artifact_id: ArtifactId,
    capability_id: CalibrationReadCapabilityId,
    completion_event_id: EventId,
    report_event_id: EventId,
    completed_at: DateTime<Utc>,
    reported_at: DateTime<Utc>,
}

impl CalibrationReportCommitRecord {
    /// Returns the durable report identity.
    #[must_use]
    pub const fn report_id(&self) -> &CalibrationReportId {
        &self.report_id
    }

    /// Returns the protected report artifact identity.
    #[must_use]
    pub const fn report_artifact_id(&self) -> &ArtifactId {
        &self.report_artifact_id
    }

    /// Returns the consumed capability identity.
    #[must_use]
    pub const fn capability_id(&self) -> &CalibrationReadCapabilityId {
        &self.capability_id
    }

    /// Returns the content-free batch completion event identity.
    #[must_use]
    pub const fn completion_event_id(&self) -> &EventId {
        &self.completion_event_id
    }

    /// Returns the report publication event identity.
    #[must_use]
    pub const fn report_event_id(&self) -> &EventId {
        &self.report_event_id
    }

    /// Returns the database-frozen completion time.
    #[must_use]
    pub const fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }

    /// Returns the database-frozen report time.
    #[must_use]
    pub const fn reported_at(&self) -> DateTime<Utc> {
        self.reported_at
    }
}

/// Result of one atomic calibration-report commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalibrationReportCommitOutcome {
    /// The report, terminal states, and both outbox facts were inserted.
    Committed(CalibrationReportCommitRecord),
    /// The exact durable report commit was already present.
    Existing(CalibrationReportCommitRecord),
    /// An identity or durable binding belongs to different input.
    Conflict,
    /// The capability, lease, runner, manifest, or source catalog is unavailable.
    Unavailable,
}

impl CalibrationReportCommitOutcome {
    /// Returns the stable terminal reason code for structured audit callers.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Committed(_) => REPORT_EVENT_REASON,
            Self::Existing(_) => "CALIBRATION_REPORT_ALREADY_COMMITTED",
            Self::Conflict => "CALIBRATION_REPORT_COMMIT_CONFLICT",
            Self::Unavailable => "CALIBRATION_REPORT_COMMIT_UNAVAILABLE",
        }
    }
}

impl PostgresIdentityStore {
    /// Atomically persists a report artifact projection and consumes its batch.
    ///
    /// `PostgreSQL`'s `clock_timestamp()` is used for all commit timestamps. A
    /// retry after an unknown result returns [`CalibrationReportCommitOutcome::Existing`]
    /// only when the report row, authenticated metadata, lease token digest,
    /// runner, event IDs, and both reconstructed envelopes are exact matches.
    /// A consumed capability from the legacy completion path is never used to
    /// authorize a new report commit.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database or corrupt durable-state failures.
    #[allow(clippy::too_many_lines)]
    pub async fn complete_and_publish_calibration_report(
        &self,
        command: CalibrationReportCommit<'_, '_>,
    ) -> Result<CalibrationReportCommitOutcome, StoreError> {
        let capability = command.completion.session().capability();
        let mut transaction = self.pool.begin().await?;
        set_report_timeouts(&mut transaction).await?;
        let Some(header) = find_report_capability(&mut transaction, capability).await? else {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Unavailable);
        };
        let status: &str = header.try_get("status")?;
        if status == "consumed" {
            let result = existing_report_commit(&mut transaction, &header, &command).await?;
            transaction.rollback().await?;
            return Ok(result);
        }
        if status != "leased"
            || !report_header_matches(&header, capability)?
            || !report_members_match_live_catalog(&mut transaction, &header, capability).await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Unavailable);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        if now < unix_timestamp(capability.not_before())?
            || now >= unix_timestamp(capability.expires_at())?
            || !report_manifest_available(command.manifest.manifest(), now)?
            || !report_active_lease_matches(&mut transaction, &header, &command, now).await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Unavailable);
        }
        if report_event_identity_is_used(
            &mut transaction,
            command.completion_event_id,
            command.report_event_id,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Conflict);
        }

        let timestamp = date_millis(now);
        let artifact_inserted =
            insert_report_artifact(&mut transaction, command.manifest.manifest(), timestamp)
                .await?;
        if !artifact_inserted {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Conflict);
        }
        let report_inserted = insert_report_row(&mut transaction, &command, timestamp).await?;
        if !report_inserted {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Conflict);
        }
        let completion_envelope =
            completion_event(command.completion_event_id, capability, timestamp)?;
        let report_envelope = report_event(
            command.report_event_id,
            capability,
            command.publication,
            timestamp,
        )?;
        let completion_outbox_inserted = insert_report_outbox(
            &mut transaction,
            command.completion_event_id,
            capability.tenant_id().as_str(),
            capability.site_id().as_str(),
            capability.capability_id().as_str(),
            COMPLETION_EVENT_TYPE,
            &completion_envelope,
        )
        .await?;
        let report_outbox_inserted = insert_report_outbox(
            &mut transaction,
            command.report_event_id,
            capability.tenant_id().as_str(),
            capability.site_id().as_str(),
            command.publication.report_id().as_str(),
            REPORT_EVENT_TYPE,
            &report_envelope,
        )
        .await?;
        if !completion_outbox_inserted || !report_outbox_inserted {
            transaction.rollback().await?;
            return Ok(CalibrationReportCommitOutcome::Conflict);
        }
        consume_report_lease_and_header(&mut transaction, &header, &command, timestamp).await?;
        transaction.commit().await?;
        Ok(CalibrationReportCommitOutcome::Committed(
            CalibrationReportCommitRecord {
                report_id: command.publication.report_id().clone(),
                report_artifact_id: command.publication.report_artifact_id().clone(),
                capability_id: capability.capability_id().clone(),
                completion_event_id: command.completion_event_id.clone(),
                report_event_id: command.report_event_id.clone(),
                completed_at: timestamp,
                reported_at: timestamp,
            },
        ))
    }
}

async fn set_report_timeouts(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut **connection)
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **connection)
        .await?;
    Ok(())
}

async fn find_report_capability(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    capability: &xshield_core::calibration::read_capability::CalibrationEvidenceReadCapability,
) -> Result<Option<PgRow>, StoreError> {
    Ok(sqlx::query(
        "SELECT * FROM xshield.calibration_read_capabilities
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .fetch_optional(&mut **connection)
    .await?)
}

fn report_header_matches(
    row: &PgRow,
    capability: &xshield_core::calibration::read_capability::CalibrationEvidenceReadCapability,
) -> Result<bool, StoreError> {
    let provenance = capability.provenance();
    let model = provenance.model();
    Ok(
        row.try_get::<&str, _>("tenant_id")? == capability.tenant_id().as_str()
            && row.try_get::<&str, _>("site_id")? == capability.site_id().as_str()
            && row.try_get::<&str, _>("capability_id")? == capability.capability_id().as_str()
            && row.try_get::<&str, _>("approval_ref")? == provenance.approval_ref().as_str()
            && row.try_get::<&str, _>("dataset_revision")?
                == provenance.dataset_revision().as_str()
            && row.try_get::<&str, _>("label_revision")? == provenance.label_revision().as_str()
            && row.try_get::<&str, _>("task_revision")? == provenance.task_revision().as_str()
            && row.try_get::<&str, _>("threshold_policy_revision")?
                == provenance.threshold_policy_revision().as_str()
            && row.try_get::<&str, _>("mapping_revision")?
                == provenance.mapping_revision().as_str()
            && row.try_get::<&str, _>("provider")? == model.provider().as_str()
            && row.try_get::<&str, _>("provider_model_id")? == model.provider_model_id()
            && row.try_get::<&str, _>("model_revision")? == model.model_revision().as_str()
            && row.try_get::<&str, _>("prompt_revision")? == model.prompt_revision().as_str()
            && row.try_get::<Option<&str>, _>("resolved_model_revision")?
                == model.resolved_model_revision().map(ModelRevision::as_str)
            && row.try_get::<DateTime<Utc>, _>("not_before")?
                == unix_timestamp(capability.not_before())?
            && row.try_get::<DateTime<Utc>, _>("expires_at")?
                == unix_timestamp(capability.expires_at())?
            && row.try_get::<i64, _>("max_total_bytes")?
                == i64::try_from(capability.max_total_bytes())
                    .map_err(|_| StoreError::NumericRange("max_total_bytes"))?
            && row.try_get::<i32, _>("sample_count")?
                == i32::try_from(capability.sources().len())
                    .map_err(|_| StoreError::NumericRange("sample_count"))?
            && row.try_get::<i32, _>("member_count")?
                == i32::try_from(capability.evidence_refs().len())
                    .map_err(|_| StoreError::NumericRange("member_count"))?,
    )
}

#[derive(Clone)]
struct ReportFrozenMember {
    role: String,
    sample_index: Option<i32>,
    artifact_id: String,
    bytes_saved: u64,
    integrity_digest: String,
    kind: String,
    content_type: String,
    fidelity: String,
    classification: String,
    expires_at: DateTime<Utc>,
    catalog_event_id: String,
}

#[allow(clippy::too_many_lines)]
async fn report_members_match_live_catalog(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    header: &PgRow,
    capability: &xshield_core::calibration::read_capability::CalibrationEvidenceReadCapability,
) -> Result<bool, StoreError> {
    let rows = sqlx::query(
        "SELECT member.role, member.sample_index, member.artifact_id,
                member.catalog_bytes_saved, member.catalog_integrity_digest,
                member.catalog_kind, member.catalog_content_type,
                member.catalog_fidelity, member.catalog_classification,
                member.catalog_expires_at, member.catalog_event_id,
                catalog.bytes_saved AS live_bytes_saved,
                catalog.integrity_digest AS live_integrity_digest,
                catalog.kind AS live_kind, catalog.content_type AS live_content_type,
                catalog.fidelity AS live_fidelity, catalog.classification AS live_classification,
                catalog.expires_at AS live_expires_at, catalog.catalog_event_id AS live_event_id,
                catalog.status AS live_status, catalog.deleted_at AS live_deleted_at,
                catalog.purge_requested_event_id AS live_purge_requested_event_id
         FROM xshield.calibration_read_capability_members member
         JOIN xshield.artifact_catalog catalog
           ON catalog.tenant_id=member.tenant_id AND catalog.site_id=member.site_id
          AND catalog.artifact_id=member.artifact_id
         WHERE member.tenant_id=$1 AND member.site_id=$2 AND member.capability_id=$3
         ORDER BY member.artifact_id FOR UPDATE OF member, catalog",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .fetch_all(&mut **connection)
    .await?;
    if rows.len() != capability.evidence_refs().len() {
        return Ok(false);
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **connection)
        .await?;
    let end = unix_timestamp(capability.expires_at())?;
    let mut members = BTreeMap::new();
    let mut total = 0_u64;
    for row in rows {
        let member = ReportFrozenMember {
            role: row.try_get("role")?,
            sample_index: row.try_get("sample_index")?,
            artifact_id: row.try_get("artifact_id")?,
            bytes_saved: u64::try_from(row.try_get::<i64, _>("catalog_bytes_saved")?)
                .map_err(|_| StoreError::CorruptData("calibration_catalog_bytes_saved"))?,
            integrity_digest: row.try_get("catalog_integrity_digest")?,
            kind: row.try_get("catalog_kind")?,
            content_type: row.try_get("catalog_content_type")?,
            fidelity: row.try_get("catalog_fidelity")?,
            classification: row.try_get("catalog_classification")?,
            expires_at: row.try_get("catalog_expires_at")?,
            catalog_event_id: row.try_get("catalog_event_id")?,
        };
        let key = (member.role.clone(), member.sample_index);
        if members.insert(key, member.clone()).is_some() {
            return Err(StoreError::CorruptData("duplicate_calibration_member"));
        }
        if row.try_get::<&str, _>("live_status")? != "active"
            || row
                .try_get::<Option<DateTime<Utc>>, _>("live_deleted_at")?
                .is_some()
            || row
                .try_get::<Option<&str>, _>("live_purge_requested_event_id")?
                .is_some()
            || row.try_get::<DateTime<Utc>, _>("live_expires_at")? <= now
            || row.try_get::<DateTime<Utc>, _>("live_expires_at")? < end
            || row.try_get::<i64, _>("live_bytes_saved")?
                != i64::try_from(member.bytes_saved).unwrap_or(-1)
            || row.try_get::<&str, _>("live_integrity_digest")? != member.integrity_digest
            || row.try_get::<&str, _>("live_kind")? != member.kind
            || row.try_get::<&str, _>("live_content_type")? != member.content_type
            || row.try_get::<&str, _>("live_fidelity")? != member.fidelity
            || row.try_get::<&str, _>("live_classification")? != member.classification
            || row.try_get::<DateTime<Utc>, _>("live_expires_at")? != member.expires_at
            || row.try_get::<&str, _>("live_event_id")? != member.catalog_event_id
        {
            return Ok(false);
        }
        total = total
            .checked_add(member.bytes_saved)
            .ok_or(StoreError::NumericRange("calibration_catalog_total"))?;
    }
    let mut ordered = Vec::with_capacity(capability.evidence_refs().len());
    for reference in capability.evidence_refs() {
        let key = (
            reference.role().as_str().to_owned(),
            reference.sample_index().map(i32::from),
        );
        let Some(member) = members.remove(&key) else {
            return Ok(false);
        };
        if member.artifact_id != reference.artifact_id().as_str() {
            return Ok(false);
        }
        ordered.push(member);
    }
    if !members.is_empty()
        || total
            != u64::try_from(header.try_get::<i64, _>("frozen_total_bytes")?)
                .map_err(|_| StoreError::CorruptData("calibration_frozen_total_bytes"))?
        || total > capability.max_total_bytes()
    {
        return Ok(false);
    }
    let persisted_digest: [u8; 32] = header
        .try_get::<Vec<u8>, _>("scope_digest")?
        .try_into()
        .map_err(|_| StoreError::CorruptData("calibration_scope_digest"))?;
    Ok(report_scope_digest(capability, &ordered) == persisted_digest)
}

async fn report_active_lease_matches(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    header: &PgRow,
    command: &CalibrationReportCommit<'_, '_>,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let session = command.completion.session();
    let lease = sqlx::query(
        "SELECT status, runner_id, lease_token_digest, acquired_at, lease_until
         FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4 FOR UPDATE",
    )
    .bind(header.try_get::<&str, _>("tenant_id")?)
    .bind(header.try_get::<&str, _>("site_id")?)
    .bind(header.try_get::<&str, _>("capability_id")?)
    .bind(session.lease().lease_id().as_str())
    .fetch_optional(&mut **connection)
    .await?;
    let Some(lease) = lease else { return Ok(false) };
    let token_digest = sha256(session.lease().token());
    Ok(lease.try_get::<&str, _>("status")? == "active"
        && lease.try_get::<&str, _>("runner_id")? == command.runner_id
        && lease
            .try_get::<Vec<u8>, _>("lease_token_digest")?
            .as_slice()
            == token_digest
        && lease.try_get::<DateTime<Utc>, _>("acquired_at")? <= now
        && lease.try_get::<DateTime<Utc>, _>("lease_until")? > now)
}

async fn consume_report_lease_and_header(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    header: &PgRow,
    command: &CalibrationReportCommit<'_, '_>,
    timestamp: DateTime<Utc>,
) -> Result<(), StoreError> {
    let capability = command.completion.session().capability();
    let token_digest = sha256(command.completion.session().lease().token());
    let lease_changed = sqlx::query(
        "UPDATE xshield.calibration_read_capability_leases
         SET status='completed', completed_at=$6
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
           AND runner_id=$5 AND status='active' AND lease_token_digest=$7",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(command.completion.session().lease().lease_id().as_str())
    .bind(command.runner_id)
    .bind(timestamp)
    .bind(token_digest.as_slice())
    .execute(&mut **connection)
    .await?
    .rows_affected();
    if lease_changed != 1 {
        return Err(StoreError::CorruptData("calibration_report_lease"));
    }
    let header_changed = sqlx::query(
        "UPDATE xshield.calibration_read_capabilities
         SET status='consumed', consumed_at=$4, recovery_required_at=NULL,
             completion_event_id=$5
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND status='leased'",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(timestamp)
    .bind(command.completion_event_id.as_str())
    .execute(&mut **connection)
    .await?
    .rows_affected();
    if header_changed != 1 || header.try_get::<&str, _>("status")? != "leased" {
        return Err(StoreError::CorruptData("calibration_report_header"));
    }
    Ok(())
}

async fn insert_report_artifact(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    manifest: &xshield_evidence::CalibrationReportEvidenceManifest,
    timestamp: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| StoreError::InvalidCommand)?
        .with_timezone(&Utc);
    let bytes = i64::try_from(manifest.bytes_saved)
        .map_err(|_| StoreError::NumericRange("report_artifact_bytes_saved"))?;
    let key_ref = manifest
        .storage
        .key_ref
        .as_deref()
        .ok_or(StoreError::InvalidCommand)?;
    Ok(sqlx::query(
        "INSERT INTO xshield.calibration_report_artifacts (
             tenant_id, site_id, report_id, artifact_id, schema_version, kind,
             content_type, canonical_body_encoding, capture_status, fidelity,
             bytes_observed, bytes_saved, classification, storage_profile,
             storage_locator, key_ref, integrity_algorithm, integrity_digest,
             recorded_at, published_at, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
         ON CONFLICT DO NOTHING",
    )
    .bind(&manifest.tenant_id)
    .bind(&manifest.site_id)
    .bind(&manifest.report_id)
    .bind(&manifest.artifact_id)
    .bind(i16::from(manifest.schema_version))
    .bind(&manifest.kind)
    .bind(&manifest.content_type)
    .bind(&manifest.canonical_body_encoding)
    .bind(&manifest.capture_status)
    .bind("entity_exact")
    .bind(bytes)
    .bind(bytes)
    .bind("RESTRICTED")
    .bind(&manifest.storage.profile)
    .bind(&manifest.storage.locator)
    .bind(key_ref)
    .bind(&manifest.integrity.algorithm)
    .bind(&manifest.integrity.digest)
    .bind(timestamp)
    .bind(timestamp)
    .bind(expires_at)
    .execute(&mut **connection)
    .await?
    .rows_affected()
        == 1)
}

async fn insert_report_row(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    command: &CalibrationReportCommit<'_, '_>,
    timestamp: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let publication = command.publication;
    let provenance = publication;
    let model = publication.model();
    let capability = command.completion.session().capability();
    Ok(sqlx::query(
        "INSERT INTO xshield.calibration_reports (
             tenant_id, site_id, report_id, report_artifact_id, capability_id,
             approval_ref, dataset_revision, label_revision, task_revision,
             threshold_policy_revision, mapping_revision,
             evaluation_manifest_artifact_id, training_manifest_artifact_id,
             calibration_manifest_artifact_id, label_manifest_artifact_id,
             provider, provider_model_id, model_revision, prompt_revision,
             resolved_model_revision, completion_event_id, reported_event_id,
             completed_at, reported_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
         ON CONFLICT DO NOTHING",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(publication.report_id().as_str())
    .bind(publication.report_artifact_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(provenance.approval_ref().as_str())
    .bind(provenance.dataset_revision().as_str())
    .bind(provenance.label_revision().as_str())
    .bind(provenance.task_revision().as_str())
    .bind(provenance.threshold_policy_revision().as_str())
    .bind(provenance.mapping_revision().as_str())
    .bind(provenance.evaluation_manifest_artifact_id().as_str())
    .bind(provenance.training_manifest_artifact_id().as_str())
    .bind(provenance.calibration_manifest_artifact_id().as_str())
    .bind(provenance.label_manifest_artifact_id().as_str())
    .bind(model.provider().as_str())
    .bind(model.provider_model_id())
    .bind(model.model_revision().as_str())
    .bind(model.prompt_revision().as_str())
    .bind(model.resolved_model_revision().map(ModelRevision::as_str))
    .bind(command.completion_event_id.as_str())
    .bind(command.report_event_id.as_str())
    .bind(timestamp)
    .bind(timestamp)
    .execute(&mut **connection)
    .await?
    .rows_affected()
        == 1)
}

async fn insert_report_outbox(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_id: &EventId,
    tenant_id: &str,
    site_id: &str,
    aggregate_ref: &str,
    event_type: &str,
    envelope: &Value,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "INSERT INTO xshield.audit_outbox
             (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT DO NOTHING",
    )
    .bind(event_id.as_str())
    .bind(tenant_id)
    .bind(site_id)
    .bind(aggregate_ref)
    .bind(event_type)
    .bind(envelope)
    .execute(&mut **connection)
    .await?
    .rows_affected()
        == 1)
}

async fn report_event_identity_is_used(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    completion_event_id: &EventId,
    report_event_id: &EventId,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox WHERE event_id = ANY($1))",
    )
    .bind(vec![completion_event_id.as_str(), report_event_id.as_str()])
    .fetch_one(&mut **connection)
    .await?)
}

async fn existing_report_commit(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    header: &PgRow,
    command: &CalibrationReportCommit<'_, '_>,
) -> Result<CalibrationReportCommitOutcome, StoreError> {
    let capability = command.completion.session().capability();
    let Some(report_row) = sqlx::query(
        "SELECT * FROM xshield.calibration_reports
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .fetch_optional(&mut **connection)
    .await?
    else {
        return Ok(CalibrationReportCommitOutcome::Unavailable);
    };
    let lease = sqlx::query(
        "SELECT status, runner_id, lease_token_digest
         FROM xshield.calibration_read_capability_leases
         WHERE tenant_id=$1 AND site_id=$2 AND capability_id=$3 AND lease_id=$4
         FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(command.completion.session().lease().lease_id().as_str())
    .fetch_optional(&mut **connection)
    .await?
    .ok_or(StoreError::CorruptData("calibration_report_lease"))?;
    let token_digest = sha256(command.completion.session().lease().token());
    if lease.try_get::<&str, _>("status")? != "completed"
        || lease.try_get::<&str, _>("runner_id")? != command.runner_id
        || lease
            .try_get::<Vec<u8>, _>("lease_token_digest")?
            .as_slice()
            != token_digest
    {
        return Ok(CalibrationReportCommitOutcome::Unavailable);
    }
    if header.try_get::<Option<&str>, _>("completion_event_id")?
        != Some(command.completion_event_id.as_str())
        || !report_row_matches(&report_row, command)?
    {
        return Ok(CalibrationReportCommitOutcome::Conflict);
    }
    let artifact = sqlx::query(
        "SELECT * FROM xshield.calibration_report_artifacts
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3 FOR UPDATE",
    )
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(command.publication.report_artifact_id().as_str())
    .fetch_optional(&mut **connection)
    .await?
    .ok_or(StoreError::CorruptData("calibration_report_artifact"))?;
    if !report_artifact_row_matches(&artifact, command.manifest.manifest())? {
        return Ok(CalibrationReportCommitOutcome::Conflict);
    }
    let completed_at: DateTime<Utc> = report_row.try_get("completed_at")?;
    let reported_at: DateTime<Utc> = report_row.try_get("reported_at")?;
    let completion_envelope =
        completion_event(command.completion_event_id, capability, completed_at)?;
    let report_envelope = report_event(
        command.report_event_id,
        capability,
        command.publication,
        reported_at,
    )?;
    let exact_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM xshield.audit_outbox
         WHERE (event_id=$1 AND tenant_id=$2 AND site_id=$3 AND aggregate_ref=$4
                AND event_type=$5 AND envelope=$6)
            OR (event_id=$7 AND tenant_id=$2 AND site_id=$3 AND aggregate_ref=$8
                AND event_type=$9 AND envelope=$10)",
    )
    .bind(command.completion_event_id.as_str())
    .bind(capability.tenant_id().as_str())
    .bind(capability.site_id().as_str())
    .bind(capability.capability_id().as_str())
    .bind(COMPLETION_EVENT_TYPE)
    .bind(completion_envelope)
    .bind(command.report_event_id.as_str())
    .bind(command.publication.report_id().as_str())
    .bind(REPORT_EVENT_TYPE)
    .bind(report_envelope)
    .fetch_one(&mut **connection)
    .await?;
    if exact_events != 2 {
        return Ok(CalibrationReportCommitOutcome::Conflict);
    }
    Ok(CalibrationReportCommitOutcome::Existing(
        record_from_report_row(&report_row)?,
    ))
}

fn report_row_matches(
    row: &PgRow,
    command: &CalibrationReportCommit<'_, '_>,
) -> Result<bool, StoreError> {
    let publication = command.publication;
    let capability = command.completion.session().capability();
    let model = publication.model();
    Ok(
        row.try_get::<&str, _>("tenant_id")? == capability.tenant_id().as_str()
            && row.try_get::<&str, _>("site_id")? == capability.site_id().as_str()
            && row.try_get::<&str, _>("report_id")? == publication.report_id().as_str()
            && row.try_get::<&str, _>("report_artifact_id")?
                == publication.report_artifact_id().as_str()
            && row.try_get::<&str, _>("capability_id")? == capability.capability_id().as_str()
            && row.try_get::<&str, _>("approval_ref")? == publication.approval_ref().as_str()
            && row.try_get::<&str, _>("dataset_revision")?
                == publication.dataset_revision().as_str()
            && row.try_get::<&str, _>("label_revision")? == publication.label_revision().as_str()
            && row.try_get::<&str, _>("task_revision")? == publication.task_revision().as_str()
            && row.try_get::<&str, _>("threshold_policy_revision")?
                == publication.threshold_policy_revision().as_str()
            && row.try_get::<&str, _>("mapping_revision")?
                == publication.mapping_revision().as_str()
            && row.try_get::<&str, _>("evaluation_manifest_artifact_id")?
                == publication.evaluation_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("training_manifest_artifact_id")?
                == publication.training_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("calibration_manifest_artifact_id")?
                == publication.calibration_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("label_manifest_artifact_id")?
                == publication.label_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("provider")? == model.provider().as_str()
            && row.try_get::<&str, _>("provider_model_id")? == model.provider_model_id()
            && row.try_get::<&str, _>("model_revision")? == model.model_revision().as_str()
            && row.try_get::<&str, _>("prompt_revision")? == model.prompt_revision().as_str()
            && row.try_get::<Option<&str>, _>("resolved_model_revision")?
                == model.resolved_model_revision().map(ModelRevision::as_str)
            && row.try_get::<&str, _>("completion_event_id")?
                == command.completion_event_id.as_str()
            && row.try_get::<&str, _>("reported_event_id")? == command.report_event_id.as_str(),
    )
}

fn report_artifact_row_matches(
    row: &PgRow,
    manifest: &xshield_evidence::CalibrationReportEvidenceManifest,
) -> Result<bool, StoreError> {
    Ok(row.try_get::<&str, _>("tenant_id")? == manifest.tenant_id
        && row.try_get::<&str, _>("site_id")? == manifest.site_id
        && row.try_get::<&str, _>("report_id")? == manifest.report_id
        && row.try_get::<&str, _>("artifact_id")? == manifest.artifact_id
        && row.try_get::<i16, _>("schema_version")? == i16::from(manifest.schema_version)
        && row.try_get::<&str, _>("kind")? == manifest.kind
        && row.try_get::<&str, _>("content_type")? == manifest.content_type
        && row.try_get::<&str, _>("canonical_body_encoding")? == manifest.canonical_body_encoding
        && row.try_get::<&str, _>("capture_status")? == manifest.capture_status
        && row.try_get::<&str, _>("fidelity")? == "entity_exact"
        && row.try_get::<i64, _>("bytes_observed")?
            == i64::try_from(manifest.bytes_observed).unwrap_or(-1)
        && row.try_get::<i64, _>("bytes_saved")?
            == i64::try_from(manifest.bytes_saved).unwrap_or(-1)
        && row.try_get::<&str, _>("classification")? == "RESTRICTED"
        && row.try_get::<&str, _>("storage_profile")? == manifest.storage.profile
        && row.try_get::<&str, _>("storage_locator")? == manifest.storage.locator
        && row.try_get::<Option<&str>, _>("key_ref")? == manifest.storage.key_ref.as_deref()
        && row.try_get::<&str, _>("integrity_algorithm")? == manifest.integrity.algorithm
        && row.try_get::<&str, _>("integrity_digest")? == manifest.integrity.digest
        && row.try_get::<DateTime<Utc>, _>("expires_at")?
            == DateTime::parse_from_rfc3339(&manifest.expires_at)
                .map_err(|_| StoreError::CorruptData("report_artifact_expiry"))?
                .with_timezone(&Utc))
}

fn record_from_report_row(row: &PgRow) -> Result<CalibrationReportCommitRecord, StoreError> {
    Ok(CalibrationReportCommitRecord {
        report_id: CalibrationReportId::parse(row.try_get::<&str, _>("report_id")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_id"))?,
        report_artifact_id: ArtifactId::parse(row.try_get::<&str, _>("report_artifact_id")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_artifact_id"))?,
        capability_id: CalibrationReadCapabilityId::parse(row.try_get::<&str, _>("capability_id")?)
            .map_err(|_| StoreError::CorruptData("calibration_capability_id"))?,
        completion_event_id: EventId::parse(row.try_get::<&str, _>("completion_event_id")?)
            .map_err(|_| StoreError::CorruptData("calibration_completion_event_id"))?,
        report_event_id: EventId::parse(row.try_get::<&str, _>("reported_event_id")?)
            .map_err(|_| StoreError::CorruptData("calibration_report_event_id"))?,
        completed_at: row.try_get("completed_at")?,
        reported_at: row.try_get("reported_at")?,
    })
}

fn report_manifest_available(
    manifest: &xshield_evidence::CalibrationReportEvidenceManifest,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| StoreError::InvalidCommand)?
        .with_timezone(&Utc);
    Ok(expires_at > now)
}

fn completion_event(
    event_id: &EventId,
    capability: &xshield_core::calibration::read_capability::CalibrationEvidenceReadCapability,
    timestamp: DateTime<Utc>,
) -> Result<Value, StoreError> {
    let trace_id = capability
        .capability_id()
        .as_str()
        .strip_prefix("calcap_")
        .ok_or(StoreError::CorruptData("calibration_capability_id"))?
        .replace('-', "");
    let occurred_at = timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
    if trace_id.len() != 32 || occurred_at.len() != 24 {
        return Err(StoreError::CorruptData("calibration_completion_event"));
    }
    Ok(json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": COMPLETION_EVENT_TYPE,
        "tenant_id": capability.tenant_id().as_str(), "site_id": capability.site_id().as_str(),
        "request_id": null, "trace_id": trace_id, "span_id": &trace_id[..16],
        "producer_id": "calibration-evidence-batch-completer", "producer_boot_id": event_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": occurred_at, "observed_at": occurred_at,
        "policy_revision": "calibration-v1", "example_only": false,
        "evidence_refs": [], "cause_event_ids": [], "sensitivity": "RESTRICTED",
        "integrity": {"state":"pending", "previous_hash":null, "event_hash":null},
        "payload": {"stage":"calibration_read_batch", "outcome":"PASS", "reason_code":COMPLETION_EVENT_REASON,
                    "capability_id": capability.capability_id().as_str()}
    }))
}

fn report_event(
    event_id: &EventId,
    capability: &xshield_core::calibration::read_capability::CalibrationEvidenceReadCapability,
    publication: &CalibrationReportPublication,
    timestamp: DateTime<Utc>,
) -> Result<Value, StoreError> {
    let trace_id = publication
        .report_id()
        .as_str()
        .strip_prefix("calr_")
        .ok_or(StoreError::CorruptData("calibration_report_id"))?
        .replace('-', "");
    let occurred_at = timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
    if trace_id.len() != 32 || occurred_at.len() != 24 {
        return Err(StoreError::CorruptData("calibration_report_event"));
    }
    let model = publication.model();
    Ok(json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": REPORT_EVENT_TYPE,
        "tenant_id": capability.tenant_id().as_str(), "site_id": capability.site_id().as_str(),
        "request_id": null, "trace_id": trace_id, "span_id": &trace_id[..16],
        "producer_id": "calibration-evaluator", "producer_boot_id": event_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": occurred_at, "observed_at": occurred_at,
        "policy_revision": "calibration-v1", "example_only": false,
        "evidence_refs": [publication.report_artifact_id().as_str()], "cause_event_ids": [],
        "sensitivity": "RESTRICTED", "integrity": {"state":"pending", "previous_hash":null, "event_hash":null},
        "payload": {
            "stage":"calibration_report", "outcome":"PASS", "reason_code":REPORT_EVENT_REASON,
            "report_id": publication.report_id().as_str(), "report_artifact_id": publication.report_artifact_id().as_str(),
            "approval_ref": publication.approval_ref().as_str(), "dataset_revision": publication.dataset_revision().as_str(),
            "label_revision": publication.label_revision().as_str(), "task_revision": publication.task_revision().as_str(),
            "threshold_policy_revision": publication.threshold_policy_revision().as_str(), "mapping_revision": publication.mapping_revision().as_str(),
            "evaluation_manifest_artifact_id": publication.evaluation_manifest_artifact_id().as_str(),
            "training_manifest_artifact_id": publication.training_manifest_artifact_id().as_str(),
            "calibration_manifest_artifact_id": publication.calibration_manifest_artifact_id().as_str(),
            "label_manifest_artifact_id": publication.label_manifest_artifact_id().as_str(),
            "provider": model.provider().as_str(), "provider_model_id": model.provider_model_id(),
            "model_revision": model.model_revision().as_str(), "prompt_revision": model.prompt_revision().as_str(),
            "resolved_model_revision": model.resolved_model_revision().map(ModelRevision::as_str)
        }
    }))
}

fn report_scope_digest(
    capability: &xshield_core::calibration::read_capability::CalibrationEvidenceReadCapability,
    members: &[ReportFrozenMember],
) -> [u8; 32] {
    let mut canonical = Vec::with_capacity(4096);
    append_scope_field(
        &mut canonical,
        "xshield-calibration-read-capability-scope-v1",
    );
    append_scope_field(&mut canonical, capability.tenant_id().as_str());
    append_scope_field(&mut canonical, capability.site_id().as_str());
    append_scope_field(&mut canonical, &capability.not_before().value().to_string());
    append_scope_field(&mut canonical, &capability.expires_at().value().to_string());
    append_scope_field(&mut canonical, &capability.max_total_bytes().to_string());
    let provenance = capability.provenance();
    for field in [
        provenance.approval_ref().as_str(),
        provenance.dataset_revision().as_str(),
        provenance.label_revision().as_str(),
        provenance.task_revision().as_str(),
        provenance.threshold_policy_revision().as_str(),
        provenance.mapping_revision().as_str(),
        provenance.evaluation_manifest_artifact_id().as_str(),
        provenance.training_manifest_artifact_id().as_str(),
        provenance.calibration_manifest_artifact_id().as_str(),
        provenance.label_manifest_artifact_id().as_str(),
        provenance.model().provider().as_str(),
        provenance.model().provider_model_id(),
        provenance.model().model_revision().as_str(),
        provenance.model().prompt_revision().as_str(),
        provenance
            .model()
            .resolved_model_revision()
            .map_or("", ModelRevision::as_str),
    ] {
        append_scope_field(&mut canonical, field);
    }
    for member in members {
        append_scope_field(&mut canonical, &member.role);
        append_scope_field(
            &mut canonical,
            &member
                .sample_index
                .map_or_else(|| "-".to_owned(), |v| v.to_string()),
        );
        append_scope_field(&mut canonical, &member.artifact_id);
        append_scope_field(&mut canonical, &member.bytes_saved.to_string());
        append_scope_field(&mut canonical, &member.integrity_digest);
        append_scope_field(
            &mut canonical,
            &member.expires_at.timestamp_micros().to_string(),
        );
        append_scope_field(&mut canonical, &member.catalog_event_id);
        append_scope_field(&mut canonical, &member.kind);
        append_scope_field(&mut canonical, &member.content_type);
        append_scope_field(&mut canonical, &member.fidelity);
        append_scope_field(&mut canonical, &member.classification);
    }
    sha256(&canonical)
}

fn append_scope_field(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}

fn unix_timestamp(value: xshield_core::identity::UnixSeconds) -> Result<DateTime<Utc>, StoreError> {
    DateTime::from_timestamp(
        i64::try_from(value.value()).map_err(|_| StoreError::NumericRange("unix_seconds"))?,
        0,
    )
    .ok_or(StoreError::InvalidCommand)
}

fn date_millis(value: DateTime<Utc>) -> DateTime<Utc> {
    value
        .with_nanosecond(value.timestamp_subsec_millis() * 1_000_000)
        .unwrap_or(value)
}

fn valid_event_id(event_id: &EventId) -> bool {
    let value = event_id.as_str();
    value
        .strip_prefix("ev_")
        .is_some_and(|uuid| uuid.len() == 36 && uuid.as_bytes().get(14) == Some(&b'7'))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
