//! Atomic persistence for a declaration-only calibration lineage review.
//!
//! The encrypted body and its fresh vault attestation are produced outside this
//! adapter. `PostgreSQL` retains only authenticated fixed metadata, frozen
//! provenance and four catalog manifest references, then emits one restricted
//! history fact. Neither the review row nor its outbox event authorizes an
//! evidence read, threshold publication, or business operation.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use openssl::sha::sha256;
use serde_json::{Value, json};
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    calibration::lineage_review::{
        CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE, CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND,
        CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION,
        CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION, CalibrationLineageReviewArtifact,
    },
    domain::{ArtifactId, CalibrationLineageReviewId, EventId, ModelRevision, SiteId, TenantId},
};
use xshield_evidence::{
    AttestedCalibrationLineageReviewManifest, CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING,
    CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION,
    CalibrationLineageReviewEvidenceManifest, EvidenceClassification, EvidenceFidelity,
};

const REVIEWED_EVENT_TYPE: &str = "calibration.partition_lineage.reviewed";
const REVIEWED_EVENT_REASON: &str = "CALIBRATION_PARTITION_LINEAGE_REVIEWED";

/// Fully cross-checked command for one durable lineage review.
pub struct CalibrationLineageReviewCommit<'a> {
    review: &'a CalibrationLineageReviewArtifact,
    manifest: &'a AttestedCalibrationLineageReviewManifest,
    event_id: &'a EventId,
}

impl<'a> CalibrationLineageReviewCommit<'a> {
    /// Validates an attested review body and its immutable sidecar bindings.
    ///
    /// The constructor performs no database, vault, model, or outbox I/O. The
    /// attestation wrapper can only be obtained after the vault read-back
    /// boundary; this method verifies its fixed metadata again before a short
    /// database transaction performs catalog and identity checks.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the body, sidecar, event, or
    /// fixed representation identifiers do not describe exactly one review.
    pub fn new(
        review: &'a CalibrationLineageReviewArtifact,
        manifest: &'a AttestedCalibrationLineageReviewManifest,
        event_id: &'a EventId,
    ) -> Result<Self, StoreError> {
        let sidecar = manifest.manifest();
        let artifact_id =
            ArtifactId::parse(&sidecar.artifact_id).map_err(|_| StoreError::InvalidCommand)?;
        if !valid_event_id(event_id)
            || sidecar.review_id != review.review_id().as_str()
            || artifact_id != *review.review_artifact_id()
            || sidecar.schema_version != CALIBRATION_LINEAGE_REVIEW_EVIDENCE_MANIFEST_SCHEMA_VERSION
            || sidecar.kind != CALIBRATION_LINEAGE_REVIEW_ARTIFACT_KIND
            || sidecar.content_type != CALIBRATION_LINEAGE_REVIEW_ARTIFACT_CONTENT_TYPE
            || sidecar.canonical_body_encoding != CALIBRATION_LINEAGE_REVIEW_CANONICAL_BODY_ENCODING
            || sidecar.capture_status != "complete"
            || sidecar.fidelity != EvidenceFidelity::EntityExact
            || sidecar.classification != EvidenceClassification::Restricted
            || sidecar.storage.profile != "aead_envelope_v1"
            || sidecar.storage.locator != format!("{artifact_id}.xev")
            || sidecar.storage.key_ref.is_none()
            || sidecar.integrity.algorithm != "sha256_ciphertext"
            || sidecar.bytes_observed == 0
            || sidecar.bytes_observed != sidecar.bytes_saved
        {
            return Err(StoreError::InvalidCommand);
        }
        sidecar
            .validate_catalog_structure()
            .map_err(|_| StoreError::InvalidCommand)?;
        Ok(Self {
            review,
            manifest,
            event_id,
        })
    }
}

/// Durable non-content identity returned by a lineage-review commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CalibrationLineageReviewCommitRecord {
    review_id: CalibrationLineageReviewId,
    review_artifact_id: ArtifactId,
    event_id: EventId,
    reviewed_at: DateTime<Utc>,
}

impl CalibrationLineageReviewCommitRecord {
    /// Returns the immutable review identity.
    #[must_use]
    pub const fn review_id(&self) -> &CalibrationLineageReviewId {
        &self.review_id
    }

    /// Returns the protected review-artifact identity.
    #[must_use]
    pub const fn review_artifact_id(&self) -> &ArtifactId {
        &self.review_artifact_id
    }

    /// Returns the restricted reviewed-event identity.
    #[must_use]
    pub const fn event_id(&self) -> &EventId {
        &self.event_id
    }

    /// Returns the database-frozen review time.
    #[must_use]
    pub const fn reviewed_at(&self) -> DateTime<Utc> {
        self.reviewed_at
    }
}

/// Result of an atomic lineage-review persistence attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalibrationLineageReviewCommitOutcome {
    /// Artifact metadata, review projection, and restricted event committed.
    Committed(CalibrationLineageReviewCommitRecord),
    /// An earlier transaction committed the exact same immutable review.
    Existing(CalibrationLineageReviewCommitRecord),
    /// A review, artifact, or event identity belongs to different inputs.
    Conflict,
    /// A manifest catalog row or authenticated sidecar cannot support commit.
    Unavailable,
}

impl CalibrationLineageReviewCommitOutcome {
    /// Returns the stable terminal reason code for structured audit callers.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Committed(_) => REVIEWED_EVENT_REASON,
            Self::Existing(_) => "CALIBRATION_LINEAGE_REVIEW_ALREADY_COMMITTED",
            Self::Conflict => "CALIBRATION_LINEAGE_REVIEW_COMMIT_CONFLICT",
            Self::Unavailable => "CALIBRATION_LINEAGE_REVIEW_COMMIT_UNAVAILABLE",
        }
    }
}

impl PostgresIdentityStore {
    /// Atomically persists one vault-attested lineage review and audit fact.
    ///
    /// Exact unknown-result recovery checks the existing immutable review before
    /// checking present-day catalog liveness, because historical completion
    /// remains valid after normal retention. A new commit locks all four
    /// frozen manifest catalog rows, verifies their role-specific fixed shape
    /// and database-clock availability, then inserts the artifact sidecar,
    /// review projection, and its closed outbox envelope in one transaction.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database or corrupt durable-state failures.
    /// Expected conflicts and unavailable inputs return a closed outcome and
    /// have no authorization, plaintext, or policy-publication side effect.
    pub async fn commit_calibration_lineage_review(
        &self,
        command: CalibrationLineageReviewCommit<'_>,
    ) -> Result<CalibrationLineageReviewCommitOutcome, StoreError> {
        let review = command.review;
        let tenant_id = TenantId::parse(&command.manifest.manifest().tenant_id)
            .map_err(|_| StoreError::InvalidCommand)?;
        let site_id = SiteId::parse(&command.manifest.manifest().site_id)
            .map_err(|_| StoreError::InvalidCommand)?;
        if tenant_id.as_str().is_empty()
            || site_id.as_str().is_empty()
            || review.provenance().evaluation_manifest_artifact_id()
                == review.provenance().training_manifest_artifact_id()
        {
            return Err(StoreError::InvalidCommand);
        }
        let mut transaction = self.pool.begin().await?;
        set_timeouts(&mut transaction).await?;
        lock_review_identities(
            &mut transaction,
            review.review_id(),
            review.review_artifact_id(),
        )
        .await?;
        if let Some(existing) = find_review(&mut transaction, &tenant_id, &site_id, review).await? {
            let result = existing_outcome(&mut transaction, &existing, &command).await?;
            transaction.rollback().await?;
            return Ok(result);
        }
        if orphan_identity_is_fenced(
            &mut transaction,
            &tenant_id,
            &site_id,
            review.review_id(),
            review.review_artifact_id(),
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
        }
        if event_is_used(&mut transaction, command.event_id).await? {
            transaction.rollback().await?;
            return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await?;
        if !manifest_available(command.manifest.manifest(), now)?
            || !catalog_manifests_are_live(&mut transaction, &tenant_id, &site_id, review, now)
                .await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationLineageReviewCommitOutcome::Unavailable);
        }
        let timestamp = date_millis(now);
        if !claim_artifact_identity(
            &mut transaction,
            &tenant_id,
            &site_id,
            review.review_artifact_id(),
            timestamp,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
        }
        if !insert_artifact(&mut transaction, command.manifest.manifest(), timestamp).await?
            || !insert_review(&mut transaction, &tenant_id, &site_id, &command, timestamp).await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
        }
        let envelope = reviewed_event(command.event_id, &tenant_id, &site_id, review, timestamp)?;
        if !insert_outbox(
            &mut transaction,
            command.event_id,
            tenant_id.as_str(),
            site_id.as_str(),
            review.review_id().as_str(),
            &envelope,
        )
        .await?
        {
            transaction.rollback().await?;
            return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
        }
        transaction.commit().await?;
        Ok(CalibrationLineageReviewCommitOutcome::Committed(
            CalibrationLineageReviewCommitRecord {
                review_id: review.review_id().clone(),
                review_artifact_id: review.review_artifact_id().clone(),
                event_id: command.event_id.clone(),
                reviewed_at: timestamp,
            },
        ))
    }
}

async fn set_timeouts(
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

async fn lock_review_identities(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    review_id: &CalibrationLineageReviewId,
    artifact_id: &ArtifactId,
) -> Result<(), StoreError> {
    let mut identities = [
        format!("xshield-calibration-lineage-review-v1:artifact:{artifact_id}"),
        format!("xshield-calibration-lineage-review-v1:review:{review_id}"),
    ];
    identities.sort_unstable();
    for identity in identities {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(identity)
            .execute(&mut **connection)
            .await?;
    }
    Ok(())
}

/// Detects an orphan-purge identity that has durably fenced new publication.
///
/// The orphan row outlives a physical removal. Once deletion intent exists,
/// even a fresh review writer with the same identities cannot safely commit:
/// its just-attested ciphertext may be removed by the maintenance owner.
async fn orphan_identity_is_fenced(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    review_id: &CalibrationLineageReviewId,
    artifact_id: &ArtifactId,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM xshield.calibration_lineage_review_orphan_purges
             WHERE tenant_id=$1 AND site_id=$2
               AND (review_id=$3 OR artifact_id=$4)
         )",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(review_id.as_str())
    .bind(artifact_id.as_str())
    .fetch_one(&mut **connection)
    .await?)
}

async fn find_review(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    review: &CalibrationLineageReviewArtifact,
) -> Result<Option<PgRow>, StoreError> {
    Ok(sqlx::query(
        "SELECT * FROM xshield.calibration_lineage_reviews
         WHERE review_id=$1 OR (tenant_id=$2 AND site_id=$3 AND review_artifact_id=$4)
         FOR UPDATE",
    )
    .bind(review.review_id().as_str())
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(review.review_artifact_id().as_str())
    .fetch_optional(&mut **connection)
    .await?)
}

async fn event_is_used(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_id: &EventId,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox WHERE event_id=$1)",
    )
    .bind(event_id.as_str())
    .fetch_one(&mut **connection)
    .await?)
}

/// Claims the global artifact identity before inserting its owner row.
///
/// The preclaim closes the race between a read-only availability probe and the
/// owner insert: a concurrent family now loses through this closed `false`
/// result, instead of surfacing its registry trigger's unique violation as a
/// storage error. The `AFTER INSERT` trigger remains the final guard for every
/// writer, including older adapters that do not preclaim an identity.
async fn claim_artifact_identity(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    artifact_id: &ArtifactId,
    registered_at: DateTime<Utc>,
) -> Result<bool, StoreError> {
    Ok(sqlx::query(
        "INSERT INTO xshield.artifact_identity_registry
             (artifact_id, tenant_id, site_id, family, registered_at)
         VALUES ($1,$2,$3,'calibration_lineage_review',$4)
         ON CONFLICT (artifact_id) DO NOTHING",
    )
    .bind(artifact_id.as_str())
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(registered_at)
    .execute(&mut **connection)
    .await?
    .rows_affected()
        == 1)
}

async fn catalog_manifests_are_live(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    review: &CalibrationLineageReviewArtifact,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let provenance = review.provenance();
    let expectations = [
        (
            "evaluation_manifest",
            provenance.evaluation_manifest_artifact_id(),
        ),
        (
            "training_manifest",
            provenance.training_manifest_artifact_id(),
        ),
        (
            "calibration_manifest",
            provenance.calibration_manifest_artifact_id(),
        ),
        ("label_manifest", provenance.label_manifest_artifact_id()),
    ];
    let ids = expectations
        .iter()
        .map(|(_, artifact)| artifact.as_str())
        .collect::<Vec<_>>();
    let rows = sqlx::query(
        "SELECT artifact_id, kind, content_type, fidelity, classification, status, deleted_at,
                purge_requested_event_id, expires_at
         FROM xshield.artifact_catalog
         WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=ANY($3)
         ORDER BY artifact_id FOR UPDATE",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(ids)
    .fetch_all(&mut **connection)
    .await?;
    if rows.len() != expectations.len() {
        return Ok(false);
    }
    for (expected_kind, artifact_id) in expectations {
        let Some(row) = rows
            .iter()
            .find(|row| row.try_get::<&str, _>("artifact_id").ok() == Some(artifact_id.as_str()))
        else {
            return Ok(false);
        };
        if row.try_get::<&str, _>("kind")? != expected_kind
            || row.try_get::<&str, _>("content_type")? != "application/json"
            || row.try_get::<&str, _>("fidelity")? != "semantic"
            || row.try_get::<&str, _>("classification")? != "RESTRICTED"
            || row.try_get::<&str, _>("status")? != "active"
            || row
                .try_get::<Option<DateTime<Utc>>, _>("deleted_at")?
                .is_some()
            || row
                .try_get::<Option<&str>, _>("purge_requested_event_id")?
                .is_some()
            || row.try_get::<DateTime<Utc>, _>("expires_at")? <= now
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn insert_artifact(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    manifest: &CalibrationLineageReviewEvidenceManifest,
    timestamp: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let expires_at = DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| StoreError::InvalidCommand)?
        .with_timezone(&Utc);
    let bytes = i64::try_from(manifest.bytes_saved)
        .map_err(|_| StoreError::NumericRange("lineage_review_artifact_bytes_saved"))?;
    let key_ref = manifest
        .storage
        .key_ref
        .as_deref()
        .ok_or(StoreError::InvalidCommand)?;
    Ok(sqlx::query(
        "INSERT INTO xshield.calibration_lineage_review_artifacts (
             tenant_id, site_id, review_id, artifact_id, schema_version, kind,
             content_type, canonical_body_encoding, capture_status, fidelity,
             bytes_observed, bytes_saved, classification, storage_profile,
             storage_locator, key_ref, integrity_algorithm, integrity_digest,
             recorded_at, reviewed_at, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
         ON CONFLICT DO NOTHING",
    )
    .bind(&manifest.tenant_id)
    .bind(&manifest.site_id)
    .bind(&manifest.review_id)
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

async fn insert_review(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    command: &CalibrationLineageReviewCommit<'_>,
    timestamp: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let review = command.review;
    let provenance = review.provenance();
    let model = provenance.model();
    Ok(sqlx::query(
        "INSERT INTO xshield.calibration_lineage_reviews (
             tenant_id, site_id, review_id, review_artifact_id, schema_version,
             policy_revision, approval_ref, dataset_revision, label_revision,
             task_revision, threshold_policy_revision, mapping_revision,
             evaluation_manifest_artifact_id, training_manifest_artifact_id,
             calibration_manifest_artifact_id, label_manifest_artifact_id,
             provider, provider_model_id, model_revision, prompt_revision,
             resolved_model_revision, reviewed_event_id, reviewed_at
             , source_graph_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(review.review_id().as_str())
    .bind(review.review_artifact_id().as_str())
    .bind(i16::from(CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION))
    .bind(CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION)
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
    .bind(command.event_id.as_str())
    .bind(timestamp)
    .bind(source_graph_digest(review).as_slice())
    .execute(&mut **connection)
    .await?
    .rows_affected()
        == 1)
}

async fn insert_outbox(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event_id: &EventId,
    tenant_id: &str,
    site_id: &str,
    aggregate_ref: &str,
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
    .bind(REVIEWED_EVENT_TYPE)
    .bind(envelope)
    .execute(&mut **connection)
    .await?
    .rows_affected()
        == 1)
}

async fn existing_outcome(
    connection: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &PgRow,
    command: &CalibrationLineageReviewCommit<'_>,
) -> Result<CalibrationLineageReviewCommitOutcome, StoreError> {
    if !review_row_matches(row, command)? {
        return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
    }
    let sidecar = command.manifest.manifest();
    let artifact = sqlx::query(
        "SELECT * FROM xshield.calibration_lineage_review_artifacts
         WHERE artifact_id=$1 FOR UPDATE",
    )
    .bind(command.review.review_artifact_id().as_str())
    .fetch_optional(&mut **connection)
    .await?
    .ok_or(StoreError::CorruptData(
        "calibration_lineage_review_artifact",
    ))?;
    if !artifact_row_matches(&artifact, sidecar)? {
        return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
    }
    let reviewed_at: DateTime<Utc> = row.try_get("reviewed_at")?;
    let tenant_id = TenantId::parse(row.try_get::<&str, _>("tenant_id")?)
        .map_err(|_| StoreError::CorruptData("calibration_lineage_review_tenant"))?;
    let site_id = SiteId::parse(row.try_get::<&str, _>("site_id")?)
        .map_err(|_| StoreError::CorruptData("calibration_lineage_review_site"))?;
    let envelope = reviewed_event(
        command.event_id,
        &tenant_id,
        &site_id,
        command.review,
        reviewed_at,
    )?;
    let exact_event: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM xshield.audit_outbox
             WHERE event_id=$1 AND tenant_id=$2 AND site_id=$3 AND aggregate_ref=$4
               AND event_type=$5 AND envelope=$6
         )",
    )
    .bind(command.event_id.as_str())
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(command.review.review_id().as_str())
    .bind(REVIEWED_EVENT_TYPE)
    .bind(envelope)
    .fetch_one(&mut **connection)
    .await?;
    if !exact_event {
        return Ok(CalibrationLineageReviewCommitOutcome::Conflict);
    }
    Ok(CalibrationLineageReviewCommitOutcome::Existing(
        CalibrationLineageReviewCommitRecord {
            review_id: command.review.review_id().clone(),
            review_artifact_id: command.review.review_artifact_id().clone(),
            event_id: command.event_id.clone(),
            reviewed_at,
        },
    ))
}

fn review_row_matches(
    row: &PgRow,
    command: &CalibrationLineageReviewCommit<'_>,
) -> Result<bool, StoreError> {
    let review = command.review;
    let provenance = review.provenance();
    let model = provenance.model();
    Ok(
        row.try_get::<&str, _>("tenant_id")? == command.manifest.manifest().tenant_id
            && row.try_get::<&str, _>("site_id")? == command.manifest.manifest().site_id
            && row.try_get::<&str, _>("review_id")? == review.review_id().as_str()
            && row.try_get::<&str, _>("review_artifact_id")?
                == review.review_artifact_id().as_str()
            && row.try_get::<i16, _>("schema_version")?
                == i16::from(CALIBRATION_LINEAGE_REVIEW_ARTIFACT_SCHEMA_VERSION)
            && row.try_get::<&str, _>("policy_revision")?
                == CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION
            && row.try_get::<&str, _>("approval_ref")? == provenance.approval_ref().as_str()
            && row.try_get::<&str, _>("dataset_revision")?
                == provenance.dataset_revision().as_str()
            && row.try_get::<&str, _>("label_revision")? == provenance.label_revision().as_str()
            && row.try_get::<&str, _>("task_revision")? == provenance.task_revision().as_str()
            && row.try_get::<&str, _>("threshold_policy_revision")?
                == provenance.threshold_policy_revision().as_str()
            && row.try_get::<&str, _>("mapping_revision")?
                == provenance.mapping_revision().as_str()
            && row.try_get::<&str, _>("evaluation_manifest_artifact_id")?
                == provenance.evaluation_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("training_manifest_artifact_id")?
                == provenance.training_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("calibration_manifest_artifact_id")?
                == provenance.calibration_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("label_manifest_artifact_id")?
                == provenance.label_manifest_artifact_id().as_str()
            && row.try_get::<&str, _>("provider")? == model.provider().as_str()
            && row.try_get::<&str, _>("provider_model_id")? == model.provider_model_id()
            && row.try_get::<&str, _>("model_revision")? == model.model_revision().as_str()
            && row.try_get::<&str, _>("prompt_revision")? == model.prompt_revision().as_str()
            && row.try_get::<Option<&str>, _>("resolved_model_revision")?
                == model.resolved_model_revision().map(ModelRevision::as_str)
            && row.try_get::<&str, _>("reviewed_event_id")? == command.event_id.as_str()
            && row.try_get::<Vec<u8>, _>("source_graph_digest")?.as_slice()
                == source_graph_digest(review).as_slice(),
    )
}

fn artifact_row_matches(
    row: &PgRow,
    manifest: &CalibrationLineageReviewEvidenceManifest,
) -> Result<bool, StoreError> {
    Ok(row.try_get::<&str, _>("tenant_id")? == manifest.tenant_id
        && row.try_get::<&str, _>("site_id")? == manifest.site_id
        && row.try_get::<&str, _>("review_id")? == manifest.review_id
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
                .map_err(|_| StoreError::CorruptData("lineage_review_artifact_expiry"))?
                .with_timezone(&Utc))
}

fn manifest_available(
    manifest: &CalibrationLineageReviewEvidenceManifest,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    Ok(DateTime::parse_from_rfc3339(&manifest.expires_at)
        .map_err(|_| StoreError::InvalidCommand)?
        .with_timezone(&Utc)
        > now)
}

fn reviewed_event(
    event_id: &EventId,
    tenant_id: &TenantId,
    site_id: &SiteId,
    review: &CalibrationLineageReviewArtifact,
    timestamp: DateTime<Utc>,
) -> Result<Value, StoreError> {
    let trace_id = review
        .review_id()
        .as_str()
        .strip_prefix("calrev_")
        .ok_or(StoreError::CorruptData("calibration_lineage_review_id"))?
        .replace('-', "");
    let occurred_at = timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
    if trace_id.len() != 32 || occurred_at.len() != 24 {
        return Err(StoreError::CorruptData("calibration_lineage_review_event"));
    }
    let provenance = review.provenance();
    let model = provenance.model();
    Ok(json!({
        "schema_version": 3, "event_id": event_id.as_str(), "event_type": REVIEWED_EVENT_TYPE,
        "tenant_id": tenant_id.as_str(), "site_id": site_id.as_str(), "request_id": null,
        "trace_id": trace_id, "span_id": &trace_id[..16],
        "producer_id": "calibration-lineage-reviewer", "producer_boot_id": event_id.as_str(),
        "producer_seq": 1, "request_seq": 1, "occurred_at": occurred_at, "observed_at": occurred_at,
        "policy_revision": CALIBRATION_LINEAGE_REVIEW_POLICY_REVISION, "example_only": false,
        "evidence_refs": [review.review_artifact_id().as_str()], "cause_event_ids": [],
        "sensitivity": "RESTRICTED", "integrity": {"state":"pending","previous_hash":null,"event_hash":null},
        "payload": {
            "stage":"calibration_partition_lineage", "outcome":"PASS", "reason_code":REVIEWED_EVENT_REASON,
            "review_id": review.review_id().as_str(), "review_artifact_id": review.review_artifact_id().as_str(),
            "approval_ref": provenance.approval_ref().as_str(), "dataset_revision": provenance.dataset_revision().as_str(),
            "label_revision": provenance.label_revision().as_str(), "task_revision": provenance.task_revision().as_str(),
            "threshold_policy_revision": provenance.threshold_policy_revision().as_str(), "mapping_revision": provenance.mapping_revision().as_str(),
            "evaluation_manifest_artifact_id": provenance.evaluation_manifest_artifact_id().as_str(),
            "training_manifest_artifact_id": provenance.training_manifest_artifact_id().as_str(),
            "calibration_manifest_artifact_id": provenance.calibration_manifest_artifact_id().as_str(),
            "label_manifest_artifact_id": provenance.label_manifest_artifact_id().as_str(),
            "provider": model.provider().as_str(), "provider_model_id": model.provider_model_id(),
            "model_revision": model.model_revision().as_str(), "prompt_revision": model.prompt_revision().as_str(),
            "resolved_model_revision": model.resolved_model_revision().map(ModelRevision::as_str)
        }
    }))
}

fn date_millis(timestamp: DateTime<Utc>) -> DateTime<Utc> {
    timestamp.with_nanosecond(0).unwrap_or(timestamp)
        + chrono::TimeDelta::milliseconds(i64::from(timestamp.timestamp_subsec_millis()))
}

fn valid_event_id(event_id: &EventId) -> bool {
    event_id.as_str().starts_with("ev_")
}

/// Hashes the canonical partition roots and source graph without putting any
/// source IDs or revisions into the database projection or outbox payload.
fn source_graph_digest(review: &CalibrationLineageReviewArtifact) -> [u8; 32] {
    let mut canonical = Vec::with_capacity(4096);
    append_digest_field(&mut canonical, "xshield-calibration-lineage-graph-v1");
    for partition in review.partitions() {
        append_digest_field(&mut canonical, partition.role().as_str());
        append_digest_field(&mut canonical, partition.manifest_artifact_id().as_str());
        for source in partition.direct_sources() {
            append_digest_field(&mut canonical, source.source_id());
            append_digest_field(&mut canonical, source.source_revision());
        }
    }
    for source in review.sources() {
        append_digest_field(&mut canonical, source.source_id());
        append_digest_field(&mut canonical, source.source_revision());
        append_digest_field(&mut canonical, source.partition().as_str());
        append_digest_field(&mut canonical, source.kind().as_str());
        for parent in source.parent_sources() {
            append_digest_field(&mut canonical, parent.source_id());
            append_digest_field(&mut canonical, parent.source_revision());
        }
    }
    sha256(&canonical)
}

fn append_digest_field(target: &mut Vec<u8>, value: &str) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value.as_bytes());
}
