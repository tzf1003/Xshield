//! Durable expiry retention for calibration-lineage-review evidence.
//!
//! A calibration lineage review is a request-free encrypted object. This adapter owns
//! its separate intent, terminal tombstone, and restricted maintenance facts;
//! it does not consult or modify `artifact_catalog`.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use xshield_core::domain::{ArtifactId, CalibrationLineageReviewId, EventId, SiteId, TenantId};
use xshield_evidence::{
    CalibrationLineageReviewEvidenceManifest, CalibrationLineageReviewOrphanCandidate,
    EvidenceClassification, EvidenceFidelity, EvidenceIntegrity, EvidencePurgeOutcome,
    EvidenceStorage,
};

const REQUESTED_EVENT_TYPE: &str = "calibration.lineage_review_retention.purge_requested";
const DELETED_EVENT_TYPE: &str = "calibration.lineage_review_retention.deleted";
const FAILED_EVENT_TYPE: &str = "calibration.lineage_review_retention.purge_failed";
const ORPHAN_REQUESTED_EVENT_TYPE: &str =
    "calibration.lineage_review_retention.orphan_purge_requested";
const ORPHAN_DELETED_EVENT_TYPE: &str = "calibration.lineage_review_retention.orphan_deleted";
const ORPHAN_FAILED_EVENT_TYPE: &str = "calibration.lineage_review_retention.orphan_purge_failed";

/// Exact lineage-review-sidecar snapshot backed by a committed deletion-intent event.
pub struct CalibrationLineageReviewPurgeJob {
    manifest: CalibrationLineageReviewEvidenceManifest,
    intent_event_id: EventId,
}

impl CalibrationLineageReviewPurgeJob {
    /// Returns the exact lineage-review sidecar the vault must reauthenticate.
    #[must_use]
    pub const fn manifest(&self) -> &CalibrationLineageReviewEvidenceManifest {
        &self.manifest
    }

    /// Returns the durable deletion-intent event bound to this job.
    #[must_use]
    pub const fn intent_event_id(&self) -> &EventId {
        &self.intent_event_id
    }
}

/// Terminal result of one lineage-review-body deletion attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationLineageReviewPurgeResult {
    /// Directory-synced ciphertext removal, including an already absent retry.
    Deleted(EvidencePurgeOutcome),
    /// Sidecar, scope, expiry, digest, or local storage validation rejected removal.
    Rejected,
    /// The vault or cryptographic operation was unavailable.
    Unavailable,
}

/// Exact request-free lineage-review sidecar observation backed by an orphan intent.
pub struct CalibrationLineageReviewOrphanPurgeJob {
    tenant_id: TenantId,
    site_id: SiteId,
    candidate: CalibrationLineageReviewOrphanCandidate,
    intent_event_id: EventId,
}

impl CalibrationLineageReviewOrphanPurgeJob {
    /// Returns the authenticated lineage-review sidecar observation.
    #[must_use]
    pub const fn candidate(&self) -> &CalibrationLineageReviewOrphanCandidate {
        &self.candidate
    }

    /// Returns the scope tied to the observation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the scope tied to the observation.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }

    /// Returns the durable orphan intent event.
    #[must_use]
    pub const fn intent_event_id(&self) -> &EventId {
        &self.intent_event_id
    }
}

/// Result of one lineage-review-only orphan deletion attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationLineageReviewOrphanPurgeResult {
    /// Ciphertext removed or already absent after sidecar revalidation.
    Deleted(EvidencePurgeOutcome),
    /// The observation or sidecar changed and remains retained.
    Rejected,
    /// Local storage or cryptographic operation was unavailable.
    Unavailable,
}

impl CalibrationLineageReviewOrphanPurgeResult {
    /// Returns the stable maintenance reason code.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Deleted(EvidencePurgeOutcome::Removed) => {
                "CALIBRATION_LINEAGE_REVIEW_ORPHAN_DELETED"
            }
            Self::Deleted(EvidencePurgeOutcome::AlreadyAbsent) => {
                "CALIBRATION_LINEAGE_REVIEW_ORPHAN_DELETE_ALREADY_ABSENT"
            }
            Self::Rejected => "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_REJECTED",
            Self::Unavailable => "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_UNAVAILABLE",
        }
    }
}

impl CalibrationLineageReviewPurgeResult {
    /// Returns the stable non-content audit reason for this result.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Deleted(EvidencePurgeOutcome::Removed) => "CALIBRATION_LINEAGE_REVIEW_DELETED",
            Self::Deleted(EvidencePurgeOutcome::AlreadyAbsent) => {
                "CALIBRATION_LINEAGE_REVIEW_DELETE_ALREADY_ABSENT"
            }
            Self::Rejected => "CALIBRATION_LINEAGE_REVIEW_PURGE_REJECTED",
            Self::Unavailable => "CALIBRATION_LINEAGE_REVIEW_PURGE_UNAVAILABLE",
        }
    }
}

impl PostgresIdentityStore {
    /// Commits expiry-deletion intent for up to 32 lineage-review bodies in one scope/key.
    ///
    /// `PostgreSQL` time, scoped row locks, and an outbox event are committed
    /// before a caller may ask the vault to remove any ciphertext. Existing
    /// intent is returned for recovery; lineage reviews remain entirely separate from
    /// generic evidence catalog retention.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid input, corrupted durable state, or a
    /// database failure. No job is returned until its intent transaction commits.
    pub async fn prepare_calibration_lineage_review_purge(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        key_id: &str,
        limit: u16,
    ) -> Result<Vec<CalibrationLineageReviewPurgeJob>, StoreError> {
        if !valid_key_id(key_id) || !(1..=32).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.retention_transaction().await?;
        let rows = sqlx::query(
            "SELECT * FROM xshield.calibration_lineage_review_artifacts
             WHERE tenant_id = $1 AND site_id = $2 AND key_ref = $3
               AND retention_status = 'active' AND expires_at <= clock_timestamp()
             ORDER BY expires_at, artifact_id LIMIT $4 FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(key_id)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            let manifest = lineage_review_manifest(&row)?;
            let intent_event_id = if let Some(event_id) =
                row.try_get::<Option<String>, _>("purge_requested_event_id")?
            {
                let event_id = EventId::parse(event_id).map_err(|_| {
                    StoreError::CorruptData("calibration_lineage_review_purge_intent_id")
                })?;
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(
                        SELECT 1 FROM xshield.audit_outbox
                         WHERE event_id = $1 AND tenant_id = $2 AND site_id = $3
                           AND aggregate_ref = $4 AND event_type = $5
                           AND envelope->'payload'->>'reason_code' =
                               'CALIBRATION_LINEAGE_REVIEW_PURGE_REQUESTED'
                    )",
                )
                .bind(event_id.as_str())
                .bind(tenant.as_str())
                .bind(site.as_str())
                .bind(&manifest.review_id)
                .bind(REQUESTED_EVENT_TYPE)
                .fetch_one(&mut *tx)
                .await?;
                if !exists {
                    return Err(StoreError::CorruptData(
                        "calibration_lineage_review_purge_intent_audit",
                    ));
                }
                event_id
            } else {
                let event_id = retention_event(
                    &mut tx,
                    &manifest,
                    REQUESTED_EVENT_TYPE,
                    "CALIBRATION_LINEAGE_REVIEW_PURGE_REQUESTED",
                    "PASS",
                    None,
                )
                .await?;
                sqlx::query(
                    "UPDATE xshield.calibration_lineage_review_artifacts
                     SET purge_requested_event_id = $4
                     WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3",
                )
                .bind(tenant.as_str())
                .bind(site.as_str())
                .bind(&manifest.artifact_id)
                .bind(event_id.as_str())
                .execute(&mut *tx)
                .await?;
                event_id
            };
            jobs.push(CalibrationLineageReviewPurgeJob {
                manifest,
                intent_event_id,
            });
        }
        tx.commit().await?;
        Ok(jobs)
    }

    /// Records a lineage-review-body deletion result and writes a terminal tombstone on success.
    ///
    /// The exact sidecar snapshot and committed intent are rechecked under the
    /// same row lock. Physical removal must have completed and the directory
    /// must have been synced before a successful result is provided.
    ///
    /// # Errors
    /// Returns [`StoreError`] for a changed review row, expiry mismatch, or a
    /// database failure. A failed completion retains the existing intent for a
    /// later idempotent vault retry.
    pub async fn finish_calibration_lineage_review_purge(
        &self,
        job: &CalibrationLineageReviewPurgeJob,
        result: CalibrationLineageReviewPurgeResult,
    ) -> Result<(), StoreError> {
        let mut tx = self.retention_transaction().await?;
        let row = sqlx::query(
            "SELECT *, expires_at <= clock_timestamp() AS expired
             FROM xshield.calibration_lineage_review_artifacts
             WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3 FOR UPDATE",
        )
        .bind(&job.manifest.tenant_id)
        .bind(&job.manifest.site_id)
        .bind(&job.manifest.artifact_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::InvalidCommand)?;
        if lineage_review_manifest(&row)? != job.manifest
            || row.try_get::<Option<&str>, _>("purge_requested_event_id")?
                != Some(job.intent_event_id.as_str())
        {
            return Err(StoreError::CorruptData(
                "calibration_lineage_review_purge_snapshot",
            ));
        }
        if row.try_get::<&str, _>("retention_status")? == "deleted"
            && row
                .try_get::<Option<&str>, _>("purge_completed_event_id")?
                .is_some()
        {
            tx.commit().await?;
            return Ok(());
        }
        if row.try_get::<&str, _>("retention_status")? != "active"
            || !row.try_get::<bool, _>("expired")?
        {
            return Err(StoreError::InvalidCommand);
        }
        let success = matches!(result, CalibrationLineageReviewPurgeResult::Deleted(_));
        let event_id = retention_event(
            &mut tx,
            &job.manifest,
            if success {
                DELETED_EVENT_TYPE
            } else {
                FAILED_EVENT_TYPE
            },
            result.reason_code(),
            if success { "PASS" } else { "ERROR" },
            Some(&job.intent_event_id),
        )
        .await?;
        if success {
            sqlx::query(
                "UPDATE xshield.calibration_lineage_review_artifacts
                 SET retention_status = 'deleted', deleted_at = clock_timestamp(),
                     purge_completed_event_id = $4
                 WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3",
            )
            .bind(&job.manifest.tenant_id)
            .bind(&job.manifest.site_id)
            .bind(&job.manifest.artifact_id)
            .bind(event_id.as_str())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Creates or reuses bounded deletion intents for lineage-review sidecars without metadata rows.
    ///
    /// The transaction rules out any committed lineage-review metadata and stores the
    /// complete sidecar observation. The generic catalog and orphan tables are
    /// never touched.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the candidate is malformed, durable state
    /// is inconsistent, or the intent transaction cannot commit.
    #[allow(clippy::too_many_lines)]
    pub async fn prepare_calibration_lineage_review_orphan_purge(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        candidates: &[CalibrationLineageReviewOrphanCandidate],
    ) -> Result<Vec<CalibrationLineageReviewOrphanPurgeJob>, StoreError> {
        if candidates.is_empty() || candidates.len() > 32 {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.retention_transaction().await?;
        let mut jobs = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let artifact_id = ArtifactId::parse(candidate.artifact_id())
                .map_err(|_| StoreError::InvalidCommand)?;
            let review_id = CalibrationLineageReviewId::parse(candidate.review_id())
                .map_err(|_| StoreError::InvalidCommand)?;
            lock_lineage_review_identities(&mut tx, &review_id, &artifact_id).await?;
            let committed: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM xshield.calibration_lineage_review_artifacts
                 WHERE artifact_id = $1 OR review_id = $2)",
            )
            .bind(artifact_id.as_str())
            .bind(review_id.as_str())
            .fetch_one(&mut *tx)
            .await?;
            if committed {
                continue;
            }
            let existing = sqlx::query(
                "SELECT * FROM xshield.calibration_lineage_review_orphan_purges
                 WHERE tenant_id = $1 AND site_id = $2 AND artifact_id = $3 FOR UPDATE",
            )
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(artifact_id.as_str())
            .fetch_optional(&mut *tx)
            .await?;
            let intent_event_id = if let Some(row) = existing {
                if row.try_get::<&str, _>("status")? == "deleted"
                    || !orphan_snapshot_matches(&row, candidate)?
                {
                    continue;
                }
                let event_id =
                    EventId::parse(row.try_get::<&str, _>("requested_event_id")?.to_owned())
                        .map_err(|_| {
                            StoreError::CorruptData("calibration_lineage_review_orphan_intent_id")
                        })?;
                ensure_retention_event(
                    &mut tx,
                    &event_id,
                    tenant,
                    site,
                    review_id.as_str(),
                    ORPHAN_REQUESTED_EVENT_TYPE,
                )
                .await?;
                event_id
            } else {
                let event_id = retention_event_with_refs(
                    &mut tx,
                    tenant,
                    site,
                    &review_id,
                    &artifact_id,
                    candidate.expires_at(),
                    ORPHAN_REQUESTED_EVENT_TYPE,
                    "CALIBRATION_LINEAGE_REVIEW_ORPHAN_PURGE_REQUESTED",
                    "PASS",
                    None,
                )
                .await?;
                sqlx::query(
                    "INSERT INTO xshield.calibration_lineage_review_orphan_purges
                     (tenant_id, site_id, review_id, artifact_id, storage_locator,
                      sidecar_digest, observed_bytes, observed_modified_seconds,
                      observed_modified_nanos, expires_at, requested_event_id, status, requested_at)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending',clock_timestamp())",
                )
                .bind(tenant.as_str())
                .bind(site.as_str())
                .bind(review_id.as_str())
                .bind(artifact_id.as_str())
                .bind(format!("{}.xev", artifact_id.as_str()))
                .bind(candidate.sidecar_digest())
                .bind(i64::try_from(candidate.observed_bytes()).map_err(|_| {
                    StoreError::NumericRange("calibration_lineage_review_orphan_bytes")
                })?)
                .bind(i64::try_from(candidate.observed_modified().0).map_err(|_| {
                    StoreError::NumericRange("calibration_lineage_review_orphan_mtime")
                })?)
                .bind(i32::try_from(candidate.observed_modified().1).map_err(|_| {
                    StoreError::NumericRange("calibration_lineage_review_orphan_mtime_nanos")
                })?)
                .bind(
                    DateTime::parse_from_rfc3339(candidate.expires_at())
                        .map_err(|_| StoreError::InvalidCommand)?
                        .with_timezone(&Utc),
                )
                .bind(event_id.as_str())
                .execute(&mut *tx)
                .await?;
                event_id
            };
            jobs.push(CalibrationLineageReviewOrphanPurgeJob {
                tenant_id: tenant.clone(),
                site_id: site.clone(),
                candidate: candidate.clone(),
                intent_event_id,
            });
        }
        tx.commit().await?;
        Ok(jobs)
    }

    /// Returns pending lineage-review-orphan intents for crash recovery.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the bound is invalid, the intent audit is
    /// missing, or the recovery transaction cannot commit.
    pub async fn pending_calibration_lineage_review_orphan_purges(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        limit: u16,
    ) -> Result<Vec<CalibrationLineageReviewOrphanPurgeJob>, StoreError> {
        if !(1..=32).contains(&limit) {
            return Err(StoreError::InvalidCommand);
        }
        let mut tx = self.retention_transaction().await?;
        let rows = sqlx::query(
            "SELECT orphan.* FROM xshield.calibration_lineage_review_orphan_purges orphan
             WHERE tenant_id=$1 AND site_id=$2 AND status='pending'
             AND NOT EXISTS (SELECT 1 FROM xshield.calibration_lineage_review_artifacts review
                              WHERE review.artifact_id=orphan.artifact_id OR review.review_id=orphan.review_id)
             ORDER BY requested_at, artifact_id LIMIT $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await?;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            let event_id = EventId::parse(row.try_get::<&str, _>("requested_event_id")?.to_owned())
                .map_err(|_| {
                    StoreError::CorruptData("calibration_lineage_review_orphan_intent_id")
                })?;
            ensure_retention_event(
                &mut tx,
                &event_id,
                tenant,
                site,
                row.try_get("review_id")?,
                ORPHAN_REQUESTED_EVENT_TYPE,
            )
            .await?;
            jobs.push(orphan_job_from_row(&row)?);
        }
        tx.commit().await?;
        Ok(jobs)
    }

    /// Records one lineage-review-orphan attempt and terminal audit fact.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the job snapshot, committed metadata, or
    /// terminal audit state no longer matches the durable orphan row.
    pub async fn finish_calibration_lineage_review_orphan_purge(
        &self,
        job: &CalibrationLineageReviewOrphanPurgeJob,
        result: CalibrationLineageReviewOrphanPurgeResult,
    ) -> Result<(), StoreError> {
        let mut tx = self.retention_transaction().await?;
        let row = sqlx::query(
            "SELECT * FROM xshield.calibration_lineage_review_orphan_purges
             WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3 FOR UPDATE",
        )
        .bind(job.tenant_id.as_str())
        .bind(job.site_id.as_str())
        .bind(job.candidate.artifact_id())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(StoreError::InvalidCommand)?;
        if row.try_get::<&str, _>("requested_event_id")? != job.intent_event_id.as_str()
            || !orphan_snapshot_matches(&row, &job.candidate)?
        {
            return Err(StoreError::CorruptData(
                "calibration_lineage_review_orphan_snapshot",
            ));
        }
        if row.try_get::<&str, _>("status")? == "deleted" {
            tx.commit().await?;
            return Ok(());
        }
        let committed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM xshield.calibration_lineage_review_artifacts
             WHERE artifact_id=$1 OR review_id=$2)",
        )
        .bind(job.candidate.artifact_id())
        .bind(job.candidate.review_id())
        .fetch_one(&mut *tx)
        .await?;
        if committed {
            return Err(StoreError::InvalidCommand);
        }
        let success = matches!(
            result,
            CalibrationLineageReviewOrphanPurgeResult::Deleted(_)
        );
        let event_id = retention_event_with_refs(
            &mut tx,
            &job.tenant_id,
            &job.site_id,
            &CalibrationLineageReviewId::parse(job.candidate.review_id()).map_err(|_| {
                StoreError::CorruptData("calibration_lineage_review_orphan_review_id")
            })?,
            &ArtifactId::parse(job.candidate.artifact_id()).map_err(|_| {
                StoreError::CorruptData("calibration_lineage_review_orphan_artifact_id")
            })?,
            job.candidate.expires_at(),
            if success {
                ORPHAN_DELETED_EVENT_TYPE
            } else {
                ORPHAN_FAILED_EVENT_TYPE
            },
            result.reason_code(),
            if success { "PASS" } else { "ERROR" },
            Some(&job.intent_event_id),
        )
        .await?;
        if success {
            sqlx::query(
                "UPDATE xshield.calibration_lineage_review_orphan_purges
                 SET status='deleted', completed_event_id=$4, completed_at=clock_timestamp()
                 WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3",
            )
            .bind(job.tenant_id.as_str())
            .bind(job.site_id.as_str())
            .bind(job.candidate.artifact_id())
            .bind(event_id.as_str())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}

async fn lock_lineage_review_identities(
    transaction: &mut Transaction<'_, Postgres>,
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
            .execute(&mut **transaction)
            .await?;
    }
    Ok(())
}

fn orphan_snapshot_matches(
    row: &sqlx::postgres::PgRow,
    candidate: &CalibrationLineageReviewOrphanCandidate,
) -> Result<bool, StoreError> {
    Ok(
        row.try_get::<&str, _>("review_id")? == candidate.review_id()
            && row.try_get::<&str, _>("sidecar_digest")? == candidate.sidecar_digest()
            && row.try_get::<i64, _>("observed_bytes")?
                == i64::try_from(candidate.observed_bytes()).map_err(|_| {
                    StoreError::NumericRange("calibration_lineage_review_orphan_bytes")
                })?
            && row.try_get::<i64, _>("observed_modified_seconds")?
                == i64::try_from(candidate.observed_modified().0).map_err(|_| {
                    StoreError::NumericRange("calibration_lineage_review_orphan_mtime")
                })?
            && row.try_get::<i32, _>("observed_modified_nanos")?
                == i32::try_from(candidate.observed_modified().1).map_err(|_| {
                    StoreError::NumericRange("calibration_lineage_review_orphan_mtime_nanos")
                })?
            && row.try_get::<DateTime<Utc>, _>("expires_at")?
                == DateTime::parse_from_rfc3339(candidate.expires_at())
                    .map_err(|_| StoreError::InvalidCommand)?
                    .with_timezone(&Utc),
    )
}

fn orphan_job_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<CalibrationLineageReviewOrphanPurgeJob, StoreError> {
    Ok(CalibrationLineageReviewOrphanPurgeJob {
        tenant_id: TenantId::parse(row.try_get::<&str, _>("tenant_id")?.to_owned())
            .map_err(|_| StoreError::CorruptData("calibration_lineage_review_orphan_tenant"))?,
        site_id: SiteId::parse(row.try_get::<&str, _>("site_id")?.to_owned())
            .map_err(|_| StoreError::CorruptData("calibration_lineage_review_orphan_site"))?,
        candidate: CalibrationLineageReviewOrphanCandidate::from_observation(
            row.try_get::<&str, _>("review_id")?.to_owned(),
            row.try_get::<&str, _>("artifact_id")?.to_owned(),
            row.try_get::<&str, _>("sidecar_digest")?.to_owned(),
            row.try_get::<DateTime<Utc>, _>("expires_at")?
                .to_rfc3339_opts(SecondsFormat::Millis, true),
            u64::try_from(row.try_get::<i64, _>("observed_bytes")?)
                .map_err(|_| StoreError::CorruptData("calibration_lineage_review_orphan_bytes"))?,
            u64::try_from(row.try_get::<i64, _>("observed_modified_seconds")?)
                .map_err(|_| StoreError::CorruptData("calibration_lineage_review_orphan_mtime"))?,
            u32::try_from(row.try_get::<i32, _>("observed_modified_nanos")?).map_err(|_| {
                StoreError::CorruptData("calibration_lineage_review_orphan_mtime_nanos")
            })?,
        )
        .map_err(|_| StoreError::CorruptData("calibration_lineage_review_orphan_observation"))?,
        intent_event_id: EventId::parse(row.try_get::<&str, _>("requested_event_id")?.to_owned())
            .map_err(|_| {
            StoreError::CorruptData("calibration_lineage_review_orphan_intent")
        })?,
    })
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn lineage_review_manifest(
    row: &sqlx::postgres::PgRow,
) -> Result<CalibrationLineageReviewEvidenceManifest, StoreError> {
    let manifest = CalibrationLineageReviewEvidenceManifest {
        schema_version: u8::try_from(row.try_get::<i16, _>("schema_version")?)
            .map_err(|_| StoreError::CorruptData("calibration_lineage_review_schema_version"))?,
        review_id: row.try_get("review_id")?,
        artifact_id: row.try_get("artifact_id")?,
        tenant_id: row.try_get("tenant_id")?,
        site_id: row.try_get("site_id")?,
        kind: row.try_get("kind")?,
        content_type: row.try_get("content_type")?,
        canonical_body_encoding: row.try_get("canonical_body_encoding")?,
        capture_status: row.try_get("capture_status")?,
        bytes_observed: u64::try_from(row.try_get::<i64, _>("bytes_observed")?)
            .map_err(|_| StoreError::CorruptData("calibration_lineage_review_bytes_observed"))?,
        bytes_saved: u64::try_from(row.try_get::<i64, _>("bytes_saved")?)
            .map_err(|_| StoreError::CorruptData("calibration_lineage_review_bytes_saved"))?,
        fidelity: parse_fidelity(row.try_get("fidelity")?)?,
        classification: parse_classification(row.try_get("classification")?)?,
        storage: EvidenceStorage {
            profile: row.try_get("storage_profile")?,
            locator: row.try_get("storage_locator")?,
            key_ref: Some(row.try_get("key_ref")?),
        },
        integrity: EvidenceIntegrity {
            algorithm: row.try_get("integrity_algorithm")?,
            digest: row.try_get("integrity_digest")?,
        },
        expires_at: row
            .try_get::<DateTime<Utc>, _>("expires_at")?
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    };
    manifest
        .validate_catalog_structure()
        .map_err(|_| StoreError::CorruptData("calibration_lineage_review_artifact"))?;
    Ok(manifest)
}

fn parse_fidelity(value: &str) -> Result<EvidenceFidelity, StoreError> {
    match value {
        "entity_exact" => Ok(EvidenceFidelity::EntityExact),
        _ => Err(StoreError::CorruptData(
            "calibration_lineage_review_fidelity",
        )),
    }
}

fn parse_classification(value: &str) -> Result<EvidenceClassification, StoreError> {
    match value {
        "RESTRICTED" => Ok(EvidenceClassification::Restricted),
        _ => Err(StoreError::CorruptData(
            "calibration_lineage_review_classification",
        )),
    }
}

async fn retention_event(
    tx: &mut Transaction<'_, Postgres>,
    manifest: &CalibrationLineageReviewEvidenceManifest,
    event_type: &str,
    reason_code: &str,
    outcome: &str,
    cause: Option<&EventId>,
) -> Result<EventId, StoreError> {
    let event_id =
        EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| StoreError::InvalidCommand)?;
    let review_id = CalibrationLineageReviewId::parse(&manifest.review_id)
        .map_err(|_| StoreError::CorruptData("calibration_lineage_review_id"))?;
    let artifact_id = ArtifactId::parse(&manifest.artifact_id)
        .map_err(|_| StoreError::CorruptData("calibration_lineage_review_artifact_id"))?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let now = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = review_id
        .as_str()
        .strip_prefix("calrev_")
        .ok_or(StoreError::CorruptData("calibration_lineage_review_id"))?
        .replace('-', "");
    if trace_id.len() != 32 {
        return Err(StoreError::CorruptData("calibration_lineage_review_trace"));
    }
    let envelope = json!({
        "schema_version":3, "event_id":event_id.as_str(), "event_type":event_type,
        "tenant_id":manifest.tenant_id, "site_id":manifest.site_id,
        "request_id":null, "trace_id":trace_id, "span_id":&trace_id[..16],
        "producer_id":"calibration-lineage-review-retention", "producer_boot_id":Uuid::now_v7().to_string(),
        "producer_seq":1, "request_seq":1, "occurred_at":now, "observed_at":now,
        "policy_revision":"calibration-retention-v1", "example_only":false,
        "evidence_refs":[artifact_id.as_str()],
        "cause_event_ids":cause.map(EventId::as_str).into_iter().collect::<Vec<_>>(),
        "payload":{"stage":"calibration_lineage_review_retention", "outcome":outcome,
            "reason_code":reason_code, "proof_kind":"deterministic", "confidence":null,
            "confidence_status":"not_applicable", "review_id":review_id.as_str(),
            "review_artifact_id":artifact_id.as_str(), "expires_at":manifest.expires_at,
            "retained_metadata":true},
        "sensitivity":"RESTRICTED",
        "integrity":{"state":"pending", "previous_hash":null, "event_hash":null}
    });
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(event_id.as_str())
    .bind(&manifest.tenant_id)
    .bind(&manifest.site_id)
    .bind(review_id.as_str())
    .bind(event_type)
    .bind(envelope)
    .execute(&mut **tx)
    .await?;
    Ok(event_id)
}

async fn ensure_retention_event(
    tx: &mut Transaction<'_, Postgres>,
    event_id: &EventId,
    tenant: &TenantId,
    site: &SiteId,
    review_id: &str,
    event_type: &str,
) -> Result<(), StoreError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM xshield.audit_outbox
         WHERE event_id=$1 AND tenant_id=$2 AND site_id=$3
           AND aggregate_ref=$4 AND event_type=$5)",
    )
    .bind(event_id.as_str())
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(review_id)
    .bind(event_type)
    .fetch_one(&mut **tx)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(StoreError::CorruptData(
            "calibration_lineage_review_orphan_intent_audit",
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn retention_event_with_refs(
    tx: &mut Transaction<'_, Postgres>,
    tenant: &TenantId,
    site: &SiteId,
    review_id: &CalibrationLineageReviewId,
    artifact_id: &ArtifactId,
    expires_at: &str,
    event_type: &str,
    reason_code: &str,
    outcome: &str,
    cause: Option<&EventId>,
) -> Result<EventId, StoreError> {
    let event_id =
        EventId::parse(format!("ev_{}", Uuid::now_v7())).map_err(|_| StoreError::InvalidCommand)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    let now = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let trace_id = review_id
        .as_str()
        .strip_prefix("calrev_")
        .ok_or(StoreError::CorruptData(
            "calibration_lineage_review_orphan_review_id",
        ))?
        .replace('-', "");
    let envelope = json!({
        "schema_version":3, "event_id":event_id.as_str(), "event_type":event_type,
        "tenant_id":tenant.as_str(), "site_id":site.as_str(), "request_id":null,
        "trace_id":trace_id, "span_id":&trace_id[..16],
        "producer_id":"calibration-lineage-review-retention", "producer_boot_id":Uuid::now_v7().to_string(),
        "producer_seq":1, "request_seq":1, "occurred_at":now, "observed_at":now,
        "policy_revision":"calibration-retention-v1", "example_only":false,
        "evidence_refs":[artifact_id.as_str()],
        "cause_event_ids":cause.map(EventId::as_str).into_iter().collect::<Vec<_>>(),
        "payload":{"stage":"calibration_lineage_review_retention", "outcome":outcome,
            "reason_code":reason_code, "proof_kind":"deterministic", "confidence":null,
            "confidence_status":"not_applicable", "review_id":review_id.as_str(),
            "review_artifact_id":artifact_id.as_str(), "expires_at":expires_at,
            "retained_metadata":true},
        "sensitivity":"RESTRICTED",
        "integrity":{"state":"pending", "previous_hash":null, "event_hash":null}
    });
    sqlx::query(
        "INSERT INTO xshield.audit_outbox
         (event_id, tenant_id, site_id, aggregate_ref, event_type, envelope)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(event_id.as_str())
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(review_id.as_str())
    .bind(event_type)
    .bind(envelope)
    .execute(&mut **tx)
    .await?;
    Ok(event_id)
}
