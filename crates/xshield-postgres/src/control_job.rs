//! Durable control-plane job state for bounded investigation work.
//!
//! The first job is a read-only case inventory. Its result is committed with
//! the job row, so a client never mistakes an in-memory task for durable work.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::domain::{CaseId, JobId, SiteId, TenantId};

const CASE_ANALYSIS_KIND: &str = "case_analysis";
const SUCCEEDED: &str = "succeeded";
const CHECKPOINT_COMPLETE: &str = "inventory_committed";
const COMPLETE_REASON: &str = "CONTROL_CASE_ANALYSIS_COMPLETE";

/// Validated input for one idempotent case-inventory analysis job.
pub struct CaseAnalysisJobCreate<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    case_id: &'a CaseId,
    owner: &'a str,
    job_id: &'a JobId,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
}

impl<'a> CaseAnalysisJobCreate<'a> {
    /// Validates scope, owner and the typed job/case identifiers.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an empty or unbounded owner.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        case_id: &'a CaseId,
        owner: &'a str,
        job_id: &'a JobId,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
    ) -> Result<Self, StoreError> {
        if owner.is_empty() || owner.len() > 256 || owner.chars().any(char::is_control) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            case_id,
            owner,
            job_id,
            idempotency_digest,
            request_digest,
        })
    }
}

/// Durable, redacted result of a control-plane job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlJobRecord {
    job_id: JobId,
    kind: &'static str,
    case_id: CaseId,
    status: &'static str,
    checkpoint: String,
    reason_code: String,
    retryable: bool,
    artifact_count: i64,
    active_artifact_count: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl ControlJobRecord {
    /// Returns the durable job identity.
    #[must_use]
    pub const fn job_id(&self) -> &JobId {
        &self.job_id
    }

    /// Returns the allowlisted job kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the case authorized for this job.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the current durable state.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the last durable checkpoint.
    #[must_use]
    pub fn checkpoint(&self) -> &str {
        &self.checkpoint
    }

    /// Returns the stable terminal or retry reason.
    #[must_use]
    pub fn reason_code(&self) -> &str {
        &self.reason_code
    }

    /// Returns whether retrying the job is safe and expected.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// Returns the total evidence references observed in the case snapshot.
    #[must_use]
    pub const fn artifact_count(&self) -> i64 {
        self.artifact_count
    }

    /// Returns references whose catalog row was active at the snapshot time.
    #[must_use]
    pub const fn active_artifact_count(&self) -> i64 {
        self.active_artifact_count
    }

    /// Returns the durable creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Returns the last state-update timestamp.
    #[must_use]
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Returns the terminal timestamp when the job completed.
    #[must_use]
    pub const fn completed_at(&self) -> Option<DateTime<Utc>> {
        self.completed_at
    }
}

/// Outcome of an idempotent case-analysis admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlJobWriteOutcome {
    /// A new job and its completed inventory snapshot were committed.
    Created(ControlJobRecord),
    /// The exact request was already committed.
    Existing(ControlJobRecord),
    /// The idempotency key was reused with a different case or request digest.
    Conflict,
    /// The case is not owned by the authenticated subject in this scope.
    TargetUnavailable,
}

impl PostgresIdentityStore {
    /// Commits one owner-scoped, idempotent case inventory job.
    ///
    /// The case ownership check and bounded aggregate run in the same
    /// transaction as the job insert. No evidence object or plaintext is read.
    ///
    /// # Errors
    /// Returns [`StoreError`] for a database failure or corrupt durable state.
    #[allow(clippy::too_many_lines)]
    pub async fn create_case_analysis_job(
        &self,
        command: CaseAnalysisJobCreate<'_>,
    ) -> Result<ControlJobWriteOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-control-job-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.owner)
        .execute(&mut *transaction)
        .await?;

        if let Some(outcome) = existing_job(&mut transaction, &command).await? {
            transaction.rollback().await?;
            return Ok(outcome);
        }

        let Some((case_status, artifact_count, active_artifact_count)) = sqlx::query(
            "SELECT case_record.status,
                    count(item.artifact_id)::bigint AS artifact_count,
                    count(item.artifact_id) FILTER (
                        WHERE catalog.status = 'active'
                          AND catalog.deleted_at IS NULL
                          AND catalog.expires_at > statement_timestamp()
                    )::bigint AS active_artifact_count
             FROM xshield.investigation_cases case_record
             LEFT JOIN xshield.case_items item
               ON item.tenant_id = case_record.tenant_id
              AND item.site_id = case_record.site_id
              AND item.case_id = case_record.case_id
             LEFT JOIN xshield.artifact_catalog catalog
               ON catalog.tenant_id = item.tenant_id
              AND catalog.site_id = item.site_id
              AND catalog.artifact_id = item.artifact_id
             WHERE case_record.tenant_id = $1 AND case_record.site_id = $2
               AND case_record.case_id = $3 AND case_record.owner_ref = $4
             GROUP BY case_record.status",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.case_id.as_str())
        .bind(command.owner)
        .fetch_optional(&mut *transaction)
        .await?
        .map(|row| {
            Ok::<_, StoreError>((
                row.try_get::<String, _>("status")?,
                row.try_get::<i64, _>("artifact_count")?,
                row.try_get::<i64, _>("active_artifact_count")?,
            ))
        })
        .transpose()?
        else {
            transaction.rollback().await?;
            return Ok(ControlJobWriteOutcome::TargetUnavailable);
        };

        if !matches!(case_status.as_str(), "open" | "closed")
            || artifact_count < 0
            || active_artifact_count < 0
            || active_artifact_count > artifact_count
        {
            return Err(StoreError::CorruptData("case_analysis_counts"));
        }

        let row = sqlx::query(
            "INSERT INTO xshield.control_jobs (
                tenant_id, site_id, job_id, kind, owner_ref, case_id,
                status, checkpoint, reason_code, retryable,
                artifact_count, active_artifact_count,
                idempotency_digest, request_digest,
                created_at, updated_at, completed_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6,
                'succeeded', $7, $8, false,
                $9, $10, $11, $12,
                statement_timestamp(), statement_timestamp(), statement_timestamp()
             )
             RETURNING job_id, kind, case_id, status, checkpoint, reason_code,
                       retryable, artifact_count, active_artifact_count,
                       created_at, updated_at, completed_at",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.job_id.as_str())
        .bind(CASE_ANALYSIS_KIND)
        .bind(command.owner)
        .bind(command.case_id.as_str())
        .bind(CHECKPOINT_COMPLETE)
        .bind(COMPLETE_REASON)
        .bind(artifact_count)
        .bind(active_artifact_count)
        .bind(command.idempotency_digest.as_slice())
        .bind(command.request_digest.as_slice())
        .fetch_one(&mut *transaction)
        .await?;
        let record = decode_job(&row)?;
        transaction.commit().await?;
        Ok(ControlJobWriteOutcome::Created(record))
    }

    /// Reads one job owned by the authenticated subject in the fixed scope.
    ///
    /// Missing and foreign jobs both return `None`, preventing an identifier
    /// probe from revealing another investigator's work.
    ///
    /// # Errors
    /// Returns [`StoreError`] for a database failure or corrupt visible row.
    pub async fn read_control_job(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        owner: &str,
        job_id: &JobId,
    ) -> Result<Option<ControlJobRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT job_id, kind, case_id, status, checkpoint, reason_code,
                    retryable, artifact_count, active_artifact_count,
                    created_at, updated_at, completed_at
             FROM xshield.control_jobs
             WHERE tenant_id = $1 AND site_id = $2
               AND owner_ref = $3 AND job_id = $4",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(owner)
        .bind(job_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_job(&row)).transpose()
    }
}

async fn existing_job(
    connection: &mut sqlx::PgConnection,
    command: &CaseAnalysisJobCreate<'_>,
) -> Result<Option<ControlJobWriteOutcome>, StoreError> {
    let row = sqlx::query(
        "SELECT job_id, kind, case_id, status, checkpoint, reason_code,
                retryable, artifact_count, active_artifact_count,
                created_at, updated_at, completed_at, request_digest
         FROM xshield.control_jobs
         WHERE tenant_id = $1 AND site_id = $2
           AND owner_ref = $3 AND idempotency_digest = $4",
    )
    .bind(command.tenant.as_str())
    .bind(command.site.as_str())
    .bind(command.owner)
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let record = decode_job(&row)?;
    let stored_request_digest: Vec<u8> = row.try_get("request_digest")?;
    if stored_request_digest.as_slice() != command.request_digest.as_slice() {
        return Ok(Some(ControlJobWriteOutcome::Conflict));
    }
    Ok(Some(ControlJobWriteOutcome::Existing(record)))
}

pub(crate) fn decode_job(row: &PgRow) -> Result<ControlJobRecord, StoreError> {
    let job_id = JobId::parse(row.try_get::<String, _>("job_id")?)
        .map_err(|_| StoreError::CorruptData("job_id"))?;
    let kind = row.try_get::<String, _>("kind")?;
    if kind != CASE_ANALYSIS_KIND {
        return Err(StoreError::CorruptData("job_kind"));
    }
    let case_id = CaseId::parse(row.try_get::<String, _>("case_id")?)
        .map_err(|_| StoreError::CorruptData("case_id"))?;
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "queued" => "queued",
        "running" => "running",
        SUCCEEDED => SUCCEEDED,
        "failed" => "failed",
        "cancelled" => "cancelled",
        _ => return Err(StoreError::CorruptData("job_status")),
    };
    let artifact_count = row.try_get::<i64, _>("artifact_count")?;
    let active_artifact_count = row.try_get::<i64, _>("active_artifact_count")?;
    if artifact_count < 0 || active_artifact_count < 0 || active_artifact_count > artifact_count {
        return Err(StoreError::CorruptData("job_counts"));
    }
    let checkpoint = row.try_get::<String, _>("checkpoint")?;
    let reason_code = row.try_get::<String, _>("reason_code")?;
    let completed_at = row.try_get::<Option<DateTime<Utc>>, _>("completed_at")?;
    if matches!(status, "queued" | "running") && completed_at.is_some()
        || matches!(status, "succeeded" | "failed" | "cancelled") && completed_at.is_none()
    {
        return Err(StoreError::CorruptData("job_completion"));
    }
    Ok(ControlJobRecord {
        job_id,
        kind: CASE_ANALYSIS_KIND,
        case_id,
        status,
        checkpoint,
        reason_code,
        retryable: row.try_get("retryable")?,
        artifact_count,
        active_artifact_count,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        completed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::CaseAnalysisJobCreate;
    use xshield_core::domain::{CaseId, JobId, SiteId, TenantId};

    #[test]
    fn analysis_command_rejects_unbounded_owner_and_keeps_typed_scope() {
        let tenant = TenantId::parse("tenant_demo").unwrap();
        let site = SiteId::parse("site_demo").unwrap();
        let case_id = CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000004").unwrap();
        let job_id = JobId::parse("job_018f2a3b-4c5d-7000-8000-00000000000e").unwrap();
        let idempotency = [1_u8; 32];
        let request = [2_u8; 32];
        assert!(
            CaseAnalysisJobCreate::new(
                &tenant,
                &site,
                &case_id,
                "operator-1",
                &job_id,
                &idempotency,
                &request,
            )
            .is_ok()
        );
        assert!(
            CaseAnalysisJobCreate::new(
                &tenant,
                &site,
                &case_id,
                "bad\nowner",
                &job_id,
                &idempotency,
                &request,
            )
            .is_err()
        );
    }
}
