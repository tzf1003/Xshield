//! Case-scoped evidence retention holds.
//!
//! Holds postpone physical removal for an existing case membership. The caller
//! authenticates `AuditAdministrator` scope and audits each attempt. Successful
//! transitions commit with outbox facts; read deadlines remain immutable.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row};
use xshield_core::domain::{ArtifactId, CaseId, EventId, SiteId, TenantId};

/// Maximum lifetime accepted for one hold.
pub const CASE_EVIDENCE_HOLD_MAX_DAYS: i64 = 30;
/// Lifetime history bound per case, including expired and released holds.
pub const CASE_EVIDENCE_HOLD_HISTORY_MAX: i64 = 128;
/// Maximum simultaneous active holds per tenant/site.
pub const CASE_EVIDENCE_HOLD_ACTIVE_MAX: i64 = 1_000;

mod record;
use record::{decode_hold, insert_event, verify_events};

/// Validated request to create or replay a case evidence hold.
pub struct CaseEvidenceHoldCreate<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    case_id: &'a CaseId,
    artifact_id: &'a ArtifactId,
    created_by: &'a str,
    reason: &'a str,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    created_event_id: &'a EventId,
    hold_until: DateTime<Utc>,
}

impl<'a> CaseEvidenceHoldCreate<'a> {
    /// Validates scope, bounded reason and a finite hold interval.
    ///
    /// The transaction checks the deadline against its database clock. An
    /// expired object may be held until deletion intent has been committed.
    /// Construction has no storage or audit effects. The caller authenticates
    /// the actor as `AuditAdministrator` for this exact scope.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for unbounded text or an invalid
    /// timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        case_id: &'a CaseId,
        artifact_id: &'a ArtifactId,
        created_by: &'a str,
        reason: &'a str,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        created_event_id: &'a EventId,
        hold_until: DateTime<Utc>,
    ) -> Result<Self, StoreError> {
        if !valid_text(created_by, 256) || !valid_text(reason, 512) || !valid_time(hold_until) {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            case_id,
            artifact_id,
            created_by,
            reason,
            idempotency_digest,
            request_digest,
            created_event_id,
            hold_until,
        })
    }
}

/// Validated request to release an existing hold.
pub struct CaseEvidenceHoldRelease<'a> {
    tenant: &'a TenantId,
    site: &'a SiteId,
    created_event_id: &'a EventId,
    released_by: &'a str,
    reason: &'a str,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
    released_event_id: &'a EventId,
}

impl<'a> CaseEvidenceHoldRelease<'a> {
    /// Validates the bounded release reason and identity fields.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for unbounded text.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &'a TenantId,
        site: &'a SiteId,
        created_event_id: &'a EventId,
        released_by: &'a str,
        reason: &'a str,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
        released_event_id: &'a EventId,
    ) -> Result<Self, StoreError> {
        if !valid_text(released_by, 256)
            || !valid_text(reason, 512)
            || created_event_id == released_event_id
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant,
            site,
            created_event_id,
            released_by,
            reason,
            idempotency_digest,
            request_digest,
            released_event_id,
        })
    }
}

/// Durable hold metadata with no content or key locator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseEvidenceHoldRecord {
    /// The immutable creation event and hold identity.
    pub created_event_id: EventId,
    /// Scope and target case.
    pub tenant_id: TenantId,
    /// Scope site.
    pub site_id: SiteId,
    /// Target case.
    pub case_id: CaseId,
    /// Target artifact.
    pub artifact_id: ArtifactId,
    /// Creating principal reference.
    pub created_by: String,
    /// Operator reason.
    pub reason: String,
    /// Database creation time.
    pub created_at: DateTime<Utc>,
    /// Absolute hold deadline.
    pub hold_until: DateTime<Utc>,
    /// Release event, if released.
    pub released_event_id: Option<EventId>,
    /// Releasing principal, if released.
    pub released_by: Option<String>,
    /// Release reason, if released.
    pub released_reason: Option<String>,
    /// Release database time, if released.
    pub released_at: Option<DateTime<Utc>>,
}

/// Result of an idempotent hold creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseEvidenceHoldCreateOutcome {
    /// A new active hold was committed.
    Created(CaseEvidenceHoldRecord),
    /// The exact idempotency request was already committed.
    Existing(CaseEvidenceHoldRecord),
    /// The idempotency key or target is bound to different parameters.
    Conflict,
    /// Case membership/catalog state cannot support a new hold.
    TargetUnavailable,
    /// Per-case history or per-scope active capacity is exhausted.
    CapacityExceeded,
}

/// Result of an idempotent hold release.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseEvidenceHoldReleaseOutcome {
    /// A hold was released now.
    Released(CaseEvidenceHoldRecord),
    /// The exact release request was already committed.
    Existing(CaseEvidenceHoldRecord),
    /// The release key is bound to different parameters.
    Conflict,
    /// The hold does not exist in this scope.
    NotFound,
}

impl PostgresIdentityStore {
    /// Creates a bounded hold with an atomic outbox fact.
    ///
    /// Locks scope, case, then catalog. The catalog lock serializes deletion
    /// intent and creation; membership changes serialize on the case lock.
    /// Historical retries return their original record without extending it.
    ///
    /// # Errors
    /// Returns `InvalidCommand` for invalid deadlines, or [`StoreError`] for database
    /// failures/corrupt rows. Statements and lock waits are capped at five seconds.
    pub async fn create_case_evidence_hold(
        &self,
        command: CaseEvidenceHoldCreate<'_>,
    ) -> Result<CaseEvidenceHoldCreateOutcome, StoreError> {
        let mut tx = self.retention_transaction().await?;
        lock_scope(&mut tx, command.tenant, command.site).await?;
        if let Some(existing) = existing_create(&mut tx, &command).await? {
            tx.rollback().await?;
            return Ok(existing);
        }
        let case_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM xshield.investigation_cases WHERE tenant_id=$1 AND site_id=$2 AND case_id=$3 FOR UPDATE")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.case_id.as_str())
            .fetch_optional(&mut *tx).await?;
        let membership: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM xshield.case_items WHERE tenant_id=$1 AND site_id=$2 AND case_id=$3 AND artifact_id=$4)")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.case_id.as_str())
            .bind(command.artifact_id.as_str()).fetch_one(&mut *tx).await?;
        if case_status.as_deref() != Some("open") || !membership {
            tx.rollback().await?;
            return Ok(CaseEvidenceHoldCreateOutcome::TargetUnavailable);
        }
        let catalog = sqlx::query(
            "SELECT status, deleted_at, purge_requested_event_id FROM xshield.artifact_catalog
             WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3 FOR UPDATE",
        )
        .bind(command.tenant.as_str())
        .bind(command.site.as_str())
        .bind(command.artifact_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let available = catalog
            .as_ref()
            .map(|row| -> Result<bool, StoreError> {
                Ok(row.try_get::<&str, _>("status")? == "active"
                    && row
                        .try_get::<Option<DateTime<Utc>>, _>("deleted_at")?
                        .is_none()
                    && row
                        .try_get::<Option<String>, _>("purge_requested_event_id")?
                        .is_none())
            })
            .transpose()?
            .unwrap_or(false);
        if !available {
            tx.rollback().await?;
            return Ok(CaseEvidenceHoldCreateOutcome::TargetUnavailable);
        }
        // Expired holds retain their identity until explicitly released.
        let occupied: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM xshield.case_evidence_holds
             WHERE tenant_id=$1 AND site_id=$2 AND case_id=$3 AND artifact_id=$4 AND released_at IS NULL)")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.case_id.as_str())
            .bind(command.artifact_id.as_str()).fetch_one(&mut *tx).await?;
        if occupied {
            tx.rollback().await?;
            return Ok(CaseEvidenceHoldCreateOutcome::Conflict);
        }
        let counts = sqlx::query(
            "SELECT count(*) FILTER (WHERE case_id=$3) AS history,
                    count(*) FILTER (WHERE released_at IS NULL AND hold_until>clock_timestamp()) AS active
             FROM xshield.case_evidence_holds WHERE tenant_id=$1 AND site_id=$2")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.case_id.as_str())
            .fetch_one(&mut *tx).await?;
        if counts.try_get::<i64, _>("history")? >= CASE_EVIDENCE_HOLD_HISTORY_MAX
            || counts.try_get::<i64, _>("active")? >= CASE_EVIDENCE_HOLD_ACTIVE_MAX
        {
            tx.rollback().await?;
            return Ok(CaseEvidenceHoldCreateOutcome::CapacityExceeded);
        }
        let valid_until: bool = sqlx::query_scalar(
            "SELECT $1::timestamptz > clock_timestamp()
             AND $1::timestamptz <= date_trunc('milliseconds', clock_timestamp()) + interval '720 hours'")
            .bind(command.hold_until).fetch_one(&mut *tx).await?;
        if !valid_until {
            return Err(StoreError::InvalidCommand);
        }
        let row = sqlx::query(
            "INSERT INTO xshield.case_evidence_holds
             (tenant_id,site_id,case_id,artifact_id,created_event_id,created_by,reason,hold_until,idempotency_digest,request_digest)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.case_id.as_str())
            .bind(command.artifact_id.as_str()).bind(command.created_event_id.as_str()).bind(command.created_by)
            .bind(command.reason).bind(command.hold_until).bind(command.idempotency_digest.as_slice())
            .bind(command.request_digest.as_slice()).fetch_one(&mut *tx).await?;
        let record = decode_hold(&row)?;
        insert_event(&mut tx, &row, false).await?;
        // An outbox uniqueness wait can consume the remaining hold lifetime.
        let still_active: bool = sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
            .bind(record.hold_until)
            .fetch_one(&mut *tx)
            .await?;
        if !still_active {
            return Err(StoreError::InvalidCommand);
        }
        tx.commit().await?;
        Ok(CaseEvidenceHoldCreateOutcome::Created(record))
    }

    /// Releases a hold atomically with its audit fact, including expired holds
    /// or closed cases. The caller authenticates the exact administrator scope.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or inconsistent durable facts.
    /// Statement and lock waits are bounded to five seconds.
    pub async fn release_case_evidence_hold(
        &self,
        command: CaseEvidenceHoldRelease<'_>,
    ) -> Result<CaseEvidenceHoldReleaseOutcome, StoreError> {
        let mut tx = self.retention_transaction().await?;
        lock_scope(&mut tx, command.tenant, command.site).await?;
        let key_owner: Option<String> = sqlx::query_scalar(
            "SELECT created_event_id FROM xshield.case_evidence_holds
             WHERE tenant_id=$1 AND site_id=$2 AND released_by=$3 AND release_idempotency_digest=$4")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.released_by)
            .bind(command.idempotency_digest.as_slice()).fetch_optional(&mut *tx).await?;
        if key_owner
            .as_deref()
            .is_some_and(|id| id != command.created_event_id.as_str())
        {
            tx.rollback().await?;
            return Ok(CaseEvidenceHoldReleaseOutcome::Conflict);
        }
        let row = sqlx::query(
            "SELECT * FROM xshield.case_evidence_holds WHERE tenant_id=$1 AND site_id=$2 AND created_event_id=$3")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.created_event_id.as_str())
            .fetch_optional(&mut *tx).await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(CaseEvidenceHoldReleaseOutcome::NotFound);
        };
        let record = decode_hold(&row)?;
        verify_events(&mut tx, &row).await?;
        sqlx::query("SELECT 1 FROM xshield.investigation_cases WHERE tenant_id=$1 AND site_id=$2 AND case_id=$3 FOR UPDATE")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(record.case_id.as_str())
            .fetch_one(&mut *tx).await?;
        sqlx::query("SELECT 1 FROM xshield.artifact_catalog WHERE tenant_id=$1 AND site_id=$2 AND artifact_id=$3 FOR UPDATE")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(record.artifact_id.as_str())
            .fetch_one(&mut *tx).await?;
        if record.released_at.is_some() {
            let same = row
                .try_get::<Vec<u8>, _>("release_idempotency_digest")?
                .as_slice()
                == command.idempotency_digest
                && row
                    .try_get::<Vec<u8>, _>("release_request_digest")?
                    .as_slice()
                    == command.request_digest
                && record.released_by.as_deref() == Some(command.released_by)
                && record.released_reason.as_deref() == Some(command.reason);
            tx.rollback().await?;
            return Ok(if same {
                CaseEvidenceHoldReleaseOutcome::Existing(record)
            } else {
                CaseEvidenceHoldReleaseOutcome::Conflict
            });
        }
        let updated = sqlx::query(
            "UPDATE xshield.case_evidence_holds SET released_event_id=$4,released_by=$5,released_reason=$6,
             released_at=date_trunc('milliseconds', clock_timestamp()),release_idempotency_digest=$7,release_request_digest=$8
             WHERE tenant_id=$1 AND site_id=$2 AND created_event_id=$3 RETURNING *")
            .bind(command.tenant.as_str()).bind(command.site.as_str()).bind(command.created_event_id.as_str())
            .bind(command.released_event_id.as_str()).bind(command.released_by).bind(command.reason)
            .bind(command.idempotency_digest.as_slice()).bind(command.request_digest.as_slice())
            .fetch_one(&mut *tx).await?;
        let record = decode_hold(&updated)?;
        insert_event(&mut tx, &updated, true).await?;
        tx.commit().await?;
        Ok(CaseEvidenceHoldReleaseOutcome::Released(record))
    }
}

async fn lock_scope(
    connection: &mut PgConnection,
    tenant: &TenantId,
    site: &SiteId,
) -> Result<(), StoreError> {
    // ponytail: scope-wide serialization bounds capacity; shard the counter if
    // measured administrator-write throughput requires finer locking.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('xshield-case-hold-v1:' || $1 || ':' || $2, 0))")
        .bind(tenant.as_str()).bind(site.as_str()).execute(connection).await?;
    Ok(())
}

async fn existing_create(
    connection: &mut PgConnection,
    command: &CaseEvidenceHoldCreate<'_>,
) -> Result<Option<CaseEvidenceHoldCreateOutcome>, StoreError> {
    let row = sqlx::query(
        "SELECT * FROM xshield.case_evidence_holds
         WHERE tenant_id=$1 AND site_id=$2 AND created_by=$3 AND idempotency_digest=$4",
    )
    .bind(command.tenant.as_str())
    .bind(command.site.as_str())
    .bind(command.created_by)
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let record = decode_hold(&row)?;
    verify_events(connection, &row).await?;
    let same = record.case_id == *command.case_id
        && record.artifact_id == *command.artifact_id
        && record.reason == command.reason
        && record.hold_until == command.hold_until
        && row.try_get::<Vec<u8>, _>("request_digest")?.as_slice() == command.request_digest;
    Ok(Some(if same {
        CaseEvidenceHoldCreateOutcome::Existing(record)
    } else {
        CaseEvidenceHoldCreateOutcome::Conflict
    }))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_time(value: DateTime<Utc>) -> bool {
    value.timestamp() >= 0
        && value.timestamp_nanos_opt().is_some()
        && value.timestamp_subsec_nanos().is_multiple_of(1_000_000)
}
