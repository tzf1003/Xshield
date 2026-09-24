//! Durable, independently approved metadata-only investigation exports.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::{AssertSqlSafe, PgConnection, Row, postgres::PgRow};
use xshield_core::{
    domain::{ArtifactId, CaseId, ExportId, RequestId, SiteId, TenantId},
    investigation::InvestigationExportDraft,
};

const EXPORT_KIND: &str = "metadata_only";
const MAX_DOWNLOADS: i64 = 2;

/// Validated input for one idempotent export request.
pub struct InvestigationExportCreate<'a> {
    draft: &'a InvestigationExportDraft,
    idempotency_digest: &'a [u8; 32],
    request_digest: &'a [u8; 32],
}

impl<'a> InvestigationExportCreate<'a> {
    /// Binds an export request to its authenticated scope and digests.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the digest inputs are not
    /// exactly 32 bytes.
    pub fn new(
        draft: &'a InvestigationExportDraft,
        idempotency_digest: &'a [u8; 32],
        request_digest: &'a [u8; 32],
    ) -> Result<Self, StoreError> {
        if idempotency_digest.len() != 32 || request_digest.len() != 32 {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            draft,
            idempotency_digest,
            request_digest,
        })
    }
}

/// Validated terminal export decision.
pub struct InvestigationExportDecision<'a> {
    export_id: &'a ExportId,
    decided_by: &'a str,
    reason: &'a str,
    approval_digest: &'a [u8; 32],
    decision_request_digest: &'a [u8; 32],
    approve: bool,
    ttl_seconds: u32,
}

impl<'a> InvestigationExportDecision<'a> {
    /// Creates an approval or denial command with a bounded reason.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for unbounded text, digests, or
    /// approval lifetime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        export_id: &'a ExportId,
        decided_by: &'a str,
        reason: &'a str,
        approval_digest: &'a [u8; 32],
        decision_request_digest: &'a [u8; 32],
        approve: bool,
        ttl_seconds: u32,
    ) -> Result<Self, StoreError> {
        if decided_by.is_empty()
            || decided_by.len() > 256
            || decided_by.chars().any(char::is_control)
            || reason.is_empty()
            || reason.len() > 512
            || reason.trim() != reason
            || reason.chars().any(char::is_control)
            || approval_digest.len() != 32
            || decision_request_digest.len() != 32
            || approve && !(1..=86_400).contains(&ttl_seconds)
            || !approve && ttl_seconds != 0
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            export_id,
            decided_by,
            reason,
            approval_digest,
            decision_request_digest,
            approve,
            ttl_seconds,
        })
    }
}

/// Authenticated package metadata attached to a ready export.
pub struct InvestigationExportPackage<'a> {
    export_id: &'a ExportId,
    artifact_id: &'a ArtifactId,
    request_id: &'a RequestId,
    digest: &'a str,
    bytes: u64,
}

impl<'a> InvestigationExportPackage<'a> {
    /// Binds the encrypted package identity to one export row.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an empty or malformed
    /// package digest or an unrepresentable byte count.
    pub fn new(
        export_id: &'a ExportId,
        artifact_id: &'a ArtifactId,
        request_id: &'a RequestId,
        digest: &'a str,
        bytes: u64,
    ) -> Result<Self, StoreError> {
        if digest.len() != 64
            || digest.bytes().any(|byte| !byte.is_ascii_hexdigit())
            || digest.chars().any(char::is_uppercase)
            || i64::try_from(bytes).is_err()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            export_id,
            artifact_id,
            request_id,
            digest,
            bytes,
        })
    }
}

/// Durable export state visible to the control plane.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationExportRecord {
    export_id: ExportId,
    case_id: CaseId,
    requested_by: String,
    purpose: String,
    kind: &'static str,
    status: &'static str,
    decided_by: Option<String>,
    decided_at: Option<DateTime<Utc>>,
    decision_reason: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    package_artifact_id: Option<ArtifactId>,
    package_request_id: Option<RequestId>,
    package_digest: Option<String>,
    package_bytes: Option<u64>,
    download_count: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl InvestigationExportRecord {
    /// Returns the export identity.
    #[must_use]
    pub const fn export_id(&self) -> &ExportId {
        &self.export_id
    }

    /// Returns the associated case.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the authenticated requester.
    #[must_use]
    pub fn requested_by(&self) -> &str {
        &self.requested_by
    }

    /// Returns the original bounded purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Returns the fixed export scope.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the current durable status.
    #[must_use]
    pub const fn status(&self) -> &'static str {
        self.status
    }

    /// Returns the independent decision subject, if decided.
    #[must_use]
    pub fn decided_by(&self) -> Option<&str> {
        self.decided_by.as_deref()
    }

    /// Returns the decision timestamp, if decided.
    #[must_use]
    pub const fn decided_at(&self) -> Option<DateTime<Utc>> {
        self.decided_at
    }

    /// Returns the bounded decision reason, if decided.
    #[must_use]
    pub fn decision_reason(&self) -> Option<&str> {
        self.decision_reason.as_deref()
    }

    /// Returns the short-lived package deadline, if approved.
    #[must_use]
    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// Returns the encrypted package artifact identity, if ready.
    #[must_use]
    pub const fn package_artifact_id(&self) -> Option<&ArtifactId> {
        self.package_artifact_id.as_ref()
    }

    /// Returns the request identity bound into the package AAD, if ready.
    #[must_use]
    pub const fn package_request_id(&self) -> Option<&RequestId> {
        self.package_request_id.as_ref()
    }

    /// Returns the authenticated package digest, if ready.
    #[must_use]
    pub fn package_digest(&self) -> Option<&str> {
        self.package_digest.as_deref()
    }

    /// Returns encrypted package plaintext bytes, if ready.
    #[must_use]
    pub const fn package_bytes(&self) -> Option<u64> {
        self.package_bytes
    }

    /// Returns the number of claimed downloads.
    #[must_use]
    pub const fn download_count(&self) -> i64 {
        self.download_count
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
}

/// Package-safe case and catalog metadata captured at approval time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationExportSnapshot {
    case_id: CaseId,
    case_status: &'static str,
    purpose: String,
    created_at: DateTime<Utc>,
    artifacts: Vec<InvestigationExportArtifact>,
}

impl InvestigationExportSnapshot {
    /// Returns the case identity.
    #[must_use]
    pub const fn case_id(&self) -> &CaseId {
        &self.case_id
    }

    /// Returns the case status observed by the approval transaction.
    #[must_use]
    pub const fn case_status(&self) -> &'static str {
        self.case_status
    }

    /// Returns the case purpose.
    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Returns the case creation time.
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Returns bounded artifact metadata.
    #[must_use]
    pub fn artifacts(&self) -> &[InvestigationExportArtifact] {
        &self.artifacts
    }
}

/// One artifact summary included in an export package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvestigationExportArtifact {
    artifact_id: ArtifactId,
    availability: &'static str,
    request_id: Option<RequestId>,
    kind: Option<String>,
    content_type: Option<String>,
    classification: Option<&'static str>,
    bytes_saved: Option<u64>,
    integrity_digest: Option<String>,
    recorded_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

impl InvestigationExportArtifact {
    /// Returns the historical member identity.
    #[must_use]
    pub const fn artifact_id(&self) -> &ArtifactId {
        &self.artifact_id
    }

    /// Returns active, expired, deleted, or unavailable catalog state.
    #[must_use]
    pub const fn availability(&self) -> &'static str {
        self.availability
    }

    /// Returns the source request when catalog metadata remains available.
    #[must_use]
    pub const fn request_id(&self) -> Option<&RequestId> {
        self.request_id.as_ref()
    }

    /// Returns the versioned artifact kind.
    #[must_use]
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Returns the safe media type.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Returns the catalog classification.
    #[must_use]
    pub const fn classification(&self) -> Option<&'static str> {
        self.classification
    }

    /// Returns plaintext bytes recorded by the catalog.
    #[must_use]
    pub const fn bytes_saved(&self) -> Option<u64> {
        self.bytes_saved
    }

    /// Returns the catalog ciphertext digest, not plaintext.
    #[must_use]
    pub fn integrity_digest(&self) -> Option<&str> {
        self.integrity_digest.as_deref()
    }

    /// Returns when the catalog observed the object.
    #[must_use]
    pub const fn recorded_at(&self) -> Option<DateTime<Utc>> {
        self.recorded_at
    }

    /// Returns the object deadline.
    #[must_use]
    pub const fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }
}

/// Result of an idempotent export request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvestigationExportWriteOutcome {
    /// A new pending approval was committed.
    Created(InvestigationExportRecord),
    /// The exact request was already committed.
    Existing(InvestigationExportRecord),
    /// The idempotency key was reused with different parameters.
    Conflict,
    /// The owned case is not available in this scope.
    TargetUnavailable,
}

/// Result of one independent export decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvestigationExportDecisionOutcome {
    /// The decision changed the pending state.
    Decided(
        InvestigationExportRecord,
        Option<InvestigationExportSnapshot>,
    ),
    /// The exact decision was already committed.
    Existing(InvestigationExportRecord),
    /// The decision key was reused with different parameters.
    Conflict,
    /// The export is missing in this scope.
    TargetUnavailable,
    /// The requester attempted to decide their own export.
    SelfApproval,
    /// A different terminal decision already exists.
    AlreadyDecided(InvestigationExportRecord),
}

/// Result of attaching an encrypted package to an approved export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvestigationExportPackageOutcome {
    /// The package metadata was committed.
    Completed(InvestigationExportRecord),
    /// The package was already attached.
    Existing(InvestigationExportRecord),
    /// A ready export was submitted with different package metadata.
    Conflict,
    /// The export is not currently attachable.
    Unavailable,
}

impl PostgresIdentityStore {
    /// Creates one owner-scoped, idempotent pending export request.
    ///
    /// The case ownership check and row insert share an advisory lock. No
    /// evidence object or plaintext is read.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt visible state.
    pub async fn create_investigation_export(
        &self,
        command: InvestigationExportCreate<'_>,
    ) -> Result<InvestigationExportWriteOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;
        set_export_timeouts(&mut tx).await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-investigation-export-v1:' || $1 || ':' || $2 || ':' || $3, 0
             ))",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.requested_by())
        .execute(&mut *tx)
        .await?;
        if let Some(outcome) = existing_export(&mut tx, &command).await? {
            tx.rollback().await?;
            return Ok(outcome);
        }
        let case_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM xshield.investigation_cases
                 WHERE tenant_id = $1 AND site_id = $2 AND case_id = $3
                   AND owner_ref = $4 AND status IN ('open', 'closed')
             )",
        )
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.case_id().as_str())
        .bind(command.draft.requested_by())
        .fetch_one(&mut *tx)
        .await?;
        if !case_exists {
            tx.rollback().await?;
            return Ok(InvestigationExportWriteOutcome::TargetUnavailable);
        }
        let row = sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO xshield.investigation_exports (
                tenant_id, site_id, export_id, case_id, requested_by, purpose,
                kind, status, idempotency_digest, request_digest,
                created_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, '{EXPORT_KIND}',
                       'pending_approval', $7, $8,
                       clock_timestamp(), clock_timestamp())
             RETURNING {EXPORT_COLUMNS}"
        )))
        .bind(command.draft.tenant_id().as_str())
        .bind(command.draft.site_id().as_str())
        .bind(command.draft.export_id().as_str())
        .bind(command.draft.case_id().as_str())
        .bind(command.draft.requested_by())
        .bind(command.draft.purpose())
        .bind(command.idempotency_digest.as_slice())
        .bind(command.request_digest.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let record = decode_export(&row)?;
        tx.commit().await?;
        Ok(InvestigationExportWriteOutcome::Created(record))
    }

    /// Reads one export by exact tenant/site/export identity.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt durable state.
    pub async fn read_investigation_export(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        export_id: &ExportId,
    ) -> Result<Option<InvestigationExportRecord>, StoreError> {
        let row = sqlx::query(AssertSqlSafe(format!(
            "SELECT {EXPORT_COLUMNS} FROM xshield.investigation_exports
             WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3"
        )))
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(export_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_export(&row)).transpose()
    }

    /// Captures the same bounded case metadata needed to retry package
    /// generation after an approval transaction already committed.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt durable state.
    pub async fn snapshot_investigation_export(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        export_id: &ExportId,
    ) -> Result<Option<InvestigationExportSnapshot>, StoreError> {
        let row = sqlx::query(
            "SELECT case_id, requested_by FROM xshield.investigation_exports
             WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(export_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let case_id = CaseId::parse(row.try_get::<String, _>("case_id")?)
            .map_err(|_| StoreError::CorruptData("investigation_export_case_id"))?;
        let owner = row.try_get::<String, _>("requested_by")?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await?;
        set_export_timeouts(&mut tx).await?;
        let snapshot = snapshot_case(&mut tx, tenant, site, &case_id, &owner).await?;
        tx.commit().await?;
        Ok(snapshot)
    }

    /// Applies an independent approval or denial and returns the case snapshot
    /// that the approver saw. The requester can never decide their own export.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt durable state.
    pub async fn decide_investigation_export(
        &self,
        command: InvestigationExportDecision<'_>,
        tenant: &TenantId,
        site: &SiteId,
    ) -> Result<InvestigationExportDecisionOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;
        set_export_timeouts(&mut tx).await?;
        let row = sqlx::query(AssertSqlSafe(format!(
            "SELECT {EXPORT_COLUMNS}, approval_digest, decision_request_digest
             FROM xshield.investigation_exports
             WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3
             FOR UPDATE"
        )))
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(command.export_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(InvestigationExportDecisionOutcome::TargetUnavailable);
        };
        let record = decode_export(&row)?;
        if record.requested_by() == command.decided_by {
            tx.rollback().await?;
            return Ok(InvestigationExportDecisionOutcome::SelfApproval);
        }
        let stored_approval = row.try_get::<Option<Vec<u8>>, _>("approval_digest")?;
        let stored_request = row.try_get::<Option<Vec<u8>>, _>("decision_request_digest")?;
        if let (Some(approval), Some(request)) = (stored_approval, stored_request) {
            tx.rollback().await?;
            return Ok(
                if approval.as_slice() == command.approval_digest.as_slice()
                    && request.as_slice() == command.decision_request_digest.as_slice()
                {
                    InvestigationExportDecisionOutcome::Existing(record)
                } else {
                    InvestigationExportDecisionOutcome::Conflict
                },
            );
        }
        if record.status() != "pending_approval" {
            tx.rollback().await?;
            return Ok(InvestigationExportDecisionOutcome::AlreadyDecided(record));
        }
        if command.approve {
            let row = sqlx::query(AssertSqlSafe(format!(
                "UPDATE xshield.investigation_exports
                 SET status = 'approved', decided_by = $4, decided_at = clock_timestamp(),
                     decision_reason = $5,
                     expires_at = clock_timestamp() + ($6::bigint * interval '1 second'),
                     approval_digest = $7, decision_request_digest = $8,
                     updated_at = clock_timestamp()
                 WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3
                 RETURNING {EXPORT_COLUMNS}"
            )))
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(command.export_id.as_str())
            .bind(command.decided_by)
            .bind(command.reason)
            .bind(i64::from(command.ttl_seconds))
            .bind(command.approval_digest.as_slice())
            .bind(command.decision_request_digest.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            let record = decode_export(&row)?;
            let snapshot = snapshot_case(
                &mut tx,
                tenant,
                site,
                record.case_id(),
                record.requested_by(),
            )
            .await?
            .ok_or(StoreError::CorruptData("investigation_export_case"))?;
            tx.commit().await?;
            Ok(InvestigationExportDecisionOutcome::Decided(
                record,
                Some(snapshot),
            ))
        } else {
            let row = sqlx::query(AssertSqlSafe(format!(
                "UPDATE xshield.investigation_exports
                 SET status = 'rejected', decided_by = $4, decided_at = clock_timestamp(),
                     decision_reason = $5, approval_digest = $6,
                     decision_request_digest = $7, updated_at = clock_timestamp()
                 WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3
                 RETURNING {EXPORT_COLUMNS}"
            )))
            .bind(tenant.as_str())
            .bind(site.as_str())
            .bind(command.export_id.as_str())
            .bind(command.decided_by)
            .bind(command.reason)
            .bind(command.approval_digest.as_slice())
            .bind(command.decision_request_digest.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            let record = decode_export(&row)?;
            tx.commit().await?;
            Ok(InvestigationExportDecisionOutcome::Decided(record, None))
        }
    }

    /// Attaches a vault-backed package after an approval commit.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt durable state.
    pub async fn complete_investigation_export(
        &self,
        command: InvestigationExportPackage<'_>,
        tenant: &TenantId,
        site: &SiteId,
    ) -> Result<InvestigationExportPackageOutcome, StoreError> {
        let bytes =
            i64::try_from(command.bytes).map_err(|_| StoreError::NumericRange("package_bytes"))?;
        let row = sqlx::query(AssertSqlSafe(format!(
            "UPDATE xshield.investigation_exports
             SET status = 'ready', package_artifact_id = $4, package_request_id = $5,
                 package_digest = $6, package_bytes = $7, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3
               AND status = 'approved' AND expires_at > clock_timestamp()
               AND package_artifact_id IS NULL
             RETURNING {EXPORT_COLUMNS}"
        )))
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(command.export_id.as_str())
        .bind(command.artifact_id.as_str())
        .bind(command.request_id.as_str())
        .bind(command.digest)
        .bind(bytes)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            return Ok(InvestigationExportPackageOutcome::Completed(decode_export(
                &row,
            )?));
        }
        Ok(
            match self
                .read_investigation_export(tenant, site, command.export_id)
                .await?
            {
                Some(record) if record.status() == "ready" => {
                    let matches = record.package_artifact_id() == Some(command.artifact_id)
                        && record.package_request_id() == Some(command.request_id)
                        && record.package_digest() == Some(command.digest)
                        && record.package_bytes() == Some(command.bytes);
                    if matches {
                        InvestigationExportPackageOutcome::Existing(record)
                    } else {
                        InvestigationExportPackageOutcome::Conflict
                    }
                }
                _ => InvestigationExportPackageOutcome::Unavailable,
            },
        )
    }

    /// Claims one short-lived package download, bounded to two claims.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failure or corrupt durable state.
    pub async fn claim_investigation_export_download(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        export_id: &ExportId,
    ) -> Result<Option<InvestigationExportRecord>, StoreError> {
        let row = sqlx::query(AssertSqlSafe(format!(
            "UPDATE xshield.investigation_exports
             SET download_count = download_count + 1, updated_at = clock_timestamp()
             WHERE tenant_id = $1 AND site_id = $2 AND export_id = $3
               AND status = 'ready' AND expires_at > clock_timestamp()
               AND download_count < {MAX_DOWNLOADS}
             RETURNING {EXPORT_COLUMNS}"
        )))
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(export_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_export(&row)).transpose()
    }
}

async fn set_export_timeouts(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn existing_export(
    connection: &mut PgConnection,
    command: &InvestigationExportCreate<'_>,
) -> Result<Option<InvestigationExportWriteOutcome>, StoreError> {
    let row = sqlx::query(AssertSqlSafe(format!(
        "SELECT {EXPORT_COLUMNS}, request_digest
         FROM xshield.investigation_exports
         WHERE tenant_id = $1 AND site_id = $2 AND requested_by = $3
           AND idempotency_digest = $4"
    )))
    .bind(command.draft.tenant_id().as_str())
    .bind(command.draft.site_id().as_str())
    .bind(command.draft.requested_by())
    .bind(command.idempotency_digest.as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let record = decode_export(&row)?;
    let stored = row.try_get::<Vec<u8>, _>("request_digest")?;
    Ok(Some(
        if stored.as_slice() == command.request_digest.as_slice() {
            InvestigationExportWriteOutcome::Existing(record)
        } else {
            InvestigationExportWriteOutcome::Conflict
        },
    ))
}

#[allow(clippy::too_many_lines)]
async fn snapshot_case(
    connection: &mut PgConnection,
    tenant: &TenantId,
    site: &SiteId,
    case_id: &CaseId,
    owner: &str,
) -> Result<Option<InvestigationExportSnapshot>, StoreError> {
    let rows = sqlx::query(
        "SELECT case_record.case_id, case_record.status AS case_status,
                case_record.purpose, case_record.created_at,
                item.artifact_id AS member_artifact_id,
                catalog.request_id AS catalog_request_id,
                catalog.kind AS catalog_kind,
                catalog.content_type AS catalog_content_type,
                catalog.classification AS catalog_classification,
                catalog.bytes_saved AS catalog_bytes_saved,
                catalog.integrity_digest AS catalog_integrity_digest,
                catalog.recorded_at AS catalog_recorded_at,
                catalog.expires_at AS catalog_expires_at,
                catalog.status AS catalog_status,
                catalog.deleted_at AS catalog_deleted_at,
                statement_timestamp() AS as_of
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
         ORDER BY item.artifact_id
         LIMIT 129",
    )
    .bind(tenant.as_str())
    .bind(site.as_str())
    .bind(case_id.as_str())
    .bind(owner)
    .fetch_all(&mut *connection)
    .await?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    if rows.len() > 128 {
        return Err(StoreError::CorruptData("investigation_export_item_limit"));
    }
    let case = CaseId::parse(first.try_get::<String, _>("case_id")?)
        .map_err(|_| StoreError::CorruptData("investigation_export_case_id"))?;
    let case_status = match first.try_get::<String, _>("case_status")?.as_str() {
        "open" => "open",
        "closed" => "closed",
        _ => return Err(StoreError::CorruptData("investigation_export_case_status")),
    };
    let purpose = first.try_get::<String, _>("purpose")?;
    let created_at = first.try_get("created_at")?;
    let as_of: DateTime<Utc> = first.try_get("as_of")?;
    let mut artifacts = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(artifact) = row.try_get::<Option<String>, _>("member_artifact_id")? else {
            continue;
        };
        let artifact_id = ArtifactId::parse(artifact)
            .map_err(|_| StoreError::CorruptData("investigation_export_artifact_id"))?;
        let catalog_status = row.try_get::<Option<String>, _>("catalog_status")?;
        let deleted_at = row.try_get::<Option<DateTime<Utc>>, _>("catalog_deleted_at")?;
        let catalog_expires_at = row.try_get::<Option<DateTime<Utc>>, _>("catalog_expires_at")?;
        let availability = match (catalog_status.as_deref(), deleted_at, catalog_expires_at) {
            (None, _, _) => "unavailable",
            (Some("deleted"), _, _) => "deleted",
            (Some("active"), None, Some(expires)) if expires > as_of => "active",
            (Some("active"), _, Some(_)) => "expired",
            _ => {
                return Err(StoreError::CorruptData(
                    "investigation_export_catalog_status",
                ));
            }
        };
        let active = availability == "active";
        let request_id = row
            .try_get::<Option<String>, _>("catalog_request_id")?
            .map(|value| {
                RequestId::parse(value).map_err(|_| StoreError::CorruptData("export_request_id"))
            })
            .transpose()?;
        let bytes_saved = row
            .try_get::<Option<i64>, _>("catalog_bytes_saved")?
            .map(|value| u64::try_from(value).map_err(|_| StoreError::CorruptData("export_bytes")))
            .transpose()?;
        let digest = row.try_get::<Option<String>, _>("catalog_integrity_digest")?;
        if let Some(digest) = &digest
            && (digest.len() != 64 || digest.bytes().any(|byte| !byte.is_ascii_hexdigit()))
        {
            return Err(StoreError::CorruptData("export_digest"));
        }
        artifacts.push(InvestigationExportArtifact {
            artifact_id,
            availability,
            request_id: active.then_some(request_id).flatten(),
            kind: active.then(|| row.try_get("catalog_kind")).transpose()?,
            content_type: active
                .then(|| row.try_get("catalog_content_type"))
                .transpose()?,
            classification: active
                .then(|| {
                    row.try_get::<Option<String>, _>("catalog_classification")?
                        .map(|value| match value.as_str() {
                            "INTERNAL" => Ok("INTERNAL"),
                            "SENSITIVE" => Ok("SENSITIVE"),
                            "RESTRICTED" => Ok("RESTRICTED"),
                            _ => Err(StoreError::CorruptData("export_classification")),
                        })
                        .transpose()
                })
                .transpose()?
                .flatten(),
            bytes_saved: active.then_some(bytes_saved).flatten(),
            integrity_digest: active.then_some(digest).flatten(),
            recorded_at: active
                .then(|| row.try_get("catalog_recorded_at"))
                .transpose()?,
            expires_at: active.then_some(catalog_expires_at).flatten(),
        });
    }
    Ok(Some(InvestigationExportSnapshot {
        case_id: case,
        case_status,
        purpose,
        created_at,
        artifacts,
    }))
}

const EXPORT_COLUMNS: &str = "export_id, case_id, requested_by, purpose, kind, status,
    decided_by, decided_at, decision_reason, expires_at,
    package_artifact_id, package_request_id, package_digest, package_bytes,
    download_count, created_at, updated_at";

fn decode_export(row: &PgRow) -> Result<InvestigationExportRecord, StoreError> {
    let export_id = ExportId::parse(row.try_get::<String, _>("export_id")?)
        .map_err(|_| StoreError::CorruptData("export_id"))?;
    let case_id = CaseId::parse(row.try_get::<String, _>("case_id")?)
        .map_err(|_| StoreError::CorruptData("export_case_id"))?;
    let kind = row.try_get::<String, _>("kind")?;
    if kind != EXPORT_KIND {
        return Err(StoreError::CorruptData("export_kind"));
    }
    let status = match row.try_get::<String, _>("status")?.as_str() {
        "pending_approval" => "pending_approval",
        "approved" => "approved",
        "ready" => "ready",
        "rejected" => "rejected",
        "expired" => "expired",
        "failed" => "failed",
        _ => return Err(StoreError::CorruptData("export_status")),
    };
    let package_bytes = row
        .try_get::<Option<i64>, _>("package_bytes")?
        .map(|value| u64::try_from(value).map_err(|_| StoreError::CorruptData("package_bytes")))
        .transpose()?;
    let download_count = row.try_get::<i64, _>("download_count")?;
    if !(0..=MAX_DOWNLOADS).contains(&download_count) {
        return Err(StoreError::CorruptData("export_download_count"));
    }
    let package_artifact_id = row
        .try_get::<Option<String>, _>("package_artifact_id")?
        .map(|value| {
            ArtifactId::parse(value).map_err(|_| StoreError::CorruptData("package_artifact_id"))
        })
        .transpose()?;
    let package_request_id = row
        .try_get::<Option<String>, _>("package_request_id")?
        .map(|value| {
            RequestId::parse(value).map_err(|_| StoreError::CorruptData("package_request_id"))
        })
        .transpose()?;
    let package_digest = row.try_get::<Option<String>, _>("package_digest")?;
    if let Some(digest) = &package_digest
        && (digest.len() != 64 || digest.bytes().any(|byte| !byte.is_ascii_hexdigit()))
    {
        return Err(StoreError::CorruptData("package_digest"));
    }
    let record = InvestigationExportRecord {
        export_id,
        case_id,
        requested_by: row.try_get("requested_by")?,
        purpose: row.try_get("purpose")?,
        kind: EXPORT_KIND,
        status,
        decided_by: row.try_get("decided_by")?,
        decided_at: row.try_get("decided_at")?,
        decision_reason: row.try_get("decision_reason")?,
        expires_at: row.try_get("expires_at")?,
        package_artifact_id,
        package_request_id,
        package_digest,
        package_bytes,
        download_count,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    if record.status == "pending_approval"
        && (record.decided_by.is_some() || record.expires_at.is_some())
        || record.status == "ready"
            && (record.package_artifact_id.is_none()
                || record.package_request_id.is_none()
                || record.package_digest.is_none()
                || record.package_bytes.is_none())
        || record.status == "approved" && record.expires_at.is_none()
    {
        return Err(StoreError::CorruptData("export_state"));
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::{
        InvestigationExportCreate, InvestigationExportDecision, InvestigationExportPackage,
    };
    use xshield_core::{
        domain::{ArtifactId, CaseId, ExportId, RequestId, SiteId, TenantId},
        investigation::InvestigationExportDraft,
    };

    fn draft() -> InvestigationExportDraft {
        InvestigationExportDraft::new(
            ExportId::parse("export_018f2a3b-4c5d-7000-8000-000000000901").unwrap(),
            TenantId::parse("tenant_export").unwrap(),
            SiteId::parse("site_export").unwrap(),
            CaseId::parse("case_018f2a3b-4c5d-7000-8000-000000000902").unwrap(),
            "investigator-1",
            "metadata review",
        )
        .unwrap()
    }

    #[test]
    fn export_commands_keep_typed_scope_and_bounded_inputs() {
        let draft = draft();
        assert!(InvestigationExportCreate::new(&draft, &[1; 32], &[2; 32]).is_ok());
        let _decision = InvestigationExportDecision::new(
            draft.export_id(),
            "approver-1",
            "approved for incident review",
            &[3; 32],
            &[4; 32],
            true,
            900,
        )
        .unwrap();
        assert!(
            InvestigationExportDecision::new(
                draft.export_id(),
                "approver-1",
                " padded ",
                &[3; 32],
                &[4; 32],
                false,
                0,
            )
            .is_err()
        );
        let artifact = ArtifactId::parse("artifact_018f2a3b-4c5d-7000-8000-000000000903").unwrap();
        let request = RequestId::parse("req_018f2a3b-4c5d-7000-8000-000000000904").unwrap();
        assert!(
            InvestigationExportPackage::new(
                draft.export_id(),
                &artifact,
                &request,
                &"a".repeat(64),
                12,
            )
            .is_ok()
        );
    }
}
