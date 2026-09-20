//! Scoped identity-ledger observations for investigation, separate from admission.
//!
//! A bounded read-only snapshot projects lifecycle metadata only. Identity
//! material and credentials stay outside this adapter's result and SQL projection.

use crate::{
    BindingRecordStatus, PostgresIdentityStore, StoreError,
    grant_inspection::{epoch, time},
};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    domain::{AuthBindingId, SiteId, TenantId},
    identity::{AuthEpoch, CredentialGeneration},
};

/// Non-secret binding lifecycle observation, without credential verification.
///
/// This metadata is neither an authenticated identity snapshot nor an online
/// eligibility result. Expiry is observed independently of the stored label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingInspection {
    /// Database statement time for this single-snapshot observation.
    pub as_of: DateTime<Utc>,
    /// Exact identity within the authenticated tenant/site scope.
    pub binding_id: AuthBindingId,
    /// Current identity epoch, which invalidates qualifications when advanced.
    pub auth_epoch: AuthEpoch,
    /// Current credential generation counter, without credential material.
    pub credential_generation: CredentialGeneration,
    /// Stored lifecycle label, separate from time-based expiry.
    pub status: BindingRecordStatus,
    /// Server-side absolute binding expiry, without extending its lease.
    pub expires_at: DateTime<Utc>,
    /// Last recorded binding update; revocation may occur after expiry.
    pub updated_at: DateTime<Utc>,
}

impl PostgresIdentityStore {
    /// Reads one scoped binding's lifecycle metadata in a read-only snapshot.
    ///
    /// Missing and foreign-scope IDs return `None`; revoked, expired and anonymous
    /// bindings remain observable. No business row is locked, changed or renewed.
    /// Statement and lock waits are bounded to five seconds, and cancellation
    /// rolls back the read. The caller authenticates scope, bounds total runtime,
    /// and durably audits access before releasing any result.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or malformed stored metadata.
    pub async fn read_binding_summary(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        binding: &AuthBindingId,
    ) -> Result<Option<BindingInspection>, StoreError> {
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
        let row = sqlx::query(
            "SELECT statement_timestamp() AS as_of, binding_id, auth_epoch,
                    credential_generation, status, absolute_expires_at AS expires_at,
                    updated_at,
                    (isfinite(absolute_expires_at) AND isfinite(updated_at)) AS finite_timestamps
             FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(binding.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let summary = row
            .as_ref()
            .map(decode_summary)
            .transpose()
            .map_err(|error| match error {
                StoreError::Database(_) => StoreError::CorruptData("binding_inspection_row"),
                other => other,
            });
        tx.rollback().await?;
        summary
    }
}

fn decode_summary(row: &PgRow) -> Result<BindingInspection, StoreError> {
    if !row.try_get::<bool, _>("finite_timestamps")? {
        return Err(StoreError::CorruptData("binding_inspection_time"));
    }
    let summary = BindingInspection {
        as_of: time(row, "as_of")?,
        binding_id: AuthBindingId::parse(row.try_get::<&str, _>("binding_id")?)
            .map_err(|_| StoreError::CorruptData("binding_id"))?,
        auth_epoch: epoch(row, "auth_epoch")?,
        credential_generation: u64::try_from(row.try_get::<i64, _>("credential_generation")?)
            .map(CredentialGeneration::new)
            .map_err(|_| StoreError::CorruptData("credential_generation"))?,
        status: BindingRecordStatus::parse(row.try_get("status")?)?,
        expires_at: time(row, "expires_at")?,
        updated_at: time(row, "updated_at")?,
    };
    // Anonymous establishment persists zero counters; authenticated establishment
    // starts both at one. Revocation/expiry may retain either kind of history.
    let epoch = summary.auth_epoch.value();
    let generation = summary.credential_generation.value();
    if (summary.status == BindingRecordStatus::Anonymous && (epoch != 0 || generation != 0))
        || (summary.status == BindingRecordStatus::Active && (epoch == 0 || generation == 0))
    {
        return Err(StoreError::CorruptData("binding_inspection_generation"));
    }
    Ok(summary)
}
