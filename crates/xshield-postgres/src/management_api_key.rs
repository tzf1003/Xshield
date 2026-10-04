//! Persistence for tenant/site scoped management API keys.
//!
//! Lifecycle changes are staged inside an open transaction and become visible
//! only on [`PendingManagementApiKeyChange::commit`]. The control plane appends
//! the change's audit record between staging and commit, so a key can never be
//! created, revoked or rotated without its durable audit event, and a rotation
//! either swaps both keys or neither.
#![allow(clippy::missing_errors_doc)]

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::Row;

/// One database scope row belonging to an authenticated management key.
#[allow(missing_docs)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementApiKeyScope {
    pub api_key_id: String,
    pub subject: String,
    pub tenant_id: String,
    pub site_id: String,
    pub capability: String,
    pub expires_at: DateTime<Utc>,
}

/// Non-secret management key metadata returned by list operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementApiKeyRecord {
    /// Stable key identifier.
    pub api_key_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Agent subject.
    pub subject: String,
    /// Human-readable label.
    pub display_name: String,
    /// Non-secret display prefix.
    pub key_prefix: String,
    /// Lifecycle state.
    pub status: String,
    /// Expiry time.
    pub expires_at: DateTime<Utc>,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last use time, stamped at most once per minute.
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Scope requested when issuing a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementApiKeyScopeInput {
    /// Tenant scope.
    pub tenant_id: String,
    /// Site scope.
    pub site_id: String,
    /// Capability name.
    pub capability: String,
}

/// A new key and its exact scopes, persisted together.
///
/// The caller has already validated every field; only the keyed fingerprint of
/// the secret is stored, never the secret.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub struct NewManagementApiKey<'a> {
    pub api_key_id: &'a str,
    pub tenant_id: &'a str,
    pub subject: &'a str,
    pub display_name: &'a str,
    pub key_prefix: &'a str,
    pub fingerprint: &'a [u8; 32],
    pub expires_at: DateTime<Utc>,
    pub created_by: &'a str,
    pub scopes: &'a [ManagementApiKeyScopeInput],
}

/// A key lifecycle change staged in an open transaction.
///
/// Nothing is visible to other connections until [`Self::commit`]. Dropping the
/// value, or any error before commit, rolls the whole change back.
#[derive(Debug)]
pub struct PendingManagementApiKeyChange {
    tx: sqlx::Transaction<'static, sqlx::Postgres>,
}

impl PendingManagementApiKeyChange {
    /// Makes the staged change visible.
    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }
}

async fn insert_key(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    key: &NewManagementApiKey<'_>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.management_api_keys
         (api_key_id, tenant_id, subject, display_name, key_prefix, fingerprint, status, expires_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8)",
    )
    .bind(key.api_key_id)
    .bind(key.tenant_id)
    .bind(key.subject)
    .bind(key.display_name)
    .bind(key.key_prefix)
    .bind(key.fingerprint.as_slice())
    .bind(key.expires_at)
    .bind(key.created_by)
    .execute(&mut **tx)
    .await?;
    for scope in key.scopes {
        sqlx::query(
            "INSERT INTO xshield.management_api_key_scopes
             (api_key_id, tenant_id, site_id, capability)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(key.api_key_id)
        .bind(&scope.tenant_id)
        .bind(&scope.site_id)
        .bind(&scope.capability)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Revokes one active key of the tenant; `false` when there is none. The row
/// lock taken here serializes concurrent revocations and rotations.
async fn revoke_active_key(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    tenant_id: &str,
    api_key_id: &str,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        "UPDATE xshield.management_api_keys
         SET status = 'revoked', revoked_at = clock_timestamp()
         WHERE tenant_id = $1 AND api_key_id = $2 AND status = 'active'",
    )
    .bind(tenant_id)
    .bind(api_key_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

impl PostgresIdentityStore {
    /// Stages a key and all of its exact scopes.
    pub async fn stage_create_management_api_key(
        &self,
        key: &NewManagementApiKey<'_>,
    ) -> Result<PendingManagementApiKeyChange, StoreError> {
        let mut tx = self.pool.begin().await?;
        insert_key(&mut tx, key).await?;
        Ok(PendingManagementApiKeyChange { tx })
    }

    /// Stages the revocation of one active key; `None` when the tenant has no
    /// such active key (unknown, foreign or already revoked).
    pub async fn stage_revoke_management_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> Result<Option<PendingManagementApiKeyChange>, StoreError> {
        let mut tx = self.pool.begin().await?;
        if !revoke_active_key(&mut tx, tenant_id, api_key_id).await? {
            return Ok(None);
        }
        Ok(Some(PendingManagementApiKeyChange { tx }))
    }

    /// Stages revoking `old_api_key_id` and issuing `replacement` as one change.
    /// `None` when the tenant has no such active key; then nothing is staged,
    /// so a rotation can never leave the old key dead without a replacement.
    pub async fn stage_rotate_management_api_key(
        &self,
        old_api_key_id: &str,
        replacement: &NewManagementApiKey<'_>,
    ) -> Result<Option<PendingManagementApiKeyChange>, StoreError> {
        let mut tx = self.pool.begin().await?;
        if !revoke_active_key(&mut tx, replacement.tenant_id, old_api_key_id).await? {
            return Ok(None);
        }
        insert_key(&mut tx, replacement).await?;
        Ok(Some(PendingManagementApiKeyChange { tx }))
    }

    /// Lists key metadata for one tenant without returning secret material.
    pub async fn list_management_api_keys(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManagementApiKeyRecord>, StoreError> {
        let rows = sqlx::query(
            "SELECT api_key_id, tenant_id, subject, display_name, key_prefix, status,
                    expires_at, created_at, last_used_at
             FROM xshield.management_api_keys WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ManagementApiKeyRecord {
                    api_key_id: row.try_get("api_key_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    subject: row.try_get("subject")?,
                    display_name: row.try_get("display_name")?,
                    key_prefix: row.try_get("key_prefix")?,
                    status: row.try_get("status")?,
                    expires_at: row.try_get("expires_at")?,
                    created_at: row.try_get("created_at")?,
                    last_used_at: row.try_get("last_used_at")?,
                })
            })
            .collect()
    }

    /// Loads all active scopes for a keyed management identity.
    ///
    /// A scope row is returned only when it names the key's own tenant: the
    /// schema does not tie the two together, so the join does.
    pub async fn lookup_management_api_key_scopes(
        &self,
        fingerprint: &[u8; 32],
        tenant_id: &str,
    ) -> Result<Vec<ManagementApiKeyScope>, StoreError> {
        let rows = sqlx::query(
            "SELECT k.api_key_id, k.subject, s.tenant_id, s.site_id,
                    s.capability, k.expires_at
             FROM xshield.management_api_keys k
             JOIN xshield.management_api_key_scopes s
               ON s.api_key_id = k.api_key_id AND s.tenant_id = k.tenant_id
             WHERE k.tenant_id = $1 AND k.fingerprint = $2 AND k.status = 'active'
               AND k.expires_at > clock_timestamp()",
        )
        .bind(tenant_id)
        .bind(fingerprint.as_slice())
        .fetch_all(&self.pool)
        .await?;
        let mut scopes = Vec::with_capacity(rows.len());
        for row in rows {
            scopes.push(ManagementApiKeyScope {
                api_key_id: row.try_get("api_key_id")?,
                subject: row.try_get("subject")?,
                tenant_id: row.try_get("tenant_id")?,
                site_id: row.try_get("site_id")?,
                capability: row.try_get("capability")?,
                expires_at: row.try_get("expires_at")?,
            });
        }
        Ok(scopes)
    }

    /// Stamps `last_used_at` for an active key, at most once per minute.
    ///
    /// The throttle lives in the statement, so every control instance shares it
    /// and the authentication path normally issues an UPDATE that matches no
    /// row and writes nothing. Returns whether the stamp was written.
    pub async fn touch_management_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE xshield.management_api_keys
             SET last_used_at = clock_timestamp()
             WHERE tenant_id = $1 AND api_key_id = $2 AND status = 'active'
               AND (last_used_at IS NULL
                    OR last_used_at < clock_timestamp() - interval '1 minute')",
        )
        .bind(tenant_id)
        .bind(api_key_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }
}
