//! Persistence for tenant/site scoped management API keys.
#![allow(clippy::missing_errors_doc, clippy::too_many_arguments)]

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::Row;

/// Authenticated API-key principal and its exact capability scope.
#[allow(missing_docs)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementApiKeyPrincipal {
    pub api_key_id: String,
    pub subject: String,
    pub tenant_id: String,
    pub site_id: String,
    pub capability: String,
    pub expires_at: DateTime<Utc>,
}

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
    /// Last use time.
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

impl PostgresIdentityStore {
    /// Inserts a key and all of its exact scopes in one transaction.
    pub async fn create_management_api_key(
        &self,
        api_key_id: &str,
        tenant_id: &str,
        subject: &str,
        display_name: &str,
        key_prefix: &str,
        fingerprint: &[u8; 32],
        expires_at: DateTime<Utc>,
        created_by: &str,
        scopes: &[ManagementApiKeyScopeInput],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO xshield.management_api_keys
             (api_key_id, tenant_id, subject, display_name, key_prefix, fingerprint, status, expires_at, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,'active',$7,$8)",
        )
        .bind(api_key_id)
        .bind(tenant_id)
        .bind(subject)
        .bind(display_name)
        .bind(key_prefix)
        .bind(fingerprint.as_slice())
        .bind(expires_at)
        .bind(created_by)
        .execute(&mut *tx)
        .await?;
        for scope in scopes {
            sqlx::query(
                "INSERT INTO xshield.management_api_key_scopes
                 (api_key_id, tenant_id, site_id, capability)
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(api_key_id)
            .bind(&scope.tenant_id)
            .bind(&scope.site_id)
            .bind(&scope.capability)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
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

    /// Revokes a key and returns whether it belonged to the tenant.
    pub async fn revoke_management_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
        revoked_by: &str,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(
            "UPDATE xshield.management_api_keys
             SET status = 'revoked', revoked_at = clock_timestamp()
             WHERE tenant_id = $1 AND api_key_id = $2 AND status = 'active'",
        )
        .bind(tenant_id)
        .bind(api_key_id)
        .execute(&self.pool)
        .await?;
        let _ = revoked_by;
        Ok(result.rows_affected() == 1)
    }
}

impl PostgresIdentityStore {
    /// Loads all active scopes for a keyed management identity.
    pub async fn lookup_management_api_key_scopes(
        &self,
        fingerprint: &[u8; 32],
        tenant_id: &str,
    ) -> Result<Vec<ManagementApiKeyScope>, StoreError> {
        let rows = sqlx::query(
            "SELECT k.api_key_id, k.subject, s.tenant_id, s.site_id,
                    s.capability, k.expires_at
             FROM xshield.management_api_keys k
             JOIN xshield.management_api_key_scopes s ON s.api_key_id = k.api_key_id
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

    /// Looks up one active, unexpired key capability by its keyed fingerprint.
    /// The caller supplies the already authenticated tenant/site requested by
    /// the endpoint; database scope remains authoritative.
    pub async fn lookup_management_api_key(
        &self,
        fingerprint: &[u8; 32],
        tenant_id: &str,
        site_id: &str,
        capability: &str,
    ) -> Result<Option<ManagementApiKeyPrincipal>, StoreError> {
        let row = sqlx::query(
            "SELECT k.api_key_id, k.subject, k.tenant_id, s.site_id, s.capability,
                    k.expires_at
             FROM xshield.management_api_keys k
             JOIN xshield.management_api_key_scopes s ON s.api_key_id = k.api_key_id
             WHERE k.tenant_id = $1 AND k.fingerprint = $2 AND k.status = 'active'
               AND k.expires_at > clock_timestamp()
               AND s.tenant_id = $1 AND s.site_id = $3 AND s.capability = $4",
        )
        .bind(tenant_id)
        .bind(fingerprint.as_slice())
        .bind(site_id)
        .bind(capability)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        sqlx::query(
            "UPDATE xshield.management_api_keys
             SET last_used_at = clock_timestamp()
             WHERE api_key_id = $1",
        )
        .bind(row.try_get::<String, _>("api_key_id")?)
        .execute(&self.pool)
        .await?;
        Ok(Some(ManagementApiKeyPrincipal {
            api_key_id: row.try_get("api_key_id")?,
            subject: row.try_get("subject")?,
            tenant_id: row.try_get("tenant_id")?,
            site_id: row.try_get("site_id")?,
            capability: row.try_get("capability")?,
            expires_at: row.try_get("expires_at")?,
        }))
    }
}
