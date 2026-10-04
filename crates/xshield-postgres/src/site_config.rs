//! Durable protected-site configuration owned by the control plane.
#![allow(missing_docs)]

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    SitePolicyConfig,
    domain::{SiteId, TenantId},
};

/// Validated site configuration ready for an atomic upsert.
pub struct ProtectedSiteConfigUpsert<'a> {
    pub tenant_id: &'a TenantId,
    pub site_id: &'a SiteId,
    pub display_name: &'a str,
    pub public_origin: &'a str,
    pub upstream_address: &'a str,
    pub upstream_server_name: &'a str,
    pub upstream_tls: bool,
    /// Zero asks `PostgreSQL` to allocate the next scoped port.
    pub listen_port: u16,
    pub entry_path: &'a str,
    pub security_entry: &'a str,
    pub sensor_enabled: bool,
    pub policy_revision: &'a str,
    pub status: &'a str,
    pub policy: &'a SitePolicyConfig,
    pub requires_approval: bool,
    pub config_digest: &'a [u8; 32],
    pub updated_by: &'a str,
    pub idempotency_digest: &'a [u8; 32],
    pub request_digest: &'a [u8; 32],
}

impl ProtectedSiteConfigUpsert<'_> {
    /// Rejects values that would bypass the database contract.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidCommand`] when a field violates the
    /// bounded storage contract.
    pub fn new(command: Self) -> Result<Self, StoreError> {
        if command.display_name.is_empty()
            || command.display_name.len() > 128
            || command.public_origin.is_empty()
            || command.public_origin.len() > 512
            || command.upstream_address.is_empty()
            || command.upstream_address.len() > 128
            || command.upstream_server_name.is_empty()
            || command.upstream_server_name.len() > 253
            || (command.listen_port != 0 && !(6100..=65535).contains(&command.listen_port))
            || command.entry_path.is_empty()
            || command.entry_path.len() > 256
            || !command.entry_path.starts_with('/')
            || command.entry_path.contains(['?', '#'])
            || !matches!(
                command.security_entry,
                "public" | "authenticated_root" | "ui_action_required"
            )
            || !matches!(command.status, "draft" | "active" | "paused")
            || command.policy_revision.is_empty()
            || command.policy_revision.len() > 128
            || command.updated_by.is_empty()
            || command.updated_by.len() > 256
            || command.policy.validate().is_err()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(command)
    }
}

/// Persisted protected-site configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSiteConfigRecord {
    pub(super) display_name: String,
    pub(super) public_origin: String,
    pub(super) upstream_address: String,
    pub(super) upstream_server_name: String,
    pub(super) upstream_tls: bool,
    pub(super) listen_port: u16,
    pub(super) entry_path: String,
    pub(super) security_entry: String,
    pub(super) sensor_enabled: bool,
    pub(super) policy_revision: String,
    pub(super) status: String,
    pub(super) policy: SitePolicyConfig,
    pub(super) revision: u64,
    pub(super) config_digest: [u8; 32],
    pub(super) updated_by: String,
    pub(super) created_at: DateTime<Utc>,
    pub(super) updated_at: DateTime<Utc>,
}

/// Bounded site metadata used by the control-plane registry view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSiteConfigListItem {
    pub site_id: String,
    pub display_name: String,
    pub public_origin: String,
    pub listen_port: u16,
    pub security_entry: String,
    pub sensor_enabled: bool,
    pub policy_revision: String,
    pub status: String,
    pub revision: u64,
    pub config_digest: [u8; 32],
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
    pub desired_revision: u64,
    pub active_revision: Option<u64>,
    pub apply_id: String,
    pub apply_state: String,
    pub reason_code: String,
    pub requires_approval: bool,
}

/// Durable desired/active boundary for one site.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSiteApplyState {
    pub desired_revision: u64,
    pub active_revision: Option<u64>,
    pub apply_id: String,
    pub apply_state: String,
    pub reason_code: String,
    pub retry_count: u32,
    pub requires_approval: bool,
    pub approved_by: Option<String>,
    pub approval_id: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Outcome of an idempotent high-risk approval attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectedSiteApprovalOutcome {
    Applied { approval_id: String },
    Existing { approval_id: String },
    NotRequired,
    Conflict,
}

/// Immutable policy revision metadata used by the release history endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSitePolicyRevision {
    pub revision: u64,
    pub policy_revision: String,
    pub config_digest: [u8; 32],
    pub config_json: Value,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

impl ProtectedSiteConfigRecord {
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
    #[must_use]
    pub fn public_origin(&self) -> &str {
        &self.public_origin
    }
    #[must_use]
    pub fn upstream_address(&self) -> &str {
        &self.upstream_address
    }
    #[must_use]
    pub fn upstream_server_name(&self) -> &str {
        &self.upstream_server_name
    }
    #[must_use]
    pub const fn upstream_tls(&self) -> bool {
        self.upstream_tls
    }
    #[must_use]
    pub const fn listen_port(&self) -> u16 {
        self.listen_port
    }
    #[must_use]
    pub fn entry_path(&self) -> &str {
        &self.entry_path
    }
    #[must_use]
    pub fn security_entry(&self) -> &str {
        &self.security_entry
    }
    #[must_use]
    pub const fn sensor_enabled(&self) -> bool {
        self.sensor_enabled
    }
    #[must_use]
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
    #[must_use]
    pub fn policy(&self) -> &SitePolicyConfig {
        &self.policy
    }
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    #[must_use]
    pub fn config_digest(&self) -> &[u8; 32] {
        &self.config_digest
    }
    #[must_use]
    pub fn updated_by(&self) -> &str {
        &self.updated_by
    }
    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
    #[must_use]
    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Result of an idempotent site configuration write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectedSiteConfigWriteOutcome {
    Created(ProtectedSiteConfigRecord),
    Updated(ProtectedSiteConfigRecord),
    Existing(ProtectedSiteConfigRecord),
    Conflict,
    PortConflict,
}

impl PostgresIdentityStore {
    /// Allocates the next tenant-scoped complete-snapshot revision.
    ///
    /// The row lock supplied by `INSERT ... ON CONFLICT DO UPDATE` makes the
    /// sequence safe across control-plane instances; gaps are acceptable when
    /// an edge apply fails because revisions identify ordering, not storage
    /// continuity.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the sequence cannot be
    /// allocated or contains an invalid revision.
    pub async fn next_protected_site_snapshot_revision(
        &self,
        tenant_id: &TenantId,
    ) -> Result<u64, StoreError> {
        let revision = sqlx::query_scalar::<_, i64>(
            "INSERT INTO xshield.site_snapshot_sequences (tenant_id, current_revision)
             VALUES ($1, 1)
             ON CONFLICT (tenant_id) DO UPDATE SET
                 current_revision = xshield.site_snapshot_sequences.current_revision + 1,
                 updated_at = now()
             RETURNING current_revision",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&self.pool)
        .await?;
        u64::try_from(revision).map_err(|_| StoreError::CorruptData("snapshot_revision"))
    }

    /// Persists one bounded health observation for a tenant/site.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for an invalid state or
    /// [`StoreError`] when the insert cannot be committed.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_protected_site_health_snapshot(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        edge_state: &str,
        upstream_state: &str,
        config_state: &str,
        audit_state: &str,
        reason_code: &str,
        details: &Value,
    ) -> Result<(), StoreError> {
        if !matches!(
            edge_state,
            "unknown" | "healthy" | "degraded" | "unavailable"
        ) || !matches!(
            upstream_state,
            "unknown" | "healthy" | "degraded" | "unavailable"
        ) || !matches!(
            config_state,
            "unknown" | "active" | "pending" | "failed" | "paused"
        ) || !matches!(
            audit_state,
            "unknown" | "healthy" | "degraded" | "unavailable"
        ) || reason_code.is_empty()
            || reason_code.len() > 96
            || !reason_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || !details.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        sqlx::query(
            "INSERT INTO xshield.site_health_snapshots
                 (tenant_id, site_id, edge_state, upstream_state, config_state,
                  audit_state, reason_code, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(edge_state)
        .bind(upstream_state)
        .bind(config_state)
        .bind(audit_state)
        .bind(reason_code)
        .bind(details)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Reads one immutable normalized policy payload for rollback preparation.
    /// The payload contains metadata only; secret references are never stored
    /// in this table.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the revision cannot be read.
    pub async fn read_protected_site_revision_config(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        revision: u64,
    ) -> Result<Option<Value>, StoreError> {
        let revision = i64::try_from(revision).map_err(|_| StoreError::InvalidCommand)?;
        let row = sqlx::query_scalar::<_, Value>(
            "SELECT config_json
             FROM xshield.site_policy_revisions
             WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Reads the complete compatibility projection used to compile an edge
    /// snapshot. All rows are tenant scoped and returned in stable site order.
    /// The result is bounded by the unique internal port pool (6100..65535).
    ///
    /// # Errors
    /// Returns a storage or corruption error when a scoped row cannot be read.
    pub async fn list_protected_site_config_records(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<(SiteId, ProtectedSiteConfigRecord)>, StoreError> {
        // ponytail: one consistent snapshot query; the internal port pool caps
        // rows, avoiding a silently truncated tenant edge snapshot.
        let rows = sqlx::query(
            "SELECT site_id, display_name, public_origin, upstream_address,
                    upstream_server_name, upstream_tls, listen_port, entry_path,
                    security_entry, sensor_enabled, policy_revision, status,
                    policy_json,
                    revision, config_digest, updated_by, created_at, updated_at
             FROM xshield.protected_site_configs
             WHERE tenant_id = $1
             ORDER BY site_id ASC",
        )
        .bind(tenant_id.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let site_id = SiteId::parse(row.try_get::<String, _>("site_id")?)
                    .map_err(|_| StoreError::CorruptData("site_id"))?;
                Ok((site_id, decode_record(&row)?))
            })
            .collect()
    }

    /// Lists immutable, tenant/site-scoped policy revisions in newest-first
    /// order. The stored payload contains validated metadata only.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the revision history cannot be read or is
    /// corrupt.
    pub async fn list_protected_site_revisions(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        limit: u16,
    ) -> Result<Vec<ProtectedSitePolicyRevision>, StoreError> {
        let limit = i64::from(limit.clamp(1, 128));
        let rows = sqlx::query(
            "SELECT revision, policy_revision, config_digest, config_json,
                    created_by, created_at
             FROM xshield.site_policy_revisions
             WHERE tenant_id = $1 AND site_id = $2
             ORDER BY revision DESC
             LIMIT $3",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let revision = u64::try_from(row.try_get::<i64, _>("revision")?)
                    .map_err(|_| StoreError::CorruptData("revision"))?;
                Ok(ProtectedSitePolicyRevision {
                    revision,
                    policy_revision: row.try_get("policy_revision")?,
                    config_digest: bytes32(&row, "config_digest")?,
                    config_json: row.try_get("config_json")?,
                    created_by: row.try_get("created_by")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    /// Marks the exact desired revisions from one complete edge snapshot in a
    /// single transaction. A concurrent write leaves every row unchanged so
    /// the caller can reconcile the acknowledged snapshot without advertising
    /// a partially active tenant.
    ///
    /// # Errors
    /// Returns a storage error when the transaction cannot be completed.
    pub async fn mark_protected_site_applies_active_batch(
        &self,
        tenant_id: &TenantId,
        states: &[(SiteId, u64, String)],
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('xshield-site-config-v1:' || $1, 0))",
        )
        .bind(tenant_id.as_str())
        .execute(&mut *transaction)
        .await?;
        for (site_id, desired_revision, apply_id) in states {
            let result = sqlx::query(
                "UPDATE xshield.site_apply_intents
                 SET active_revision = desired_revision,
                     apply_state = CASE WHEN apply_state = 'paused' THEN 'paused' ELSE 'active' END,
                     reason_code = CASE WHEN apply_state = 'paused'
                         THEN 'CONTROL_SITE_PAUSED' ELSE 'EDGE_APPLY_CONFIRMED' END,
                     updated_at = now()
                 WHERE tenant_id = $1 AND site_id = $2
                   AND desired_revision = $3 AND apply_id = $4",
            )
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(i64::try_from(*desired_revision).map_err(|_| StoreError::InvalidCommand)?)
            .bind(apply_id)
            .execute(&mut *transaction)
            .await?;
            if result.rows_affected() != 1 {
                transaction.rollback().await?;
                return Ok(false);
            }
        }
        transaction.commit().await?;
        Ok(true)
    }

    /// Marks one desired revision failed while preserving its last active
    /// revision for safe retry and rollback.
    ///
    /// # Errors
    /// Returns a storage error when the state transition cannot be committed.
    pub async fn mark_protected_site_apply_failed(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        desired_revision: u64,
        apply_id: &str,
        reason_code: &str,
    ) -> Result<(), StoreError> {
        if reason_code.is_empty()
            || reason_code.len() > 96
            || !reason_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(StoreError::InvalidCommand);
        }
        sqlx::query(
            "UPDATE xshield.site_apply_intents
             SET apply_state = 'failed', reason_code = $5,
                 retry_count = retry_count + 1, updated_at = now()
             WHERE tenant_id = $1 AND site_id = $2
               AND desired_revision = $3 AND apply_id = $4",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(i64::try_from(desired_revision).map_err(|_| StoreError::InvalidCommand)?)
        .bind(apply_id)
        .bind(reason_code)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Records an independent approval for a high-risk desired revision.
    /// Approval is bound to the current apply identifier and cannot approve a
    /// later configuration accidentally.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the approval input is invalid or the
    /// transaction cannot lock and update the apply intent.
    pub async fn approve_protected_site_apply(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        approval_id: &str,
        approved_by: &str,
        idempotency_digest: &[u8; 32],
    ) -> Result<ProtectedSiteApprovalOutcome, StoreError> {
        if !approval_id.starts_with("approval_")
            || approval_id.len() != 45
            || approved_by.is_empty()
            || approved_by.len() > 256
        {
            return Err(StoreError::InvalidCommand);
        }
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT requires_approval, approval_id, approval_idempotency_digest
             FROM xshield.site_apply_intents
             WHERE tenant_id = $1 AND site_id = $2
             FOR UPDATE",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(row) = row else {
            transaction.rollback().await?;
            return Ok(ProtectedSiteApprovalOutcome::NotRequired);
        };
        let requires_approval: bool = row.try_get("requires_approval")?;
        let existing_digest = row.try_get::<Option<Vec<u8>>, _>("approval_idempotency_digest")?;
        let existing_approval_id = row.try_get::<Option<String>, _>("approval_id")?;
        if !requires_approval {
            let same_request = existing_digest
                .as_deref()
                .is_some_and(|value| value == idempotency_digest.as_slice());
            transaction.rollback().await?;
            return Ok(if same_request {
                existing_approval_id
                    .map_or(ProtectedSiteApprovalOutcome::NotRequired, |approval_id| {
                        ProtectedSiteApprovalOutcome::Existing { approval_id }
                    })
            } else {
                ProtectedSiteApprovalOutcome::Conflict
            });
        }
        sqlx::query(
            "UPDATE xshield.site_apply_intents
             SET requires_approval = false,
                 approved_by = $3,
                 approval_id = $4,
                 approval_idempotency_digest = $5,
                 apply_state = CASE WHEN apply_state = 'paused' THEN 'paused' ELSE 'pending' END,
                 reason_code = CASE WHEN apply_state = 'paused'
                     THEN 'CONTROL_SITE_PAUSED' ELSE 'CONTROL_SITE_APPROVED' END,
                 updated_at = now()
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(approved_by)
        .bind(approval_id)
        .bind(idempotency_digest.as_slice())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(ProtectedSiteApprovalOutcome::Applied {
            approval_id: approval_id.to_owned(),
        })
    }

    /// Deletes one site and releases its internal listener lease atomically.
    ///
    /// # Errors
    /// Returns a storage error when the transaction cannot be completed.
    pub async fn delete_protected_site_config(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
    ) -> Result<bool, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('xshield-site-config-v1:' || $1, 0))",
        )
        .bind(tenant_id.as_str())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE xshield.site_port_leases
             SET state = 'released', updated_at = now()
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM xshield.protected_sites
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .execute(&mut *transaction)
        .await?;
        let result = sqlx::query(
            "DELETE FROM xshield.protected_site_configs
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    /// Lists bounded site metadata in one tenant scope.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the scoped snapshot cannot
    /// be read safely.
    pub async fn list_protected_site_configs(
        &self,
        tenant_id: &TenantId,
        after_site_id: Option<&str>,
        limit: u16,
    ) -> Result<Vec<ProtectedSiteConfigListItem>, StoreError> {
        let limit = i64::from(limit.clamp(1, 128));
        let rows = sqlx::query(
            "SELECT config.site_id, config.display_name, config.public_origin, config.listen_port,
                    config.security_entry, config.sensor_enabled, config.policy_revision, config.status,
                    config.revision, config.config_digest, config.updated_by, config.updated_at,
                    apply.desired_revision, apply.active_revision, apply.apply_id,
                    apply.apply_state, apply.reason_code, apply.requires_approval
             FROM xshield.protected_site_configs AS config
             JOIN xshield.site_apply_intents AS apply
               ON apply.tenant_id = config.tenant_id AND apply.site_id = config.site_id
             WHERE config.tenant_id = $1
               AND ($2::text IS NULL OR config.site_id > $2)
             ORDER BY config.site_id ASC
             LIMIT $3",
        )
        .bind(tenant_id.as_str())
        .bind(after_site_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let port = row.try_get::<i32, _>("listen_port")?;
                let revision = row.try_get::<i64, _>("revision")?;
                Ok(ProtectedSiteConfigListItem {
                    site_id: row.try_get("site_id")?,
                    display_name: row.try_get("display_name")?,
                    public_origin: row.try_get("public_origin")?,
                    listen_port: u16::try_from(port)
                        .map_err(|_| StoreError::CorruptData("listen_port"))?,
                    security_entry: row.try_get("security_entry")?,
                    sensor_enabled: row.try_get("sensor_enabled")?,
                    policy_revision: row.try_get("policy_revision")?,
                    status: row.try_get("status")?,
                    revision: u64::try_from(revision)
                        .map_err(|_| StoreError::CorruptData("revision"))?,
                    config_digest: bytes32(&row, "config_digest")?,
                    updated_by: row.try_get("updated_by")?,
                    updated_at: row.try_get("updated_at")?,
                    desired_revision: u64::try_from(row.try_get::<i64, _>("desired_revision")?)
                        .map_err(|_| StoreError::CorruptData("desired_revision"))?,
                    active_revision: row
                        .try_get::<Option<i64>, _>("active_revision")?
                        .map(|value| {
                            u64::try_from(value)
                                .map_err(|_| StoreError::CorruptData("active_revision"))
                        })
                        .transpose()?,
                    apply_id: row.try_get("apply_id")?,
                    apply_state: row.try_get("apply_state")?,
                    reason_code: row.try_get("reason_code")?,
                    requires_approval: row.try_get("requires_approval")?,
                })
            })
            .collect()
    }

    /// Reads one site configuration in the supplied scope.
    ///
    /// # Errors
    ///
    /// Returns a storage error when `PostgreSQL` cannot execute or decode the
    /// scoped read.
    pub async fn read_protected_site_config(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
    ) -> Result<Option<ProtectedSiteConfigRecord>, StoreError> {
        let row = sqlx::query(
            "SELECT display_name, public_origin, upstream_address, upstream_server_name, upstream_tls, listen_port,
                    entry_path, security_entry, sensor_enabled, policy_revision,
                    status, policy_json, revision, config_digest, updated_by, created_at, updated_at
             FROM xshield.protected_site_configs
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(decode_record).transpose()
    }

    /// Reads the durable desired/active boundary for one site.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the apply state is unavailable.
    pub async fn read_protected_site_apply_state(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
    ) -> Result<Option<ProtectedSiteApplyState>, StoreError> {
        let row = sqlx::query(
            "SELECT desired_revision, active_revision, apply_id, apply_state,
                    reason_code, retry_count, requires_approval, approved_by,
                    approval_id, updated_at
             FROM xshield.site_apply_intents
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let desired_revision = u64::try_from(row.try_get::<i64, _>("desired_revision")?)
                .map_err(|_| StoreError::CorruptData("desired_revision"))?;
            let active_revision = row
                .try_get::<Option<i64>, _>("active_revision")?
                .map(|value| {
                    u64::try_from(value).map_err(|_| StoreError::CorruptData("active_revision"))
                })
                .transpose()?;
            let retry_count = u32::try_from(row.try_get::<i32, _>("retry_count")?)
                .map_err(|_| StoreError::CorruptData("retry_count"))?;
            Ok(ProtectedSiteApplyState {
                desired_revision,
                active_revision,
                apply_id: row.try_get("apply_id")?,
                apply_state: row.try_get("apply_state")?,
                reason_code: row.try_get("reason_code")?,
                retry_count,
                requires_approval: row.try_get("requires_approval")?,
                approved_by: row.try_get("approved_by")?,
                approval_id: row.try_get("approval_id")?,
                updated_at: row.try_get("updated_at")?,
            })
        })
        .transpose()
    }

    /// Creates or replaces the scoped configuration.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the transaction cannot be completed or a
    /// returned row is corrupt.
    #[allow(clippy::too_many_lines)]
    pub async fn upsert_protected_site_config(
        &self,
        command: ProtectedSiteConfigUpsert<'_>,
    ) -> Result<ProtectedSiteConfigWriteOutcome, StoreError> {
        let command = ProtectedSiteConfigUpsert::new(command)?;
        let policy_json =
            serde_json::to_value(command.policy).map_err(|_| StoreError::InvalidCommand)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-site-config-v1:' || $1, 0
             ))",
        )
        .bind(command.tenant_id.as_str())
        .execute(&mut *transaction)
        .await?;

        if let Some(row) = sqlx::query(
            "SELECT idempotency_digest, request_digest,
                    display_name, public_origin, upstream_address, upstream_server_name, upstream_tls, listen_port,
                    entry_path, security_entry, sensor_enabled, policy_revision,
                    status, policy_json, revision, config_digest, updated_by, created_at, updated_at
             FROM xshield.protected_site_configs
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        {
            let existing_idempotency = bytes32(&row, "idempotency_digest")?;
            let existing_request = bytes32(&row, "request_digest")?;
            let record = decode_record(&row)?;
            if existing_idempotency == *command.idempotency_digest {
                transaction.rollback().await?;
                return Ok(if existing_request == *command.request_digest {
                    ProtectedSiteConfigWriteOutcome::Existing(record)
                } else {
                    ProtectedSiteConfigWriteOutcome::Conflict
                });
            }
        }

        let existing_port = sqlx::query_scalar::<_, i32>(
            "SELECT listen_port
             FROM xshield.site_port_leases
             WHERE tenant_id = $1 AND site_id = $2 AND state = 'active'
             FOR UPDATE",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let requested_port = if command.listen_port == 0 {
            if let Some(existing_port) = existing_port {
                existing_port
            } else {
                sqlx::query_scalar::<_, i32>(
                    "SELECT candidate
                     FROM generate_series(6100, 65535) AS candidate
                     WHERE NOT EXISTS (
                         SELECT 1 FROM xshield.site_port_leases
                         WHERE tenant_id = $1 AND listen_port = candidate AND state = 'active'
                     )
                     ORDER BY candidate
                     LIMIT 1",
                )
                .bind(command.tenant_id.as_str())
                .fetch_optional(&mut *transaction)
                .await?
                .unwrap_or(0)
            }
        } else {
            i32::from(command.listen_port)
        };
        if !(6100..=65535).contains(&requested_port) {
            transaction.rollback().await?;
            return Ok(ProtectedSiteConfigWriteOutcome::PortConflict);
        }
        let port_taken = sqlx::query_scalar::<_, String>(
            "SELECT site_id FROM xshield.site_port_leases
             WHERE tenant_id = $1 AND listen_port = $2 AND site_id <> $3 AND state = 'active'",
        )
        .bind(command.tenant_id.as_str())
        .bind(requested_port)
        .bind(command.site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        if port_taken.is_some() {
            transaction.rollback().await?;
            return Ok(ProtectedSiteConfigWriteOutcome::PortConflict);
        }

        let previous = sqlx::query_scalar::<_, i64>(
            "SELECT revision FROM xshield.protected_site_configs
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(previous_port) = existing_port
            && previous_port != requested_port
        {
            sqlx::query(
                "UPDATE xshield.site_port_leases
                 SET state = 'released', updated_at = now()
                 WHERE tenant_id = $1 AND site_id = $2",
            )
            .bind(command.tenant_id.as_str())
            .bind(command.site_id.as_str())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO xshield.site_port_leases (tenant_id, site_id, listen_port, state)
             VALUES ($1, $2, $3, 'active')
             ON CONFLICT (tenant_id, site_id) DO UPDATE SET
                 listen_port = EXCLUDED.listen_port,
                 state = 'active',
                 updated_at = now()",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(requested_port)
        .execute(&mut *transaction)
        .await?;
        let revision = previous.unwrap_or(0).saturating_add(1);
        let row = sqlx::query(
            "INSERT INTO xshield.protected_site_configs (
                tenant_id, site_id, display_name, public_origin, upstream_address, upstream_server_name, upstream_tls,
                listen_port, entry_path, security_entry, sensor_enabled,
                policy_revision, status, policy_json, revision, config_digest, updated_by,
                idempotency_digest, request_digest
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
             ON CONFLICT (tenant_id, site_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                public_origin = EXCLUDED.public_origin,
                upstream_address = EXCLUDED.upstream_address,
                upstream_server_name = EXCLUDED.upstream_server_name,
                upstream_tls = EXCLUDED.upstream_tls,
                listen_port = EXCLUDED.listen_port,
                entry_path = EXCLUDED.entry_path,
                security_entry = EXCLUDED.security_entry,
                sensor_enabled = EXCLUDED.sensor_enabled,
                policy_revision = EXCLUDED.policy_revision,
                status = EXCLUDED.status,
                policy_json = EXCLUDED.policy_json,
                revision = EXCLUDED.revision,
                config_digest = EXCLUDED.config_digest,
                updated_by = EXCLUDED.updated_by,
                idempotency_digest = EXCLUDED.idempotency_digest,
                request_digest = EXCLUDED.request_digest,
                updated_at = now()
             RETURNING display_name, public_origin, upstream_address, upstream_server_name, upstream_tls, listen_port,
                       entry_path, security_entry, sensor_enabled, policy_revision,
                       status, policy_json, revision, config_digest, updated_by, created_at, updated_at",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(command.display_name)
        .bind(command.public_origin)
        .bind(command.upstream_address)
        .bind(command.upstream_server_name)
        .bind(command.upstream_tls)
        .bind(requested_port)
        .bind(command.entry_path)
        .bind(command.security_entry)
        .bind(command.sensor_enabled)
        .bind(command.policy_revision)
        .bind(command.status)
        .bind(&policy_json)
        .bind(revision)
        .bind(command.config_digest.as_slice())
        .bind(command.updated_by)
        .bind(command.idempotency_digest.as_slice())
        .bind(command.request_digest.as_slice())
        .fetch_one(&mut *transaction)
        .await;
        let row = match row {
            Ok(row) => row,
            Err(sqlx::Error::Database(error))
                if error.constraint().is_some_and(|name| {
                    name == "protected_site_configs_tenant_id_listen_port_key"
                        || name == "site_port_leases_active_unique"
                }) =>
            {
                transaction.rollback().await?;
                return Ok(ProtectedSiteConfigWriteOutcome::PortConflict);
            }
            Err(error) => return Err(error.into()),
        };
        let record = decode_record(&row)?;
        // Expand-contract dual write: the compatibility row remains the
        // idempotent boundary while normalized tables become the next read
        // source. All statements share this transaction and tenant lock.
        sqlx::query(
            "INSERT INTO xshield.protected_sites
                 (tenant_id, site_id, display_name, status)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (tenant_id, site_id) DO UPDATE SET
                 display_name = EXCLUDED.display_name,
                 status = EXCLUDED.status,
                 updated_at = now()",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(command.display_name)
        .bind(command.status)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO xshield.site_origins
                 (tenant_id, site_id, public_origin, upstream_address,
                  upstream_server_name, upstream_tls, health_path)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, site_id) DO UPDATE SET
                 public_origin = EXCLUDED.public_origin,
                 upstream_address = EXCLUDED.upstream_address,
                 upstream_server_name = EXCLUDED.upstream_server_name,
                 upstream_tls = EXCLUDED.upstream_tls,
                 health_path = EXCLUDED.health_path,
                 updated_at = now()",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(command.public_origin)
        .bind(command.upstream_address)
        .bind(command.upstream_server_name)
        .bind(command.upstream_tls)
        .bind(&command.policy.health_check.path)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("DELETE FROM xshield.site_routes WHERE tenant_id = $1 AND site_id = $2")
            .bind(command.tenant_id.as_str())
            .bind(command.site_id.as_str())
            .execute(&mut *transaction)
            .await?;
        if command.policy.routes.is_empty() {
            sqlx::query(
                "INSERT INTO xshield.site_routes
                     (tenant_id, site_id, operation_id, method, path, admission)
                 VALUES ($1, $2, 'protected.entry', 'GET', $3,
                         CASE $4
                             WHEN 'public' THEN 'PUBLIC'
                             WHEN 'authenticated_root' THEN 'AUTHENTICATED_ROOT'
                             ELSE 'UI_ACTION_REQUIRED'
                         END)",
            )
            .bind(command.tenant_id.as_str())
            .bind(command.site_id.as_str())
            .bind(command.entry_path)
            .bind(command.security_entry)
            .execute(&mut *transaction)
            .await?;
        } else {
            for route in &command.policy.routes {
                let admission = match route.security_entry {
                    xshield_core::SecurityEntry::Public => "PUBLIC",
                    xshield_core::SecurityEntry::AuthenticatedRoot => "AUTHENTICATED_ROOT",
                    xshield_core::SecurityEntry::UiActionRequired => "UI_ACTION_REQUIRED",
                };
                let response_config = (!route.response_mode.is_empty()
                    || route.response_crypto.is_some())
                    .then(|| serde_json::json!({
                        "mode": if route.response_mode.is_empty() { "BUFFERED_JSON" } else { route.response_mode.as_str() },
                        "max_bytes": route.max_response_bytes,
                        "crypto": route.response_crypto.as_ref(),
                    }));
                sqlx::query(
                    "INSERT INTO xshield.site_routes
                         (tenant_id, site_id, operation_id, method, path, admission,
                          source_action, view_profile, resource_query_parameter,
                          resource_path_parameter, request_crypto, response_config)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                     ON CONFLICT (tenant_id, site_id, operation_id) DO UPDATE SET
                         method = EXCLUDED.method, path = EXCLUDED.path,
                         admission = EXCLUDED.admission, source_action = EXCLUDED.source_action,
                         view_profile = EXCLUDED.view_profile,
                         resource_query_parameter = EXCLUDED.resource_query_parameter,
                         resource_path_parameter = EXCLUDED.resource_path_parameter,
                         request_crypto = EXCLUDED.request_crypto,
                         response_config = EXCLUDED.response_config,
                         updated_at = now()",
                )
                .bind(command.tenant_id.as_str())
                .bind(command.site_id.as_str())
                .bind(&route.operation_id)
                .bind(&route.method)
                .bind(&route.path)
                .bind(admission)
                .bind(route.source_action.as_deref())
                .bind(route.view_profile.as_deref())
                .bind(route.resource_query_parameter.as_deref())
                .bind(route.resource_path_parameter.as_deref())
                .bind(
                    route
                        .request_crypto
                        .as_ref()
                        .map(serde_json::to_value)
                        .transpose()
                        .map_err(|_| StoreError::InvalidCommand)?,
                )
                .bind(response_config)
                .execute(&mut *transaction)
                .await?;
            }
        }
        sqlx::query(
            "DELETE FROM xshield.site_secret_refs
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .execute(&mut *transaction)
        .await?;
        for secret in &command.policy.secret_refs {
            sqlx::query(
                "INSERT INTO xshield.site_secret_refs
                     (tenant_id, site_id, secret_kind, secret_ref, key_id, state)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(command.tenant_id.as_str())
            .bind(command.site_id.as_str())
            .bind(&secret.kind)
            .bind(&secret.secret_ref)
            .bind(&secret.key_id)
            .bind(&secret.state)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO xshield.site_policy_revisions
                 (tenant_id, site_id, revision, policy_revision, config_digest,
                  config_json, signature, created_by)
             VALUES ($1, $2, $3, $4,
                     $5,
                     jsonb_build_object(
                         'display_name', $6,
                         'public_origin', $7,
                         'upstream_address', $8,
                         'upstream_server_name', $9,
                         'upstream_tls', $10,
                         'listen_port', $11,
                         'entry_path', $12,
                         'security_entry', $13,
                         'sensor_enabled', $14,
                         'status', $15,
                         'policy', $16
                     ),
                     $17, $18)
             ON CONFLICT (tenant_id, site_id, revision) DO NOTHING",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(revision)
        .bind(command.policy_revision)
        .bind(command.config_digest.as_slice())
        .bind(command.display_name)
        .bind(command.public_origin)
        .bind(command.upstream_address)
        .bind(command.upstream_server_name)
        .bind(command.upstream_tls)
        .bind(requested_port)
        .bind(command.entry_path)
        .bind(command.security_entry)
        .bind(command.sensor_enabled)
        .bind(command.status)
        .bind(&policy_json)
        .bind(command.request_digest.as_slice())
        .bind(command.updated_by)
        .execute(&mut *transaction)
        .await?;
        let apply_id = format!("apply_{}", uuid::Uuid::now_v7());
        sqlx::query(
            "INSERT INTO xshield.site_apply_intents (
                tenant_id, site_id, desired_revision, active_revision, apply_id,
                apply_state, reason_code, requires_approval
             ) VALUES ($1, $2, $3, NULL, $4, $5, $6, $7)
             ON CONFLICT (tenant_id, site_id) DO UPDATE SET
                desired_revision = EXCLUDED.desired_revision,
                active_revision = xshield.site_apply_intents.active_revision,
                apply_id = EXCLUDED.apply_id,
                apply_state = EXCLUDED.apply_state,
                reason_code = EXCLUDED.reason_code,
                requires_approval = EXCLUDED.requires_approval,
                approved_by = NULL,
                approval_id = NULL,
                approval_idempotency_digest = NULL,
                retry_count = 0,
                updated_at = now()",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(revision)
        .bind(apply_id)
        .bind(if command.status == "paused" {
            "paused"
        } else {
            "pending"
        })
        .bind(if command.requires_approval {
            "CONTROL_SITE_APPROVAL_REQUIRED"
        } else {
            "EDGE_APPLY_NOT_CONFIRMED"
        })
        .bind(command.requires_approval)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(if previous.is_some() {
            ProtectedSiteConfigWriteOutcome::Updated(record)
        } else {
            ProtectedSiteConfigWriteOutcome::Created(record)
        })
    }
}

fn bytes32(row: &PgRow, field: &'static str) -> Result<[u8; 32], StoreError> {
    row.try_get::<Vec<u8>, _>(field)?
        .try_into()
        .map_err(|_| StoreError::CorruptData(field))
}

fn decode_record(row: &PgRow) -> Result<ProtectedSiteConfigRecord, StoreError> {
    let port = row.try_get::<i32, _>("listen_port")?;
    let revision = row.try_get::<i64, _>("revision")?;
    Ok(ProtectedSiteConfigRecord {
        display_name: row.try_get("display_name")?,
        public_origin: row.try_get("public_origin")?,
        upstream_address: row.try_get("upstream_address")?,
        upstream_server_name: row.try_get("upstream_server_name")?,
        upstream_tls: row.try_get("upstream_tls")?,
        listen_port: u16::try_from(port).map_err(|_| StoreError::CorruptData("listen_port"))?,
        entry_path: row.try_get("entry_path")?,
        security_entry: row.try_get("security_entry")?,
        sensor_enabled: row.try_get("sensor_enabled")?,
        policy_revision: row.try_get("policy_revision")?,
        status: row.try_get("status")?,
        policy: serde_json::from_value(row.try_get("policy_json")?)
            .map_err(|_| StoreError::CorruptData("policy_json"))?,
        revision: u64::try_from(revision).map_err(|_| StoreError::CorruptData("revision"))?,
        config_digest: bytes32(row, "config_digest")?,
        updated_by: row.try_get("updated_by")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
