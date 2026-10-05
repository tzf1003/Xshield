//! Durable protected-site configuration owned by the control plane.
#![allow(missing_docs)]

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    SiteConfig, SiteIssuedBy, SitePolicyConfig, SiteRequestCrypto, SiteRouteConfig,
    domain::{SiteId, TenantId},
    site::{assess_change_risk, direct_apply_may_waive},
};

/// Newest health observations kept per site; see
/// [`PostgresIdentityStore::insert_protected_site_health_snapshot`].
pub const HEALTH_SNAPSHOT_HISTORY: i64 = 64;

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
    /// Whether the revision needs independent approval is decided *inside*
    /// the write transaction from the active revision's stored configuration
    /// and this desired one; callers cannot supply or clear it. The only
    /// override is an explicit, named pre-authorization: the delete flow sets
    /// it after the caller completed a fresh browser MFA step-up, and the
    /// store then records an approval of kind `delete_step_up` bound to the
    /// exact revision it creates.
    pub pre_authorized_by: Option<&'a str>,
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
            || command
                .pre_authorized_by
                .is_some_and(|subject| subject.is_empty() || subject.len() > 256)
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
    /// Why the desired revision needs approval (stable tokens computed by the
    /// domain layer at write time); empty when it does not.
    pub risk_reasons: Vec<String>,
    pub approved_by: Option<String>,
    pub approval_id: Option<String>,
    pub updated_at: DateTime<Utc>,
}

/// Most recent persisted health observation of one site.
///
/// It records what a health read saw at `captured_at`; it is not a live probe
/// and carries no probe details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSiteHealthSnapshot {
    pub site_id: String,
    pub captured_at: DateTime<Utc>,
    pub edge_state: String,
    pub upstream_state: String,
    pub config_state: String,
    pub audit_state: String,
    pub reason_code: String,
}

/// Outcome of an idempotent high-risk approval attempt.
///
/// An approval is bound to the exact `(desired revision, configuration digest,
/// apply id)` read inside the approving transaction; every outcome other than
/// `Applied` and `Existing` leaves the apply intent untouched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectedSiteApprovalOutcome {
    /// The approval was recorded and the revision may now be applied.
    Applied { approval_id: String },
    /// The same idempotency key already approved this exact revision.
    Existing { approval_id: String },
    /// The desired revision does not need approval.
    NotRequired,
    /// The site does not exist.
    NotFound,
    /// The idempotency key (or the caller's expected digest) is bound to a
    /// different revision than the one currently desired.
    RevisionMismatch,
    /// The approver wrote the revision under approval.
    SelfApproval,
}

/// Outcome of authorizing a direct apply under the explicit
/// `site.config.apply_direct` capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtectedSiteDirectApplyOutcome {
    /// A `direct_apply` approval now covers the exact desired revision.
    Authorized { approval_id: String },
    /// The revision needs no approval (never did, or already approved).
    NotRequired,
    /// The site does not exist.
    NotFound,
    /// The desired revision changed since the caller read it.
    Stale,
    /// A stored reason (a browser provenance-flow change, or a reason this
    /// version does not recognize) can only be cleared by an independent
    /// `PolicyApprover`; nothing was recorded and the requirement stands.
    IndependentApprovalRequired,
}

/// A previously stored write recognised by its idempotency key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedSiteWriteMatch {
    pub revision: u64,
    pub request_digest: [u8; 32],
    /// Whether the revision is still the site's latest.
    pub is_latest: bool,
}

/// One site of a consistent tenant snapshot read.
#[derive(Clone, Debug)]
pub struct ProtectedSiteSnapshotSite {
    pub site_id: SiteId,
    /// The desired configuration row.
    pub record: ProtectedSiteConfigRecord,
    pub apply_id: String,
    pub apply_state: String,
    pub requires_approval: bool,
    pub active_revision: Option<u64>,
    /// The stored configuration of `active_revision`, i.e. what the edge
    /// serves for this site today.
    pub active_config: Option<SiteConfig>,
}

/// Tenant-wide state read in one transaction together with the monotonic
/// snapshot revision allocated for it.
#[derive(Clone, Debug)]
pub struct ProtectedSiteSnapshot {
    pub revision: u64,
    pub sites: Vec<ProtectedSiteSnapshotSite>,
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
    /// The typed configuration stored in this row.
    #[must_use]
    pub fn site_config(&self) -> SiteConfig {
        SiteConfig {
            display_name: self.display_name.clone(),
            public_origin: self.public_origin.clone(),
            upstream_address: self.upstream_address.clone(),
            upstream_server_name: self.upstream_server_name.clone(),
            upstream_tls: self.upstream_tls,
            listen_port: self.listen_port,
            entry_path: self.entry_path.clone(),
            security_entry: self.security_entry.clone(),
            sensor_enabled: self.sensor_enabled,
            policy_revision: self.policy_revision.clone(),
            status: self.status.clone(),
            policy: self.policy.clone(),
        }
    }

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
    /// The idempotency key is bound to different content.
    Conflict,
    PortConflict,
    /// The idempotency key belongs to an earlier write that a later one has
    /// superseded; replaying it would silently resurrect stale content.
    Superseded,
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

    /// Persists one bounded health observation for a tenant/site and prunes
    /// that site's history in the same transaction.
    ///
    /// A health read is an operator-triggered action, and any Observer can
    /// repeat it, so the table must not grow with the number of reads: only
    /// the newest [`HEALTH_SNAPSHOT_HISTORY`] observations per site are kept.
    /// Consumers read the latest row; the rest is short debugging history.
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
        let mut transaction = self.pool.begin().await?;
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
        .execute(&mut *transaction)
        .await?;
        // The row at OFFSET HISTORY is the oldest one past the limit; it and
        // everything older goes. With fewer rows the sub-select is NULL and
        // nothing is deleted. The (tenant, site, captured_at DESC) index
        // serves both the sub-select and the range delete.
        sqlx::query(
            "DELETE FROM xshield.site_health_snapshots
             WHERE tenant_id = $1 AND site_id = $2
               AND captured_at <= (
                   SELECT captured_at FROM xshield.site_health_snapshots
                   WHERE tenant_id = $1 AND site_id = $2
                   ORDER BY captured_at DESC
                   OFFSET $3 LIMIT 1)",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(HEALTH_SNAPSHOT_HISTORY)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Reads the newest persisted health observation of each site in a tenant,
    /// ordered by site ID. Sites that were never observed are simply absent.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the rows cannot be read.
    pub async fn latest_protected_site_health_snapshots(
        &self,
        tenant_id: &TenantId,
        limit: u16,
    ) -> Result<Vec<ProtectedSiteHealthSnapshot>, StoreError> {
        let rows = sqlx::query(
            "SELECT DISTINCT ON (site_id)
                    site_id, captured_at, edge_state, upstream_state, config_state,
                    audit_state, reason_code
             FROM xshield.site_health_snapshots
             WHERE tenant_id = $1
             ORDER BY site_id ASC, captured_at DESC
             LIMIT $2",
        )
        .bind(tenant_id.as_str())
        .bind(i64::from(limit.clamp(1, 128)))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ProtectedSiteHealthSnapshot {
                    site_id: row.try_get("site_id")?,
                    captured_at: row.try_get("captured_at")?,
                    edge_state: row.try_get("edge_state")?,
                    upstream_state: row.try_get("upstream_state")?,
                    config_state: row.try_get("config_state")?,
                    audit_state: row.try_get("audit_state")?,
                    reason_code: row.try_get("reason_code")?,
                })
            })
            .collect()
    }

    /// Reads one immutable stored revision as a typed configuration, for
    /// rollback and baseline comparison. The payload contains metadata only;
    /// secret references are never stored in this table.
    ///
    /// # Errors
    /// Returns a storage error when the revision cannot be read, or
    /// [`StoreError::CorruptData`] when a stored payload is not a complete
    /// site configuration (a corrupt baseline must stop the operation rather
    /// than be guessed at).
    pub async fn read_protected_site_revision_config(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        revision: u64,
    ) -> Result<Option<SiteConfig>, StoreError> {
        let revision = i64::try_from(revision).map_err(|_| StoreError::InvalidCommand)?;
        let row = sqlx::query(
            "SELECT config_json, policy_revision
             FROM xshield.site_policy_revisions
             WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| decode_stored_config(&row, "config_json", "policy_revision"))
            .transpose()
    }

    /// Returns the revision that was active immediately before the current
    /// active one, or `None` when the site has only ever had one.
    ///
    /// Revision numbers are never reused, so "the revision before this one"
    /// is not `active - 1`: failed or never-approved revisions sit in between.
    /// Activation order is recorded when the edge confirms a snapshot.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the history cannot be read.
    pub async fn read_protected_site_previous_active_revision(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
    ) -> Result<Option<u64>, StoreError> {
        let revision = sqlx::query_scalar::<_, i64>(
            "SELECT revision.revision
             FROM xshield.site_policy_revisions AS revision
             JOIN xshield.site_apply_intents AS intent
               ON intent.tenant_id = revision.tenant_id AND intent.site_id = revision.site_id
             WHERE revision.tenant_id = $1 AND revision.site_id = $2
               AND revision.activated_at IS NOT NULL
               AND revision.revision IS DISTINCT FROM intent.active_revision
             ORDER BY revision.activated_at DESC, revision.revision DESC
             LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        revision
            .map(|value| u64::try_from(value).map_err(|_| StoreError::CorruptData("revision")))
            .transpose()
    }

    /// Looks up a stored write by its idempotency identity, so a caller can
    /// tell a replay (of the latest or of a superseded write) from a new
    /// request before it resolves anything that depends on current state.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the lookup fails.
    pub async fn find_protected_site_write(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        idempotency_digest: &[u8; 32],
    ) -> Result<Option<ProtectedSiteWriteMatch>, StoreError> {
        let latest = sqlx::query(
            "SELECT revision, request_digest FROM xshield.protected_site_configs
             WHERE tenant_id = $1 AND site_id = $2 AND idempotency_digest = $3",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(idempotency_digest.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = latest {
            return Ok(Some(ProtectedSiteWriteMatch {
                revision: u64::try_from(row.try_get::<i64, _>("revision")?)
                    .map_err(|_| StoreError::CorruptData("revision"))?,
                request_digest: bytes32(&row, "request_digest")?,
                is_latest: true,
            }));
        }
        let older = sqlx::query(
            "SELECT revision, signature FROM xshield.site_policy_revisions
             WHERE tenant_id = $1 AND site_id = $2 AND idempotency_digest = $3",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(idempotency_digest.as_slice())
        .fetch_optional(&self.pool)
        .await?;
        older
            .map(|row| {
                Ok(ProtectedSiteWriteMatch {
                    revision: u64::try_from(row.try_get::<i64, _>("revision")?)
                        .map_err(|_| StoreError::CorruptData("revision"))?,
                    request_digest: bytes32(&row, "signature")?,
                    is_latest: false,
                })
            })
            .transpose()
    }

    /// Reads the tenant's complete site state and allocates the next
    /// snapshot revision in one transaction under the tenant lock.
    ///
    /// Doing both together makes the revision order agree with content
    /// freshness: a snapshot with a higher revision was read later, so the
    /// edge's monotonic check can never let an older read overwrite a newer
    /// one. Each site carries its desired row, its apply state and the stored
    /// configuration of its active revision (what the edge serves today), so
    /// the caller can keep a site whose desired revision awaits approval on
    /// its last approved configuration.
    ///
    /// # Errors
    /// Returns a storage or corruption error when the state cannot be read.
    pub async fn begin_protected_site_snapshot(
        &self,
        tenant_id: &TenantId,
    ) -> Result<ProtectedSiteSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('xshield-site-config-v1:' || $1, 0))",
        )
        .bind(tenant_id.as_str())
        .execute(&mut *transaction)
        .await?;
        let revision = sqlx::query_scalar::<_, i64>(
            "INSERT INTO xshield.site_snapshot_sequences (tenant_id, current_revision)
             VALUES ($1, 1)
             ON CONFLICT (tenant_id) DO UPDATE SET
                 current_revision = xshield.site_snapshot_sequences.current_revision + 1,
                 updated_at = now()
             RETURNING current_revision",
        )
        .bind(tenant_id.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        let rows = sqlx::query(
            "SELECT config.site_id, config.display_name, config.public_origin,
                    config.upstream_address, config.upstream_server_name, config.upstream_tls,
                    config.listen_port, config.entry_path, config.security_entry,
                    config.sensor_enabled, config.policy_revision, config.status,
                    config.policy_json, config.revision, config.config_digest,
                    config.updated_by, config.created_at, config.updated_at,
                    intent.apply_id, intent.apply_state, intent.requires_approval,
                    intent.active_revision,
                    active.config_json AS active_config_json,
                    active.policy_revision AS active_policy_revision
             FROM xshield.protected_site_configs AS config
             JOIN xshield.site_apply_intents AS intent
               ON intent.tenant_id = config.tenant_id AND intent.site_id = config.site_id
             LEFT JOIN xshield.site_policy_revisions AS active
               ON active.tenant_id = intent.tenant_id AND active.site_id = intent.site_id
              AND active.revision = intent.active_revision
             WHERE config.tenant_id = $1
             ORDER BY config.site_id ASC",
        )
        .bind(tenant_id.as_str())
        .fetch_all(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let sites = rows
            .into_iter()
            .map(|row| {
                let active_revision = row
                    .try_get::<Option<i64>, _>("active_revision")?
                    .map(|value| {
                        u64::try_from(value).map_err(|_| StoreError::CorruptData("active_revision"))
                    })
                    .transpose()?;
                let active_config = match (
                    active_revision,
                    row.try_get::<Option<Value>, _>("active_config_json")?,
                ) {
                    (None, _) => None,
                    (Some(_), Some(_)) => Some(decode_stored_config(
                        &row,
                        "active_config_json",
                        "active_policy_revision",
                    )?),
                    // An active revision whose history row is gone cannot be
                    // reconstructed; refuse to publish around it.
                    (Some(_), None) => return Err(StoreError::CorruptData("active_revision")),
                };
                Ok(ProtectedSiteSnapshotSite {
                    site_id: SiteId::parse(row.try_get::<String, _>("site_id")?)
                        .map_err(|_| StoreError::CorruptData("site_id"))?,
                    record: decode_record(&row)?,
                    apply_id: row.try_get("apply_id")?,
                    apply_state: row.try_get("apply_state")?,
                    requires_approval: row.try_get("requires_approval")?,
                    active_revision,
                    active_config,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(ProtectedSiteSnapshot {
            revision: u64::try_from(revision)
                .map_err(|_| StoreError::CorruptData("snapshot_revision"))?,
            sites,
        })
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
            // Remember when this revision first became active; rollback finds
            // "the revision before the current one" from this order.
            sqlx::query(
                "UPDATE xshield.site_policy_revisions
                 SET activated_at = COALESCE(activated_at, clock_timestamp())
                 WHERE tenant_id = $1 AND site_id = $2 AND revision = $3",
            )
            .bind(tenant_id.as_str())
            .bind(site_id.as_str())
            .bind(i64::try_from(*desired_revision).map_err(|_| StoreError::InvalidCommand)?)
            .execute(&mut *transaction)
            .await?;
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

    /// Records an independent approval for the high-risk desired revision.
    ///
    /// Everything is decided inside one transaction that holds the tenant lock
    /// and a row lock on the apply intent, so it sees exactly one revision and
    /// that revision cannot change underneath it:
    ///
    /// - an idempotency key already bound to an approval replays only against
    ///   the exact `(revision, digest, apply id)` it approved, and is a
    ///   [`ProtectedSiteApprovalOutcome::RevisionMismatch`] against any other;
    /// - `expected_config_digest`, when the caller supplies the digest it
    ///   reviewed, must equal the current desired digest;
    /// - the approver must differ from the author of *that* revision, checked
    ///   here and enforced again by a database constraint;
    /// - the approval row and the cleared requirement are written together,
    ///   and the clearing update is conditioned on the revision and apply id
    ///   that were read.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the approval input is invalid or the
    /// transaction cannot lock and update the apply intent.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn approve_protected_site_apply(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        approval_id: &str,
        approved_by: &str,
        idempotency_digest: &[u8; 32],
        expected_config_digest: Option<&[u8; 32]>,
    ) -> Result<ProtectedSiteApprovalOutcome, StoreError> {
        if !valid_approval_id(approval_id) || approved_by.is_empty() || approved_by.len() > 256 {
            return Err(StoreError::InvalidCommand);
        }
        let mut transaction = self.pool.begin().await?;
        lock_site_tenant(&mut transaction, tenant_id).await?;
        let Some(target) = lock_approval_target(&mut transaction, tenant_id, site_id).await? else {
            transaction.rollback().await?;
            return Ok(ProtectedSiteApprovalOutcome::NotFound);
        };
        if let Some(row) = sqlx::query(
            "SELECT approval_id, desired_revision, config_digest, apply_id
             FROM xshield.site_apply_approvals
             WHERE tenant_id = $1 AND site_id = $2 AND idempotency_digest = $3",
        )
        .bind(tenant_id.as_str())
        .bind(site_id.as_str())
        .bind(idempotency_digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        {
            let bound_to_current = row.try_get::<i64, _>("desired_revision")? == target.revision
                && row.try_get::<String, _>("apply_id")? == target.apply_id
                && bytes32(&row, "config_digest")? == target.config_digest;
            let prior_id: String = row.try_get("approval_id")?;
            transaction.rollback().await?;
            return Ok(if bound_to_current {
                ProtectedSiteApprovalOutcome::Existing {
                    approval_id: prior_id,
                }
            } else {
                ProtectedSiteApprovalOutcome::RevisionMismatch
            });
        }
        if !target.requires_approval {
            transaction.rollback().await?;
            return Ok(ProtectedSiteApprovalOutcome::NotRequired);
        }
        if expected_config_digest.is_some_and(|expected| *expected != target.config_digest) {
            transaction.rollback().await?;
            return Ok(ProtectedSiteApprovalOutcome::RevisionMismatch);
        }
        if target.author == approved_by {
            transaction.rollback().await?;
            return Ok(ProtectedSiteApprovalOutcome::SelfApproval);
        }
        record_approval(
            &mut transaction,
            tenant_id,
            site_id,
            &target,
            approval_id,
            "independent",
            approved_by,
            Some(idempotency_digest),
        )
        .await?;
        transaction.commit().await?;
        Ok(ProtectedSiteApprovalOutcome::Applied {
            approval_id: approval_id.to_owned(),
        })
    }

    /// Authorizes applying the desired revision directly, for a caller that
    /// holds the explicit `site.config.apply_direct` capability.
    ///
    /// The capability replaces the second pair of eyes, not the record of it:
    /// an approval row of kind `direct_apply` is written naming the caller and
    /// bound to the exact `(revision, digest, apply id)` the caller read,
    /// and the stale flag is cleared in the same transaction, so a direct
    /// apply leaves neither an unrecorded bypass nor a leftover
    /// `requires_approval` that would block other work.
    ///
    /// It never replaces the second pair of eyes for a provenance-flow change
    /// (`xshield_core::site::direct_apply_may_waive`): the stored reasons are
    /// read under the same row lock that decides the outcome, so they belong
    /// to exactly the revision that would otherwise be authorized.
    ///
    /// # Errors
    /// Returns [`StoreError`] when the input is invalid or the transaction
    /// cannot complete.
    pub async fn authorize_protected_site_direct_apply(
        &self,
        tenant_id: &TenantId,
        site_id: &SiteId,
        approval_id: &str,
        applied_by: &str,
        expected_revision: u64,
        expected_apply_id: &str,
    ) -> Result<ProtectedSiteDirectApplyOutcome, StoreError> {
        if !valid_approval_id(approval_id) || applied_by.is_empty() || applied_by.len() > 256 {
            return Err(StoreError::InvalidCommand);
        }
        let expected_revision =
            i64::try_from(expected_revision).map_err(|_| StoreError::InvalidCommand)?;
        let mut transaction = self.pool.begin().await?;
        lock_site_tenant(&mut transaction, tenant_id).await?;
        let Some(target) = lock_approval_target(&mut transaction, tenant_id, site_id).await? else {
            transaction.rollback().await?;
            return Ok(ProtectedSiteDirectApplyOutcome::NotFound);
        };
        if target.revision != expected_revision || target.apply_id != expected_apply_id {
            transaction.rollback().await?;
            return Ok(ProtectedSiteDirectApplyOutcome::Stale);
        }
        if !target.requires_approval {
            transaction.rollback().await?;
            return Ok(ProtectedSiteDirectApplyOutcome::NotRequired);
        }
        if !direct_apply_may_waive(&target.risk_reasons) {
            transaction.rollback().await?;
            return Ok(ProtectedSiteDirectApplyOutcome::IndependentApprovalRequired);
        }
        record_approval(
            &mut transaction,
            tenant_id,
            site_id,
            &target,
            approval_id,
            "direct_apply",
            applied_by,
            None,
        )
        .await?;
        transaction.commit().await?;
        Ok(ProtectedSiteDirectApplyOutcome::Authorized {
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
                    reason_code, retry_count, requires_approval, risk_reasons,
                    approved_by, approval_id, updated_at
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
                risk_reasons: row.try_get("risk_reasons")?,
                approved_by: row.try_get("approved_by")?,
                approval_id: row.try_get("approval_id")?,
                updated_at: row.try_get("updated_at")?,
            })
        })
        .transpose()
    }

    /// Creates or replaces the scoped configuration.
    ///
    /// The whole decision happens in one transaction under the tenant lock:
    ///
    /// - an idempotency key recognised from an *earlier* write (not the latest)
    ///   is refused as [`ProtectedSiteConfigWriteOutcome::Superseded`] instead
    ///   of silently creating a revision from stale content;
    /// - whether the new revision needs independent approval is computed here,
    ///   from the stored configuration of the site's *active* revision (what
    ///   the edge serves) and the desired one, never from the previous desired
    ///   revision, so re-submitting equal content cannot clear it;
    /// - the full configuration, its idempotency identity and, for an explicit
    ///   pre-authorization, the approval record are stored with the revision.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the transaction cannot be completed or a
    /// returned row is corrupt, including a corrupt baseline revision (the
    /// write is refused rather than evaluated against a guess).
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
            // Only the latest write is remembered by the row above; earlier
            // writes are remembered per revision. Replaying one of those must
            // not create a new revision out of stale content.
            if let Some(older) = sqlx::query(
                "SELECT signature FROM xshield.site_policy_revisions
                 WHERE tenant_id = $1 AND site_id = $2 AND idempotency_digest = $3",
            )
            .bind(command.tenant_id.as_str())
            .bind(command.site_id.as_str())
            .bind(command.idempotency_digest.as_slice())
            .fetch_optional(&mut *transaction)
            .await?
            {
                let stored_request = bytes32(&older, "signature")?;
                transaction.rollback().await?;
                return Ok(if stored_request == *command.request_digest {
                    ProtectedSiteConfigWriteOutcome::Superseded
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
        // The baseline is what the edge serves: the stored configuration of
        // the *active* revision. The tenant lock is held, so the active
        // revision cannot move between this read and the write below.
        let baseline_row = sqlx::query(
            "SELECT revision.config_json, revision.policy_revision
             FROM xshield.site_apply_intents AS intent
             JOIN xshield.site_policy_revisions AS revision
               ON revision.tenant_id = intent.tenant_id
              AND revision.site_id = intent.site_id
              AND revision.revision = intent.active_revision
             WHERE intent.tenant_id = $1 AND intent.site_id = $2",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?;
        let has_active_revision = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT active_revision FROM xshield.site_apply_intents
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .fetch_optional(&mut *transaction)
        .await?
        .flatten()
        .is_some();
        let baseline = match baseline_row {
            Some(row) => Some(decode_stored_config(
                &row,
                "config_json",
                "policy_revision",
            )?),
            // An active revision whose history row is missing is corruption,
            // not "never applied": refuse to evaluate against a guess.
            None if has_active_revision => {
                return Err(StoreError::CorruptData("active_revision"));
            }
            None => None,
        };
        let desired = SiteConfig {
            display_name: command.display_name.to_owned(),
            public_origin: command.public_origin.to_owned(),
            upstream_address: command.upstream_address.to_owned(),
            upstream_server_name: command.upstream_server_name.to_owned(),
            upstream_tls: command.upstream_tls,
            listen_port: u16::try_from(requested_port).map_err(|_| StoreError::InvalidCommand)?,
            entry_path: command.entry_path.to_owned(),
            security_entry: command.security_entry.to_owned(),
            sensor_enabled: command.sensor_enabled,
            policy_revision: command.policy_revision.to_owned(),
            status: command.status.to_owned(),
            policy: command.policy.clone(),
        };
        let risks = assess_change_risk(baseline.as_ref(), &desired);
        let requires_approval = !risks.is_empty() && command.pre_authorized_by.is_none();
        let risk_reasons = risks
            .iter()
            .map(|risk| risk.as_str().to_owned())
            .collect::<Vec<_>>();
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
                let projected = RouteProjection::of(route)?;
                sqlx::query(
                    "INSERT INTO xshield.site_routes
                         (tenant_id, site_id, operation_id, method, path, admission,
                          resource_type, source_action, view_profile, resource_query_parameter,
                          resource_path_parameter, request_crypto, response_config, issued_by)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                     ON CONFLICT (tenant_id, site_id, operation_id) DO UPDATE SET
                         method = EXCLUDED.method, path = EXCLUDED.path,
                         admission = EXCLUDED.admission,
                         resource_type = EXCLUDED.resource_type,
                         source_action = EXCLUDED.source_action,
                         view_profile = EXCLUDED.view_profile,
                         resource_query_parameter = EXCLUDED.resource_query_parameter,
                         resource_path_parameter = EXCLUDED.resource_path_parameter,
                         request_crypto = EXCLUDED.request_crypto,
                         response_config = EXCLUDED.response_config,
                         issued_by = EXCLUDED.issued_by,
                         updated_at = now()",
                )
                .bind(command.tenant_id.as_str())
                .bind(command.site_id.as_str())
                .bind(&route.operation_id)
                .bind(&route.method)
                .bind(&route.path)
                .bind(projected.admission)
                .bind(route.resource_type.as_deref())
                .bind(route.source_action.as_deref())
                .bind(route.view_profile.as_deref())
                .bind(route.resource_query_parameter.as_deref())
                .bind(route.resource_path_parameter.as_deref())
                .bind(projected.request_crypto)
                .bind(projected.response_config)
                .bind(projected.issued_by)
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
        // The revision stores the *complete* configuration (including
        // `policy_revision`), so it can be read back as a baseline and
        // restored by rollback, together with the identity of the request
        // that created it.
        sqlx::query(
            "INSERT INTO xshield.site_policy_revisions
                 (tenant_id, site_id, revision, policy_revision, config_digest,
                  config_json, signature, created_by, idempotency_digest)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, site_id, revision) DO NOTHING",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(revision)
        .bind(command.policy_revision)
        .bind(command.config_digest.as_slice())
        .bind(serde_json::to_value(&desired).map_err(|_| StoreError::InvalidCommand)?)
        .bind(command.request_digest.as_slice())
        .bind(command.updated_by)
        .bind(command.idempotency_digest.as_slice())
        .execute(&mut *transaction)
        .await?;
        let apply_id = format!("apply_{}", uuid::Uuid::now_v7());
        // A draft is never applied; say so in the durable state instead of
        // the generic "not confirmed".
        let reason_code = if requires_approval {
            "CONTROL_SITE_APPROVAL_REQUIRED"
        } else if command.status == "draft" {
            "CONTROL_SITE_DRAFT_NOT_APPLICABLE"
        } else {
            "EDGE_APPLY_NOT_CONFIRMED"
        };
        let pre_approval_id = command
            .pre_authorized_by
            .filter(|_| !risks.is_empty())
            .map(|_| format!("approval_{}", uuid::Uuid::now_v7()));
        sqlx::query(
            "INSERT INTO xshield.site_apply_intents (
                tenant_id, site_id, desired_revision, active_revision, apply_id,
                apply_state, reason_code, requires_approval, risk_reasons,
                approved_by, approval_id
             ) VALUES ($1, $2, $3, NULL, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT (tenant_id, site_id) DO UPDATE SET
                desired_revision = EXCLUDED.desired_revision,
                active_revision = xshield.site_apply_intents.active_revision,
                apply_id = EXCLUDED.apply_id,
                apply_state = EXCLUDED.apply_state,
                reason_code = EXCLUDED.reason_code,
                requires_approval = EXCLUDED.requires_approval,
                risk_reasons = EXCLUDED.risk_reasons,
                approved_by = EXCLUDED.approved_by,
                approval_id = EXCLUDED.approval_id,
                approval_idempotency_digest = NULL,
                retry_count = 0,
                updated_at = now()",
        )
        .bind(command.tenant_id.as_str())
        .bind(command.site_id.as_str())
        .bind(revision)
        .bind(&apply_id)
        .bind(if command.status == "paused" {
            "paused"
        } else {
            "pending"
        })
        .bind(reason_code)
        .bind(requires_approval)
        .bind(&risk_reasons)
        .bind(pre_approval_id.as_ref().and(command.pre_authorized_by))
        .bind(pre_approval_id.as_deref())
        .execute(&mut *transaction)
        .await?;
        if let (Some(approval_id), Some(approved_by)) =
            (pre_approval_id.as_deref(), command.pre_authorized_by)
        {
            // The pre-authorization is recorded like any other approval:
            // bound to this exact revision, digest and apply id.
            sqlx::query(
                "INSERT INTO xshield.site_apply_approvals
                     (tenant_id, site_id, approval_id, desired_revision, config_digest,
                      apply_id, approval_kind, approved_by, authored_by)
                 VALUES ($1, $2, $3, $4, $5, $6, 'delete_step_up', $7, $8)",
            )
            .bind(command.tenant_id.as_str())
            .bind(command.site_id.as_str())
            .bind(approval_id)
            .bind(revision)
            .bind(command.config_digest.as_slice())
            .bind(&apply_id)
            .bind(approved_by)
            .bind(command.updated_by)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(if previous.is_some() {
            ProtectedSiteConfigWriteOutcome::Updated(record)
        } else {
            ProtectedSiteConfigWriteOutcome::Created(record)
        })
    }
}

/// The JSON columns of one `site_routes` row.
///
/// `site_routes` is a write-only projection; the authoritative route lives in
/// `policy_json` and the revision's `config_json`. Its response and request
/// columns are taken from the same typed edge projection the control plane
/// publishes, so the row can never describe a different rule than the one the
/// edge compiles, and nothing a route carries is dropped on the way.
struct RouteProjection {
    request_crypto: Option<sqlx::types::Json<SiteRequestCrypto>>,
    response_config: Option<Value>,
    issued_by: Option<sqlx::types::Json<SiteIssuedBy>>,
    admission: &'static str,
}

impl RouteProjection {
    fn of(route: &SiteRouteConfig) -> Result<Self, StoreError> {
        let operation =
            xshield_core::site::gateway_operation(route).map_err(|_| StoreError::InvalidCommand)?;
        Ok(Self {
            request_crypto: route.request_crypto.clone().map(sqlx::types::Json),
            response_config: operation.get("response").cloned(),
            issued_by: route.issued_by.clone().map(sqlx::types::Json),
            admission: route.security_entry.edge_admission(),
        })
    }
}

fn valid_approval_id(value: &str) -> bool {
    value.starts_with("approval_") && value.len() == 45
}

/// Serializes every site-config writer of one tenant (writes, approvals,
/// activation marks and snapshot reads) on the same advisory lock.
async fn lock_site_tenant(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL statement_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('xshield-site-config-v1:' || $1, 0))",
    )
    .bind(tenant_id.as_str())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

/// The revision an approval would cover, read under lock.
struct ApprovalTarget {
    revision: i64,
    apply_id: String,
    requires_approval: bool,
    /// Why the revision needs approval, as stored with it.
    risk_reasons: Vec<String>,
    config_digest: [u8; 32],
    author: String,
}

/// Locks the site's apply intent and reads the desired revision it points at
/// together with that revision's digest and author.
async fn lock_approval_target(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
) -> Result<Option<ApprovalTarget>, StoreError> {
    let Some(intent) = sqlx::query(
        "SELECT desired_revision, apply_id, requires_approval, risk_reasons
         FROM xshield.site_apply_intents
         WHERE tenant_id = $1 AND site_id = $2
         FOR UPDATE",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .fetch_optional(&mut **transaction)
    .await?
    else {
        return Ok(None);
    };
    let config = sqlx::query(
        "SELECT revision, config_digest, updated_by
         FROM xshield.protected_site_configs
         WHERE tenant_id = $1 AND site_id = $2",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .fetch_one(&mut **transaction)
    .await?;
    let revision: i64 = intent.try_get("desired_revision")?;
    // The intent and the configuration row are written together; a mismatch
    // means the store is corrupt and nothing may be approved against it.
    if config.try_get::<i64, _>("revision")? != revision {
        return Err(StoreError::CorruptData("desired_revision"));
    }
    Ok(Some(ApprovalTarget {
        revision,
        apply_id: intent.try_get("apply_id")?,
        requires_approval: intent.try_get("requires_approval")?,
        risk_reasons: intent.try_get("risk_reasons")?,
        config_digest: bytes32(&config, "config_digest")?,
        author: config.try_get("updated_by")?,
    }))
}

/// Inserts the approval record and clears the requirement it covers. The
/// clearing update names the revision and apply id that were read, so it can
/// only ever release the exact intent the record is bound to.
#[allow(clippy::too_many_arguments)]
async fn record_approval(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &TenantId,
    site_id: &SiteId,
    target: &ApprovalTarget,
    approval_id: &str,
    kind: &'static str,
    approved_by: &str,
    idempotency_digest: Option<&[u8; 32]>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO xshield.site_apply_approvals
             (tenant_id, site_id, approval_id, desired_revision, config_digest, apply_id,
              approval_kind, approved_by, authored_by, idempotency_digest)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(approval_id)
    .bind(target.revision)
    .bind(target.config_digest.as_slice())
    .bind(&target.apply_id)
    .bind(kind)
    .bind(approved_by)
    .bind(&target.author)
    .bind(idempotency_digest.map(<[u8; 32]>::as_slice))
    .execute(&mut **transaction)
    .await?;
    let cleared = sqlx::query(
        "UPDATE xshield.site_apply_intents
         SET requires_approval = false,
             approved_by = $5,
             approval_id = $6,
             approval_idempotency_digest = $7,
             apply_state = CASE WHEN apply_state = 'paused' THEN 'paused' ELSE 'pending' END,
             reason_code = CASE WHEN apply_state = 'paused'
                 THEN 'CONTROL_SITE_PAUSED' ELSE 'CONTROL_SITE_APPROVED' END,
             updated_at = now()
         WHERE tenant_id = $1 AND site_id = $2
           AND desired_revision = $3 AND apply_id = $4
           AND requires_approval",
    )
    .bind(tenant_id.as_str())
    .bind(site_id.as_str())
    .bind(target.revision)
    .bind(&target.apply_id)
    .bind(approved_by)
    .bind(approval_id)
    .bind(idempotency_digest.map(<[u8; 32]>::as_slice))
    .execute(&mut **transaction)
    .await?;
    if cleared.rows_affected() != 1 {
        // Unreachable while the intent row is locked; failing closed here
        // rolls the approval row back with the transaction.
        return Err(StoreError::CorruptData("site_apply_intents"));
    }
    Ok(())
}

/// Decodes a stored revision payload together with its `policy_revision`
/// column into a typed configuration.
fn decode_stored_config(
    row: &PgRow,
    json_field: &'static str,
    policy_revision_field: &'static str,
) -> Result<SiteConfig, StoreError> {
    SiteConfig::from_stored(
        row.try_get::<Value, _>(json_field)?,
        &row.try_get::<String, _>(policy_revision_field)?,
    )
    .map_err(|_| StoreError::CorruptData("site_policy_revisions"))
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
