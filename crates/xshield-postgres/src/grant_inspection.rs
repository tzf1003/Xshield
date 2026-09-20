//! Scoped, read-only qualification investigation metadata.
//!
//! Historical grant and current binding facts share one SQL snapshot. The
//! projection excludes credential material and cannot authorize a request.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use sqlx::{Row, postgres::PgRow};
use xshield_core::{
    domain::{
        AuthBindingId, EventId, GrantId, OperationId, PolicyRevision, RequestId, ResourceType,
        SiteId, TenantId, ViewProfile,
    },
    identity::AuthEpoch,
};

/// Stored grant lifecycle label, independently of the database observation time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRecordStatus {
    /// The row is marked active; this does not establish current eligibility.
    Active,
    /// The row has a persisted revocation label.
    Revoked,
    /// The row has a persisted expiry label.
    Expired,
}

impl GrantRecordStatus {
    /// Returns the stable stored label without deriving an authorization result.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// Stored binding lifecycle label, independently of expiry and credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingRecordStatus {
    /// The binding is currently marked anonymous.
    Anonymous,
    /// The binding is marked active; credentials are not inspected.
    Active,
    /// The binding has a persisted revocation label.
    Revoked,
    /// The binding has a persisted expiry label.
    Expired,
}

impl BindingRecordStatus {
    /// Returns the stable stored label without deriving an authorization result.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// Non-secret historical qualification metadata and current binding observation.
///
/// This is not a capability, identity snapshot, or online admission result.
/// Source IDs locate historical evidence; they do not prove index availability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantInspection {
    /// Database statement time for this single-snapshot observation.
    pub as_of: DateTime<Utc>,
    /// Exact qualification identity within the authenticated tenant/site scope.
    pub grant_id: GrantId,
    /// Binding identity retained by the qualification record.
    pub binding_id: AuthBindingId,
    /// Immutable identity epoch captured when the qualification was issued.
    pub grant_epoch: AuthEpoch,
    /// Current binding epoch, which may have advanced since issuance.
    pub binding_epoch: AuthEpoch,
    /// Stored binding lifecycle label, separate from its time-based expiry.
    pub binding_status: BindingRecordStatus,
    /// Current binding absolute expiry, without any credential information.
    pub binding_expires_at: DateTime<Utc>,
    /// Stored qualification lifecycle label, separate from time-based expiry.
    pub grant_status: GrantRecordStatus,
    /// Original qualification issuance timestamp.
    pub issued_at: DateTime<Utc>,
    /// Original qualification absolute expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Resource category only; the resource identifier and its HMAC are excluded.
    pub resource_type: ResourceType,
    /// Exact historical operation approved at issuance.
    pub operation_id: OperationId,
    /// Historical field/view profile, without underlying constraints.
    pub view_profile: ViewProfile,
    /// Frozen policy revision associated with the grant and its source action.
    pub policy_revision: PolicyRevision,
    /// Historical issuance event reference stored by the qualification.
    pub source_event_id: EventId,
    /// Source request reference obtained from the matching historical action.
    pub source_request_id: RequestId,
}

impl PostgresIdentityStore {
    /// Reads one scoped qualification and its binding/action metadata snapshot.
    ///
    /// Missing and foreign-scope IDs uniformly return `None`. Expired/revoked
    /// rows and inactive source actions remain investigable; the caller must
    /// authenticate scope, bound total execution time, and durably audit access
    /// before releasing results. No business row is locked, changed, or renewed.
    /// The read-only transaction bounds statement/lock waits to five seconds;
    /// cancellation rolls back the read. No credentials or capabilities are read.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database failures or malformed/inconsistent
    /// visible rows. Missing linked rows are corruption rather than absence.
    pub async fn read_grant_summary(
        &self,
        tenant: &TenantId,
        site: &SiteId,
        grant: &GrantId,
    ) -> Result<Option<GrantInspection>, StoreError> {
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
        // LEFT JOIN preserves a visible grant when a linked row is damaged.
        // Filtering inconsistent linkage out would misreport corruption as absence.
        let row = sqlx::query(
            "SELECT statement_timestamp() AS as_of,
                    resource_grant.grant_id, resource_grant.binding_id,
                    resource_grant.auth_epoch AS grant_epoch,
                    resource_grant.status AS grant_status,
                    resource_grant.issued_at, resource_grant.expires_at,
                    resource_grant.resource_type, resource_grant.operation_id,
                    resource_grant.view_id, resource_grant.policy_revision,
                    resource_grant.source_event_id,
                    binding.binding_id AS current_binding_id,
                    binding.auth_epoch AS binding_epoch, binding.status AS binding_status,
                    binding.absolute_expires_at AS binding_expires_at,
                    action.binding_id AS action_binding_id, action.auth_epoch AS action_epoch,
                    action.operation_id AS action_operation_id,
                    action.field_profile AS action_view_id,
                    action.policy_revision AS action_policy_revision,
                    action.source_request_id, action.issued_at AS action_issued_at,
                    action.expires_at AS action_expires_at,
                    (isfinite(resource_grant.issued_at) AND isfinite(resource_grant.expires_at)
                     AND isfinite(binding.absolute_expires_at)
                     AND isfinite(action.issued_at) AND isfinite(action.expires_at))
                        AS finite_timestamps
             FROM xshield.resource_grants resource_grant
             LEFT JOIN xshield.auth_bindings binding
               ON binding.tenant_id = resource_grant.tenant_id
              AND binding.site_id = resource_grant.site_id
              AND binding.binding_id = resource_grant.binding_id
             LEFT JOIN xshield.ui_actions action
               ON action.tenant_id = resource_grant.tenant_id
              AND action.site_id = resource_grant.site_id
              AND action.action_ref = resource_grant.action_ref
             WHERE resource_grant.tenant_id = $1 AND resource_grant.site_id = $2
               AND resource_grant.grant_id = $3",
        )
        .bind(tenant.as_str())
        .bind(site.as_str())
        .bind(grant.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let summary = row
            .as_ref()
            .map(decode_summary)
            .transpose()
            .map_err(|error| match error {
                StoreError::Database(_) => StoreError::CorruptData("grant_inspection_row"),
                other => other,
            });
        tx.rollback().await?;
        summary
    }
}

fn decode_summary(row: &PgRow) -> Result<GrantInspection, StoreError> {
    if row.try_get::<Option<bool>, _>("finite_timestamps")? != Some(true) {
        return Err(StoreError::CorruptData("grant_inspection_time"));
    }
    let summary = GrantInspection {
        as_of: time(row, "as_of")?,
        grant_id: GrantId::parse(row.try_get::<&str, _>("grant_id")?)
            .map_err(|_| StoreError::CorruptData("grant_id"))?,
        binding_id: AuthBindingId::parse(row.try_get::<&str, _>("binding_id")?)
            .map_err(|_| StoreError::CorruptData("binding_id"))?,
        grant_epoch: epoch(row, "grant_epoch")?,
        binding_epoch: epoch(row, "binding_epoch")?,
        binding_status: match row.try_get::<&str, _>("binding_status")? {
            "anonymous" => BindingRecordStatus::Anonymous,
            "active" => BindingRecordStatus::Active,
            "revoked" => BindingRecordStatus::Revoked,
            "expired" => BindingRecordStatus::Expired,
            _ => return Err(StoreError::CorruptData("binding_status")),
        },
        binding_expires_at: time(row, "binding_expires_at")?,
        grant_status: match row.try_get::<&str, _>("grant_status")? {
            "active" => GrantRecordStatus::Active,
            "revoked" => GrantRecordStatus::Revoked,
            "expired" => GrantRecordStatus::Expired,
            _ => return Err(StoreError::CorruptData("grant_status")),
        },
        issued_at: time(row, "issued_at")?,
        expires_at: time(row, "expires_at")?,
        resource_type: ResourceType::parse(row.try_get::<&str, _>("resource_type")?)
            .map_err(|_| StoreError::CorruptData("resource_type"))?,
        operation_id: OperationId::parse(row.try_get::<&str, _>("operation_id")?)
            .map_err(|_| StoreError::CorruptData("operation_id"))?,
        view_profile: ViewProfile::parse(row.try_get::<&str, _>("view_id")?)
            .map_err(|_| StoreError::CorruptData("view_id"))?,
        policy_revision: PolicyRevision::parse(row.try_get::<&str, _>("policy_revision")?)
            .map_err(|_| StoreError::CorruptData("policy_revision"))?,
        source_event_id: EventId::parse(row.try_get::<&str, _>("source_event_id")?)
            .map_err(|_| StoreError::CorruptData("source_event_id"))?,
        source_request_id: RequestId::parse(row.try_get::<&str, _>("source_request_id")?)
            .map_err(|_| StoreError::CorruptData("source_request_id"))?,
    };
    validate_linkage(row, &summary)?;
    Ok(summary)
}

fn validate_linkage(row: &PgRow, summary: &GrantInspection) -> Result<(), StoreError> {
    let current_binding = AuthBindingId::parse(row.try_get::<&str, _>("current_binding_id")?)
        .map_err(|_| StoreError::CorruptData("current_binding_id"))?;
    let action_binding = AuthBindingId::parse(row.try_get::<&str, _>("action_binding_id")?)
        .map_err(|_| StoreError::CorruptData("action_binding_id"))?;
    let action_operation = OperationId::parse(row.try_get::<&str, _>("action_operation_id")?)
        .map_err(|_| StoreError::CorruptData("action_operation_id"))?;
    let action_view = ViewProfile::parse(row.try_get::<&str, _>("action_view_id")?)
        .map_err(|_| StoreError::CorruptData("action_view_id"))?;
    let action_policy = PolicyRevision::parse(row.try_get::<&str, _>("action_policy_revision")?)
        .map_err(|_| StoreError::CorruptData("action_policy_revision"))?;
    let action_issued = time(row, "action_issued_at")?;
    let action_expires = time(row, "action_expires_at")?;
    if current_binding != summary.binding_id
        || action_binding != summary.binding_id
        || epoch(row, "action_epoch")? != summary.grant_epoch
        || summary.binding_epoch < summary.grant_epoch
        || action_operation != summary.operation_id
        || action_view != summary.view_profile
        || action_policy != summary.policy_revision
        || summary.issued_at >= summary.expires_at
        || action_issued >= action_expires
        || summary.issued_at < action_issued
        || summary.expires_at > action_expires
    {
        return Err(StoreError::CorruptData("grant_inspection_linkage"));
    }
    Ok(())
}

fn epoch(row: &PgRow, field: &'static str) -> Result<AuthEpoch, StoreError> {
    u64::try_from(row.try_get::<i64, _>(field)?)
        .map(AuthEpoch::new)
        .map_err(|_| StoreError::CorruptData(field))
}

fn time(row: &PgRow, field: &'static str) -> Result<DateTime<Utc>, StoreError> {
    let value = row.try_get::<DateTime<Utc>, _>(field)?;
    if value.timestamp() < 0 {
        return Err(StoreError::CorruptData(field));
    }
    Ok(value)
}
