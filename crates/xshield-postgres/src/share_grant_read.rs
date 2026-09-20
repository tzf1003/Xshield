use crate::{PostgresIdentityStore, StoreError};
use sqlx::Row;
use xshield_core::{
    access::{AccessDenied, ShareGrant},
    domain::ShareGrantId,
    identity::UnixSeconds,
    ports::{ShareGrantProofQuery, ShareGrantProofState, ShareGrantProofStore},
};

impl ShareGrantProofStore for PostgresIdentityStore {
    type Error = StoreError;

    async fn load_share_grant<'a>(
        &'a self,
        query: ShareGrantProofQuery<'a>,
    ) -> Result<ShareGrantProofState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let row = sqlx::query(
            "SELECT share_id, extract(epoch FROM expires_at)::bigint AS expires_at
             FROM xshield.share_grants
             WHERE tenant_id = $1 AND site_id = $2 AND token_fingerprint = $3
               AND resource_type = $4 AND resource_key_hmac = $5
               AND operation_id = $6 AND view_id = $7
               AND use_policy = 'reusable_read' AND status = 'active'
               AND expires_at > GREATEST(to_timestamp($8), clock_timestamp())",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.token_fingerprint.as_bytes().as_slice())
        .bind(query.resource_type.as_str())
        .bind(query.resource_key.as_bytes().as_slice())
        .bind(query.operation_id.as_str())
        .bind(query.view_profile.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(ShareGrantProofState::Denied(
                AccessDenied::ShareScopeMismatch,
            ));
        };

        let share_id = ShareGrantId::parse(row.try_get::<&str, _>("share_id")?)
            .map_err(|_| StoreError::CorruptData("share_id"))?;
        let expires_at = u64::try_from(row.try_get::<i64, _>("expires_at")?)
            .map_err(|_| StoreError::CorruptData("share_expires_at"))?;
        let grant = ShareGrant::new_read_only(
            share_id,
            query.tenant_id.clone(),
            query.site_id.clone(),
            query.token_fingerprint.clone(),
            query.resource_type.clone(),
            query.resource_key.clone(),
            query.operation_id.clone(),
            query.view_profile.clone(),
            UnixSeconds::new(expires_at),
            query.now,
        )
        .map_err(|_| StoreError::CorruptData("share_grant"))?;
        Ok(ShareGrantProofState::Verified(Box::new(grant)))
    }
}
