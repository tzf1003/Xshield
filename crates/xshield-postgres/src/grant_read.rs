use crate::{PostgresIdentityStore, StoreError};
use sqlx::Row;
use xshield_core::{
    domain::{GrantId, IssuanceKey, RequestId},
    grant::{GrantDenied, GrantDraft, GrantLedger},
    identity::UnixSeconds,
    ports::{ResourceProofQuery, ResourceProofState, ResourceProofStore},
};

impl ResourceProofStore for PostgresIdentityStore {
    type Error = StoreError;

    async fn load_resource_grant<'a>(
        &'a self,
        query: ResourceProofQuery<'a>,
    ) -> Result<ResourceProofState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let epoch = i64::try_from(query.snapshot.epoch().value())
            .map_err(|_| StoreError::NumericRange("auth_epoch"))?;
        let row = sqlx::query(
            "SELECT resource_grant.grant_id, resource_grant.issuance_key, action.source_request_id,
                    extract(epoch FROM resource_grant.issued_at)::bigint AS issued_at,
                    extract(epoch FROM resource_grant.expires_at)::bigint AS expires_at
             FROM xshield.resource_grants resource_grant
             JOIN xshield.ui_actions action
               ON action.tenant_id = resource_grant.tenant_id
              AND action.site_id = resource_grant.site_id
              AND action.action_ref = resource_grant.action_ref
              AND action.binding_id = resource_grant.binding_id
              AND action.auth_epoch = resource_grant.auth_epoch
              AND action.operation_id = resource_grant.operation_id
              AND action.field_profile = resource_grant.view_id
              AND action.policy_revision = resource_grant.policy_revision
              AND resource_grant.issued_at >= action.issued_at
              AND resource_grant.expires_at <= action.expires_at
             JOIN xshield.policy_revisions policy
               ON policy.tenant_id = resource_grant.tenant_id
              AND policy.site_id = resource_grant.site_id
              AND policy.revision = resource_grant.policy_revision
             WHERE resource_grant.tenant_id = $1 AND resource_grant.site_id = $2
               AND resource_grant.binding_id = $3 AND resource_grant.auth_epoch = $4
               AND resource_grant.action_ref = $5 AND resource_grant.resource_type = $6
               AND resource_grant.resource_key_hmac = $7 AND resource_grant.operation_id = $8
               AND resource_grant.view_id = $9 AND resource_grant.policy_revision = $10
               AND resource_grant.status = 'active'
               AND resource_grant.expires_at > to_timestamp($11)
               AND action.status = 'active' AND action.expires_at > to_timestamp($11)
               AND policy.status = 'active'",
        )
        .bind(query.snapshot.tenant_id().as_str())
        .bind(query.snapshot.site_id().as_str())
        .bind(query.snapshot.binding_id().as_str())
        .bind(epoch)
        .bind(query.action_ref.as_str())
        .bind(query.resource_type.as_str())
        .bind(query.resource_key.as_bytes().as_slice())
        .bind(query.operation_id.as_str())
        .bind(query.view_profile.as_str())
        .bind(query.policy_revision.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(ResourceProofState::Denied(
                self.resource_denial(&query, epoch, now).await?,
            ));
        };

        let issued_at = time(&row, "issued_at")?;
        let mut ledger =
            GrantLedger::new(1).map_err(|_| StoreError::CorruptData("grant_ledger"))?;
        ledger
            .issue(
                query.binding,
                query.snapshot,
                GrantDraft {
                    grant_id: GrantId::parse(row.try_get::<&str, _>("grant_id")?)
                        .map_err(|_| StoreError::CorruptData("grant_id"))?,
                    issuance_key: IssuanceKey::parse(row.try_get::<&str, _>("issuance_key")?)
                        .map_err(|_| StoreError::CorruptData("issuance_key"))?,
                    resource_type: query.resource_type.clone(),
                    resource_key: query.resource_key.clone(),
                    operation_id: query.operation_id.clone(),
                    view_profile: query.view_profile.clone(),
                    source_request_id: RequestId::parse(
                        row.try_get::<&str, _>("source_request_id")?,
                    )
                    .map_err(|_| StoreError::CorruptData("source_request_id"))?,
                    policy_revision: query.policy_revision.clone(),
                    expires_at: time(&row, "expires_at")?,
                },
                issued_at,
            )
            .map_err(|_| StoreError::CorruptData("resource_grant"))?;
        Ok(ResourceProofState::Verified(Box::new(ledger)))
    }
}

impl PostgresIdentityStore {
    async fn resource_denial(
        &self,
        query: &ResourceProofQuery<'_>,
        epoch: i64,
        now: i64,
    ) -> Result<GrantDenied, StoreError> {
        let resource_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM xshield.resource_grants resource_grant
                JOIN xshield.ui_actions action
                  ON action.tenant_id = resource_grant.tenant_id
                 AND action.site_id = resource_grant.site_id
                 AND action.action_ref = resource_grant.action_ref
                 AND action.binding_id = resource_grant.binding_id
                 AND action.auth_epoch = resource_grant.auth_epoch
                 AND action.policy_revision = resource_grant.policy_revision
                 AND resource_grant.issued_at >= action.issued_at
                 AND resource_grant.expires_at <= action.expires_at
                JOIN xshield.policy_revisions policy
                  ON policy.tenant_id = resource_grant.tenant_id
                 AND policy.site_id = resource_grant.site_id
                 AND policy.revision = resource_grant.policy_revision
                WHERE resource_grant.tenant_id = $1 AND resource_grant.site_id = $2
                  AND resource_grant.binding_id = $3 AND resource_grant.auth_epoch = $4
                  AND resource_grant.action_ref = $5 AND resource_grant.resource_type = $6
                  AND resource_grant.resource_key_hmac = $7
                  AND resource_grant.policy_revision = $8
                  AND resource_grant.status = 'active'
                  AND resource_grant.expires_at > to_timestamp($9)
                  AND action.status = 'active' AND action.expires_at > to_timestamp($9)
                  AND policy.status = 'active'
             )",
        )
        .bind(query.snapshot.tenant_id().as_str())
        .bind(query.snapshot.site_id().as_str())
        .bind(query.snapshot.binding_id().as_str())
        .bind(epoch)
        .bind(query.action_ref.as_str())
        .bind(query.resource_type.as_str())
        .bind(query.resource_key.as_bytes().as_slice())
        .bind(query.policy_revision.as_str())
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(if resource_exists {
            GrantDenied::OperationNotGranted
        } else {
            GrantDenied::CapabilityMissing
        })
    }
}

fn time(row: &sqlx::postgres::PgRow, field: &'static str) -> Result<UnixSeconds, StoreError> {
    Ok(UnixSeconds::new(
        u64::try_from(row.try_get::<i64, _>(field)?).map_err(|_| StoreError::CorruptData(field))?,
    ))
}
