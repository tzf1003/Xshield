use crate::{PostgresIdentityStore, StoreError};
use sqlx::Row;
use std::collections::BTreeSet;
use xshield_core::{
    access::{AccessDenied, ServiceIdentity},
    domain::{OperationId, ServiceIdentityId},
    identity::UnixSeconds,
    ports::{ServiceIdentityProofQuery, ServiceIdentityProofState, ServiceIdentityProofStore},
};

impl ServiceIdentityProofStore for PostgresIdentityStore {
    type Error = StoreError;

    async fn load_service_identity<'a>(
        &'a self,
        query: ServiceIdentityProofQuery<'a>,
    ) -> Result<ServiceIdentityProofState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let row = sqlx::query(
            "SELECT service_id, operation_ids,
                    extract(epoch FROM expires_at)::bigint AS expires_at
             FROM xshield.service_identities
             WHERE tenant_id = $1 AND site_id = $2 AND credential_fingerprint = $3
               AND status = 'active' AND expires_at > to_timestamp($4)",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.credential_fingerprint.as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(ServiceIdentityProofState::Denied(
                AccessDenied::ServiceIdentityMismatch,
            ));
        };

        let identity_id = ServiceIdentityId::parse(row.try_get::<&str, _>("service_id")?)
            .map_err(|_| StoreError::CorruptData("service_id"))?;
        let operations = row
            .try_get::<Vec<String>, _>("operation_ids")?
            .into_iter()
            .map(OperationId::parse)
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|_| StoreError::CorruptData("service_operation"))?;
        let expires_at = u64::try_from(row.try_get::<i64, _>("expires_at")?)
            .map_err(|_| StoreError::CorruptData("service_expires_at"))?;
        let identity = ServiceIdentity::new(
            identity_id,
            query.tenant_id.clone(),
            query.site_id.clone(),
            query.credential_fingerprint.clone(),
            operations,
            UnixSeconds::new(expires_at),
            query.now,
        )
        .map_err(|_| StoreError::CorruptData("service_identity"))?;
        Ok(ServiceIdentityProofState::Verified(Box::new(identity)))
    }
}
