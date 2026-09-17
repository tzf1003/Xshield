use crate::{PostgresIdentityStore, StoreError};
use sqlx::Row;
use std::collections::BTreeMap;
use xshield_core::{
    domain::AuthBindingId,
    identity::{
        AuthBinding, AuthEpoch, CredentialFingerprint, CredentialGeneration, CredentialSlot,
        IdentityDenied, UnixSeconds,
    },
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};

impl IdentityProofStore for PostgresIdentityStore {
    type Error = StoreError;

    async fn load_identity<'a>(
        &'a self,
        query: IdentityProofQuery<'a>,
    ) -> Result<IdentityProofState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let row = sqlx::query(
            "SELECT binding_id, principal_ref, auth_epoch, credential_generation,
                    extract(epoch FROM absolute_expires_at)::bigint AS absolute_expires_at
             FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND waf_sid_fingerprint = $3
               AND status = 'active' AND absolute_expires_at > to_timestamp($4)",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.session_fingerprint.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(IdentityProofState::Denied(IdentityDenied::BindingMismatch));
        };

        let binding_id = AuthBindingId::parse(row.try_get::<&str, _>("binding_id")?)
            .map_err(|_| StoreError::CorruptData("binding_id"))?;
        let principal_ref = row.try_get::<&str, _>("principal_ref")?;
        let epoch = nonnegative(row.try_get("auth_epoch")?, "auth_epoch")?;
        let generation = nonnegative(
            row.try_get("credential_generation")?,
            "credential_generation",
        )?;
        let absolute_expires_at =
            nonnegative(row.try_get("absolute_expires_at")?, "absolute_expires_at")?;
        let credential_rows = sqlx::query(
            "SELECT credential_kind, fingerprint
             FROM xshield.credential_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
               AND generation = $4 AND status = 'active'
               AND expires_at > to_timestamp($5)",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(binding_id.as_str())
        .bind(i64::try_from(generation).map_err(|_| StoreError::NumericRange("generation"))?)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let mut stored_credentials = BTreeMap::new();
        for credential in credential_rows {
            let slot = match credential.try_get::<&str, _>("credential_kind")? {
                "cookie" => CredentialSlot::Cookie,
                "bearer" => CredentialSlot::Bearer,
                "body_token" => CredentialSlot::BodyToken,
                _ => return Err(StoreError::CorruptData("credential_kind")),
            };
            let bytes = credential.try_get::<Vec<u8>, _>("fingerprint")?;
            let fingerprint = CredentialFingerprint::from_bytes(
                bytes
                    .try_into()
                    .map_err(|_| StoreError::CorruptData("credential_fingerprint"))?,
            );
            if stored_credentials.insert(slot, fingerprint).is_some() {
                return Err(StoreError::CorruptData("duplicate_credential_kind"));
            }
        }
        if stored_credentials.is_empty() {
            return Ok(IdentityProofState::Denied(IdentityDenied::BindingMismatch));
        }

        let binding = AuthBinding::new(
            binding_id,
            query.session_id.clone(),
            query.tenant_id.clone(),
            query.site_id.clone(),
            principal_ref,
            AuthEpoch::new(epoch),
            CredentialGeneration::new(generation),
            stored_credentials,
            UnixSeconds::new(absolute_expires_at),
        )
        .map_err(|_| StoreError::CorruptData("auth_binding"))?;
        match binding.verify(
            query.tenant_id,
            query.site_id,
            query.session_id,
            query.credentials,
            query.now,
        ) {
            Ok(snapshot) => Ok(IdentityProofState::Verified {
                binding: Box::new(binding),
                snapshot,
            }),
            Err(error) => Ok(IdentityProofState::Denied(error)),
        }
    }
}

fn nonnegative(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptData(field))
}
