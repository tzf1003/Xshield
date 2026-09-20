use crate::{PostgresIdentityStore, StoreError};
use sqlx::Row;
use std::collections::BTreeMap;
use xshield_core::{
    domain::{AuthBindingId, SiteId, TenantId},
    identity::{
        AuthBinding, AuthEpoch, AuthorizationContextRef, CredentialFingerprint,
        CredentialGeneration, CredentialSlot, IdentityDenied, UnixSeconds,
    },
    ports::{IdentityProofQuery, IdentityProofState, IdentityProofStore},
};

/// Session-only proof query for restricted sensor metadata ingestion.
pub struct SensorSessionQuery<'a> {
    /// Tenant selected by trusted gateway configuration.
    pub tenant_id: &'a TenantId,
    /// Site selected by trusted gateway configuration.
    pub site_id: &'a SiteId,
    /// Tenant-scoped fingerprint of the `HttpOnly` WAF session cookie.
    pub session_fingerprint: &'a [u8; 32],
    /// Server time used for expiry checks.
    pub now: UnixSeconds,
}

/// Current identity coordinates attached to a sensor observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensorSession {
    binding_id: AuthBindingId,
    epoch: AuthEpoch,
    authenticated: bool,
}

impl SensorSession {
    /// Returns the current binding identifier.
    #[must_use]
    pub const fn binding_id(&self) -> &AuthBindingId {
        &self.binding_id
    }

    /// Returns the current identity epoch.
    #[must_use]
    pub const fn epoch(&self) -> AuthEpoch {
        self.epoch
    }

    /// Returns whether this is an active authenticated binding.
    #[must_use]
    pub const fn authenticated(&self) -> bool {
        self.authenticated
    }
}

/// Result of a session-only sensor lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SensorSessionState {
    /// An active or anonymous unexpired WAF session matched exactly.
    Verified(SensorSession),
    /// No current session matched the presented cookie fingerprint.
    Denied,
}

impl IdentityProofStore for PostgresIdentityStore {
    type Error = StoreError;

    async fn load_identity<'a>(
        &'a self,
        query: IdentityProofQuery<'a>,
    ) -> Result<IdentityProofState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let row = sqlx::query(
            "SELECT binding_id, principal_ref, authorization_context_ref,
                    auth_epoch, credential_generation,
                    extract(epoch FROM absolute_expires_at)::bigint AS absolute_expires_at
             FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND waf_sid_fingerprint = $3
               AND status = 'active'
               AND absolute_expires_at > GREATEST(to_timestamp($4), clock_timestamp())",
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
        let authorization_context_ref =
            AuthorizationContextRef::parse(row.try_get::<&str, _>("authorization_context_ref")?)
                .map_err(|_| StoreError::CorruptData("authorization_context_ref"))?;
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
               AND expires_at > GREATEST(to_timestamp($5), clock_timestamp())",
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
            authorization_context_ref,
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

impl PostgresIdentityStore {
    /// Loads current session coordinates without accepting business operations.
    ///
    /// This lookup is reserved for sensor metadata. It never returns a full
    /// authentication proof and cannot satisfy normal operation admission.
    ///
    /// # Errors
    /// Returns [`StoreError`] for database or stored-data failures.
    pub async fn load_sensor_session(
        &self,
        query: SensorSessionQuery<'_>,
    ) -> Result<SensorSessionState, StoreError> {
        let now = i64::try_from(query.now.value()).map_err(|_| StoreError::NumericRange("now"))?;
        let row = sqlx::query(
            "SELECT binding_id, auth_epoch, status
             FROM xshield.auth_bindings
             WHERE tenant_id = $1 AND site_id = $2 AND waf_sid_fingerprint = $3
               AND status IN ('anonymous', 'active')
               AND absolute_expires_at > GREATEST(to_timestamp($4), clock_timestamp())",
        )
        .bind(query.tenant_id.as_str())
        .bind(query.site_id.as_str())
        .bind(query.session_fingerprint.as_slice())
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(SensorSessionState::Denied);
        };
        let binding_id = AuthBindingId::parse(row.try_get::<&str, _>("binding_id")?)
            .map_err(|_| StoreError::CorruptData("binding_id"))?;
        let epoch = AuthEpoch::new(nonnegative(row.try_get("auth_epoch")?, "auth_epoch")?);
        let authenticated = match row.try_get::<&str, _>("status")? {
            "active" => true,
            "anonymous" => false,
            _ => return Err(StoreError::CorruptData("binding_status")),
        };
        Ok(SensorSessionState::Verified(SensorSession {
            binding_id,
            epoch,
            authenticated,
        }))
    }
}

fn nonnegative(value: i64, field: &'static str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::CorruptData(field))
}
