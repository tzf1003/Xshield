//! `PostgreSQL` adapters for identity and grant transactions.
//!
//! SQL statements always include tenant and site scope. Security state changes
//! and their outbox event commit in one database transaction.

#![warn(missing_docs)]

mod action_read;
mod grant;
mod grant_read;
mod identity_read;
mod provenance;
mod response_grant;
mod service_identity_read;
mod share_grant_issue;
mod share_grant_read;

pub use action_read::ResponseActionDescriptorQuery;
pub use grant::{GrantPersistence, GrantWriteOutcome};
pub use provenance::{ProvenancePersistence, ProvenanceWriteOutcome};
pub use response_grant::{
    CommittedResponseGrant, ResponseGrantItem, ResponseGrantPersistence, ResponseGrantWriteOutcome,
};
pub use share_grant_issue::{ShareGrantPersistence, ShareGrantWriteOutcome};

use serde_json::Value;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{collections::BTreeMap, error::Error, fmt, time::Duration};
use xshield_core::{
    domain::EventId,
    identity::{
        AuthBinding, AuthEpoch, AuthSnapshot, BindingStatus, CredentialFingerprint,
        CredentialGeneration, CredentialSlot, UnixSeconds,
    },
};

/// One verified authentication result ready for atomic binding establishment.
pub struct BindingEstablishment<'a> {
    binding: &'a AuthBinding,
    session_fingerprint: &'a [u8; 32],
    credentials_expire_at: UnixSeconds,
    now: UnixSeconds,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> BindingEstablishment<'a> {
    /// Validates an initial binding persistence command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the binding is not a fresh
    /// active generation, expiry bounds are incoherent, or the event is invalid.
    pub fn new(
        binding: &'a AuthBinding,
        session_fingerprint: &'a [u8; 32],
        credentials_expire_at: UnixSeconds,
        now: UnixSeconds,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if binding.status() != BindingStatus::Active
            || binding.epoch() != AuthEpoch::new(1)
            || binding.generation() != CredentialGeneration::new(1)
            || binding.absolute_expires_at() <= now
            || credentials_expire_at <= now
            || credentials_expire_at > binding.absolute_expires_at()
            || !event_envelope.is_object()
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            binding,
            session_fingerprint,
            credentials_expire_at,
            now,
            event_id,
            event_envelope,
        })
    }
}

/// Complete replacement credential set for a verified same-context refresh.
pub struct CredentialRefresh<'a> {
    snapshot: &'a AuthSnapshot,
    credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
    credentials_expire_at: UnixSeconds,
    now: UnixSeconds,
    event_id: &'a EventId,
    event_envelope: &'a Value,
}

impl<'a> CredentialRefresh<'a> {
    /// Validates a refresh persistence command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] when the credential set is empty,
    /// already expired, or the event envelope is not a JSON object.
    pub fn new(
        snapshot: &'a AuthSnapshot,
        credentials: &'a BTreeMap<CredentialSlot, CredentialFingerprint>,
        credentials_expire_at: UnixSeconds,
        now: UnixSeconds,
        event_id: &'a EventId,
        event_envelope: &'a Value,
    ) -> Result<Self, StoreError> {
        if credentials.is_empty() || credentials_expire_at <= now || !event_envelope.is_object() {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            snapshot,
            credentials,
            credentials_expire_at,
            now,
            event_id,
            event_envelope,
        })
    }
}

/// Result of an optimistic identity refresh transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshOutcome {
    /// Binding, credentials, and outbox event committed atomically.
    Updated {
        /// Generation required by the command.
        previous_generation: CredentialGeneration,
        /// Newly committed generation.
        current_generation: CredentialGeneration,
    },
    /// Binding state no longer matches the request snapshot.
    Conflict,
}

/// PostgreSQL-backed identity state writer.
#[derive(Clone, Debug)]
pub struct PostgresIdentityStore {
    pool: PgPool,
}

impl PostgresIdentityStore {
    /// Connects a bounded `PostgreSQL` pool.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid pool bounds or connection failure.
    pub async fn connect(
        database_url: &str,
        max_connections: u32,
        acquire_timeout: Duration,
    ) -> Result<Self, StoreError> {
        if max_connections == 0 || acquire_timeout.is_zero() {
            return Err(StoreError::InvalidPoolConfig);
        }
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(acquire_timeout)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    /// Uses an existing pool configured by the executable composition root.
    #[must_use]
    pub const fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Atomically creates one authenticated binding, its credential generation,
    /// and the corresponding outbox event.
    ///
    /// # Errors
    /// Returns [`StoreError`] when numeric bounds, uniqueness, or database
    /// durability prevents the complete transaction from committing.
    pub async fn establish_binding(
        &self,
        command: BindingEstablishment<'_>,
    ) -> Result<(), StoreError> {
        let epoch = to_i64(command.binding.epoch().value(), "auth_epoch")?;
        let generation = to_i64(
            command.binding.generation().value(),
            "credential_generation",
        )?;
        let now = to_i64(command.now.value(), "now")?;
        let absolute_expires_at = to_i64(
            command.binding.absolute_expires_at().value(),
            "absolute_expires_at",
        )?;
        let credentials_expire_at = to_i64(
            command.credentials_expire_at.value(),
            "credentials_expire_at",
        )?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO xshield.auth_bindings (
                tenant_id, site_id, binding_id, waf_sid_fingerprint, principal_ref,
                auth_epoch, credential_generation, status, absolute_expires_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', to_timestamp($8), to_timestamp($9))",
        )
        .bind(command.binding.tenant_id().as_str())
        .bind(command.binding.site_id().as_str())
        .bind(command.binding.binding_id().as_str())
        .bind(command.session_fingerprint.as_slice())
        .bind(command.binding.principal_ref())
        .bind(epoch)
        .bind(generation)
        .bind(absolute_expires_at)
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        for (slot, fingerprint) in command.binding.credentials() {
            sqlx::query(
                "INSERT INTO xshield.credential_bindings (
                    tenant_id, site_id, binding_id, generation, credential_kind,
                    fingerprint, expires_at, status
                 ) VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), 'active')",
            )
            .bind(command.binding.tenant_id().as_str())
            .bind(command.binding.site_id().as_str())
            .bind(command.binding.binding_id().as_str())
            .bind(generation)
            .bind(slot.as_str())
            .bind(fingerprint.as_bytes().as_slice())
            .bind(credentials_expire_at)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, 'binding.created', $5)",
        )
        .bind(command.event_id.as_str())
        .bind(command.binding.tenant_id().as_str())
        .bind(command.binding.site_id().as_str())
        .bind(command.binding.binding_id().as_str())
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically advances a same-context credential generation and writes its outbox event.
    ///
    /// The SQL predicate compares tenant, site, binding, principal, epoch,
    /// generation, active status, and both server-side expiry bounds. A zero-row
    /// update is a deterministic conflict rather than an automatic retry.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid numeric bounds or a database failure.
    pub async fn refresh_same_context(
        &self,
        command: CredentialRefresh<'_>,
    ) -> Result<RefreshOutcome, StoreError> {
        let expected_generation = to_i64(
            command.snapshot.generation().value(),
            "credential_generation",
        )?;
        let current_generation = expected_generation
            .checked_add(1)
            .ok_or(StoreError::NumericRange("credential_generation"))?;
        let epoch = to_i64(command.snapshot.epoch().value(), "auth_epoch")?;
        let now = to_i64(command.now.value(), "now")?;
        let credentials_expire_at = to_i64(
            command.credentials_expire_at.value(),
            "credentials_expire_at",
        )?;
        let mut transaction = self.pool.begin().await?;

        let updated = sqlx::query(
            "UPDATE xshield.auth_bindings
             SET credential_generation = $1, updated_at = to_timestamp($2)
             WHERE tenant_id = $3 AND site_id = $4 AND binding_id = $5
               AND principal_ref = $6 AND auth_epoch = $7
               AND credential_generation = $8 AND status = 'active'
               AND absolute_expires_at > to_timestamp($2)
               AND absolute_expires_at >= to_timestamp($9)",
        )
        .bind(current_generation)
        .bind(now)
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .bind(command.snapshot.principal_ref())
        .bind(epoch)
        .bind(expected_generation)
        .bind(credentials_expire_at)
        .execute(&mut *transaction)
        .await?;

        if updated.rows_affected() == 0 {
            transaction.rollback().await?;
            return Ok(RefreshOutcome::Conflict);
        }

        sqlx::query(
            "UPDATE xshield.credential_bindings
             SET status = 'revoked'
             WHERE tenant_id = $1 AND site_id = $2 AND binding_id = $3
               AND generation = $4 AND status IN ('active', 'transition')",
        )
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .bind(expected_generation)
        .execute(&mut *transaction)
        .await?;

        for (slot, fingerprint) in command.credentials {
            sqlx::query(
                "INSERT INTO xshield.credential_bindings (
                    tenant_id, site_id, binding_id, generation, credential_kind,
                    fingerprint, predecessor_generation, expires_at, status
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8), 'active')",
            )
            .bind(command.snapshot.tenant_id().as_str())
            .bind(command.snapshot.site_id().as_str())
            .bind(command.snapshot.binding_id().as_str())
            .bind(current_generation)
            .bind(slot.as_str())
            .bind(fingerprint.as_bytes().as_slice())
            .bind(expected_generation)
            .bind(credentials_expire_at)
            .execute(&mut *transaction)
            .await?;
        }

        sqlx::query(
            "INSERT INTO xshield.audit_outbox (
                event_id, tenant_id, site_id, aggregate_ref, event_type, envelope
             ) VALUES ($1, $2, $3, $4, 'identity.refreshed', $5)",
        )
        .bind(command.event_id.as_str())
        .bind(command.snapshot.tenant_id().as_str())
        .bind(command.snapshot.site_id().as_str())
        .bind(command.snapshot.binding_id().as_str())
        .bind(command.event_envelope)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(RefreshOutcome::Updated {
            previous_generation: CredentialGeneration::new(
                u64::try_from(expected_generation)
                    .map_err(|_| StoreError::NumericRange("credential_generation"))?,
            ),
            current_generation: CredentialGeneration::new(
                u64::try_from(current_generation)
                    .map_err(|_| StoreError::NumericRange("credential_generation"))?,
            ),
        })
    }
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::NumericRange(field))
}

/// `PostgreSQL` adapter failure with safe, non-secret context.
#[derive(Debug)]
pub enum StoreError {
    /// Pool configuration cannot serve requests.
    InvalidPoolConfig,
    /// Persistence command violates a local trust-boundary invariant.
    InvalidCommand,
    /// Unsigned domain value cannot fit the `PostgreSQL` signed integer column.
    NumericRange(&'static str),
    /// A stored value violates the adapter's domain contract.
    CorruptData(&'static str),
    /// `SQLx` connection, statement, or transaction failure.
    Database(sqlx::Error),
}

impl From<sqlx::Error> for StoreError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPoolConfig => formatter.write_str("invalid PostgreSQL pool configuration"),
            Self::InvalidCommand => formatter.write_str("invalid persistence command"),
            Self::NumericRange(field) => write!(formatter, "{field} exceeds PostgreSQL range"),
            Self::CorruptData(field) => write!(formatter, "invalid stored {field}"),
            Self::Database(_) => formatter.write_str("PostgreSQL operation failed"),
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            Self::InvalidPoolConfig
            | Self::InvalidCommand
            | Self::NumericRange(_)
            | Self::CorruptData(_) => None,
        }
    }
}
