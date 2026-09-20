use crate::{PostgresIdentityStore, StoreError, lease_is_live, to_i64};
use sqlx::Row;
use xshield_core::{
    domain::{RequestId, SiteId, TenantId},
    identity::UnixSeconds,
};

/// One authenticated request message ready for atomic replay consumption.
pub struct RequestCryptoMessage<'a> {
    tenant_id: &'a TenantId,
    site_id: &'a SiteId,
    key_id: &'a str,
    message_id: &'a str,
    nonce: &'a [u8; 12],
    request_id: &'a RequestId,
    expires_at: UnixSeconds,
    now: UnixSeconds,
    max_active_messages: u32,
}

impl<'a> RequestCryptoMessage<'a> {
    /// Validates an authenticated replay-consumption command.
    ///
    /// # Errors
    /// Returns [`StoreError::InvalidCommand`] for invalid identifiers, expiry,
    /// or capacity. Cryptographic authentication remains the caller's duty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: &'a TenantId,
        site_id: &'a SiteId,
        key_id: &'a str,
        message_id: &'a str,
        nonce: &'a [u8; 12],
        request_id: &'a RequestId,
        expires_at: UnixSeconds,
        now: UnixSeconds,
        max_active_messages: u32,
    ) -> Result<Self, StoreError> {
        if key_id.is_empty()
            || message_id.is_empty()
            || expires_at <= now
            || max_active_messages == 0
        {
            return Err(StoreError::InvalidCommand);
        }
        Ok(Self {
            tenant_id,
            site_id,
            key_id,
            message_id,
            nonce,
            request_id,
            expires_at,
            now,
            max_active_messages,
        })
    }
}

/// Result of atomically consuming one authenticated request message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestCryptoMessageOutcome {
    /// The nonce and message identifier were unused and are now consumed.
    Consumed,
    /// The nonce or message identifier was already consumed for this key.
    Replayed,
    /// The database clock reached the frozen message deadline; nothing commits.
    Expired,
    /// The configured active-message bound is already reached.
    CapacityExceeded,
}

impl PostgresIdentityStore {
    /// Atomically consumes a key-scoped message identifier and nonce.
    ///
    /// Rows expired under both the application and database clocks are removed
    /// before a site-wide capacity check. A transaction advisory lock makes the
    /// check and dual unique constraints deterministic across gateway instances.
    /// The database deadline is rechecked after the lock and before commit;
    /// expiry rolls back cleanup and consumption. The caller must audit every
    /// result before forwarding a consumed message to the origin.
    ///
    /// # Errors
    /// Returns [`StoreError`] when validation, conversion, or persistence fails.
    pub async fn consume_request_crypto_message(
        &self,
        message: RequestCryptoMessage<'_>,
    ) -> Result<RequestCryptoMessageOutcome, StoreError> {
        let now = to_i64(message.now.value(), "now")?;
        let expires_at = to_i64(message.expires_at.value(), "expires_at")?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(
                 'xshield-request-crypto-v1:' || $1 || ':' || $2, 0
             ))",
        )
        .bind(message.tenant_id.as_str())
        .bind(message.site_id.as_str())
        .execute(&mut *transaction)
        .await?;
        if !lease_is_live(&mut transaction, expires_at).await? {
            transaction.rollback().await?;
            return Ok(RequestCryptoMessageOutcome::Expired);
        }
        // A fast edge must retain nonces that other edges can still accept.
        sqlx::query(
            "DELETE FROM xshield.request_crypto_messages
             WHERE tenant_id = $1 AND site_id = $2
               AND expires_at <= LEAST(to_timestamp($3), clock_timestamp())",
        )
        .bind(message.tenant_id.as_str())
        .bind(message.site_id.as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
        let active = sqlx::query(
            "SELECT count(*) AS count
             FROM xshield.request_crypto_messages
             WHERE tenant_id = $1 AND site_id = $2",
        )
        .bind(message.tenant_id.as_str())
        .bind(message.site_id.as_str())
        .fetch_one(&mut *transaction)
        .await?
        .try_get::<i64, _>("count")?;
        if active >= i64::from(message.max_active_messages) {
            transaction.rollback().await?;
            return Ok(RequestCryptoMessageOutcome::CapacityExceeded);
        }
        let inserted = sqlx::query(
            "INSERT INTO xshield.request_crypto_messages (
                 tenant_id, site_id, key_id, message_id, nonce,
                 source_request_id, expires_at, consumed_at
             ) VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($8))
             ON CONFLICT DO NOTHING",
        )
        .bind(message.tenant_id.as_str())
        .bind(message.site_id.as_str())
        .bind(message.key_id)
        .bind(message.message_id)
        .bind(message.nonce.as_slice())
        .bind(message.request_id.as_str())
        .bind(expires_at)
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if !lease_is_live(&mut transaction, expires_at).await? {
            transaction.rollback().await?;
            return Ok(RequestCryptoMessageOutcome::Expired);
        }
        transaction.commit().await?;
        Ok(if inserted == 1 {
            RequestCryptoMessageOutcome::Consumed
        } else {
            RequestCryptoMessageOutcome::Replayed
        })
    }
}
