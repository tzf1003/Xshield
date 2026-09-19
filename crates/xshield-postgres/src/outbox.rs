//! Bounded, tenant-scoped `PostgreSQL` outbox delivery leases.

use crate::{PostgresIdentityStore, StoreError};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::{convert::TryFrom, time::Duration};
use uuid::Uuid;
use xshield_core::domain::{EventId, SiteId, TenantId};

const MAX_TEXT_BYTES: usize = 256;
const MAX_EVENTS: u32 = 256;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEASE_SECONDS: u64 = 3600;
const MAX_RETRY_SECONDS: i64 = 3600;

/// Fixed tenant/site scope used for every outbox operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboxScope {
    tenant_id: TenantId,
    site_id: SiteId,
}

impl OutboxScope {
    /// Copies validated tenant and site identifiers into an operation scope.
    #[must_use]
    pub fn new(tenant_id: &TenantId, site_id: &SiteId) -> Self {
        Self {
            tenant_id: tenant_id.clone(),
            site_id: site_id.clone(),
        }
    }

    /// Returns the tenant bound to this scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns the site bound to this scope.
    #[must_use]
    pub const fn site_id(&self) -> &SiteId {
        &self.site_id
    }
}

/// Limits and lease duration for one claim transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboxLeaseConfig {
    /// Maximum number of rows returned by a claim.
    pub max_events: u32,
    /// Maximum UTF-8 byte length of the selected JSON envelopes.
    pub max_bytes: u64,
    /// How long a claimed row remains owned by this lease.
    pub lease_for: Duration,
}

impl OutboxLeaseConfig {
    /// Creates a bounded claim configuration.
    ///
    /// Errors are returned when a bound is zero, or when the duration cannot
    /// be represented as whole `PostgreSQL` seconds.
    ///
    /// # Errors
    /// Returns [`StoreError`] when a bound is zero, exceeds the hard cap, or
    /// cannot be represented by `PostgreSQL`.
    pub fn new(max_events: u32, max_bytes: u64, lease_for: Duration) -> Result<Self, StoreError> {
        if max_events == 0
            || max_events > MAX_EVENTS
            || max_bytes == 0
            || max_bytes > MAX_BYTES
            || lease_for.as_secs() == 0
            || lease_for.as_secs() > MAX_LEASE_SECONDS
            || lease_for.subsec_nanos() != 0
        {
            return Err(StoreError::InvalidCommand);
        }
        i64::try_from(max_bytes).map_err(|_| StoreError::NumericRange("max_bytes"))?;
        i64::try_from(lease_for.as_secs()).map_err(|_| StoreError::NumericRange("lease_for"))?;
        Ok(Self {
            max_events,
            max_bytes,
            lease_for,
        })
    }
}

/// One claimed outbox event and its current delivery lease.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboxEvent {
    /// Stable event identity used for at-least-once deduplication.
    pub event_id: EventId,
    /// Event tenant; equal to the claim scope tenant.
    pub tenant_id: TenantId,
    /// Event site; equal to the claim scope site.
    pub site_id: SiteId,
    /// Aggregate whose state produced the event.
    pub aggregate_ref: String,
    /// Stable event type discriminator.
    pub event_type: String,
    /// Typed JSON envelope persisted by the producer transaction.
    pub envelope: Value,
    /// Database creation time.
    pub created_at: DateTime<Utc>,
    /// Number of claims, including this claim.
    pub delivery_attempts: u32,
    /// Opaque token required to acknowledge or fail this lease.
    pub lease_token: String,
    /// Database time at which this lease expires.
    pub lease_until: DateTime<Utc>,
    /// Earliest database time at which another claim may be made.
    pub next_attempt_at: DateTime<Utc>,
    /// Stable publisher failure code from the previous attempt, if any.
    pub last_error_code: Option<String>,
}

/// Alias used by publishers when they only need to name the lease result.
pub type OutboxLease = OutboxEvent;

/// Result of an acknowledgement attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxAckOutcome {
    /// The event was marked published while the supplied lease was current.
    Acknowledged,
    /// The event was absent, already published, or owned by another/expired lease.
    Rejected,
}

/// Result of recording a failed delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxFailureOutcome {
    /// The lease was released and a retry was scheduled.
    Scheduled,
    /// The event was absent, already published, or owned by another/expired lease.
    Rejected,
}

/// Claims a bounded set of ready events for one tenant/site.
///
/// The transaction takes row locks with FOR UPDATE SKIP LOCKED, computes a
/// cumulative envelope-byte bound, and assigns one fresh token to every row.
/// All timestamps come from `PostgreSQL` `clock_timestamp()`, so workers do not
/// rely on unsynchronised host clocks.
///
/// Errors are returned for invalid bounds or when a stored row cannot be
/// represented by the typed result. Database errors roll back the claim
/// transaction.
///
/// # Errors
/// Returns [`StoreError`] for invalid bounds, database failures, or corrupt
/// stored rows.
pub async fn claim_outbox_batch(
    pool: &PgPool,
    scope: &OutboxScope,
    config: OutboxLeaseConfig,
) -> Result<Vec<OutboxLease>, StoreError> {
    claim_outbox_batch_for_types(pool, scope, config, &[]).await
}

/// Claims a bounded set of ready events restricted to explicit event families.
///
/// An empty family list preserves the generic all-family behavior. Non-empty
/// lists are validated before SQL construction so a family-specific worker
/// cannot lease and mutate another producer's rows.
///
/// # Errors
/// Returns [`StoreError`] for invalid bounds/families, database failures, or
/// corrupt stored rows.
pub async fn claim_outbox_batch_for_types(
    pool: &PgPool,
    scope: &OutboxScope,
    config: OutboxLeaseConfig,
    event_types: &[&str],
) -> Result<Vec<OutboxLease>, StoreError> {
    let event_types = event_types
        .iter()
        .map(|event_type| {
            validate_event_type(event_type)?;
            Ok((*event_type).to_owned())
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    let lease_seconds = i64::try_from(config.lease_for.as_secs())
        .map_err(|_| StoreError::NumericRange("lease_for"))?;
    let max_bytes =
        i64::try_from(config.max_bytes).map_err(|_| StoreError::NumericRange("max_bytes"))?;
    if config.max_events == 0
        || config.max_events > MAX_EVENTS
        || config.max_bytes == 0
        || config.max_bytes > MAX_BYTES
        || lease_seconds == 0
        || lease_seconds > 3600
        || config.lease_for.subsec_nanos() != 0
    {
        return Err(StoreError::InvalidCommand);
    }

    let token = Uuid::now_v7().to_string();
    let mut transaction = pool.begin().await?;
    let rows = sqlx::query(
        "WITH db_clock AS (
             SELECT clock_timestamp() AS now
         ), candidates AS (
             SELECT outbox.event_id, outbox.created_at, outbox.envelope,
                    db_clock.now
             FROM xshield.audit_outbox AS outbox
             CROSS JOIN db_clock
             WHERE outbox.tenant_id = $1
               AND outbox.site_id = $2
               AND outbox.published_at IS NULL
               AND outbox.next_attempt_at <= db_clock.now
               AND (outbox.lease_until IS NULL OR outbox.lease_until <= db_clock.now)
               AND (cardinality($7::text[]) = 0 OR outbox.event_type = ANY($7::text[]))
             ORDER BY outbox.created_at, outbox.event_id
             LIMIT $3
             FOR UPDATE SKIP LOCKED
         ), bounded AS (
             SELECT event_id, now,
                    SUM(octet_length(envelope::text)::bigint)
                        OVER (ORDER BY created_at, event_id) AS envelope_bytes
             FROM candidates
         )
         UPDATE xshield.audit_outbox AS outbox
         SET lease_token = $4,
             lease_until = bounded.now
                 + make_interval(secs => $5::double precision),
             delivery_attempts = outbox.delivery_attempts + 1
         FROM bounded
         WHERE outbox.tenant_id = $1
           AND outbox.site_id = $2
           AND outbox.event_id = bounded.event_id
           AND bounded.envelope_bytes <= $6
         RETURNING outbox.event_id, outbox.tenant_id, outbox.site_id,
                   outbox.aggregate_ref, outbox.event_type, outbox.envelope,
                   outbox.created_at, outbox.delivery_attempts,
                   outbox.lease_token, outbox.lease_until,
                   outbox.next_attempt_at, outbox.last_error_code",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(i64::from(config.max_events))
    .bind(&token)
    .bind(lease_seconds)
    .bind(max_bytes)
    .bind(event_types)
    .fetch_all(&mut *transaction)
    .await?;
    let leases = rows
        .into_iter()
        .map(|row| parse_lease(&row))
        .collect::<Result<Vec<_>, _>>()?;
    transaction.commit().await?;
    Ok(leases)
}

/// Acknowledges an event only while its exact scoped lease is current.
///
/// # Errors
/// Returns [`StoreError`] for an invalid lease token or database failure.
pub async fn ack_outbox_event(
    pool: &PgPool,
    scope: &OutboxScope,
    event_id: &EventId,
    lease_token: &str,
) -> Result<OutboxAckOutcome, StoreError> {
    validate_token(lease_token)?;
    let changed = sqlx::query(
        "UPDATE xshield.audit_outbox
         SET published_at = clock_timestamp(), lease_until = NULL, lease_token = NULL
         WHERE tenant_id = $1 AND site_id = $2 AND event_id = $3
           AND published_at IS NULL AND lease_token = $4
           AND lease_until > clock_timestamp()",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(event_id.as_str())
    .bind(lease_token)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(if changed == 1 {
        OutboxAckOutcome::Acknowledged
    } else {
        OutboxAckOutcome::Rejected
    })
}

/// Releases an event lease and schedules a bounded retry.
///
/// `retry_after` is interpreted by `PostgreSQL` relative to its own clock. The
/// caller's error code is persisted as a stable, non-secret diagnostic.
///
/// # Errors
/// Returns [`StoreError`] for invalid lease/error input, out-of-range retry
/// duration, or database failure.
pub async fn fail_outbox_event(
    pool: &PgPool,
    scope: &OutboxScope,
    event_id: &EventId,
    lease_token: &str,
    error_code: &str,
    retry_after: Duration,
) -> Result<OutboxFailureOutcome, StoreError> {
    validate_token(lease_token)?;
    validate_error_code(error_code)?;
    let retry_seconds = i64::try_from(retry_after.as_secs())
        .map_err(|_| StoreError::NumericRange("retry_after"))?;
    if !(1..=MAX_RETRY_SECONDS).contains(&retry_seconds) || retry_after.subsec_nanos() != 0 {
        return Err(StoreError::InvalidCommand);
    }
    let changed = sqlx::query(
        "UPDATE xshield.audit_outbox
         SET lease_until = NULL,
             lease_token = NULL,
             next_attempt_at = clock_timestamp()
                 + make_interval(secs => $5::double precision),
             last_error_code = $6
         WHERE tenant_id = $1 AND site_id = $2 AND event_id = $3
           AND published_at IS NULL AND lease_token = $4
           AND lease_until > clock_timestamp()",
    )
    .bind(scope.tenant_id().as_str())
    .bind(scope.site_id().as_str())
    .bind(event_id.as_str())
    .bind(lease_token)
    .bind(retry_seconds)
    .bind(error_code)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(if changed == 1 {
        OutboxFailureOutcome::Scheduled
    } else {
        OutboxFailureOutcome::Rejected
    })
}

impl PostgresIdentityStore {
    /// Claims outbox rows using this store's pool.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid bounds, database failures, or
    /// corrupt stored rows.
    pub async fn claim_outbox_batch(
        &self,
        scope: &OutboxScope,
        config: OutboxLeaseConfig,
    ) -> Result<Vec<OutboxLease>, StoreError> {
        // The free function documents and enforces the command invariants.
        claim_outbox_batch(&self.pool, scope, config).await
    }

    /// Claims outbox rows restricted to explicit event families.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid bounds/families, database failures,
    /// or corrupt stored rows.
    pub async fn claim_outbox_batch_for_types(
        &self,
        scope: &OutboxScope,
        config: OutboxLeaseConfig,
        event_types: &[&str],
    ) -> Result<Vec<OutboxLease>, StoreError> {
        claim_outbox_batch_for_types(&self.pool, scope, config, event_types).await
    }

    /// Acknowledges an outbox row using this store's pool.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid lease input or database failure.
    pub async fn ack_outbox_event(
        &self,
        scope: &OutboxScope,
        event_id: &EventId,
        lease_token: &str,
    ) -> Result<OutboxAckOutcome, StoreError> {
        // The free function documents and enforces the command invariants.
        ack_outbox_event(&self.pool, scope, event_id, lease_token).await
    }

    /// Records a failed delivery using this store's pool.
    ///
    /// # Errors
    /// Returns [`StoreError`] for invalid lease/error input, an out-of-range
    /// retry duration, or database failure.
    pub async fn fail_outbox_event(
        &self,
        scope: &OutboxScope,
        event_id: &EventId,
        lease_token: &str,
        error_code: &str,
        retry_after: Duration,
    ) -> Result<OutboxFailureOutcome, StoreError> {
        // The free function documents and enforces the command invariants.
        fail_outbox_event(
            &self.pool,
            scope,
            event_id,
            lease_token,
            error_code,
            retry_after,
        )
        .await
    }
}

fn parse_lease(row: &sqlx::postgres::PgRow) -> Result<OutboxLease, StoreError> {
    let event_id = EventId::parse(row.try_get::<String, _>("event_id")?)
        .map_err(|_| StoreError::CorruptData("outbox_event_id"))?;
    let tenant_id = TenantId::parse(row.try_get::<String, _>("tenant_id")?)
        .map_err(|_| StoreError::CorruptData("outbox_tenant_id"))?;
    let site_id = SiteId::parse(row.try_get::<String, _>("site_id")?)
        .map_err(|_| StoreError::CorruptData("outbox_site_id"))?;
    let envelope: Value = row.try_get("envelope")?;
    if !envelope.is_object() {
        return Err(StoreError::CorruptData("outbox_envelope"));
    }
    let delivery_attempts = row.try_get::<i32, _>("delivery_attempts")?;
    let delivery_attempts = u32::try_from(delivery_attempts)
        .map_err(|_| StoreError::CorruptData("outbox_delivery_attempts"))?;
    let lease_token: String = row.try_get("lease_token")?;
    validate_token(&lease_token).map_err(|_| StoreError::CorruptData("outbox_lease_token"))?;
    let last_error_code: Option<String> = row.try_get("last_error_code")?;
    if let Some(code) = &last_error_code {
        validate_error_code(code).map_err(|_| StoreError::CorruptData("outbox_last_error_code"))?;
    }
    let aggregate_ref: String = row.try_get("aggregate_ref")?;
    validate_text(&aggregate_ref).map_err(|_| StoreError::CorruptData("outbox_aggregate_ref"))?;
    let event_type: String = row.try_get("event_type")?;
    if validate_text(&event_type).is_err()
        || !event_type.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
    {
        return Err(StoreError::CorruptData("outbox_event_type"));
    }
    Ok(OutboxLease {
        event_id,
        tenant_id,
        site_id,
        aggregate_ref,
        event_type,
        envelope,
        created_at: row.try_get("created_at")?,
        delivery_attempts,
        lease_token,
        lease_until: row.try_get("lease_until")?,
        next_attempt_at: row.try_get("next_attempt_at")?,
        last_error_code,
    })
}

fn validate_token(token: &str) -> Result<(), StoreError> {
    validate_text(token)
}

fn validate_text(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(StoreError::InvalidCommand);
    }
    Ok(())
}

fn validate_event_type(value: &str) -> Result<(), StoreError> {
    if validate_text(value).is_err()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        })
    {
        return Err(StoreError::InvalidCommand);
    }
    Ok(())
}

fn validate_error_code(error_code: &str) -> Result<(), StoreError> {
    if error_code.is_empty()
        || error_code.len() > 128
        || !error_code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(StoreError::InvalidCommand);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_config_is_bounded() {
        assert!(OutboxLeaseConfig::new(1, 1, Duration::from_secs(1)).is_ok());
        assert!(OutboxLeaseConfig::new(0, 1, Duration::from_secs(1)).is_err());
        assert!(OutboxLeaseConfig::new(1, 0, Duration::from_secs(1)).is_err());
        assert!(OutboxLeaseConfig::new(1, 1, Duration::ZERO).is_err());
        assert!(OutboxLeaseConfig::new(1, 1, Duration::from_millis(1_001)).is_err());
    }

    #[test]
    fn lease_inputs_reject_control_values() {
        assert!(validate_token("lease\n").is_err());
        assert!(validate_error_code("publisher\0error").is_err());
        assert!(validate_error_code("DELIVERY_TIMEOUT").is_ok());
        assert!(validate_event_type("case.created").is_ok());
        assert!(validate_event_type("CASE.CREATED").is_err());
    }
}
